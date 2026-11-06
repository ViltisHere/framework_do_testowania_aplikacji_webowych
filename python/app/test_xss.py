
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


DEFAULT_TARGET = "http://localhost/techstore-lab/"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

REPORTS_DIR = Path(__file__).resolve().parent / "reports"

# Nieszkodliwy payload testowy.
XSS_PAYLOAD = "<script>alert(1)</script>"
ESCAPED_PAYLOAD = "&lt;script&gt;alert(1)&lt;/script&gt;"


def normalize_target(target_url):
    """Sprawdza lokalny adres bazowy aplikacji."""
    parsed = urlparse(target_url)

    if parsed.scheme != "http":
        raise ValueError(
            "Test XSS dopuszcza tylko lokalny adres HTTP."
        )

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "Test XSS jest ograniczony do localhost."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "Adres URL nie może zawierać danych logowania."
        )

    if parsed.query or parsed.fragment:
        raise ValueError(
            "Adres bazowy nie może zawierać parametrów "
            "zapytania ani fragmentu URL."
        )

    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Nieprawidłowy port w adresie URL.")

    return target_url.rstrip("/") + "/"


def run_test(target):
    target_url = urljoin(target, "checkout.php")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    result = {
        "test": "XSS - pole notes formularza zamówienia",
        "url": target_url,
        "target": target,
        "payload": XSS_PAYLOAD,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    session = requests.Session()

    try:
        # Krok 1: pobranie formularza i sesyjnego tokenu CSRF.
        get_response = session.get(
            target_url,
            timeout=5,
            allow_redirects=True,
        )

        if get_response.status_code != 200:
            result.update({
                "result": "ERROR",
                "description": (
                    "Nie udało się pobrać formularza. "
                    f"HTTP {get_response.status_code}."
                ),
                "http_status": get_response.status_code,
            })
        else:
            soup = BeautifulSoup(
                get_response.text,
                "html.parser"
            )

            token_input = soup.find(
                "input",
                attrs={"name": "csrf_token"}
            )

            if (
                token_input is None
                or not token_input.get("value")
            ):
                result.update({
                    "result": "ERROR",
                    "description": (
                        "Nie znaleziono tokenu CSRF w formularzu. "
                        "Test XSS nie może być przeprowadzony."
                    ),
                })
            else:
                csrf_token = token_input["value"]

                # Brak zgody na regulamin celowo zatrzyma zapis
                # zamówienia, ale pozwoli sprawdzić odpowiedź HTML.
                form_data = {
                    "csrf_token": csrf_token,
                    "first_name": "Jan",
                    "last_name": "Testowy",
                    "email": "test@example.com",
                    "phone": "123456789",
                    "street": "Testowa 1",
                    "postal_code": "00-001",
                    "city": "Warszawa",
                    "product_id": "1",
                    "quantity": "1",
                    "delivery": "courier",
                    "payment": "transfer",
                    "notes": XSS_PAYLOAD,
                    # Celowo bez pola terms.
                }

                response = session.post(
                    target_url,
                    data=form_data,
                    timeout=5,
                    allow_redirects=False,
                )

                escaped_found = (
                    ESCAPED_PAYLOAD in response.text
                )
                raw_found = XSS_PAYLOAD in response.text

                # Nie uznajemy odpowiedzi 403 za test XSS zakończony
                # powodzeniem — oznaczałaby blokadę CSRF.
                passed = (
                    response.status_code == 200
                    and escaped_found
                    and not raw_found
                )

                result.update({
                    "http_status": response.status_code,
                    "initial_http_status": get_response.status_code,
                    "csrf_token_found": True,
                    "escaped_payload_found": escaped_found,
                    "raw_payload_found": raw_found,
                    "result": "PASS" if passed else "FAIL",
                    "description": (
                        "Payload został bezpiecznie zakodowany "
                        "w odpowiedzi HTML."
                        if passed
                        else (
                            "Nie potwierdzono oczekiwanego kodowania. "
                            "Sprawdź status HTTP i odpowiedź formularza."
                        )
                    ),
                })

    except requests.RequestException as exc:
        result.update({
            "result": "ERROR",
            "description": (
                f"Nie udało się połączyć z aplikacją: {exc}"
            ),
        })

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"xss_{timestamp}.json"

    report_path.write_text(
        json.dumps(result, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print("=== Test XSS ===")
    print(f"Cel: {target}")
    print(f"URL testu: {target_url}")
    print(f"Wynik: {result['result']}")
    print(f"Opis: {result['description']}")

    if "http_status" in result:
        print(f"HTTP POST: {result['http_status']}")

    if "escaped_payload_found" in result:
        print(
            "Zakodowany payload znaleziony: "
            f"{result['escaped_payload_found']}"
        )
        print(
            "Surowy payload znaleziony: "
            f"{result['raw_payload_found']}"
        )

    print(f"Raport: {report_path}")

    session.close()


def main():
    if len(sys.argv) > 2:
        print("Użycie: python test_xss.py [adres_docelowy]")
        sys.exit(2)

    requested_target = (
        sys.argv[1].strip()
        if len(sys.argv) == 2
        else DEFAULT_TARGET
    )

    try:
        target = normalize_target(requested_target)
    except ValueError as error:
        print(f"[BŁĄD] {error}")
        sys.exit(2)

    run_test(target)


if __name__ == "__main__":
    main()
