
import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


TIMEOUT = 8
MAX_FORM_PAGES = 8

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Ogranicza źródła skryptów i innych zasobów ładowanych przez stronę."
    ),
    "X-Content-Type-Options": (
        "Powinien mieć wartość nosniff, aby ograniczyć błędne interpretowanie typów MIME."
    ),
    "X-Frame-Options": (
        "Ogranicza możliwość osadzania strony w ramce i pomaga chronić przed clickjackingiem."
    ),
    "Referrer-Policy": (
        "Kontroluje informacje o adresie strony przekazywane w nagłówku Referer."
    ),
    "Permissions-Policy": (
        "Pozwala ograniczać dostęp strony do wybranych funkcji przeglądarki."
    ),
}

CSRF_FIELD_PATTERN = re.compile(
    r"(csrf|xsrf|_token|authenticity_token)",
    re.IGNORECASE,
)


def validate_local_target(target):
    """Dopuszcza wyłącznie lokalne adresy HTTP/HTTPS."""
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Adres musi zaczynać się od http:// lub https://.")

    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            "Ten moduł jest obecnie ograniczony do localhost, 127.0.0.1 lub ::1."
        )

    if parsed.username or parsed.password:
        raise ValueError("Adres nie może zawierać danych logowania.")

    return target.rstrip("/") + "/"


def add_result(results, test_type, url, status, explanation, **details):
    item = {
        "test_type": test_type,
        "url": url,
        "status": status,
        "explanation": explanation,
    }
    item.update(details)
    results.append(item)

    print(f"[{status}] {test_type}: {explanation}")
    print(f"       URL: {url}")


def check_security_headers(session, url, results):
    """Sprawdza nagłówki odpowiedzi HTTP."""
    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        add_result(
            results,
            "HTTP_HEADERS",
            url,
            "ERROR",
            f"Nie udało się pobrać strony: {exc}",
        )
        return None

    headers = response.headers

    # HSTS ma zastosowanie do połączeń HTTPS, nie do zwykłego HTTP na localhost.
    if urlparse(response.url).scheme == "https":
        if "Strict-Transport-Security" in headers:
            add_result(
                results,
                "SECURITY_HEADER",
                response.url,
                "PASS",
                "Nagłówek Strict-Transport-Security jest obecny.",
                header="Strict-Transport-Security",
                value=headers.get("Strict-Transport-Security"),
            )
        else:
            add_result(
                results,
                "SECURITY_HEADER",
                response.url,
                "FAIL",
                "Brak nagłówka Strict-Transport-Security dla HTTPS.",
                header="Strict-Transport-Security",
            )

    for header, description in SECURITY_HEADERS.items():
        value = headers.get(header)

        if value:
            add_result(
                results,
                "SECURITY_HEADER",
                response.url,
                "PASS",
                f"Obecny nagłówek {header}.",
                header=header,
                value=value,
                purpose=description,
            )
        else:
            add_result(
                results,
                "SECURITY_HEADER",
                response.url,
                "FAIL",
                f"Brak nagłówka {header}. {description}",
                header=header,
                purpose=description,
            )

    # Secure ma znaczenie przy HTTPS. Nie zgłaszamy jego braku jako
    # problemu na lokalnej stronie działającej przez zwykłe HTTP.
    cookie_headers = []
    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_headers = raw_headers.getlist("Set-Cookie")

    if not cookie_headers:
        add_result(
            results,
            "COOKIE_FLAGS",
            response.url,
            "INFO",
            "Odpowiedź nie ustawiła ciasteczek; nie ma flag do sprawdzenia.",
        )
    else:
        for cookie in cookie_headers:
            cookie_name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()

            for flag in ("httponly", "samesite"):
                if flag == "httponly":
                    present = "httponly" in flags
                    label = "HttpOnly"
                else:
                    present = "samesite=" in flags
                    label = "SameSite"

                add_result(
                    results,
                    "COOKIE_FLAG",
                    response.url,
                    "PASS" if present else "FAIL",
                    (
                        f"Ciasteczko {cookie_name}: obecna flaga {label}."
                        if present
                        else f"Ciasteczko {cookie_name}: brak flagi {label}."
                    ),
                    cookie_name=cookie_name,
                    flag=label,
                )

            if urlparse(response.url).scheme == "https":
                secure_present = "secure" in flags.split(";")

                add_result(
                    results,
                    "COOKIE_FLAG",
                    response.url,
                    "PASS" if secure_present else "FAIL",
                    (
                        f"Ciasteczko {cookie_name}: obecna flaga Secure."
                        if secure_present
                        else f"Ciasteczko {cookie_name}: brak flagi Secure przy HTTPS."
                    ),
                    cookie_name=cookie_name,
                    flag="Secure",
                )

    return response


def check_api_me(session, url, results):
    """Sprawdza, czy endpoint użytkownika wymaga uwierzytelnienia."""
    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        add_result(
            results,
            "API_AUTH",
            url,
            "ERROR",
            f"Nie udało się sprawdzić endpointu: {exc}",
        )
        return

    if response.status_code in (401, 403):
        add_result(
            results,
            "API_AUTH",
            url,
            "PASS",
            f"Endpoint bez logowania zwrócił HTTP {response.status_code}.",
            http_status=response.status_code,
        )
    elif response.status_code in (301, 302, 303, 307, 308):
        add_result(
            results,
            "API_AUTH",
            url,
            "INFO",
            "Endpoint przekierowuje; należy sprawdzić, czy przekierowanie prowadzi do logowania.",
            http_status=response.status_code,
            location=response.headers.get("Location"),
        )
    elif response.status_code == 200:
        add_result(
            results,
            "API_AUTH",
            url,
            "FAIL",
            "Endpoint zwrócił HTTP 200 bez logowania. Sprawdź, czy ujawnia dane użytkownika.",
            http_status=response.status_code,
        )
    else:
        add_result(
            results,
            "API_AUTH",
            url,
            "INFO",
            f"Endpoint zwrócił HTTP {response.status_code}; wymaga ręcznej interpretacji.",
            http_status=response.status_code,
        )


def check_api_products(session, url, results):
    """Sprawdza status i poprawność składni JSON endpointu produktów."""
    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        add_result(
            results,
            "API_JSON",
            url,
            "ERROR",
            f"Nie udało się pobrać endpointu: {exc}",
        )
        return

    if response.status_code != 200:
        add_result(
            results,
            "API_JSON",
            url,
            "FAIL",
            f"Oczekiwano HTTP 200, otrzymano HTTP {response.status_code}.",
            http_status=response.status_code,
        )
        return

    content_type = response.headers.get("Content-Type", "").lower()

    if "application/json" not in content_type:
        add_result(
            results,
            "API_JSON",
            url,
            "FAIL",
            f"Nieprawidłowy Content-Type: {content_type or 'brak nagłówka'}.",
            http_status=response.status_code,
            content_type=content_type,
        )
        return

    try:
        data = response.json()
    except ValueError:
        add_result(
            results,
            "API_JSON",
            url,
            "FAIL",
            "Odpowiedź ma Content-Type JSON, ale nie zawiera poprawnego JSON.",
            http_status=response.status_code,
        )
        return

    add_result(
        results,
        "API_JSON",
        url,
        "PASS",
        "Endpoint zwrócił HTTP 200 oraz poprawny JSON.",
        http_status=response.status_code,
        content_type=content_type,
        json_type=type(data).__name__,
    )


def check_csrf_indicators(session, base_url, results):
    """
    Pasywnie przegląda kilka stron tej samej witryny.
    Nie wysyła formularzy i nie potwierdza podatności CSRF.
    """
    pages_to_check = [
        base_url,
        urljoin(base_url, "checkout.php"),
        urljoin(base_url, "login.php"),
        urljoin(base_url, "register.php"),
    ]

    visited = set()
    forms_checked = 0

    for page_url in pages_to_check:
        if page_url in visited or forms_checked >= MAX_FORM_PAGES:
            continue

        visited.add(page_url)

        try:
            response = session.get(page_url, timeout=TIMEOUT)
        except requests.RequestException as exc:
            add_result(
                results,
                "CSRF_INDICATOR",
                page_url,
                "ERROR",
                f"Nie udało się pobrać strony do sprawdzenia formularzy: {exc}",
            )
            continue

        if response.status_code >= 400:
            add_result(
                results,
                "CSRF_INDICATOR",
                page_url,
                "INFO",
                f"Strona zwróciła HTTP {response.status_code}; pominięto analizę formularzy.",
                http_status=response.status_code,
            )
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            forms_checked += 1
            method = form.get("method", "get").strip().lower()

            if method != "post":
                continue

            hidden_inputs = form.find_all("input", {"type": "hidden"})
            token_found = any(
                CSRF_FIELD_PATTERN.search(
                    (field.get("name") or "") + " " + (field.get("id") or "")
                )
                for field in hidden_inputs
            )

            if token_found:
                add_result(
                    results,
                    "CSRF_INDICATOR",
                    response.url,
                    "PASS",
                    "Formularz POST zawiera pole przypominające token CSRF.",
                    form_action=form.get("action", ""),
                    method=method,
                )
            else:
                add_result(
                    results,
                    "CSRF_INDICATOR",
                    response.url,
                    "INFO",
                    (
                        "Formularz POST nie zawiera rozpoznanego pola tokenu CSRF. "
                        "To heurystyka — ochrona może być realizowana inaczej."
                    ),
                    form_action=form.get("action", ""),
                    method=method,
                )

            if forms_checked >= MAX_FORM_PAGES:
                break

    if forms_checked == 0:
        add_result(
            results,
            "CSRF_INDICATOR",
            base_url,
            "INFO",
            "Nie znaleziono formularzy do analizy na sprawdzonych stronach.",
        )


def main():
    parser = argparse.ArgumentParser(
        description="Pasywne sprawdzanie podstawowych zabezpieczeń HTTP i API."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="http://localhost/techstore-lab/",
        help="Lokalny adres bazowy aplikacji.",
    )
    args = parser.parse_args()

    try:
        base_url = validate_local_target(args.target)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 2

    reports_dir = Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"http_security_{timestamp}.json"

    results = []
    session = requests.Session()
    session.headers.update(
        {"User-Agent": "LocalWebSecurityFramework/1.0"}
    )

    print("=" * 65)
    print("TESTY NAGŁÓWKÓW HTTP, CIASTECZEK, API I WSKAŹNIKÓW CSRF")
    print(f"Cel: {base_url}")
    print("=" * 65)

    # Strona główna oraz wybrane endpointy — wyłącznie żądania GET.
    check_security_headers(session, base_url, results)
    check_security_headers(
        session,
        urljoin(base_url, "api/me.php"),
        results,
    )
    check_security_headers(
        session,
        urljoin(base_url, "api/products.php"),
        results,
    )

    check_api_me(
        session,
        urljoin(base_url, "api/me.php"),
        results,
    )
    check_api_products(
        session,
        urljoin(base_url, "api/products.php"),
        results,
    )
    check_csrf_indicators(session, base_url, results)

    report = {
        "module": "http_security",
        "target": base_url,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "method": "passive_checks_and_safe_get_requests",
        "summary": {
            "total": len(results),
            "pass": sum(r["status"] == "PASS" for r in results),
            "fail": sum(r["status"] == "FAIL" for r in results),
            "error": sum(r["status"] == "ERROR" for r in results),
            "info": sum(r["status"] == "INFO" for r in results),
        },
        "results": results,
    }

    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 65)
    print("PODSUMOWANIE MODUŁU HTTP")
    print(f"PASS:  {report['summary']['pass']}")
    print(f"FAIL:  {report['summary']['fail']}")
    print(f"ERROR: {report['summary']['error']}")
    print(f"INFO:  {report['summary']['info']}")
    print(f"Raport: {report_path}")
    print("=" * 65)

    return 0


if __name__ == "__main__":
    sys.exit(main())
