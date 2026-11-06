
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests


DEFAULT_TARGET = "http://localhost/techstore-lab/"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

PAYLOAD = "1 OR 1=1"
TIMEOUT = 5
REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def normalize_target(target_url):
    """Sprawdza lokalny adres bazowy aplikacji."""
    parsed = urlparse(target_url)

    if parsed.scheme != "http":
        raise ValueError(
            "Test SQL Injection dopuszcza tylko lokalny adres HTTP."
        )

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "Test SQL Injection jest ograniczony do localhost."
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


def build_endpoints(target):
    """Buduje adresy endpointów testowych względem celu."""
    base_url = urljoin(target, "lab/sql-injection/")

    return {
        "bezpieczny": {
            "url": base_url,
            "expected": "reject_payload",
        },
        "podatny_lab": {
            "url": urljoin(base_url, "vulnerable.php"),
            "expected": "detect_injection",
        },
    }


def validate_local_url(url):
    parsed = urlparse(url)

    if (
        parsed.scheme != "http"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            f"Dozwolony jest tylko lokalny adres HTTP: {url}"
        )


def send_request(session, url, product_id):
    validate_local_url(url)

    try:
        response = session.get(
            url,
            params={"id": product_id},
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        return {
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "response_length": len(response.text),
            "body": response.text,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "status_code": None,
            "content_type": None,
            "response_length": 0,
            "body": "",
            "error": str(error),
        }


def count_json_records(body):
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if isinstance(data, list):
        return len(data)

    if isinstance(data, dict):
        for key in ("products", "results", "items", "rows", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)

    return None


def assess_result(baseline, attack, expected):
    if baseline["error"] or attack["error"]:
        return "ERROR", "Nie udało się wykonać wszystkich żądań."

    if baseline["status_code"] != 200:
        return "ERROR", "Zwykłe żądanie nie zakończyło się kodem HTTP 200."

    if expected == "reject_payload":
        if attack["status_code"] in (400, 403, 422):
            return "PASS", "Podejrzana wartość została odrzucona."

        return (
            "FAIL",
            "Endpoint nie odrzucił payloadu oczekiwanym kodem HTTP.",
        )

    if expected == "detect_injection":
        baseline_count = count_json_records(baseline["body"])
        attack_count = count_json_records(attack["body"])

        if (
            attack["status_code"] == 200
            and baseline_count is not None
            and attack_count is not None
            and attack_count > baseline_count
        ):
            return (
                "FAIL",
                "W odpowiedzi wykryto więcej rekordów niż w teście bazowym.",
            )

        return (
            "ERROR",
            "Nie udało się jednoznacznie potwierdzić scenariusza "
            "laboratoryjnego. Sprawdź odpowiedzi endpointu.",
        )

    return "ERROR", "Nieznany typ oczekiwanego zachowania."


def public_response_data(response):
    """Usuwa pełną treść odpowiedzi przed zapisaniem raportu."""
    return {
        "status_code": response["status_code"],
        "content_type": response["content_type"],
        "response_length": response["response_length"],
        "error": response["error"],
    }


def test_endpoint(session, name, config):
    url = config["url"]

    print(f"\nTest endpointu: {name}")
    print(f"URL: {url}")

    baseline = send_request(session, url, "1")
    attack = send_request(session, url, PAYLOAD)

    status, explanation = assess_result(
        baseline,
        attack,
        config["expected"],
    )

    result = {
        "endpoint_name": name,
        "url": url,
        "test_type": "SQL Injection",
        "payload": PAYLOAD,
        "expected_behavior": config["expected"],
        "baseline": public_response_data(baseline),
        "attack": public_response_data(attack),
        "baseline_json_records": count_json_records(baseline["body"]),
        "attack_json_records": count_json_records(attack["body"]),
        "status": status,
        "explanation": explanation,
    }

    print(f"  HTTP bazowy: {baseline['status_code']}")
    print(f"  HTTP payloadu: {attack['status_code']}")
    print(f"  Wynik: {status}")
    print(f"  Opis: {explanation}")

    return result


def main():
    if len(sys.argv) > 2:
        print("Użycie: python test_sql_injection.py [adres_docelowy]")
        sys.exit(2)

    requested_target = (
        sys.argv[1].strip()
        if len(sys.argv) == 2
        else DEFAULT_TARGET
    )

    try:
        target = normalize_target(requested_target)
        endpoints = build_endpoints(target)
    except ValueError as error:
        print(f"[BŁĄD] {error}")
        sys.exit(2)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    with requests.Session() as session:
        session.headers.update({
            "User-Agent": "TechStoreSecurityFramework/0.3"
        })

        for name, config in endpoints.items():
            results.append(test_endpoint(session, name, config))

    report = {
        "scan_type": "SQL Injection",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "results": results,
        "summary": {
            "pass": sum(r["status"] == "PASS" for r in results),
            "fail": sum(r["status"] == "FAIL" for r in results),
            "error": sum(r["status"] == "ERROR" for r in results),
        },
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"sqli_{timestamp}.json"

    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n=== Podsumowanie ===")
    print(f"Cel: {target}")
    print(f"PASS:  {report['summary']['pass']}")
    print(f"FAIL:  {report['summary']['fail']}")
    print(f"ERROR: {report['summary']['error']}")
    print(f"Raport: {report_path}")


if __name__ == "__main__":
    main()
