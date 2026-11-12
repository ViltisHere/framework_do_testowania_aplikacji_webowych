
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from crawler import crawl


APP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = APP_DIR / "reports"

XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "1 OR 1=1"
INVALID_CSRF_TOKEN = "invalid_csrf_token_generated_by_framework"

TEXT_TYPES = {
    "text",
    "textarea",
    "search",
    "email",
    "url",
}

SQLI_FIELD_KEYWORDS = {
    "id",
    "product_id",
    "category_id",
    "user_id",
    "search",
    "query",
}


def same_local_origin(url, target):
    """Sprawdza, czy adres formularza należy do badanej witryny."""
    parsed_url = urlparse(url)
    parsed_target = urlparse(target)

    return (
        parsed_url.scheme == parsed_target.scheme
        and parsed_url.hostname == parsed_target.hostname
        and (parsed_url.port or 80) == (parsed_target.port or 80)
    )


def generate_tests(forms, target):
    """Generuje scenariusze testowe na podstawie odnalezionych formularzy."""
    generated_tests = []

    for form_index, form in enumerate(forms, start=1):
        action_url = form.get("action_url", "")
        method = form.get("method", "GET").upper()
        fields = form.get("fields", [])

        if not action_url or not same_local_origin(action_url, target):
            continue

        form_id = f"FORM-{form_index}"

        # Generowanie testu XSS dla pól tekstowych.
        for field in fields:
            field_name = field.get("name", "")
            field_type = field.get("type", "").lower()

            if (
                field_type in TEXT_TYPES
                and field_name.lower() not in {
                    "csrf_token",
                    "password",
                    "passwd",
                }
            ):
                generated_tests.append({
                    "test_id": f"XSS-{len(generated_tests) + 1:03d}",
                    "category": "XSS",
                    "form_id": form_id,
                    "page_url": form.get("page_url", ""),
                    "action_url": action_url,
                    "method": method,
                    "field": field_name,
                    "payload": XSS_PAYLOAD,
                    "expected_behavior": (
                        "Dane powinny zostać zakodowane przed "
                        "umieszczeniem w odpowiedzi HTML."
                    ),
                    "status": "GENERATED",
                })

        # Generowanie testów SQL Injection dla pól związanych
        # z identyfikatorami i wyszukiwaniem.
        for field in fields:
            field_name = field.get("name", "").lower()
            field_type = field.get("type", "").lower()

            if (
                field_name in SQLI_FIELD_KEYWORDS
                or field_name.endswith("_id")
                or field_type == "number"
            ):
                generated_tests.append({
                    "test_id": f"SQLI-{len(generated_tests) + 1:03d}",
                    "category": "SQL_INJECTION",
                    "form_id": form_id,
                    "page_url": form.get("page_url", ""),
                    "action_url": action_url,
                    "method": method,
                    "field": field.get("name", ""),
                    "payload": SQLI_PAYLOAD,
                    "expected_behavior": (
                        "Aplikacja powinna bezpiecznie obsłużyć "
                        "nieprawidłową wartość parametru."
                    ),
                    "status": "GENERATED",
                })

        # Generowanie scenariusza CSRF dla formularzy POST.
        if method == "POST":
            csrf_fields = [
                field for field in fields
                if "csrf" in field.get("name", "").lower()
                or "token" in field.get("name", "").lower()
            ]

            if csrf_fields:
                csrf_field_name = csrf_fields[0]["name"]
                payload_description = "Nieprawidłowy token CSRF"
            else:
                csrf_field_name = "csrf_token"
                payload_description = "Brak tokenu CSRF"

            generated_tests.append({
                "test_id": f"CSRF-{len(generated_tests) + 1:03d}",
                "category": "CSRF",
                "form_id": form_id,
                "page_url": form.get("page_url", ""),
                "action_url": action_url,
                "method": method,
                "field": csrf_field_name,
                "payload": INVALID_CSRF_TOKEN,
                "payload_description": payload_description,
                "expected_behavior": (
                    "Serwer powinien odrzucić żądanie "
                    "z nieprawidłowym lub brakującym tokenem CSRF."
                ),
                "status": "GENERATED",
            })

    return generated_tests


def main():
    if len(sys.argv) < 2:
        print("Użycie: python test_generator.py http://localhost/techstore/")
        return 1

    target = sys.argv[1].strip()

    try:
        scan_result = crawl(target, max_pages=30)
    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1

    forms = scan_result.get("forms", [])
    generated_tests = generate_tests(forms, target)

    counts = {
        "XSS": sum(
            test["category"] == "XSS"
            for test in generated_tests
        ),
        "SQL_INJECTION": sum(
            test["category"] == "SQL_INJECTION"
            for test in generated_tests
        ),
        "CSRF": sum(
            test["category"] == "CSRF"
            for test in generated_tests
        ),
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"generated_tests_{timestamp}.json"

    report = {
        "module": "Test Generator",
        "target": target,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "pages_scanned": scan_result.get("pages_scanned", 0),
        "forms_found": len(forms),
        "generated_tests_count": len(generated_tests),
        "generated_tests_summary": counts,
        "generated_tests": generated_tests,
    }

    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n=== GENEROWANIE SCENARIUSZY TESTOWYCH ===")
    print(f"Adres aplikacji: {target}")
    print(f"Przeskanowane strony: {scan_result.get('pages_scanned', 0)}")
    print(f"Znalezione formularze: {len(forms)}")
    print(f"Wygenerowane scenariusze: {len(generated_tests)}")
    print(f"Scenariusze XSS: {counts['XSS']}")
    print(f"Scenariusze SQL Injection: {counts['SQL_INJECTION']}")
    print(f"Scenariusze CSRF: {counts['CSRF']}")
    print(f"Raport zapisano w: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
