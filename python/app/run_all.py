
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


APP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = APP_DIR / "reports"

MODULES = [
    ("Crawler i generator testów", "test_generator.py"),
    ("SQL Injection", "test_sql_injection.py"),
    ("XSS", "test_xss.py"),
    ("HTTP Security", "test_http_security.py"),
]


def validate_target(target_url):
    """Sprawdza, czy adres wskazuje na lokalną aplikację HTTP."""
    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Dozwolone są wyłącznie adresy HTTP i HTTPS.")

    hostname = (parsed.hostname or "").lower()

    allowed_hosts = {"localhost", "127.0.0.1", "::1"}

    if hostname not in allowed_hosts:
        raise ValueError(
            "Framework może testować wyłącznie aplikacje lokalne."
        )

    return target_url.rstrip("/") + "/"


def load_module_report(module_name, started_at):
    """Wyszukuje raport modułu utworzony podczas bieżącego uruchomienia."""
    if not REPORTS_DIR.exists():
        return None

    report_patterns = {
        "Crawler i generator testów": "generated_tests_*.json",
        "SQL Injection": "sqli_*.json",
        "XSS": "*xss*.json",
        "HTTP Security": "*http*security*.json",
    }

    pattern = report_patterns.get(module_name)

    if not pattern:
        return None

    reports = sorted(
        REPORTS_DIR.glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    for report_path in reports:
        if report_path.stat().st_mtime >= started_at:
            try:
                with report_path.open("r", encoding="utf-8") as file:
                    return {
                        "file": str(report_path),
                        "data": json.load(file),
                    }
            except (OSError, json.JSONDecodeError):
                continue

    return None


def extract_status_counts(report_data):
    """Zlicza statusy testów zapisane w raporcie modułu."""
    counts = {
        "PASS": 0,
        "FAIL": 0,
        "ERROR": 0,
        "INFO": 0,
    }

    if not isinstance(report_data, dict):
        return counts

    # Najpierw sprawdzamy, czy raport zawiera gotowe podsumowanie.
    summary = report_data.get("summary")

    if isinstance(summary, dict):
        found_summary = False

        for status in counts:
            value = summary.get(status)

            if isinstance(value, int):
                counts[status] = value
                found_summary = True

        if found_summary:
            return counts

    # Jeśli nie ma podsumowania, szukamy statusów
    # poszczególnych testów w strukturze raportu.
    def walk(node, is_root=False):
        if isinstance(node, dict):
            if not is_root:
                status = str(node.get("status", "")).upper()

                if status in counts:
                    counts[status] += 1

            for value in node.values():
                walk(value)

        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(report_data, is_root=True)

    return counts


def run_module(module_name, script_name, target_url):
    """Uruchamia pojedynczy moduł frameworka."""
    script_path = APP_DIR / script_name

    print("\n" + "=" * 60)
    print(f"MODUŁ: {module_name}")
    print("=" * 60)

    if not script_path.exists():
        print(f"[ERROR] Nie znaleziono pliku: {script_name}")

        return {
            "module": module_name,
            "script": script_name,
            "return_code": 1,
            "status": "ERROR",
            "output": "",
            "report": None,
            "test_summary": None,
        }

    command = [
        sys.executable,
        str(script_path),
        target_url,
    ]

    started_at = datetime.now().timestamp()

    try:
        process = subprocess.run(
            command,
            cwd=APP_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )

        output = process.stdout

        if process.stderr:
            output += "\n" + process.stderr

        print(output)

        report = load_module_report(module_name, started_at)
        test_summary = None

        if process.returncode != 0:
            status = "FAIL"

        elif report is not None:
            test_summary = extract_status_counts(report["data"])

            if test_summary["FAIL"] > 0:
                status = "FAIL"
            elif test_summary["ERROR"] > 0:
                status = "ERROR"
            else:
                status = "PASS"

        else:
            status = "PASS"

        return {
            "module": module_name,
            "script": script_name,
            "return_code": process.returncode,
            "status": status,
            "output": output,
            "report": report,
            "test_summary": test_summary,
        }

    except subprocess.TimeoutExpired:
        print("[ERROR] Przekroczono limit czasu wykonywania modułu.")

        return {
            "module": module_name,
            "script": script_name,
            "return_code": 1,
            "status": "ERROR",
            "output": "Timeout",
            "report": None,
            "test_summary": None,
        }

    except OSError as error:
        print(f"[ERROR] Nie udało się uruchomić modułu: {error}")

        return {
            "module": module_name,
            "script": script_name,
            "return_code": 1,
            "status": "ERROR",
            "output": str(error),
            "report": None,
            "test_summary": None,
        }


def main():
    if len(sys.argv) < 2:
        print(
            "Użycie: python run_all.py "
            "http://localhost/techstore/"
        )
        return 1

    try:
        target_url = validate_target(sys.argv[1].strip())
    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("FRAMEWORK DO AUTOMATYCZNEGO TESTOWANIA APLIKACJI WEBOWYCH")
    print("=" * 60)
    print(f"Testowana aplikacja: {target_url}")

    results = []

    for module_name, script_name in MODULES:
        result = run_module(
            module_name,
            script_name,
            target_url,
        )
        results.append(result)

    summary = {
        "PASS": 0,
        "FAIL": 0,
        "ERROR": 0,
    }

    for result in results:
        if result["status"] in summary:
            summary[result["status"]] += 1

    report_data = {
        "module": "Full scan",
        "target": target_url,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "modules_count": len(results),
        "summary": summary,
        "modules": results,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"full_scan_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print("\n" + "=" * 60)
    print("PODSUMOWANIE")
    print("=" * 60)

    for result in results:
        print(f"{result['module']}: {result['status']}")

        if result["test_summary"] is not None:
            counts = result["test_summary"]
            print(
                f"  Wyniki testów: PASS={counts['PASS']}, "
                f"FAIL={counts['FAIL']}, "
                f"ERROR={counts['ERROR']}, "
                f"INFO={counts['INFO']}"
            )

    print("\nLiczba modułów:")
    print(f"PASS:  {summary['PASS']}")
    print(f"FAIL:  {summary['FAIL']}")
    print(f"ERROR: {summary['ERROR']}")

    print(f"\nRaport zbiorczy zapisano w:\n{report_path}")

    return 0 if summary["ERROR"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
