
import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


APP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = APP_DIR / "reports"

MODULES = [
    ("Crawler", "crawler.py"),
    ("SQL Injection", "test_sql_injection.py"),
    ("XSS", "test_xss.py"),
    ("HTTP Security", "test_http_security.py"),
]


def validate_local_target(target):
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Adres musi zaczynać się od http:// lub https://.")

    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            "Uruchamianie testów aktywnych jest ograniczone do localhost, "
            "127.0.0.1 lub ::1."
        )

    if parsed.username or parsed.password:
        raise ValueError("Adres nie może zawierać danych logowania.")

    return target.rstrip("/") + "/"


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def extract_test_results(data):
    """Wyciąga wyniki testów z typowych formatów raportów modułów."""
    if not isinstance(data, dict):
        return []

    if isinstance(data.get("results"), list):
        return [
            item
            for item in data["results"]
            if isinstance(item, dict)
            and str(item.get("status", item.get("result", ""))).upper()
            in {"PASS", "FAIL", "ERROR", "INFO"}
        ]

    status = str(data.get("status", data.get("result", ""))).upper()
    if status in {"PASS", "FAIL", "ERROR", "INFO"}:
        return [data]

    return []


def run_module(name, filename, target):
    script_path = APP_DIR / filename

    if not script_path.exists():
        print(f"\n[ERROR] Nie znaleziono modułu: {script_path}")
        return {
            "module": name,
            "script": filename,
            "status": "ERROR",
            "message": "Brak pliku modułu.",
            "return_code": None,
            "report_files": [],
        }

    before = {
        path.resolve(): path.stat().st_mtime_ns
        for path in REPORTS_DIR.glob("*.json")
    } if REPORTS_DIR.exists() else {}

    print(f"\n{'=' * 65}")
    print(f"URUCHAMIAM: {name}")
    print(f"Plik: {filename}")
    print(f"{'=' * 65}")

    try:
        completed = subprocess.run(
            [sys.executable, str(script_path), target],
            cwd=str(APP_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Moduł {name} przekroczył limit 180 sekund.")
        return {
            "module": name,
            "script": filename,
            "status": "ERROR",
            "message": "Przekroczono limit czasu.",
            "return_code": None,
            "report_files": [],
        }
    except OSError as exc:
        print(f"[ERROR] Nie udało się uruchomić modułu: {exc}")
        return {
            "module": name,
            "script": filename,
            "status": "ERROR",
            "message": str(exc),
            "return_code": None,
            "report_files": [],
        }

    if completed.stdout:
        print(completed.stdout.rstrip())

    if completed.stderr:
        print("--- STDERR ---")
        print(completed.stderr.rstrip())

    report_files = []
    if REPORTS_DIR.exists():
        for path in REPORTS_DIR.glob("*.json"):
            previous_mtime = before.get(path.resolve())

            try:
                current_mtime = path.stat().st_mtime_ns
            except OSError:
                continue

            if previous_mtime is None or current_mtime > previous_mtime:
                report_files.append(path)

    status = "COMPLETED" if completed.returncode == 0 else "ERROR"

    return {
        "module": name,
        "script": filename,
        "status": status,
        "return_code": completed.returncode,
        "report_files": [str(path) for path in report_files],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Uruchamia zestaw testów lokalnej aplikacji webowej."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="http://localhost/techstore-lab/",
        help="Adres lokalnej aplikacji do testowania.",
    )
    args = parser.parse_args()

    try:
        target = validate_local_target(args.target)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 2

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("FRAMEWORK DO TESTOWANIA BEZPIECZEŃSTWA APLIKACJI WEBOWYCH")
    print(f"Katalog: {APP_DIR}")
    print(f"Cel:     {target}")
    print("=" * 65)

    module_runs = []
    for name, filename in MODULES:
        module_runs.append(run_module(name, filename, target))

    test_results = []
    report_paths = set()

    for module_run in module_runs:
        for report_name in module_run.get("report_files", []):
            report_paths.add(Path(report_name))

    for report_path in sorted(report_paths):
        data = read_json(report_path)
        if data is None:
            continue

        for item in extract_test_results(data):
            test_results.append({
                "source_report": str(report_path),
                "module": data.get("module", report_path.stem),
                "test_type": item.get("test_type", item.get("test", "")),
                "url": item.get("url", ""),
                "status": str(
                    item.get("status", item.get("result", "INFO"))
                ).upper(),
                "explanation": item.get(
                    "explanation",
                    item.get("message", ""),
                ),
            })

    counts = {
        "PASS": sum(item["status"] == "PASS" for item in test_results),
        "FAIL": sum(item["status"] == "FAIL" for item in test_results),
        "ERROR": sum(item["status"] == "ERROR" for item in test_results),
        "INFO": sum(item["status"] == "INFO" for item in test_results),
    }

    module_errors = sum(
        module_run["status"] == "ERROR" for module_run in module_runs
    )

    if module_errors:
        assessment = "MODULE_ERRORS"
    elif counts["FAIL"]:
        assessment = "FINDINGS_REQUIRE_REVIEW"
    elif counts["ERROR"]:
        assessment = "TEST_ERRORS"
    else:
        assessment = "NO_FINDINGS_IN_EXECUTED_CHECKS"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"full_scan_{timestamp}.json"

    report = {
        "framework": "Framework do testowania bezpieczeństwa aplikacji webowych",
        "target": target,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "assessment": assessment,
        "module_summary": {
            "total": len(module_runs),
            "completed": sum(
                item["status"] == "COMPLETED" for item in module_runs
            ),
            "errors": module_errors,
        },
        "test_summary": {
            "total": len(test_results),
            **{key.lower(): value for key, value in counts.items()},
        },
        "modules": [
            {
                "module": item["module"],
                "script": item["script"],
                "status": item["status"],
                "return_code": item["return_code"],
                "report_files": item["report_files"],
                "message": item.get("message", ""),
            }
            for item in module_runs
        ],
        "results": test_results,
    }

    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 65)
    print("PODSUMOWANIE CAŁEGO SKANOWANIA")
    print(f"Moduły ukończone: {report['module_summary']['completed']}/"
          f"{report['module_summary']['total']}")
    print(f"Moduły z błędami: {module_errors}")
    print(f"Testy PASS:       {counts['PASS']}")
    print(f"Testy FAIL:       {counts['FAIL']}")
    print(f"Testy ERROR:      {counts['ERROR']}")
    print(f"Testy INFO:       {counts['INFO']}")
    print(f"Ocena:            {assessment}")
    print(f"Raport:           {report_path}")
    print("=" * 65)

    print(
        "\nUwaga: FAIL oznacza wynik wymagający analizy. "
        "Nie każdy brak nagłówka lub tokenu jest samodzielnym dowodem podatności."
    )

    return 0 if module_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
