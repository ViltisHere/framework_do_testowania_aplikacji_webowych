import json
import sys
from datetime import datetime
from pathlib import Path

from crawler import crawl


REPORTS_DIR = Path(__file__).parent / "reports"

DEFAULT_TARGET = "http://localhost/techstore-lab/"


def main():
    # Jeśli podano adres jako argument, użyj go.
    # W przeciwnym razie zapytaj użytkownika.
    if len(sys.argv) > 1:
        target = sys.argv[1].strip()
    else:
        target = input(
            "Podaj lokalny adres do zbadania "
            f"(domyślnie {DEFAULT_TARGET}): "
        ).strip()

        if not target:
            target = DEFAULT_TARGET

    try:
        result = crawl(target, max_pages=30)
    except ValueError as error:
        print(f"[BŁĄD] {error}")
        sys.exit(1)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"scan_{timestamp}.json"

    report_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n=== Wyniki skanowania ===")
    print(f"Adres docelowy: {target}")
    print(f"Strony odwiedzone: {result['pages_scanned']}")
    print(f"Znalezione formularze: {result['forms_found']}")
    print(f"Błędy pobierania: {len(result['errors'])}")
    print(f"Raport zapisano w: {report_path}")


if __name__ == "__main__":
    main()
