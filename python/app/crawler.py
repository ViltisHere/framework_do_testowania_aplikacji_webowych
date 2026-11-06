from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse

import requests
from bs4 import BeautifulSoup

from form_analyzer import analyze_forms


ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_target(target_url):
    parsed = urlparse(target_url)

    if parsed.scheme != "http":
        raise ValueError("Na tym etapie dozwolone są tylko lokalne adresy HTTP.")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "Skaner może obecnie badać tylko localhost lub 127.0.0.1."
        )

    if parsed.username or parsed.password:
        raise ValueError("Adres URL nie może zawierać danych logowania.")

    return parsed


def crawl(target_url, max_pages=30):
    parsed_target = validate_target(target_url)
    origin = (
        parsed_target.scheme,
        parsed_target.hostname,
        parsed_target.port or 80,
    )

    queue = deque([target_url])
    visited = set()
    pages = []
    all_forms = []
    errors = []

    session = requests.Session()
    session.headers.update({
        "User-Agent": "TechStoreSecurityFramework/0.1"
    })

    while queue and len(visited) < max_pages:
        current_url = urldefrag(queue.popleft())[0]

        if current_url in visited:
            continue

        parsed = urlparse(current_url)
        current_origin = (
            parsed.scheme,
            parsed.hostname,
            parsed.port or 80,
        )

        if current_origin != origin:
            continue

        visited.add(current_url)

        try:
            response = session.get(
                current_url,
                timeout=5,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            errors.append({
                "url": current_url,
                "error": str(error),
            })
            continue

        content_type = response.headers.get("Content-Type", "")

        page_info = {
            "url": current_url,
            "status_code": response.status_code,
            "content_type": content_type,
            "links": [],
            "forms": [],
        }
        pages.append(page_info)

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if location:
                redirected_url = urljoin(current_url, location)
                redirect_parsed = urlparse(redirected_url)

                if (
                    redirect_parsed.scheme == "http"
                    and redirect_parsed.hostname in ALLOWED_HOSTS
                    and (
                        redirect_parsed.scheme,
                        redirect_parsed.hostname,
                        redirect_parsed.port or 80,
                    ) == origin
                ):
                    queue.append(redirected_url)

            continue

        if "text/html" not in content_type.lower():
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href", "").strip()

            if not href or href.startswith(
                ("javascript:", "mailto:", "tel:", "#")
            ):
                continue

            absolute_url = urldefrag(urljoin(current_url, href))[0]
            link_parsed = urlparse(absolute_url)

            link_origin = (
                link_parsed.scheme,
                link_parsed.hostname,
                link_parsed.port or 80,
            )

            if link_origin == origin:
                page_info["links"].append(absolute_url)
                if absolute_url not in visited:
                    queue.append(absolute_url)

        page_forms = analyze_forms(soup, current_url)
        page_info["forms"] = page_forms
        all_forms.extend(page_forms)

    session.close()

    return {
        "target": target_url,
        "pages_scanned": len(pages),
        "pages": pages,
        "forms_found": len(all_forms),
        "forms": all_forms,
        "errors": errors,
    }
