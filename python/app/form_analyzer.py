from urllib.parse import urljoin


def analyze_forms(soup, page_url):
    results = []

    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        method = form.get("method", "GET").strip().upper()

        if method not in {"GET", "POST"}:
            method = "OTHER"

        fields = []

        for element in form.find_all(["input", "textarea", "select", "button"]):
            tag = element.name
            name = element.get("name")

            if not name:
                continue

            if tag == "input":
                field_type = element.get("type", "text").lower()
            elif tag == "textarea":
                field_type = "textarea"
            elif tag == "select":
                field_type = "select"
            else:
                field_type = element.get("type", "submit").lower()

            fields.append({
                "name": name,
                "type": field_type,
                "required": element.has_attr("required"),
            })

        results.append({
            "page_url": page_url,
            "action_url": urljoin(page_url, action) if action else page_url,
            "method": method,
            "fields": fields,
        })

    return results
