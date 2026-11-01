from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

URL_RE = re.compile(r'https?://[^\s\x00"\x27<>\\)\]}]+', re.IGNORECASE)
PATH_RE = re.compile(r"""["'](/(?!/)[A-Za-z0-9_./?=&%:+~-]{1,512})["']""")
INJECTION_RE = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|you\s+are\s+now|system\s+prompt|exfiltrat",
    re.IGNORECASE,
)
CREDENTIAL_RE = re.compile(
    r'(?im)^\s*(?:export\s+)?(PASSWORD|PASSWD|API_KEY|SECRET|ACCESS_TOKEN)\s*=\s*["\x27]?([^\s"\x27<>]{4,128})'
)

# Phrases that mark an operational/infrastructure/handover document that should not be
# served to anonymous clients. Grouped so a finding can report what category leaked.
SENSITIVE_LEXICON = {
    "infrastructure": (
        r"\bx-forwarded-for\b",
        r"\bcore router\b",
        r"\bedge proxy\b",
        r"\breverse prox",
        r"\bwhitelist\b",
        r"\binternal (?:network|segment|host)\b",
        r"\bworld-readable\b",
    ),
    "operations": (
        r"\bhandover\b",
        r"\bnetops\b",
        r"\brunbook\b",
        r"\bon-call\b",
        r"\bdo not (?:whitelist|share)\b",
        r"\bTODO\(ops\)",
        r"\bnightly (?:rsync|backup|job)\b",
    ),
    "credentials": (
        r"\bpassword\s*[:=]",
        r"\bapi[_ -]?key\b",
        r"\bprivate key\b",
        r"\bssh key\b",
        r"\bBEGIN (?:RSA|OPENSSH|PRIVATE) KEY\b",
    ),
}
_SENSITIVE_COMPILED = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns] for name, patterns in SENSITIVE_LEXICON.items()
}


def sensitive_document_signature(text: str) -> list[str]:
    """Return the categories of sensitive operational content present, or an empty list.

    A plain text/small document, or a strong *multi-category* hit even when wrapped in HTML
    (e.g. a file-manager viewer rendering an ops note), counts. A single weak keyword on a
    large HTML app shell does not, so an ordinary page does not trip the check.
    """
    if len(text) > 200000:
        text = text[:200000]
    found = [name for name, patterns in _SENSITIVE_COMPILED.items() if any(p.search(text) for p in patterns)]
    if not found:
        return []
    if text.count("<") > 60 and len(found) < 2:
        return []
    return found


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.forms = []
        self.current_form = None
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src", "data-url"):
            if attrs.get(key):
                self.references.append((attrs[key], f"html:{tag}@{key}"))
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
                "fields": [],
            }
            self.forms.append(self.current_form)
            if self.current_form["method"] == "GET" and attrs.get("action"):
                self.references.append((attrs["action"], "html:form@get-action"))
        if tag in {"input", "textarea", "select"} and self.current_form is not None and attrs.get("name"):
            self.current_form["fields"].append(
                {
                    "name": attrs["name"],
                    "type": attrs.get("type", "text"),
                    "value": attrs.get("value", "") if attrs.get("type") == "hidden" else "",
                }
            )

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


def parse_page(text: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(text[:1048576])
    except (ValueError, AssertionError):
        pass
    return parser


def extract_references(url: str, text: str, headers: dict) -> list[dict]:
    parser = parse_page(text)
    refs = parser.references
    forbidden_actions = {urljoin(url, form["action"]) for form in parser.forms if form["method"] != "GET"}
    for match in URL_RE.finditer(text):
        refs.append((html.unescape(match.group()).rstrip(".,;"), f"literal@{match.start()}"))
    script_text = text
    if text.lstrip().startswith("<"):
        script_text = "\n".join(re.findall(r"(?is)<script\b[^>]*>(.*?)</script\s*>", text))
    for match in PATH_RE.finditer(script_text):
        refs.append((match.group(1), f"script-path@{match.start()}"))
    for key in ("location", "link", "content-security-policy", "x-service-url"):
        value = headers.get(key, "")
        refs.extend((m.group().rstrip(";,"), f"header:{key}@{m.start()}") for m in URL_RE.finditer(value))
        if key == "location" and value:
            refs.append((value, "header:location"))
        if key == "link":
            refs.extend((m, "header:link") for m in re.findall(r"<([^>]+)>", value))
    if url.endswith("robots.txt"):
        refs.extend(
            (m.group(1).strip(), "robots")
            for m in re.finditer(r"(?im)^(?:Allow|Disallow|Sitemap):\s*(\S+)", text)
        )
    refs.extend(
        (html.unescape(m.group(1).strip()), "sitemap:loc")
        for m in re.finditer(r"(?is)<loc>\s*([^<]{1,2048})\s*</loc>", text)
    )
    if text.lstrip().startswith(("{", "[")) and len(text) < 1048576:
        try:
            document = json.loads(text)
            if isinstance(document, dict) and (document.get("openapi") or document.get("swagger")):
                base = document.get("basePath", "/")
                for route, operations in list(document.get("paths", {}).items())[:100]:
                    if (
                        "{" not in route
                        and "}" not in route
                        and isinstance(operations, dict)
                        and "get" in operations
                    ):
                        refs.append((base.rstrip("/") + "/" + route.lstrip("/"), "openapi:path"))

            def walk(value, depth=0):
                if depth > 5:
                    return
                if isinstance(value, dict):
                    for key, item in list(value.items())[:100]:
                        if (
                            key.lower()
                            in {
                                "url",
                                "uri",
                                "endpoint",
                                "path",
                                "download",
                                "artifact",
                                "href",
                                "next",
                                "source",
                            }
                            and isinstance(item, str)
                            and len(item) < 2048
                        ):
                            refs.append((item, "json:" + key))
                        walk(item, depth + 1)
                elif isinstance(value, list):
                    for item in value[:100]:
                        walk(item, depth + 1)

            walk(document)
        except (ValueError, TypeError, AttributeError):
            pass
    if ".map" in url and len(text) < 262144:
        try:
            value = json.loads(text)
            for source in value.get("sourcesContent", [])[:32]:
                if isinstance(source, str):
                    refs.extend((m.group(), "source-map") for m in URL_RE.finditer(source[:32768]))
                    refs.extend((m.group(1), "source-map-path") for m in PATH_RE.finditer(source[:32768]))
        except (ValueError, AttributeError, TypeError):
            pass
    for match in re.finditer(r"sourceMappingURL\s*=\s*([^\s*]+)", text):
        refs.append((match.group(1), "source-map-reference"))
    result, seen = [], set()
    for ref, method in refs[:1000]:
        if not ref or ref.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
            continue
        candidate = urljoin(url, ref)
        if candidate in forbidden_actions:
            continue  # Inventory a POST action without turning its quoted URL into a GET probe.
        if candidate.startswith(("http://", "https://")) and candidate not in seen and len(candidate) <= 4096:
            seen.add(candidate)
            result.append({"url": candidate, "method": method, "source_url": url})
    return result[:200]


def is_directory_listing(text: str) -> bool:
    return bool(
        re.search(r"(?is)<(?:title|h1)[^>]*>\s*(?:Index of|Directory listing for)\s+[^<]+", text)
    ) and bool(parse_page(text).links)


def is_verbose_error(text: str) -> bool:
    return bool(
        re.search(
            r"Traceback \(most recent call last\)|(?:Exception|Error):[^\n<]{1,160}\n\s+(?:at |File )", text
        )
    )


def equivalent_response(a, b) -> bool:
    def normalized(text):
        text = re.sub(r"[0-9a-f]{16,}", "<id>", text.lower())
        text = re.sub(r"\s+", " ", text).strip()
        return text

    return a.status == b.status and normalized(a.text) == normalized(b.text)
