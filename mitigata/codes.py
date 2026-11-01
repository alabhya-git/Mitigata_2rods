"""Evidence-backed code candidates, including organizer formats and labelled values."""

from __future__ import annotations

import base64
import json
import re

BRACED = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\s{}<>]{4,256}\}")
LABELLED = re.compile(
    r'(?im)\b(?:flag|hidden[_ -]?code|challenge[_ -]?code|secret[_ -]?code)\b["\x27\s:=]+([A-Za-z0-9_:.@/+={}-]{6,256})'
)


def candidates(raw: bytes, patterns=(), source_hint=""):
    found = {}
    for start in range(0, len(raw), 64000):
        text = raw[max(0, start - 512) : start + 64000].decode(errors="replace")
        for match in BRACED.finditer(text):
            prefix = match.group().split("{", 1)[0]
            if any(c.isupper() for c in prefix) or any(
                s in prefix.lower() for s in ("flag", "ctf", "challenge", "mitigata")
            ):
                found.setdefault(match.group(), "brace_format_candidate")
        for match in LABELLED.finditer(text):
            value = match.group(1)
            if value.lower() in {
                "example",
                "placeholder",
                "changeme",
                "invalid",
                "not_found",
                "redacted",
            }:
                continue
            # A real labelled code is not a bare English word picked up from prose such as
            # "the flag resource is ...". Require code-like structure (a digit, uppercase,
            # brace or separator) unless it is implausibly long to be a word.
            if value.isalpha() and value.islower() and len(value) < 16:
                continue
            found.setdefault(value, "explicit_code_label")
        for pattern in patterns:
            if len(pattern) > 256 or any(c in pattern for c in "()|") or re.search(r"\\[1-9]", pattern):
                raise ValueError(
                    "Flag patterns support bounded character-class expressions, not groups/backreferences"
                )
            for match in re.finditer(pattern, text):
                if 4 <= len(match.group()) <= 256:
                    found.setdefault(match.group(), "configured_organizer_format")
        for match in re.finditer(
            r'(?i)(?:flag|hidden_code|challenge_code)_b64["\s:=]+([A-Za-z0-9+/=]{8,1024})', text
        ):
            try:
                decoded = base64.b64decode(match.group(1), validate=True).decode()
                if 4 <= len(decoded) <= 256 and decoded.isprintable():
                    found.setdefault(decoded, "explicitly_labelled_base64_code")
            except (ValueError, UnicodeError):
                pass
        if len(found) >= 20:
            break
    if (
        re.search(
            r"(?:^|/)(?:flag|hidden_code|challenge_code)(?:\.[a-z0-9]+)?(?:\?|$)", source_hint, re.IGNORECASE
        )
        and len(raw) < 4096
    ):
        value = raw.decode(errors="replace").strip()
        if re.fullmatch(r"[A-Za-z0-9_./+={}:@-]{6,256}", value) and value.lower() not in {
            "notfound",
            "redacted",
            "placeholder",
            "example",
        }:
            found.setdefault(value, "literal_from_code_named_resource")
    return [{"value": v, "basis": basis} for v, basis in list(found.items())[:20]]


def exposed_structured_secret(text):
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return False

    def walk(obj, depth=0):
        if depth > 6:
            return False
        if isinstance(obj, dict):
            return any(
                (
                    k.lower() in {"password", "passwd", "api_key", "apikey", "access_token", "secret"}
                    and isinstance(v, str)
                    and 6 <= len(v) <= 512
                    and v.lower() not in {"example", "password", "changeme", "placeholder", "redacted"}
                )
                or walk(v, depth + 1)
                for k, v in list(obj.items())[:100]
            )
        return isinstance(obj, list) and any(walk(v, depth + 1) for v in obj[:100])

    return walk(value)


def extended_match(primitive, text):
    if primitive == "git_head":
        return bool(re.fullmatch(r"ref: refs/heads/[A-Za-z0-9_./-]+\s*", text.strip()))
    if primitive == "structured_secret":
        return exposed_structured_secret(text)
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return False
    if not isinstance(value, dict):
        return False
    if primitive == "source_map":
        return (
            value.get("version") == 3
            and isinstance(value.get("sources"), list)
            and any(isinstance(x, str) and x.strip() for x in value.get("sourcesContent", [])[:32])
        )
    if primitive == "api_document":
        return bool(value.get("openapi") or value.get("swagger")) and isinstance(value.get("paths"), dict)
    return False
