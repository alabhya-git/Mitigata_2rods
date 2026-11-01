from __future__ import annotations

import json
import re

# Printable ASCII, the acceptance window for a recovered secret, and dictionary words
# that would make a "decoded" blob a coincidence rather than a planted secret.
_PRINTABLE = set(range(0x20, 0x7F))
_MIN_SECRET, _MAX_SECRET = 8, 64
# Planted passkeys/tokens/flags overwhelmingly use a restricted, typeable charset.
# Brute-forced XOR junk, by contrast, is peppered with random punctuation, so requiring
# the whole decode to live in this set is a strong, general precision filter.
_SECRET_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.{}"
)
_COMMON_WORDS = {
    "password",
    "username",
    "mitigata",
    "aaaaaaaa",
    "00000000",
    "function",
    "continue",
}


def _looks_like_secret(text: str) -> bool:
    if not _MIN_SECRET <= len(text) <= _MAX_SECRET:
        return False
    if text.lower() in _COMMON_WORDS:
        return False
    if any(c not in _SECRET_CHARS for c in text):
        return False
    has_alpha = any(c.isalpha() for c in text)
    has_mix = (
        any(c.isdigit() for c in text)
        or any(c in "_-.{}" for c in text)
        or (any(c.islower() for c in text) and any(c.isupper() for c in text))
    )
    # Reject a run of one repeated character (common XOR-against-padding artefact).
    varied = len(set(text)) >= max(4, len(text) // 3)
    return has_alpha and has_mix and varied


def _key_literals(raw: bytes):
    """NUL-terminated short ASCII words that commonly serve as an in-binary XOR key.

    Requiring NUL termination matches how C string literals sit in .rodata and keeps the
    scan cheap: the expensive scheme search only runs for a literal that is actually
    adjacent to an encoded blob.
    """
    seen = []
    for match in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{3,15}", raw):
        end = match.end()
        word = match.group()
        if any(0x61 <= b <= 0x7A for b in word) and end < len(raw) and raw[end] == 0:
            seen.append((match.start(), word))
        if len(seen) >= 4000:
            break
    return seen


def _decode_scheme(raw: bytes, start: int, key: bytes, a: int, b: int) -> str | None:
    """Decode a printable prefix at ``start`` using blob[i] ^ (a + b*i) ^ key[i % len]."""
    out = bytearray()
    for i in range(start, min(len(raw), start + _MAX_SECRET)):
        j = i - start
        value = raw[i] ^ ((a + b * j) & 0xFF) ^ key[j % len(key)]
        if value not in _PRINTABLE:
            break
        out.append(value)
    if len(out) < _MIN_SECRET:
        return None
    # Require a clean boundary: the next byte (if any) is NOT printable under the scheme,
    # so we are not slicing an arbitrary prefix out of a longer coincidental run.
    nxt = start + len(out)
    if nxt < len(raw):
        j = len(out)
        following = raw[nxt] ^ ((a + b * j) & 0xFF) ^ key[j % len(key)]
        if following in _PRINTABLE:
            return None
    return out.decode("ascii")


def _is_encoded_window(raw: bytes, start: int) -> bool:
    """True if the bytes at ``start`` look like an encoded blob, not plaintext or padding."""
    head = raw[start : start + _MIN_SECRET]
    if len(head) < _MIN_SECRET:
        return False
    if all(b in _PRINTABLE for b in head):
        return False  # a plain ASCII string, not an encoded blob
    # Reject a low-entropy run (e.g. NUL/padding); a planted blob is high-entropy.
    return len(set(raw[start : start + 16])) >= 6


def xor_encoded_candidates(raw: bytes):
    """Recover obfuscated secrets: an in-artifact key literal keying an adjacent byte blob.

    Generic over the common planted-CTF pattern (a short key literal immediately followed,
    after any NUL padding, by a high-entropy blob) and a small family of reversible
    transforms. Returns reproducible recipes — exact offsets and scheme parameters — never
    a guessed value. The Falsifier re-derives each one and rejects anything that reproduces
    under a shifted offset.
    """
    results = []
    for key_offset, key in _key_literals(raw):
        start = key_offset + len(key)
        while start < len(raw) and raw[start] == 0:
            start += 1
        if start >= len(raw) or not _is_encoded_window(raw, start):
            continue
        # Many XOR schemes can print *something*; the planted one is the maximal clean
        # decode in the restricted secret charset. Keep only the single best per blob so a
        # blob yields one secret, not a cloud of look-alikes.
        best = None
        for a in range(33):
            for b in range(17):
                decoded = _decode_scheme(raw, start, key, a, b)
                if decoded is None or not _looks_like_secret(decoded):
                    continue
                score = (len(decoded), len(set(decoded)))
                if best is None or score > best[0]:
                    best = (score, decoded, a, b)
        if best is not None:
            _, decoded, a, b = best
            results.append(
                {
                    "value": decoded,
                    "blob_offset": start,
                    "length": len(decoded),
                    "key_offset": key_offset,
                    "key": key.decode("ascii"),
                    "scheme": {"constant": a, "step": b, "key_mod": len(key)},
                }
            )
    return results[:16]


def rederive_xor_credential(raw: bytes, detail: dict) -> tuple[bool, bool]:
    """Falsifier re-derivation: (reproduces_at_offset, differs_when_shifted)."""
    scheme = detail["scheme"]
    key = detail["key"].encode("ascii")
    if raw[detail["key_offset"] : detail["key_offset"] + len(key)] != key:
        return False, False
    exact = _decode_scheme(raw, detail["blob_offset"], key, scheme["constant"], scheme["step"])
    shifted = _decode_scheme(raw, detail["blob_offset"] + 1, key, scheme["constant"], scheme["step"])
    return exact == detail["value"], shifted != detail["value"]


def credential_records(raw: bytes):
    """Extract only credentials explicitly bound to a URL in the same bounded config record.

    This does not guess relationships from unrelated strings or try recovered passwords broadly.
    Offsets always point to exact ASCII password bytes in the original artifact.
    """
    seen = set()
    for match in re.finditer(rb"(?:service_url|base_url|endpoint|url)=(https?://[^\s\x00]{1,1024})", raw):
        block = raw[match.end() : match.end() + 1024]
        block = re.split(rb"(?:service_url|base_url|endpoint|url)=|\n\s*\n", block, maxsplit=1)[0]
        username = re.search(rb"(?:^|[\n\r\x00])(?:username|user)=([^\s\x00]{1,128})", block)
        password = re.search(rb"(?:^|[\n\r\x00])(?:password|passwd)=([^\s\x00]{4,128})", block)
        if username and password:
            offset = match.end() + password.start(1)
            seen.add(offset)
            yield {
                "service_url": match.group(1).decode(errors="replace"),
                "username": username.group(1).decode(errors="replace"),
                "password": password.group(1).decode(errors="replace"),
                "string_offset": offset,
                "service_offset": match.start(1),
                "format": "key_value_record",
            }
    for match in re.finditer(rb"\{[^{}\x00]{8,2048}\}", raw):
        try:
            value = json.loads(match.group())
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        url = next((value[k] for k in ("service_url", "base_url", "endpoint", "url") if k in value), None)
        username = value.get("username", value.get("user"))
        password = value.get("password", value.get("passwd"))
        if not all(isinstance(v, str) for v in (url, username, password)) or not 4 <= len(password) <= 128:
            continue
        literal = password.encode("utf-8")
        offset_in_record = match.group().find(literal)
        if offset_in_record < 0 or match.start() + offset_in_record in seen:
            continue
        offset = match.start() + offset_in_record
        seen.add(offset)
        yield {
            "service_url": url,
            "username": username,
            "password": password,
            "string_offset": offset,
            "service_offset": match.start(),
            "format": "json_record",
        }
