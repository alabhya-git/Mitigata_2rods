from __future__ import annotations

import contextvars
import re
from dataclasses import dataclass
from typing import Any

from .codes import BRACED


@dataclass(frozen=True)
class WorkerIdentity:
    role: str
    task_id: str
    owner: str
    fence: int


worker_identity: contextvars.ContextVar[WorkerIdentity | None] = contextvars.ContextVar(
    "worker", default=None
)
FLAG_PATTERN = re.compile(r"\b(?:FLAG|CTF|MITIGATA)\{[A-Za-z0-9_:.@/+=-]{4,256}\}")
SECRET_PATTERN = re.compile(
    r'(?i)(\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|authorization|flag(?:_b64)?|hidden[_ -]?code|challenge[_ -]?code)\b[\s"\x27:=]+)([^\s,"\x27<>;]+)'
)


def redact(value: Any, secrets: list[str] = ()) -> Any:
    if isinstance(value, dict):
        return {
            k: (
                "[REDACTED]"
                if k.lower()
                in {
                    "password",
                    "validation_token",
                    "authorization",
                    "exact_value",
                    "set-cookie",
                    "cookie",
                    "x-api-key",
                }
                else redact(v, secrets)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        value = re.sub(r"(?im)(authorization\s*:\s*)[^\r\n]+", r"\1[REDACTED]", value)
        value = FLAG_PATTERN.sub("[REDACTED FLAG]", value)

        def hide_code(match):
            prefix = match.group().split("{", 1)[0]
            return (
                "[REDACTED CODE]"
                if any(c.isupper() for c in prefix)
                or any(s in prefix.lower() for s in ("flag", "ctf", "challenge", "mitigata"))
                else match.group()
            )

        value = BRACED.sub(hide_code, value)
        value = SECRET_PATTERN.sub(r"\1[REDACTED]", value)
        for secret in sorted(set(secrets), key=len, reverse=True):
            if len(secret) >= 4:
                value = value.replace(secret, "[REDACTED]")
        return value
    return value
