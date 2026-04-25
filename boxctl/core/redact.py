"""Secret redaction for script output.

Applied at render time so ``Output.data`` stays unmodified while rendered
JSON/plain output carries no raw secrets. Enable via ``Output.render(redact=True)``
(default) or disable with ``redact=False`` / ``--no-redact``.
"""

from __future__ import annotations

import re
from typing import Any

# Order matters: PEM (multi-line) and JWT run before the generic token patterns.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |ED25519 )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |ED25519 )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:pem-key]",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "[REDACTED:jwt]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws-key]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "[REDACTED:api-key]"),
    (
        re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "[REDACTED:github-token]",
    ),
    (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "[REDACTED:github-token]",
    ),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]+\b"), "[REDACTED:slack-token]"),
    (
        re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]+"),
        r"\1 [REDACTED:bearer-token]",
    ),
]

_DB_CRED = re.compile(
    r"\b(postgres|postgresql|mysql|mongodb|redis)://[^\s:/@]+:[^\s@]+@"
)


def _redact_str(s: str) -> str:
    s = _DB_CRED.sub(r"\1://[REDACTED:db-cred]@", s)
    for pat, repl in _PATTERNS:
        s = pat.sub(repl, s)
    return s


def redact_value(value: Any) -> Any:
    """Return a redacted copy of ``value``; non-string scalars pass through."""
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value
