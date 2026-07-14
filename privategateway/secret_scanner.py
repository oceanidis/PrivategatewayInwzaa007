from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    start: int
    end: int


_ASSIGNED_VALUE = r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.I | re.S,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("aws_secret_access_key", re.compile(rf"\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*{_ASSIGNED_VALUE}", re.I)),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", re.I)),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", re.I)),
    ("api_key", re.compile(r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{20,}\b", re.I)),
    ("oauth_token", re.compile(r"\b(?:oauth|bearer)[-_ ]?[A-Za-z0-9._-]{20,}\b", re.I)),
    (
        "credential_assignment",
        re.compile(
            rf"\b(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|github_token)\s*[:=]\s*{_ASSIGNED_VALUE}",
            re.I,
        ),
    ),
    ("connection_string", re.compile(r"\b(?:postgresql|postgres|mysql|mssql|mongodb|redis)://[^\s]+", re.I)),
]


_SECRET_HINT = re.compile(
    r"-----|\beyJ|\bAWS_SECRET_ACCESS_KEY\b|\bgh[pousr]_\b|\bxox[baprs]-|\b(?:sk|pk|api)[-_]|\b(?:oauth|bearer)[-_ ]|\b(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|github_token)\s*[:=]|://",
    re.I,
)


def may_contain_secret(text: object) -> bool:
    return bool(_SECRET_HINT.search("" if text is None else str(text)))

SECRET_COLUMN_NAMES = {
    "api_key",
    "apikey",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "aws_secret_access_key",
    "github_token",
    "connection_string",
    "private_key",
}


def scan_secrets(text: object) -> list[SecretFinding]:
    value = "" if text is None else str(text)
    if not may_contain_secret(value):
        return []
    candidates: list[SecretFinding] = []
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            candidates.append(SecretFinding(kind=kind, start=match.start(), end=match.end()))
    candidates.sort(key=lambda finding: (finding.start, -(finding.end - finding.start)))
    findings: list[SecretFinding] = []
    for candidate in candidates:
        if any(candidate.start < existing.end and candidate.end > existing.start for existing in findings):
            continue
        findings.append(candidate)
    return sorted(findings, key=lambda finding: finding.start)


def is_secret_column(column: str) -> bool:
    normalized = column.strip().lower().replace(" ", "_")
    return normalized in SECRET_COLUMN_NAMES


def drop_secrets_from_text(text: object) -> tuple[str, int]:
    value = "" if text is None else str(text)
    findings = scan_secrets(value)
    if not findings:
        return value, 0
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(value[cursor:finding.start])
        pieces.append("[DROPPED_SECRET]")
        cursor = finding.end
    pieces.append(value[cursor:])
    return "".join(pieces), len(findings)
