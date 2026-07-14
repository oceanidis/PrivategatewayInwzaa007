from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class PiiFinding:
    kind: str
    start: int
    end: int


Validator = Callable[[str], bool]
REGEX_PATTERNS: list[tuple[str, re.Pattern[str], Validator | None]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?66|0)\d{1,2}[- ]?\d{3}[- ]?\d{4}(?!\d)"), None),
    ("THAI_ID", re.compile(r"(?<!\d)\d{13}(?!\d)"), lambda value: _valid_thai_id(value)),
    ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), lambda value: _valid_luhn(value)),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), lambda value: _valid_ip(value)),
]


def scan_regex_pii(text: object) -> list[PiiFinding]:
    value = "" if text is None else str(text)
    findings: list[PiiFinding] = []
    occupied: list[range] = []
    for kind, pattern, validator in REGEX_PATTERNS:
        for match in pattern.finditer(value):
            matched = match.group(0)
            if validator is not None and not validator(matched):
                continue
            if any(match.start() < item.stop and match.end() > item.start for item in occupied):
                continue
            occupied.append(range(match.start(), match.end()))
            findings.append(PiiFinding(kind=kind, start=match.start(), end=match.end()))
    return sorted(findings, key=lambda item: item.start)


def redact_regex_pii(text: object) -> tuple[str, int]:
    value = "" if text is None else str(text)
    findings = scan_regex_pii(value)
    if not findings:
        return value, 0
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(value[cursor:finding.start])
        pieces.append(f"[REDACTED_{finding.kind}]")
        cursor = finding.end
    pieces.append(value[cursor:])
    return "".join(pieces), len(findings)


def _valid_thai_id(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13 or len(set(digits)) == 1:
        return False
    expected = (11 - sum(int(digit) * weight for digit, weight in zip(digits[:12], range(13, 1, -1))) % 11) % 10
    return expected == int(digits[-1])


def _valid_luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _valid_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
