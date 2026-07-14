from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .tokenizer import Tokenizer


_ACTIONS = {"drop", "tokenize", "redact", "keep"}


@dataclass(frozen=True)
class CustomRecognizer:
    name: str
    pattern: str
    action: str = "tokenize"
    validator: Callable[[str], bool] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        normalized_name = self.name.strip().upper().replace(" ", "_")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", normalized_name):
            raise ValueError("custom recognizer name must be a safe uppercase identifier")
        if self.action not in _ACTIONS:
            raise ValueError(f"unsupported custom recognizer action: {self.action}")
        re.compile(self.pattern)
        object.__setattr__(self, "name", normalized_name)


@dataclass(frozen=True)
class CustomFinding:
    entity_type: str
    start: int
    end: int
    action: str


def detect_custom_recognizers(
    text: object,
    recognizers: Iterable[CustomRecognizer],
) -> list[CustomFinding]:
    value = "" if text is None else str(text)
    findings: list[CustomFinding] = []
    occupied: list[range] = []
    for recognizer in recognizers:
        for match in re.finditer(recognizer.pattern, value):
            matched = match.group(0)
            if recognizer.validator is not None and not recognizer.validator(matched):
                continue
            if any(match.start() < span.stop and match.end() > span.start for span in occupied):
                continue
            occupied.append(range(match.start(), match.end()))
            findings.append(
                CustomFinding(recognizer.name, match.start(), match.end(), recognizer.action)
            )
    return sorted(findings, key=lambda finding: finding.start)


def apply_custom_recognizers(
    text: object,
    recognizers: Iterable[CustomRecognizer],
    tokenizer: Tokenizer,
) -> tuple[str, dict[str, int]]:
    value = "" if text is None else str(text)
    findings = detect_custom_recognizers(value, recognizers)
    if not findings:
        return value, {}
    pieces: list[str] = []
    cursor = 0
    counts: dict[str, int] = {}
    for finding in findings:
        original = value[finding.start : finding.end]
        pieces.append(value[cursor : finding.start])
        if finding.action == "tokenize":
            replacement = tokenizer.token_for(original, finding.entity_type)
        elif finding.action == "drop":
            replacement = f"[DROPPED_{finding.entity_type}]"
        elif finding.action == "redact":
            replacement = f"[REDACTED_{finding.entity_type}]"
        else:
            replacement = original
        pieces.append(replacement)
        cursor = finding.end
        counts[finding.entity_type] = counts.get(finding.entity_type, 0) + 1
    pieces.append(value[cursor:])
    return "".join(pieces), counts
