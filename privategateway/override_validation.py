from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pandas as pd

from .redaction_report import ReviewOverride
from .scanner import scan_regex_pii
from .secret_scanner import scan_secrets


def validate_review_override(
    review_override: ReviewOverride | None,
    input_data: Any,
) -> None:
    if review_override is None:
        return
    reason = review_override.reason
    if scan_secrets(reason) or scan_regex_pii(reason):
        raise ValueError("review override reason must not contain secrets or PII")
    folded_reason = reason.casefold()
    for original in _iter_scalar_values(input_data):
        candidate = str(original).strip()
        if len(candidate) >= 4 and candidate.casefold() in folded_reason:
            raise ValueError("review override reason must not contain an imported value")


def _iter_scalar_values(value: Any) -> Iterable[Any]:
    if isinstance(value, pd.DataFrame):
        for item in value.to_numpy().flat:
            yield from _iter_scalar_values(item)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_scalar_values(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_scalar_values(item)
        return
    if isinstance(value, (bytes, bytearray, Path)):
        return
    if value is not None:
        yield value
