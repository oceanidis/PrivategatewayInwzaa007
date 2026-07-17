from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import pandas as pd
import yaml

from .policy import column_name_aliases, load_policy
from .policy_generator import infer_policy, infer_token_domains


def generate_safe_read_policy(frame: pd.DataFrame, base_policy_path: str | Path) -> Path:
    """Create an internal, temporary policy for automatic safe table reads."""
    base = load_policy(base_policy_path)
    inferred, _, decisions, subject = infer_policy(frame)
    columns = dict(base.columns)
    buckets = dict(base.buckets)
    domains = dict(base.token_domains)
    decision_by_name = {item.source_name: item for item in decisions}

    for source, action in inferred.items():
        if any(alias in base.columns for alias in column_name_aliases(source)):
            continue
        decision = decision_by_name[source]
        if decision.role == "free_text":
            action = "tokenize"
        elif action == "review_required" and decision.role == "unknown_numeric":
            action = "bucket"
            buckets[source] = _quantile_buckets(frame[source], source)
        elif action == "review_required":
            action = "tokenize"
        columns[source] = action

    for source, domain in infer_token_domains(decisions).items():
        if source in columns and columns[source] == "tokenize":
            domains.setdefault(source, domain)

    payload: dict[str, Any] = {
        "security": {
            "key_provider": base.security.key_provider,
            "require_presidio": base.security.require_presidio,
            "store_raw_copy": base.security.store_raw_copy,
            "raw_ttl_hours": base.security.raw_ttl_hours,
            "mapping_ttl_days": base.security.mapping_ttl_days,
            "reject_duplicate_job_id": base.security.reject_duplicate_job_id,
        },
        "date_shift": {
            "scope": base.date_shift.scope,
            "subject_column": subject or base.date_shift.subject_column,
            "min_days": base.date_shift.min_days,
            "max_days": base.date_shift.max_days,
            "direction": base.date_shift.direction,
            "stability": base.date_shift.stability,
        },
        "time_shift": {
            "scope": base.time_shift.scope,
            "subject_column": subject or base.time_shift.subject_column,
            "min_minutes": base.time_shift.min_minutes,
            "max_minutes": base.time_shift.max_minutes,
            "direction": base.time_shift.direction,
            "stability": base.time_shift.stability,
        },
        "columns": columns,
        "token_domains": domains,
        "default": {"unknown_column": "review_required"},
        "bucket": buckets,
    }
    with NamedTemporaryFile(mode="w", suffix=".yaml", encoding="utf-8", delete=False) as handle:
        yaml.safe_dump(payload, handle, allow_unicode=True, sort_keys=False)
        return Path(handle.name)


def _quantile_buckets(series: pd.Series, column: str) -> list[list[Any]]:
    values = pd.to_numeric(series, errors="coerce").dropna()
    prefix = "AMOUNT" if "amount" in column.casefold() or "balance" in column.casefold() else "NUMERIC"
    if values.empty:
        return [[None, None, f"{prefix}_BUCKET_UNKNOWN"]]
    boundaries = sorted({float(value) for value in values.quantile([0.2, 0.4, 0.6, 0.8]).tolist()})
    edges: list[float | None] = [None, *boundaries, None]
    return [[edges[index], edges[index + 1], f"{prefix}_QUINTILE_{index + 1}"] for index in range(len(edges) - 1)]