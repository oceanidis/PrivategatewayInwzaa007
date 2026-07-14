from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .custom_recognizers import CustomRecognizer


_ACTIONS = {
    "drop", "tokenize", "hash", "bucket", "date_shift", "redact",
    "redact_text", "keep", "review_required", "synthesize", "time_shift",
}


def normalize_column_name(column: str) -> str:
    """Normalize common column-name styles for policy matching."""
    text = str(column).strip()
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"[^\w]+", "_", text, flags=re.UNICODE)
    return re.sub(r"_+", "_", text).strip("_").lower()


def column_name_aliases(column: str) -> tuple[str, ...]:
    normalized = normalize_column_name(column)
    compact = normalized.replace("_", "")
    return (normalized,) if compact == normalized else (normalized, compact)


@dataclass(frozen=True)
class SecurityPolicy:
    key_provider: str = "dpapi"
    require_presidio: bool = True
    raw_ttl_hours: int = 24
    mapping_ttl_days: int = 30
    reject_duplicate_job_id: bool = True


@dataclass(frozen=True)
class DateShiftPolicy:
    scope: str = "subject"
    subject_column: str = "customer_id"
    min_days: int = 1
    max_days: int = 30
    direction: str = "both"
    stability: str = "project"


@dataclass(frozen=True)
class TimeShiftPolicy:
    scope: str = "subject"
    subject_column: str = "customer_id"
    min_minutes: int = 1
    max_minutes: int = 720
    direction: str = "both"
    stability: str = "project"


@dataclass
class Policy:
    columns: dict[str, str]
    fingerprint: str
    unknown_column_action: str = "review_required"
    buckets: dict[str, list[list[Any]]] = field(default_factory=dict)
    date_shift: DateShiftPolicy = field(default_factory=DateShiftPolicy)
    time_shift: TimeShiftPolicy = field(default_factory=TimeShiftPolicy)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)
    custom_recognizers: list[CustomRecognizer] = field(default_factory=list)
    token_domains: dict[str, str] = field(default_factory=dict)

    def action_for_column(self, column: str) -> str:
        for alias in column_name_aliases(column):
            if alias in self.columns:
                return self.columns[alias]
        return self.unknown_column_action

    def token_domain_for_column(self, column: str) -> str | None:
        for alias in column_name_aliases(column):
            if alias in self.token_domains:
                return self.token_domains[alias]
        return None


def load_policy(policy_path: str | Path) -> Policy:
    path = Path(policy_path)
    if not path.exists():
        package_relative = Path(__file__).resolve().parent / path.name
        if package_relative.exists():
            path = package_relative
    payload = path.read_bytes()
    raw = yaml.safe_load(payload.decode("utf-8")) or {}
    columns = {normalize_column_name(str(key)): str(value) for key, value in (raw.get("columns") or {}).items()}
    default = raw.get("default") or {}
    unknown_action = str(default.get("unknown_column", "review_required"))
    for column, action in [*columns.items(), ("default.unknown_column", unknown_action)]:
        if action not in _ACTIONS:
            raise ValueError(f"Unsupported policy action '{action}' for '{column}'")

    token_domains = {
        normalize_column_name(str(key)): str(value).strip().upper().replace(" ", "_")
        for key, value in (raw.get("token_domains") or {}).items()
    }
    for column, domain in token_domains.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", domain):
            raise ValueError(f"Invalid token domain '{domain}' for '{column}'")

    security_raw = raw.get("security") or {}
    security = SecurityPolicy(
        key_provider=str(security_raw.get("key_provider", "dpapi")),
        require_presidio=bool(security_raw.get("require_presidio", True)),
        raw_ttl_hours=int(security_raw.get("raw_ttl_hours", 24)),
        mapping_ttl_days=int(security_raw.get("mapping_ttl_days", 30)),
        reject_duplicate_job_id=bool(security_raw.get("reject_duplicate_job_id", True)),
    )
    if security.key_provider != "dpapi":
        raise ValueError("Only the local Windows DPAPI key provider is supported")
    if security.raw_ttl_hours <= 0 or security.mapping_ttl_days <= 0:
        raise ValueError("secure artifact retention values must be positive")

    date_raw = raw.get("date_shift") or {}
    date_shift = DateShiftPolicy(
        scope=str(date_raw.get("scope", "subject")),
        subject_column=normalize_column_name(str(date_raw.get("subject_column", "customer_id"))),
        min_days=int(date_raw.get("min_days", 1)),
        max_days=int(date_raw.get("max_days", 30)),
        direction=str(date_raw.get("direction", "both")),
        stability=str(date_raw.get("stability", "project")),
    )
    if date_shift.scope != "subject" or date_shift.stability != "project":
        raise ValueError("date_shift currently requires subject scope and project stability")
    if date_shift.min_days < 1 or date_shift.max_days < date_shift.min_days:
        raise ValueError("date_shift requires 1 <= min_days <= max_days")
    if date_shift.direction not in {"both", "forward", "backward"}:
        raise ValueError("date_shift.direction must be both, forward, or backward")

    time_raw = raw.get("time_shift") or {}
    time_shift = TimeShiftPolicy(
        scope=str(time_raw.get("scope", "subject")),
        subject_column=normalize_column_name(str(time_raw.get("subject_column", "customer_id"))),
        min_minutes=int(time_raw.get("min_minutes", 1)),
        max_minutes=int(time_raw.get("max_minutes", 720)),
        direction=str(time_raw.get("direction", "both")),
        stability=str(time_raw.get("stability", "project")),
    )
    if time_shift.scope != "subject" or time_shift.stability != "project":
        raise ValueError("time_shift currently requires subject scope and project stability")
    if time_shift.min_minutes < 1 or time_shift.max_minutes < time_shift.min_minutes or time_shift.max_minutes >= 1440:
        raise ValueError("time_shift requires 1 <= min_minutes <= max_minutes < 1440")
    if time_shift.direction not in {"both", "forward", "backward"}:
        raise ValueError("time_shift.direction must be both, forward, or backward")

    recognizers = [
        CustomRecognizer(
            name=str(item["name"]),
            pattern=str(item["pattern"]),
            action=str(item.get("action", "tokenize")),
        )
        for item in (raw.get("custom_recognizers") or [])
    ]
    return Policy(
        columns=columns,
        fingerprint=hashlib.sha256(payload).hexdigest(),
        unknown_column_action=unknown_action,
        buckets=raw.get("bucket") or {},
        date_shift=date_shift,
        time_shift=time_shift,
        security=security,
        custom_recognizers=recognizers,
        token_domains=token_domains,
    )
