from __future__ import annotations

import hmac
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import time as time_value, timedelta
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from .audit import append_audit_event
from .custom_recognizers import (
    CustomRecognizer,
    apply_custom_recognizers,
    detect_custom_recognizers,
)
from .key_provider import validate_identifier
from .policy import Policy, column_name_aliases, load_policy
from .presidio_detector import PresidioDetector, get_presidio_detector
from .redaction_report import RedactionReport, ReviewOverride, SanitizeResult
from .override_validation import validate_review_override
from .scanner import redact_regex_pii, scan_regex_pii
from .schema_detector import sensitive_type_for_column
from .secret_scanner import drop_secrets_from_text, is_secret_column, scan_secrets
from .secure_store import (
    LocalSecureStore,
    SecureJobExistsError,
    SecureMappingReference,
    derive_project_key,
)
from .tokenizer import Tokenizer


_SUPPORTED_INPUTS = {"text", "csv", "excel", "json", "dataframe"}


class DuplicateJobError(RuntimeError):
    pass


class FrameSanitizationFailure(RuntimeError):
    def __init__(self, action: str, cause: Exception) -> None:
        super().__init__(f"{action}:{type(cause).__name__}")
        self.action = action
        self.cause = cause


class _NoopPresidioDetector:
    available = False

    def detect(self, text: object) -> list[dict[str, object]]:
        return []

    def redact(self, text: object) -> tuple[str, int]:
        return "" if text is None else str(text), 0


@dataclass(frozen=True)
class _TextSanitization:
    safe: str
    secret_count: int
    regex_count: int
    presidio_count: int
    custom_counts: dict[str, int]


def _policy_uses_presidio(policy: Policy, scan_mode: str) -> bool:
    if scan_mode == "strict":
        return True
    actions = set(policy.columns.values()) | {policy.unknown_column_action}
    return bool(actions & {"redact_text", "review_required"})


def _frame_uses_presidio(policy: Policy, frame: pd.DataFrame, scan_mode: str) -> bool:
    return scan_mode == "strict" or any(
        policy.action_for_column(str(column)) in {"redact_text", "review_required"}
        for column in frame.columns
    )


def _presidio_for_policy(policy: Policy, scan_mode: str) -> PresidioDetector | _NoopPresidioDetector:
    return get_presidio_detector() if _policy_uses_presidio(policy, scan_mode) else _NoopPresidioDetector()


class StreamingSanitizationSession:
    """Own the secure state shared by all batches in one imported workbook."""

    def __init__(
        self,
        *,
        policy_path: str | Path,
        project_id: str,
        job_id: str,
        raw_payload: bytes,
        input_type: str,
        secure_root: str | Path = ".privacy_gateway/secure",
        key_root: str | Path = ".privacy_gateway/keys",
        scan_mode: str = "sealed_analytics",
        custom_recognizers: Iterable[CustomRecognizer] = (),
    ) -> None:
        if scan_mode not in {"strict", "fast", "sealed_analytics"}:
            raise ValueError("scan_mode must be strict, fast, or sealed_analytics")
        self.policy = load_policy(policy_path)
        self.project_id = validate_identifier(project_id, "project_id")
        self.job_id = validate_identifier(job_id, "job_id")
        self.scan_mode = scan_mode
        try:
            self.store = LocalSecureStore(
                self.project_id, self.job_id, secure_root, key_root, reserve_job=True
            )
        except SecureJobExistsError as exc:
            raise DuplicateJobError(
                f"Secure artifacts already exist for job_id '{self.job_id}'"
            ) from exc
        self.store.write_raw(
            raw_payload,
            input_type,
            ttl=timedelta(hours=self.policy.security.raw_ttl_hours),
        )
        self.presidio: PresidioDetector | _NoopPresidioDetector = _NoopPresidioDetector()
        self.report = RedactionReport(
            project_id=self.project_id,
            job_id=self.job_id,
            input_type=input_type,
            policy_fingerprint=self.policy.fingerprint,
            presidio_available=self.presidio.available,
            date_shift={
                "scope": self.policy.date_shift.scope,
                "subject_column": self.policy.date_shift.subject_column,
                "min_days": self.policy.date_shift.min_days,
                "max_days": self.policy.date_shift.max_days,
                "direction": self.policy.date_shift.direction,
                "stability": self.policy.date_shift.stability,
            },
            time_shift={
                "scope": self.policy.time_shift.scope,
                "subject_column": self.policy.time_shift.subject_column,
                "min_minutes": self.policy.time_shift.min_minutes,
                "max_minutes": self.policy.time_shift.max_minutes,
                "direction": self.policy.time_shift.direction,
                "stability": self.policy.time_shift.stability,
            },
        )
        self.tokenizer = Tokenizer(self.store.project_key.master_key)
        self.recognizers = [*self.policy.custom_recognizers, *list(custom_recognizers)]
        self._text_cache: dict[str, _TextSanitization] = {}
        self._finalized = False
        self._mapping_reference: SecureMappingReference | None = None

    def sanitize_frame(self, frame: pd.DataFrame) -> SanitizeResult:
        if self._finalized:
            raise RuntimeError("streaming session has already been finalized")
        if _frame_uses_presidio(self.policy, frame, self.scan_mode) and not self.presidio.available:
            self.presidio = get_presidio_detector()
            self.report.presidio_available = self.presidio.available
            if self.policy.security.require_presidio and not self.presidio.available:
                self.report.add_block_reason("presidio_unavailable")
        safe = _sanitize_frame(
            frame,
            self.policy,
            self.tokenizer,
            self.report,
            self.presidio,
            self.recognizers,
            self.store.project_key.master_key,
            self.scan_mode,
            self._text_cache,
        )

        if self.report.review_required_columns:
            self.report.add_block_reason("review_required")
        self.report.blocked = bool(self.report.block_reasons)
        return SanitizeResult(
            safe_dataset=safe,
            redaction_report=self.report,
            mapping_table=None,
            can_export=not self.report.blocked,
        )

    def finalize(self) -> SanitizeResult:
        if not self._finalized:
            if self.tokenizer.mapping_table:
                self._mapping_reference = self.store.write_mapping(
                    self.tokenizer.mapping_table,
                    ttl=timedelta(days=self.policy.security.mapping_ttl_days),
                )
            self.report.blocked = bool(self.report.block_reasons)
            append_audit_event(
                self.store.secure_root,
                {
                    "event": "import_sanitized",
                    "project_id": self.project_id,
                    "job_id": self.job_id,
                    "policy_fingerprint": self.policy.fingerprint,
                    "blocked": self.report.blocked,
                    "can_export": not self.report.blocked,
                    "review_actor": None,
                    "review_reason": None,
                },
            )
            self._finalized = True
        return SanitizeResult(
            safe_dataset=None,
            redaction_report=self.report,
            mapping_table=self._mapping_reference,
            can_export=not self.report.blocked,
        )


def sanitize_import(
    input_data: Any,
    input_type: str,
    policy_path: str | Path,
    project_id: str,
    job_id: str,
    review_override: ReviewOverride | None = None,
    custom_recognizers: Iterable[CustomRecognizer] = (),
    secure_root: str | Path = ".privacy_gateway/secure",
    key_root: str | Path = ".privacy_gateway/keys",
    scan_mode: str = "strict",
) -> SanitizeResult:
    normalized_type = input_type.strip().lower()
    if scan_mode not in {"strict", "fast", "sealed_analytics"}:
        raise ValueError("scan_mode must be strict, fast, or sealed_analytics")
    if normalized_type not in _SUPPORTED_INPUTS:
        raise ValueError(f"Unsupported input_type: {input_type}")
    project_id = validate_identifier(project_id, "project_id")
    job_id = validate_identifier(job_id, "job_id")
    policy = load_policy(policy_path)
    validate_review_override(review_override, input_data)
    raw_payload = _serialize_raw_input(input_data, normalized_type)
    job_root = Path(secure_root) / project_id / job_id
    if policy.security.reject_duplicate_job_id and job_root.exists() and any(job_root.iterdir()):
        raise DuplicateJobError(f"Secure artifacts already exist for job_id '{job_id}'")

    try:
        store = LocalSecureStore(
            project_id, job_id, secure_root, key_root, reserve_job=True
        )
    except SecureJobExistsError as exc:
        raise DuplicateJobError(f"Secure artifacts already exist for job_id '{job_id}'") from exc
    store.write_raw(
        raw_payload,
        normalized_type,
        ttl=timedelta(hours=policy.security.raw_ttl_hours),
    )
    presidio = _presidio_for_policy(policy, scan_mode)
    report = RedactionReport(
        project_id=project_id,
        job_id=job_id,
        input_type=normalized_type,
        policy_fingerprint=policy.fingerprint,
        presidio_available=presidio.available,
        review_override=review_override,
        date_shift={
            "scope": policy.date_shift.scope,
            "subject_column": policy.date_shift.subject_column,
            "min_days": policy.date_shift.min_days,
            "max_days": policy.date_shift.max_days,
            "direction": policy.date_shift.direction,
            "stability": policy.date_shift.stability,
        },
        time_shift={
            "scope": policy.time_shift.scope,
            "subject_column": policy.time_shift.subject_column,
            "min_minutes": policy.time_shift.min_minutes,
            "max_minutes": policy.time_shift.max_minutes,
            "direction": policy.time_shift.direction,
            "stability": policy.time_shift.stability,
        },
    )
    if _policy_uses_presidio(policy, scan_mode) and policy.security.require_presidio and not presidio.available:
        report.add_block_reason("presidio_unavailable")

    tokenizer = Tokenizer(store.project_key.master_key)
    recognizers = [*policy.custom_recognizers, *list(custom_recognizers)]
    if normalized_type == "text":
        safe_dataset = _sanitize_text(input_data, report, presidio, recognizers, tokenizer)
    else:
        frame = _parse_tabular_input(input_data, normalized_type)
        safe_dataset = _sanitize_frame(
            frame, policy, tokenizer, report, presidio, recognizers, store.project_key.master_key, scan_mode
        )

    if normalized_type == "text":
        residual_count = _count_residual_findings(safe_dataset, policy, presidio, recognizers)
        if residual_count:
            report.residual_detections = residual_count
            report.add_block_reason("residual_sensitive_data")
    if report.review_required_columns and review_override is None:
        report.add_block_reason("review_required")
    report.blocked = bool(report.block_reasons)

    mapping_reference: SecureMappingReference | None = None
    if tokenizer.mapping_table:
        mapping_reference = store.write_mapping(
            tokenizer.mapping_table,
            ttl=timedelta(days=policy.security.mapping_ttl_days),
        )
    append_audit_event(
        secure_root,
        {
            "event": "import_sanitized",
            "project_id": project_id,
            "job_id": job_id,
            "policy_fingerprint": policy.fingerprint,
            "blocked": report.blocked,
            "can_export": not report.blocked,
            "review_actor": review_override.actor if review_override else None,
            "review_reason": review_override.reason if review_override else None,
        },
    )
    return SanitizeResult(
        safe_dataset=safe_dataset,
        redaction_report=report,
        mapping_table=mapping_reference,
        can_export=not report.blocked,
    )


def _parse_tabular_input(input_data: Any, input_type: str) -> pd.DataFrame:
    if input_type == "dataframe":
        if not isinstance(input_data, pd.DataFrame):
            raise TypeError("input_type='dataframe' requires a pandas DataFrame")
        return input_data.copy(deep=True)
    if input_type == "csv":
        if _existing_path(input_data):
            return pd.read_csv(input_data)
        content = input_data.decode("utf-8") if isinstance(input_data, bytes) else str(input_data)
        return pd.read_csv(StringIO(content))
    if input_type == "excel":
        if isinstance(input_data, bytes):
            return pd.read_excel(BytesIO(input_data))
        return pd.read_excel(input_data)
    if input_type == "json":
        if _existing_path(input_data):
            payload = json.loads(Path(input_data).read_text(encoding="utf-8"))
        else:
            payload = json.loads(input_data) if isinstance(input_data, (str, bytes, bytearray)) else input_data
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            raise TypeError("JSON input must contain an object or array of objects")
        return pd.DataFrame(payload)
    raise ValueError(f"Unsupported tabular input_type: {input_type}")


def _serialize_raw_input(input_data: Any, input_type: str) -> bytes:
    if input_type == "dataframe":
        if not isinstance(input_data, pd.DataFrame):
            raise TypeError("input_type='dataframe' requires a pandas DataFrame")
        return input_data.to_json(orient="records", force_ascii=False, date_format="iso").encode("utf-8")
    if _existing_path(input_data):
        return Path(input_data).read_bytes()
    if isinstance(input_data, bytes):
        return input_data
    if isinstance(input_data, bytearray):
        return bytes(input_data)
    if input_type == "json" and not isinstance(input_data, str):
        return json.dumps(input_data, ensure_ascii=False, default=str).encode("utf-8")
    if input_type == "excel" and hasattr(input_data, "read"):
        position = input_data.tell() if hasattr(input_data, "tell") else None
        payload = input_data.read()
        if position is not None and hasattr(input_data, "seek"):
            input_data.seek(position)
        return payload
    return str(input_data).encode("utf-8")


def _existing_path(value: Any) -> bool:
    if not isinstance(value, (str, Path)):
        return False
    try:
        return Path(value).is_file()
    except (OSError, ValueError):
        return False


def _sanitize_frame(
    frame: pd.DataFrame,
    policy: Policy,
    tokenizer: Tokenizer,
    report: RedactionReport,
    presidio: PresidioDetector,
    recognizers: list[CustomRecognizer],
    master_key: bytes,
    scan_mode: str = "strict",
    text_cache: dict[str, _TextSanitization] | None = None,
) -> pd.DataFrame:
    safe = frame.copy(deep=True)
    active_text_cache = text_cache if text_cache is not None else {}
    columns_to_drop: list[Any] = []
    for column in list(frame.columns):
        column_name = str(column)
        values = frame[column]
        action = policy.action_for_column(column_name)
        try:
            scan_secrets_for_column = (scan_mode == "strict" and action != "redact_text") or is_secret_column(column_name) or action in {"keep", "review_required"}
            secret_count = int(values.map(lambda value: len(scan_secrets(value))).sum()) if scan_secrets_for_column and not pd.api.types.is_numeric_dtype(values) else 0
            if is_secret_column(column_name) or secret_count:
                columns_to_drop.append(column)
                detected = secret_count or len(frame)
                report.secret_detections += detected
                report.add_detector("secret_scanner", detected)
                report.add_action("drop", len(frame))
                report.column_actions[column_name] = "drop"
                continue

            schema_type = sensitive_type_for_column(column_name)
            if schema_type:
                report.add_detector("schema_detector", len(frame))
            action = policy.action_for_column(column_name)
        # Presidio is expensive and unnecessary after policy/schema classification.
        # Keep and review-required columns are checked before export; redact_text performs its own single scan.
            scan_value_pii = action in {"keep", "review_required"}
            regex_count = int(values.map(lambda value: len(scan_regex_pii(value))).sum()) if scan_value_pii else 0
            if regex_count:
                report.add_detector("regex_pii_scanner", regex_count)
            presidio_count = 0
            if presidio.available and action == "review_required":
                presidio_count = int(values.map(lambda value: len(presidio.detect(value))).sum())
                if presidio_count:
                    report.add_detector("presidio_scanner", presidio_count)
            custom_count = int(
                values.map(lambda value: len(detect_custom_recognizers(value, recognizers))).sum()
            ) if scan_value_pii else 0
            if custom_count:
                report.add_detector("custom_recognizer", custom_count)

            # A keep column is emitted unchanged, so findings from this first pass
            # are sufficient to block export. Re-scanning the identical safe frame
            # after every batch only duplicated the same expensive work.
            if action == "keep" and (regex_count or presidio_count or custom_count):
                report.residual_detections += regex_count + presidio_count + custom_count
                report.add_block_reason("residual_sensitive_data")

            report.column_actions[column_name] = action
            if action == "review_required":
                report.review_required_columns.append(column_name)
                safe[column] = "[REVIEW_REQUIRED]"
                report.add_action("review_required", len(frame))
            elif action == "drop":
                columns_to_drop.append(column)
                report.add_action("drop", len(frame))
            elif action == "tokenize":
                token_type = schema_type or policy.token_domain_for_column(column_name) or "UNKNOWN_VALUE"
                safe[column] = values.map(
                    lambda value: None if _is_missing(value) else tokenizer.token_for(value, token_type)
                )
                report.add_action("tokenize", len(frame))
            elif action == "hash":
                safe[column] = values.map(lambda value: _hash_identifier(value, master_key))
                report.add_action("hash", len(frame))
            elif action == "bucket":
                safe[column] = values.map(lambda value: _bucket_value(value, column_name, policy))
                report.add_action("bucket", len(frame))
            elif action == "synthesize":
                safe[column] = _synthesize_numeric(
                    values, column_name, report.project_id, master_key
                )
                report.add_action("synthesize", len(frame))
            elif action == "date_shift":
                safe[column] = _shift_date_column(frame, values, policy, report, master_key)
                report.add_action("date_shift", len(frame))
            elif action == "time_shift":
                safe[column] = _shift_time_column(frame, values, policy, report, master_key)
                report.add_action("time_shift", len(frame))
            elif action == "redact_text":
                safe[column] = _sanitize_text_series(
                    values, report, presidio, recognizers, tokenizer, active_text_cache
                )
                report.add_action("redact_text", len(frame))
            elif action == "redact":
                label = schema_type or "UNKNOWN_VALUE"
                safe[column] = f"[REDACTED_{label}]"
                report.add_action("redact", len(frame))
            elif action == "keep":
                report.add_action("keep", len(frame))
            else:
                report.review_required_columns.append(column_name)
                safe[column] = "[REVIEW_REQUIRED]"
                report.add_action("review_required", len(frame))
        except Exception as exc:
            raise FrameSanitizationFailure(action, exc) from exc
    if columns_to_drop:
        safe = safe.drop(columns=columns_to_drop)
    return safe


def _sanitize_text(
    text: object,
    report: RedactionReport,
    presidio: PresidioDetector,
    recognizers: list[CustomRecognizer],
    tokenizer: Tokenizer,
) -> str:
    result = _sanitize_text_value(text, presidio, recognizers, tokenizer)
    _record_text_sanitization(report, result, 1)
    return result.safe


def _sanitize_text_value(
    text: object,
    presidio: PresidioDetector,
    recognizers: list[CustomRecognizer],
    tokenizer: Tokenizer,
) -> _TextSanitization:
    safe, secret_count = drop_secrets_from_text(text)
    safe, regex_count = redact_regex_pii(safe)
    safe, presidio_count = presidio.redact(safe)
    safe, custom_counts = apply_custom_recognizers(safe, recognizers, tokenizer)
    return _TextSanitization(safe, secret_count, regex_count, presidio_count, custom_counts)


def _record_text_sanitization(
    report: RedactionReport,
    result: _TextSanitization,
    occurrences: int,
) -> None:
    secret_count = result.secret_count * occurrences
    regex_count = result.regex_count * occurrences
    presidio_count = result.presidio_count * occurrences
    if secret_count:
        report.secret_detections += secret_count
        report.add_detector("secret_scanner", secret_count)
        report.add_action("drop", secret_count)
    if regex_count:
        report.add_detector("regex_pii_scanner", regex_count)
        report.add_action("redact", regex_count)
    if presidio_count:
        report.add_detector("presidio_scanner", presidio_count)
        report.add_action("redact", presidio_count)
    for count in result.custom_counts.values():
        report.add_detector("custom_recognizer", count * occurrences)


def _sanitize_text_series(
    values: pd.Series,
    report: RedactionReport,
    presidio: PresidioDetector,
    recognizers: list[CustomRecognizer],
    tokenizer: Tokenizer,
    cache: dict[str, _TextSanitization],
) -> pd.Series:
    keys = values.map(lambda value: None if _is_missing(value) else str(value))
    counts = keys.dropna().value_counts(dropna=True)
    for key, occurrences in counts.items():
        if key not in cache:
            cache[key] = _sanitize_text_value(key, presidio, recognizers, tokenizer)
        _record_text_sanitization(report, cache[key], int(occurrences))
    return keys.map(lambda key: None if pd.isna(key) else cache[str(key)].safe)


def _shift_date_column(
    frame: pd.DataFrame,
    values: pd.Series,
    policy: Policy,
    report: RedactionReport,
    master_key: bytes,
) -> pd.Series:
    subject_column = policy.date_shift.subject_column
    normalized_columns = {
        alias: column
        for column in frame.columns
        for alias in column_name_aliases(str(column))
    }
    if subject_column not in normalized_columns:
        report.add_block_reason("missing_subject_column")
        return pd.Series(["[REVIEW_REQUIRED_DATE]"] * len(frame), index=frame.index)
    subjects = frame[normalized_columns[subject_column]]
    shifted: list[str] = []
    for value, subject in zip(values, subjects):
        if _is_missing(subject):
            shifted.append("[REDACTED_DATE]")
            continue
        parsed = pd.to_datetime(value, errors="coerce")
        if pd.isna(parsed):
            shifted.append("[REDACTED_DATE]")
            continue
        offset = _date_offset(subject, report.project_id, policy, master_key)
        shifted.append((parsed + pd.Timedelta(days=offset)).strftime("%Y-%m-%d"))
    return pd.Series(shifted, index=frame.index)


def _date_offset(subject: object, project_id: str, policy: Policy, master_key: bytes) -> int:
    normalized_subject = unicodedata.normalize("NFKC", str(subject)).strip()
    key = derive_project_key(master_key, "date_shift")
    digest = hmac.new(
        key,
        b"v1\0" + project_id.encode("utf-8") + b"\0" + normalized_subject.encode("utf-8"),
        sha256,
    ).digest()
    width = policy.date_shift.max_days - policy.date_shift.min_days + 1
    choice = int.from_bytes(digest[:8], "big")
    magnitude = policy.date_shift.min_days + (choice % width)
    if policy.date_shift.direction == "forward":
        return magnitude
    if policy.date_shift.direction == "backward":
        return -magnitude
    return magnitude if (choice // width) % 2 else -magnitude


def _shift_time_column(
    frame: pd.DataFrame,
    values: pd.Series,
    policy: Policy,
    report: RedactionReport,
    master_key: bytes,
) -> pd.Series:
    subject_column = policy.time_shift.subject_column
    normalized_columns = {
        alias: column
        for column in frame.columns
        for alias in column_name_aliases(str(column))
    }
    if subject_column not in normalized_columns:
        report.add_block_reason("missing_time_subject_column")
        return pd.Series(["[REVIEW_REQUIRED_TIME]"] * len(frame), index=frame.index)
    subjects = frame[normalized_columns[subject_column]]
    shifted: list[str | None] = []
    for value, subject in zip(values, subjects):
        if _is_missing(value):
            shifted.append(None)
            continue
        if _is_missing(subject):
            shifted.append("[REDACTED_TIME]")
            continue
        components = _time_components(value)
        if components is None:
            shifted.append("[REDACTED_TIME]")
            continue
        hour, minute, second = components
        shifted_minutes = (hour * 60 + minute + _time_offset(subject, report.project_id, policy, master_key)) % 1440
        shifted.append(f"{shifted_minutes // 60:02d}:{shifted_minutes % 60:02d}:{second:02d}")
    return pd.Series(shifted, index=values.index)


def _time_components(value: object) -> tuple[int, int, int] | None:
    if isinstance(value, time_value):
        return value.hour, value.minute, value.second
    if isinstance(value, (int, float, np.integer, np.floating)) and 0 <= float(value) < 1:
        total_seconds = round(float(value) * 86_400) % 86_400
        return total_seconds // 3_600, (total_seconds % 3_600) // 60, total_seconds % 60
    match = re.fullmatch(r"\s*(\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*", str(value))
    if match is None:
        return None
    hour, minute, second = int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)
    if hour > 23 or minute > 59 or second > 59:
        return None
    return hour, minute, second


def _time_offset(subject: object, project_id: str, policy: Policy, master_key: bytes) -> int:
    normalized_subject = unicodedata.normalize("NFKC", str(subject)).strip()
    key = derive_project_key(master_key, "time_shift")
    digest = hmac.new(
        key,
        b"v1\0" + project_id.encode("utf-8") + b"\0" + normalized_subject.encode("utf-8"),
        sha256,
    ).digest()
    width = policy.time_shift.max_minutes - policy.time_shift.min_minutes + 1
    choice = int.from_bytes(digest[:8], "big")
    magnitude = policy.time_shift.min_minutes + (choice % width)
    if policy.time_shift.direction == "forward":
        return magnitude
    if policy.time_shift.direction == "backward":
        return -magnitude
    return magnitude if (choice // width) % 2 else -magnitude


def _hash_identifier(value: object, master_key: bytes) -> str:
    normalized = unicodedata.normalize("NFKC", "" if value is None else str(value)).strip()
    key = derive_project_key(master_key, "id_hash")
    digest = hmac.new(key, normalized.encode("utf-8"), sha256).hexdigest()[:24]
    return f"HASH_{digest}"


def _bucket_value(value: object, column: str, policy: Policy) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "AMOUNT_BUCKET_UNKNOWN"
    for low, high, label in policy.buckets.get(column, []):
        if (low is None or number >= float(low)) and (high is None or number < float(high)):
            return str(label)
    return "AMOUNT_BUCKET_UNKNOWN"


def _synthesize_numeric(
    values: pd.Series,
    column_name: str,
    project_id: str,
    master_key: bytes,
) -> pd.Series:
    """Generate values from quantile bins without retaining row-level amounts."""
    numeric = _coerce_numeric(values)
    source = numeric.dropna().to_numpy(dtype=float)
    if not len(source):
        return pd.Series(np.nan, index=values.index, dtype="float64")

    low, high = np.quantile(source, [0.01, 0.99])
    if low == high:
        spread = max(abs(float(low)) * 0.05, 1.0)
        low, high = float(low) - spread, float(high) + spread
    bin_count = min(16, max(2, int(np.sqrt(len(source)))))
    edges = np.quantile(source, np.linspace(0.01, 0.99, bin_count + 1))
    edges[0], edges[-1] = low, high
    key = derive_project_key(master_key, "numeric_synthesis")
    digest = hmac.new(
        key,
        b"v1\0" + project_id.encode("utf-8") + b"\0" + column_name.encode("utf-8") + b"\0" + str(len(values)).encode("ascii"),
        sha256,
    ).digest()
    rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
    generated = np.full(len(values), np.nan, dtype=float)
    positions = np.flatnonzero(numeric.notna().to_numpy())
    selected_bins = rng.integers(0, bin_count, size=len(positions))
    left = edges[selected_bins]
    right = edges[selected_bins + 1]
    generated[positions] = left + rng.random(len(positions)) * (right - left)

    integer_output = pd.api.types.is_integer_dtype(values) or np.allclose(source, np.round(source))
    if integer_output:
        generated[positions] = np.rint(generated[positions])
    original_values = set(np.rint(source).astype(int) if integer_output else source.tolist())
    step = 1.0 if integer_output else max((float(high) - float(low)) / 10_000, 1e-9)
    for position in positions:
        candidate = generated[position]
        attempts = 0
        while candidate in original_values and attempts < 128:
            candidate += step if candidate + step <= high else -step
            attempts += 1
        generated[position] = candidate

    if integer_output:
        return pd.Series(generated, index=values.index).astype("Int64")
    return pd.Series(generated, index=values.index)


def _coerce_numeric(values: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(values):
        return pd.to_numeric(values, errors="coerce")

    text = values.astype("string").str.strip()
    parenthesized = text.str.fullmatch(r"\(.*\)", na=False)
    text = text.str.replace(r"^\((.*)\)$", r"-\1", regex=True)
    text = text.str.replace(r"(?i)\b(?:THB|USD|EUR|GBP|JPY|BAHT)\b", "", regex=True)
    text = text.str.replace("\u0e1a\u0e32\u0e17", "", regex=False)
    text = text.str.replace(",", "", regex=False)
    for symbol in ("$", chr(0x0E3F), chr(0x20AC), chr(0x00A3), chr(0x00A5)):
        text = text.str.replace(symbol, "", regex=False)
    text = text.str.replace(r"\s", "", regex=True)
    valid = text.str.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", na=False)
    numeric = pd.to_numeric(text.where(valid), errors="coerce")
    numeric.loc[parenthesized & numeric.notna()] = -numeric.loc[parenthesized & numeric.notna()].abs()
    return numeric


def _count_residual_findings(
    safe_dataset: Any,
    policy: Policy,
    presidio: PresidioDetector,
    recognizers: list[CustomRecognizer],
) -> int:
    total = 0
    active_custom = [recognizer for recognizer in recognizers if recognizer.action != "keep"]
    if isinstance(safe_dataset, pd.DataFrame):
        values = (
            (value, policy.action_for_column(str(column)) != "keep")
            for column in safe_dataset.columns
            if policy.action_for_column(str(column)) in {"keep", "review_required"}
            for value in safe_dataset[column]
        )
    else:
        values = iter([(safe_dataset, True)])
    for value, run_presidio in values:
        total += len(scan_secrets(value))
        total += len(scan_regex_pii(value))
        if presidio.available and run_presidio:
            total += len(presidio.detect(value))
        total += len(detect_custom_recognizers(value, active_custom))
    return total
def _is_missing(value: object) -> bool:
    if value is None:
        return True
    try:
        missing = pd.isna(value)
        if isinstance(missing, (bool, np.bool_)) and bool(missing):
            return True
    except (TypeError, ValueError):
        pass
    return not str(value).strip()
