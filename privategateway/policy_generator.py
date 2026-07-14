from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
import re
from typing import Any

import pandas as pd

from .schema_detector import sensitive_type_for_column
from .secret_scanner import is_secret_column


ALIASES = {
    "customer_id": {"customer_id", "customerid", "รหัสลูกค้า", "เลขที่ลูกค้า"},
    "customer_name": {"customer_name", "name", "ชื่อ", "ชื่อลูกค้า", "ชื่อ-นามสกุล"},
    "email": {"email", "อีเมล", "อีเมล์", "อีเมลลูกค้า"},
    "phone": {"phone", "โทรศัพท์", "เบอร์โทร", "เบอร์โทรศัพท์", "มือถือ"},
    "loan_no": {"loan_no", "loan number", "เลขที่สัญญา", "เลขสัญญา", "เลขที่สินเชื่อ"},
    "account_no": {"account_no", "account number", "เลขบัญชี", "เลขที่บัญชี"},
    "amount": {"amount", "ยอดเงิน", "ยอดชำระ", "จำนวนเงิน", "ยอดกู้", "ยอดคงเหลือ"},
    "transaction_date": {"transaction_date", "date", "วันที่", "วันที่ทำรายการ", "วันที่ชำระ", "วันทำรายการ"},
    "address": {"address", "ที่อยู่", "ที่อยู่ลูกค้า"},
    "note": {"note", "หมายเหตุ", "รายละเอียด", "comment", "ข้อความ"},
    "province": {"province", "จังหวัด", "อำเภอ", "ตำบล", "ประเทศ", "region"},
    "status": {"status", "สถานะ", "ประเภท", "category", "ช่องทาง"},
}


@dataclass(frozen=True)
class ColumnDecision:
    source_name: str
    canonical_name: str | None
    action: str
    confidence: float
    reason: str
    role: str = "unknown"


@dataclass(frozen=True)
class ColumnProfile:
    non_null_count: int
    unique_count: int
    unique_ratio: float
    top_value_ratio: float
    rare_value_ratio: float
    average_text_length: float

    @property
    def is_category_candidate(self) -> bool:
        if self.non_null_count == 0 or self.unique_count == 0:
            return False
        if self.unique_count == 1:
            return True
        max_categories = min(100, max(20, round(sqrt(self.non_null_count))))
        if self.unique_count > max_categories:
            return False
        if self.non_null_count < 50:
            return self.unique_count <= max(2, self.non_null_count // 3)
        return self.unique_ratio <= 0.20


def canonical_name(column: object) -> str | None:
    normalized = str(column).strip().casefold()
    for canonical, values in ALIASES.items():
        if normalized in {value.casefold() for value in values}:
            return canonical
    return None


def _normalized_column(column: object) -> str:
    return "".join(character for character in str(column).casefold() if character.isalnum())


def _looks_like_identifier(column: object) -> bool:
    value = _normalized_column(column)
    return bool(re.search(r"(?:id|code|no|number)\d*$", value)) or "personalid" in value or "casenumber" in value


def _looks_like_actor(column: object) -> bool:
    value = _normalized_column(column)
    return (
        value in {"user", "username", "operator", "updatedby", "createdby", "modifiedby"}
        or value.endswith(("username", "userid"))
        or (value.endswith("by") and value.startswith(("updated", "created", "modified", "approved")))
    )


def _looks_like_date(column: object) -> bool:
    value = _normalized_column(column)
    if value.startswith("date") or value.endswith(("date", "datetime", "timestamp", "createdat", "updatedat", "modifiedat")):
        return True
    if "date" in value:
        return False
    return "date" in value or value.startswith("วันที่")


def _looks_like_time(column: object, series: pd.Series) -> bool:
    value = _normalized_column(column)
    if not value.endswith("time") or value.endswith("datetime"):
        return False
    sample = series.dropna().astype("string").str.strip().head(20)
    if sample.empty:
        return False
    time_pattern = r"(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,6})?)?(?:\s*[AaPp][Mm])?"
    return bool(sample.str.fullmatch(time_pattern).mean() >= 0.8)


def _looks_like_operational_dimension(column: object) -> bool:
    value = _normalized_column(column)
    return any(part in value for part in ("source", "organization", "organisation", "location", "branch", "department"))


def _looks_like_amount(column: object) -> bool:
    value = _normalized_column(column)
    return any(part in value for part in ("amount", "expense", "cost", "fee", "asset", "ทุนทรัพย์", "ค่าใช้จ่าย"))


def _looks_like_category(column: object) -> bool:
    value = _normalized_column(column)
    return any(part in value for part in ("status", "flag", "region", "province", "type", "category"))


def _looks_like_free_text(column: object) -> bool:
    value = _normalized_column(column)
    return any(part in value for part in ("note", "remark", "comment", "description"))


def _is_safe_category(series: pd.Series) -> bool:
    values = series.dropna().astype("string").str.strip()
    values = values[values != ""]
    if len(values) < 2:
        return False
    counts = values.value_counts(dropna=True)
    cardinality = len(counts)
    max_cardinality = min(64, max(12, len(values) // 2))
    minimum_frequency = max(2, int(len(values) * 0.01))
    return 2 <= cardinality <= max_cardinality and int(counts.min()) >= minimum_frequency


def profile_series(series: pd.Series) -> ColumnProfile:
    values = series.dropna().astype("string").str.strip()
    values = values[values != ""]
    count = len(values)
    if count == 0:
        return ColumnProfile(0, 0, 0.0, 0.0, 0.0, 0.0)
    counts = values.value_counts(dropna=True)
    unique_count = len(counts)
    rare_rows = int(counts[counts < 5].sum())
    return ColumnProfile(
        non_null_count=count,
        unique_count=unique_count,
        unique_ratio=unique_count / count,
        top_value_ratio=int(counts.iloc[0]) / count,
        rare_value_ratio=rare_rows / count,
        average_text_length=float(values.str.len().mean()),
    )


def _is_description(column: object) -> bool:
    return "description" in _normalized_column(column)


def _token_domain(column: object) -> str:
    value = _normalized_column(column)
    semantic_domains = (
        (("location",), "LOCATION"),
        (("organization", "organisation"), "ORGANIZATION"),
        (("source",), "SOURCE"),
        (("description",), "DESCRIPTION"),
        (("branch",), "BRANCH"),
        (("department",), "DEPARTMENT"),
    )
    for terms, domain in semantic_domains:
        if any(term in value for term in terms):
            return domain
    normalized = re.sub(r"[^A-Z0-9_]+", "_", str(column).strip().upper()).strip("_")
    if not normalized or not normalized[0].isalpha():
        return "CATEGORY"
    return normalized[:64]


def infer_token_domains(decisions: list[ColumnDecision]) -> dict[str, str]:
    return {
        decision.source_name: _token_domain(decision.source_name)
        for decision in decisions
        if decision.action == "tokenize"
        and (decision.role == "category" or _looks_like_operational_dimension(decision.source_name))
    }


def infer_policy(frame: pd.DataFrame) -> tuple[dict[str, str], dict[str, list[list[Any]]], list[ColumnDecision], str | None]:
    decisions: list[ColumnDecision] = []
    columns: dict[str, str] = {}
    buckets: dict[str, list[list[Any]]] = {}
    subject_column: str | None = None
    for column in frame.columns:
        source = str(column)
        canonical = canonical_name(source)
        series = frame[column]
        profile = profile_series(series)
        if is_secret_column(source):
            action, confidence, reason, role = "drop", 1.0, "secret column name", "secret"
        elif canonical in {"customer_name", "email", "phone", "loan_no", "account_no"}:
            action, confidence, reason, role = "tokenize", 0.98, f"recognized {canonical} column", "direct_identifier"
        elif canonical == "customer_id":
            action, confidence, reason, role = "tokenize", 0.99, "joinable customer identifier", "direct_identifier"
            subject_column = source
        elif canonical == "address":
            action, confidence, reason, role = "tokenize", 0.95, "direct address identifier", "direct_identifier"
        elif canonical == "amount":
            action, confidence, reason, role = "synthesize", 0.95, "numeric financial measure", "numeric_measure"
        elif canonical == "transaction_date":
            if subject_column is not None or any(canonical_name(item) == "customer_id" for item in frame.columns):
                action, confidence, reason, role = "date_shift", 0.94, "date linked to a stable subject", "date"
            else:
                action, confidence, reason, role = "review_required", 0.62, "date has no detected subject identifier", "date"
        elif canonical in {"province", "status"}:
            action, confidence, reason, role = "keep", 0.96, "low-risk categorical value", "public_category"
        elif canonical == "note":
            action, confidence, reason, role = "redact_text", 0.92, "free text scanned and selectively redacted", "free_text"
        elif sensitive_type_for_column(source):
            action, confidence, reason, role = "tokenize", 0.9, "schema detector identified sensitive field", "direct_identifier"
        elif _looks_like_actor(source):
            action, confidence, reason, role = "tokenize", 0.94, "user or audit actor identifier", "user_identifier"
        elif _looks_like_time(source, series):
            action, confidence, reason, role = "time_shift", 0.9, "time-only value shifted per subject", "time"
        elif _looks_like_category(source) and _is_safe_category(series):
            action, confidence, reason, role = "keep", 0.9, "safe low-cardinality category", "public_category"
        elif _is_description(source) and profile.is_category_candidate:
            action, confidence, reason, role = "tokenize", 0.88, "repeated description treated as a category", "category"
        elif _looks_like_free_text(source):
            action, confidence, reason, role = "redact_text", 0.8, "free text scanned and selectively redacted", "free_text"
        elif _looks_like_operational_dimension(source):
            reason = "repeated operational category" if profile.is_category_candidate else "operational business identifier"
            action, confidence, role = "tokenize", 0.88, "category"
        elif _looks_like_identifier(source):
            action, confidence, reason, role = "tokenize", 0.82, "identifier-like business column", "business_identifier"
        elif _looks_like_date(source):
            if subject_column is not None or any(canonical_name(item) == "customer_id" for item in frame.columns):
                action, confidence, reason, role = "date_shift", 0.82, "date-like business column linked to a subject", "date"
            else:
                action, confidence, reason, role = "review_required", 0.62, "date-like field has no detected subject identifier", "date"
        elif _looks_like_amount(source):
            action, confidence, reason, role = "synthesize", 0.82, "amount-like business measure", "numeric_measure"
        elif _looks_like_category(source):
            action, confidence, reason, role = "tokenize", 0.72, "high-cardinality or rare category", "category"
        elif _looks_like_date(source) or pd.api.types.is_datetime64_any_dtype(series):
            if subject_column is not None or any(canonical_name(item) == "customer_id" for item in frame.columns):
                action, confidence, reason, role = "date_shift", 0.72, "unknown date-like field linked to a subject", "date"
            else:
                action, confidence, reason, role = "review_required", 0.62, "date-like field has no detected subject identifier", "date"
        elif pd.api.types.is_bool_dtype(series):
            action, confidence, reason, role = "keep", 0.9, "boolean category", "public_category"
        elif profile.is_category_candidate:
            action, confidence, reason, role = "tokenize", 0.78, "low-cardinality repeated values", "category"
        elif pd.api.types.is_numeric_dtype(series):
            action, confidence, reason, role = "synthesize", 0.7, "unknown numeric measure synthesized for privacy", "numeric_measure"
        else:
            action, confidence, reason, role = "tokenize", 0.65, "unknown text/code field tokenized for privacy", "unknown_text"
        columns[source] = action
        decisions.append(ColumnDecision(source, canonical, action, confidence, reason, role))
    if subject_column is None:
        for item in frame.columns:
            if canonical_name(item) == "customer_id":
                subject_column = str(item)
                break
    return columns, buckets, decisions, subject_column
