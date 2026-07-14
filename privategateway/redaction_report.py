from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .secure_store import SecureMappingReference


class ExportBlockedError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReviewOverride:
    actor: str
    reason: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{1,127}", self.actor):
            raise ValueError("review override actor must be a stable account identifier")
        reason = self.reason.strip()
        if len(reason) < 3 or len(reason) > 500 or any(ord(character) < 32 for character in reason):
            raise ValueError("review override reason must contain 3-500 printable characters")
        object.__setattr__(self, "reason", reason)


@dataclass
class RedactionReport:
    project_id: str
    job_id: str
    input_type: str
    policy_fingerprint: str
    presidio_available: bool = False
    action_counts: dict[str, int] = field(default_factory=dict)
    detector_counts: dict[str, int] = field(default_factory=dict)
    column_actions: dict[str, str] = field(default_factory=dict)
    review_required_columns: list[str] = field(default_factory=list)
    block_reasons: list[str] = field(default_factory=list)
    secret_detections: int = 0
    residual_detections: int = 0
    blocked: bool = False
    review_override: ReviewOverride | None = None
    date_shift: dict[str, Any] = field(default_factory=dict)
    time_shift: dict[str, Any] = field(default_factory=dict)

    def add_action(self, action: str, count: int = 1) -> None:
        self.action_counts[action] = self.action_counts.get(action, 0) + count

    def add_detector(self, detector: str, count: int = 1) -> None:
        self.detector_counts[detector] = self.detector_counts.get(detector, 0) + count

    def add_block_reason(self, reason: str) -> None:
        if reason not in self.block_reasons:
            self.block_reasons.append(reason)

    def to_safe_dict(self) -> dict[str, Any]:
        override = None
        if self.review_override is not None:
            override = {"actor": self.review_override.actor, "reason": self.review_override.reason}
        return {
            "project_id": self.project_id,
            "job_id": self.job_id,
            "input_type": self.input_type,
            "policy_fingerprint": self.policy_fingerprint,
            "presidio_available": self.presidio_available,
            "action_counts": dict(self.action_counts),
            "detector_counts": dict(self.detector_counts),
            "column_actions": dict(self.column_actions),
            "review_required_columns": list(self.review_required_columns),
            "block_reasons": list(self.block_reasons),
            "secret_detections": self.secret_detections,
            "residual_detections": self.residual_detections,
            "blocked": self.blocked,
            "review_override": override,
            "date_shift": dict(self.date_shift),
            "time_shift": dict(self.time_shift),
        }


@dataclass
class SanitizeResult:
    safe_dataset: Any
    redaction_report: RedactionReport
    mapping_table: SecureMappingReference | None
    can_export: bool

    def export_safe(self) -> Any:
        if not self.can_export:
            reasons = ", ".join(self.redaction_report.block_reasons) or "review required"
            raise ExportBlockedError(f"Privacy gateway export is blocked: {reasons}")
        return self.safe_dataset
