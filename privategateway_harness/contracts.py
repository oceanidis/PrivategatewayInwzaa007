from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

from .errors import HarnessError


_SAFE_REF = re.compile(r"safe://([A-Za-z0-9][A-Za-z0-9_.-]{0,127})/([a-z0-9]{8,64})$")


class ToolCategory(StrEnum):
    CONTROL = "control"
    DATA_IMPORT = "data_import"
    SAFE_READ = "safe_read"
    SAFE_TRANSFORM = "safe_transform"
    OUTPUT_WRITE = "output_write"
    ADMIN = "admin"


@dataclass(frozen=True)
class SafeArtifactRef:
    session_id: str
    artifact_id: str

    @property
    def uri(self) -> str:
        return f"safe://{self.session_id}/{self.artifact_id}"

    @classmethod
    def parse(cls, value: object) -> "SafeArtifactRef":
        match = _SAFE_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            raise HarnessError("INVALID_SAFE_ARTIFACT_REF")
        return cls(session_id=match.group(1), artifact_id=match.group(2))


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    session_id: str
    actor_id: str


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    ok: bool
    output: dict[str, Any] | None = None
    error_code: str | None = None
    artifact_refs: tuple[SafeArtifactRef, ...] = ()
    warnings: tuple[str, ...] = ()

    @classmethod
    def failure(cls, call: ToolCall, error: HarnessError) -> "ToolResult":
        return cls(call_id=call.call_id, ok=False, error_code=error.code)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "ok": self.ok,
            "error_code": self.error_code,
            "output": self.output,
            "artifact_refs": [reference.uri for reference in self.artifact_refs],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: ToolCategory
    handler: Callable[[ToolCall], ToolResult]
    accepted_inputs: frozenset[str] = field(default_factory=frozenset)
    output_classification: str = "safe_derived"
    side_effect: str = "read_only"
    permission: str = "analysis"
