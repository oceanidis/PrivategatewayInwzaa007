from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class Capability(StrEnum):
    DIRECTORY_BROWSE = "directory_browse"
    METADATA_INSPECT = "metadata_inspect"
    SAFE_TABLE_READ = "safe_table_read"
    SAFE_TEXT_READ = "safe_text_read"
    SAFE_COPY_CREATE = "safe_copy_create"
    SANDBOXED_EXECUTION = "sandboxed_execution"
    SAFE_EXPORT = "safe_export"
    NETWORK_UPLOAD = "network_upload"
    ADMIN = "admin"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ROUTE_TO_GATEWAY = "route_to_gateway"


@dataclass(frozen=True)
class ExecutionRequest:
    request_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    actor_id: str = "unknown"
    trace_id: str = ""


@dataclass(frozen=True)
class CapabilitySpec:
    capability: Capability
    resource_fields: tuple[str, ...] = ()
    sandboxed: bool = False


@dataclass(frozen=True)
class Authorization:
    decision: Decision
    request_id: str
    tool_name: str
    capability: Capability | None = None
    reason_code: str = ""
