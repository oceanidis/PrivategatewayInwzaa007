from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .enums import GatewayOperation


@dataclass(frozen=True)
class GatewayRequest:
    request_id: str
    operation: GatewayOperation
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id or not self.request_id.strip():
            raise ValueError("INVALID_REQUEST_ID")
