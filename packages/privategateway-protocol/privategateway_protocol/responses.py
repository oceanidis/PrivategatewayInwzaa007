from dataclasses import dataclass
from typing import Any

from .enums import OutputClassification


@dataclass(frozen=True)
class SanitizedEnvelope:
    request_id: str
    classification: OutputClassification
    payload: Any
    policy_fingerprint: str
    source_fingerprint: str
    content_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "request_id": self.request_id,
            "classification": self.classification.value,
            "payload": self.payload,
            "policy_fingerprint": self.policy_fingerprint,
            "source_fingerprint": self.source_fingerprint,
            "content_hash": self.content_hash,
        }
