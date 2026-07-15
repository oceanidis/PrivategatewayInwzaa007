from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .session_store import Session


def schema_fingerprint(schema: dict[str, dict[str, str]]) -> str:
    return _fingerprint(schema)


class PolicyReviewStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def approve(self, policy_path: Path, schema_hash: str, *, actor: str, reason: str) -> dict[str, str]:
        policy_bytes = policy_path.read_bytes()
        policy_hash = hashlib.sha256(policy_bytes).hexdigest()
        copied_policy = self.session.root / "policies" / f"policy-{policy_hash}.yaml"
        copied_policy.write_bytes(policy_bytes)
        approval = {
            "approval_id": uuid4().hex,
            "policy_fingerprint": policy_hash,
            "schema_fingerprint": schema_hash,
            "actor": actor,
            "reason": reason,
            "status": "APPROVED",
            "approved_at": datetime.now(UTC).isoformat(),
        }
        (self.session.root / "policies" / "approvals" / f"approval-{approval['approval_id']}.json").write_text(
            json.dumps(approval, sort_keys=True), encoding="utf-8"
        )
        approvals = {**self.session.manifest.get("approvals", {}), policy_hash: approval}
        self.session.save_manifest({**self.session.manifest, "approvals": approvals})
        return approval

    def is_approved(self, policy_hash: str, schema_hash: str) -> bool:
        approval = self.session.manifest.get("approvals", {}).get(policy_hash, {})
        return approval.get("status") == "APPROVED" and approval.get("schema_fingerprint") == schema_hash


def _fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
