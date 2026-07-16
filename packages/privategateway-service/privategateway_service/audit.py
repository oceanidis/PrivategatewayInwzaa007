from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditWriteError(RuntimeError):
    pass


def append_service_audit(safe_root: Path, *, request_id: str, operation: str, outcome: str) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "operation": operation,
        "outcome": outcome,
    }
    path = safe_root / "gateway-audit.jsonl"
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n")
    except OSError as exc:
        raise AuditWriteError("AUDIT_WRITE_FAILED") from exc
