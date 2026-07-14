from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd

from .import_pipeline import sanitize_import
from .redaction_report import ReviewOverride


GATEWAY_ROOT = Path(__file__).resolve().parents[1]


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    input_type = str(request.get("input_type", "")).strip().lower()
    if input_type not in {"text", "csv", "tsv", "psv", "excel", "json", "jsonl", "xml", "yaml", "parquet", "feather", "orc", "dataframe"}:
        raise ValueError("unsupported input_type")
    data = request.get("data")
    if "data_base64" in request:
        data = base64.b64decode(str(request["data_base64"]), validate=True)
    if input_type == "dataframe":
        if isinstance(data, dict):
            data = [data]
        data = pd.DataFrame(data or [])

    policy_path = Path(request.get("policy_path") or GATEWAY_ROOT / "privategateway" / "config.yaml")
    secure_root = Path(request.get("secure_root") or GATEWAY_ROOT / ".privacy_gateway" / "secure")
    key_root = Path(request.get("key_root") or GATEWAY_ROOT / ".privacy_gateway" / "keys")
    override_data = request.get("review_override")
    review_override = None
    if override_data is not None:
        if not isinstance(override_data, dict):
            raise ValueError("review_override must be an object")
        review_override = ReviewOverride(
            actor=str(override_data.get("actor", "")),
            reason=str(override_data.get("reason", "")),
        )

    result = sanitize_import(
        input_data=data,
        input_type=input_type,
        policy_path=policy_path,
        project_id=str(request.get("project_id", "")),
        job_id=str(request.get("job_id") or f"ipc_{uuid4().hex}"),
        review_override=review_override,
        secure_root=secure_root,
        key_root=key_root,
    )
    response: dict[str, Any] = {
        "ok": True,
        "can_export": result.can_export,
        "safe_dataset": _json_safe(result.safe_dataset) if result.can_export else None,
        "redaction_report": result.redaction_report.to_safe_dict(),
        "mapping_reference": None,
    }
    return response


def _json_safe(value: Any) -> Any:
    if isinstance(value, pd.DataFrame):
        return json.loads(value.to_json(orient="records", force_ascii=False, date_format="iso"))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))
