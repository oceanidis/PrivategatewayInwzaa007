import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from privategateway.key_provider import init_project
from privategateway.masker import handle_request


def _workspace(name: str) -> Path:
    path = Path("test_runs") / f"{name}_{uuid4().hex}"
    path.mkdir(parents=True)
    return path.resolve()


def _policy(workspace: Path) -> Path:
    path = workspace / "policy.yaml"
    path.write_text(
        """
security:
  key_provider: dpapi
  require_presidio: false
  raw_ttl_hours: 24
  mapping_ttl_days: 30
date_shift:
  scope: subject
  subject_column: customer_id
  min_days: 1
  max_days: 30
  direction: both
  stability: project
columns:
  customer_id: hash
  email: tokenize
default:
  unknown_column: review_required
""".strip(),
        encoding="utf-8",
    )
    return path


@pytest.mark.skipif(os.name != "nt", reason="PrivateGateway uses Windows DPAPI")
def test_handle_request_returns_safe_json_without_mapping_values():
    workspace = _workspace("masker")
    policy = _policy(workspace)
    init_project("loan_ai", key_root=workspace / "keys")
    request = {
        "input_type": "dataframe",
        "data": [{"customer_id": "C-1", "email": "alice@example.com"}],
        "policy_path": str(policy),
        "project_id": "loan_ai",
        "job_id": "job_masker",
        "secure_root": str(workspace / "secure"),
        "key_root": str(workspace / "keys"),
    }

    response = handle_request(request)
    encoded = json.dumps(response, ensure_ascii=False)

    assert response["ok"] is True
    assert response["can_export"] is True
    assert response["safe_dataset"][0]["email"].startswith("EMAIL_")
    assert response["mapping_reference"] is None
    assert "alice@example.com" not in encoded
