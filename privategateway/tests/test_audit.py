import json

from privategateway.audit import append_audit_event, verify_audit_log
from privategateway.cli import main


def _import_event(job_id: str) -> dict[str, object]:
    return {
        "event": "import_sanitized",
        "project_id": "project",
        "job_id": job_id,
        "policy_fingerprint": "f" * 64,
        "can_export": True,
        "blocked": False,
        "review_actor": None,
        "review_reason": None,
    }


def test_audit_log_verifies_a_hash_chained_event_sequence(tmp_path):
    append_audit_event(tmp_path, _import_event("job_001"))
    append_audit_event(tmp_path, _import_event("job_002"))

    result = verify_audit_log(tmp_path)

    assert result == {"valid": True, "event_count": 2, "last_hash": result["last_hash"], "error": None}
    assert len(result["last_hash"]) == 64


def test_audit_verification_detects_modified_event(tmp_path):
    append_audit_event(tmp_path, _import_event("job_001"))
    path = tmp_path / "audit.v1.jsonl"
    event = json.loads(path.read_text(encoding="utf-8"))
    event["can_export"] = False
    path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

    result = verify_audit_log(tmp_path)

    assert result["valid"] is False
    assert result["event_count"] == 0
    assert result["error"] == "event 1 hash mismatch"


def test_verify_audit_cli_returns_machine_readable_status(tmp_path, capsys):
    append_audit_event(tmp_path, _import_event("job_001"))

    exit_code = main(["verify-audit", "--secure-root", str(tmp_path)])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
