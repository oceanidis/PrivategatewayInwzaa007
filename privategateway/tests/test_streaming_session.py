import inspect

import pandas as pd
import pytest
from openpyxl import Workbook

from privategateway import agent_plugin
from privategateway.import_pipeline import StreamingSanitizationSession
from privategateway.key_provider import init_project


def test_streaming_session_uses_one_mapping_for_multiple_batches(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join([
            "security:",
            "  require_presidio: false",
            "columns:",
            "  customer_id: tokenize",
            "default:",
            "  unknown_column: review_required",
        ]),
        encoding="utf-8",
    )
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("analytics", key_root=key_root)

    session = StreamingSanitizationSession(
        policy_path=policy,
        project_id="analytics",
        job_id="one_job",
        raw_payload=b"workbook-placeholder",
        input_type="excel",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )
    first = session.sanitize_frame(pd.DataFrame({"customer_id": ["C-001"]}))
    second = session.sanitize_frame(pd.DataFrame({"customer_id": ["C-001"]}))
    result = session.finalize()

    assert first.safe_dataset.iloc[0, 0] == second.safe_dataset.iloc[0, 0]
    assert result.mapping_table is not None
    assert result.can_export


def test_excel_export_uses_one_session_across_batches(tmp_path, monkeypatch):
    source = tmp_path / "input.xlsx"
    target = tmp_path / "safe.xlsx"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join([
            "security:",
            "  require_presidio: false",
            "columns:",
            "  customer_id: tokenize",
            "default:",
            "  unknown_column: review_required",
        ]),
        encoding="utf-8",
    )
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["customer_id"])
    sheet.append(["C-001"])
    sheet.append(["C-002"])
    workbook.save(source)
    monkeypatch.setattr(agent_plugin, "GATEWAY_ROOT", tmp_path / "gateway")
    monkeypatch.setattr(agent_plugin, "KEY_ROOT", tmp_path / "gateway" / ".privacy_gateway" / "keys")
    monkeypatch.setattr(agent_plugin, "EXCEL_BATCH_ROWS", 1)

    exported = agent_plugin.sanitize_local_file_to_file(
        str(source),
        str(target),
        input_type="excel",
        project_id="analytics",
        policy_path=str(policy),
        auto_policy=False,
        scan_mode="sealed_analytics",
    )

    assert target.exists()
    assert exported["redaction_report"]["action_counts"]["tokenize"] == 2
    assert exported["redaction_report"]["job_id"].startswith("mcp_export_")


def test_excel_export_writes_synthesized_missing_numeric_values_as_blank_cells(tmp_path, monkeypatch):
    source = tmp_path / "input.xlsx"
    target = tmp_path / "safe.xlsx"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join([
            "security:",
            "  require_presidio: false",
            "columns:",
            "  amount: synthesize",
            "default:",
            "  unknown_column: review_required",
        ]),
        encoding="utf-8",
    )
    workbook = Workbook()
    workbook.active.append(["amount"])
    workbook.active.append([100.0])
    workbook.active.append([None])
    workbook.save(source)
    monkeypatch.setattr(agent_plugin, "GATEWAY_ROOT", tmp_path / "gateway")
    monkeypatch.setattr(agent_plugin, "KEY_ROOT", tmp_path / "gateway" / ".privacy_gateway" / "keys")

    agent_plugin.sanitize_local_file_to_file(
        str(source), str(target), "excel", "analytics", str(policy), False, "sealed_analytics"
    )

    assert target.exists()


def test_large_export_runs_synchronously_by_default(tmp_path, monkeypatch):
    source = tmp_path / "input.xlsx"
    target = tmp_path / "safe.xlsx"
    source.write_bytes(b"placeholder")
    monkeypatch.setattr(agent_plugin, "_sanitize_local_file_to_file_sync", lambda *args: {"mode": "synchronous"})

    result = agent_plugin.sanitize_local_file_to_file(
        str(source), str(target), "excel", "analytics", "policy.yaml", False, "sealed_analytics"
    )

    assert result == {"mode": "synchronous"}


def test_export_public_api_is_synchronous_only():
    assert "experimental_background" not in inspect.signature(agent_plugin.sanitize_local_file_to_file).parameters
    assert not hasattr(agent_plugin, "get_export_job_status")


def test_export_rejects_auto_policy_without_an_explicit_policy(tmp_path):
    source = tmp_path / "input.xlsx"
    target = tmp_path / "safe.xlsx"
    source.write_bytes(b"placeholder")

    with pytest.raises(ValueError, match="auto_policy is preview-only"):
        agent_plugin.sanitize_local_file_to_file(
            str(source), str(target), "excel", "analytics", None, True, "sealed_analytics"
        )


def test_auto_policy_export_rejects_before_reading_excel_preview(tmp_path, monkeypatch):
    source = tmp_path / "input.xlsx"
    target = tmp_path / "safe.xlsx"
    workbook = Workbook()
    workbook.active.append(["customer_id", "status"])
    workbook.active.append(["C-001", "ACTIVE"])
    workbook.save(source)
    monkeypatch.setattr(agent_plugin, "GATEWAY_ROOT", tmp_path / "gateway")
    monkeypatch.setattr(agent_plugin, "KEY_ROOT", tmp_path / "gateway" / ".privacy_gateway" / "keys")
    calls = []

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("auto-policy export must not read a preview")

    monkeypatch.setattr(agent_plugin, "read_preview_payloads", counted)

    with pytest.raises(ValueError, match="auto_policy is preview-only"):
        agent_plugin.sanitize_local_file_to_file(
            str(source), str(target), "excel", "analytics", None, True, "sealed_analytics"
        )

    assert calls == []
