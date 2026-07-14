from types import SimpleNamespace

import pandas as pd

import privategateway.agent_plugin as agent_plugin
from privategateway.agent_plugin import _policy_payload_for_frame
from privategateway.file_inputs import FilePayload
from privategateway.policy_generator import infer_policy
from privategateway.redaction_report import RedactionReport


def test_auto_policy_keeps_low_cardinality_status_code_before_identifier_heuristic():
    frame = pd.DataFrame({
        "StatusCode": ["ACTIVE", "CLOSED", "ACTIVE", "CLOSED", "ACTIVE", "CLOSED"],
    })

    columns, _, decisions, _ = infer_policy(frame)

    assert columns["StatusCode"] == "keep"
    assert decisions[0].reason == "safe low-cardinality category"


def test_auto_policy_requires_review_for_numeric_amounts():
    frame = pd.DataFrame({"OutstandingAmount": [100.0, 250.0, 900.0, 1200.0]})

    columns, _, _, _ = infer_policy(frame)

    assert columns["OutstandingAmount"] == "review_required"


def test_policy_draft_is_complete_and_does_not_embed_source_values():
    frame = pd.DataFrame({
        "CustomerID": ["C-001", "C-002"],
        "OutstandingAmount": [100.0, 250.0],
    })

    draft = _policy_payload_for_frame(frame)

    assert draft["columns"] == {
        "CustomerID": "tokenize",
        "OutstandingAmount": "review_required",
    }
    assert draft["security"]["store_raw_copy"] is False
    assert draft["default"]["unknown_column"] == "review_required"
    assert "C-001" not in str(draft)


def test_preview_returns_complete_policy_draft(monkeypatch):
    frame = pd.DataFrame({"CustomerID": ["C-001"], "OutstandingAmount": [100.0]})
    report = RedactionReport("project", "job", "dataframe", "fingerprint")
    result = SimpleNamespace(safe_dataset=pd.DataFrame({"CustomerID": ["CUSTOMER_ID_001"]}), redaction_report=report)

    monkeypatch.setattr(agent_plugin, "_ensure_project", lambda project_id: "project")
    monkeypatch.setattr(agent_plugin, "read_preview_payloads", lambda *args, **kwargs: [FilePayload("Sheet1", "dataframe", frame)])
    monkeypatch.setattr(agent_plugin, "_sanitize_frame_direct", lambda *args, **kwargs: result)

    preview = agent_plugin.preview_local_file("preview.xlsx", input_type="xlsx")

    draft = preview["sheets"][0]["suggested_policy"]
    assert draft["security"]["store_raw_copy"] is False
    assert draft["columns"]["CustomerID"] == "tokenize"
    assert draft["columns"]["OutstandingAmount"] == "review_required"


def test_auto_policy_selectively_redacts_free_text_in_sealed_analytics_default():
    frame = pd.DataFrame({"note": ["call customer", "follow up"]})

    columns, _, _, _ = infer_policy(frame)

    assert columns["note"] == "redact_text"


def test_auto_policy_requires_review_for_unclassified_text():
    frame = pd.DataFrame({"UnclassifiedLabel": ["alpha", "beta", "gamma"]})

    columns, _, _, _ = infer_policy(frame)

    assert columns["UnclassifiedLabel"] == "review_required"


def test_auto_policy_preserves_generic_operational_dimensions_without_exposing_user_ids():
    frame = pd.DataFrame({
        "CustomerID": ["C001", "C002", "C003", "C004", "C005", "C006"],
        "IsArchived": [True, True, False, True, False, True],
        "SourceSystem": ["SYSTEM_A", "SYSTEM_A", "SYSTEM_B", "SYSTEM_B", "SYSTEM_A", "SYSTEM_B"],
        "OrganizationCode": ["ORG_A", "ORG_A", "ORG_B", "ORG_B", "ORG_A", "ORG_B"],
        "OriginLocationCode": [1, 1, 2, 2, 1, 2],
        "PriorLocationCode": [10, 10, 20, 20, 10, 20],
        "CurrentLocationCode": ["L1", "L1", "L2", "L2", "L1", "L2"],
        "Description": ["ordinary business description"] * 6,
        "RecordedDate": pd.to_datetime(["2025-01-01"] * 6),
        "Notes": ["ordinary note"] * 6,
        "LastModifiedDate": pd.to_datetime(["2025-01-02"] * 6),
        "AuditTime": ["08:15:00", "09:30:00"] * 3,
        "ProcessedBy": ["operator_a", "operator_b"] * 3,
        "AgentCode": ["AGENT001", "AGENT002"] * 3,
        "OfficeCode": ["OFFICE_A", "OFFICE_B"] * 3,
        "Amount": ["1,200.50", "2,400.00"] * 3,
    })

    columns, _, _, _ = infer_policy(frame)

    assert columns["CustomerID"] == "tokenize"
    assert columns["IsArchived"] == "keep"
    for column in ("SourceSystem", "OrganizationCode", "OriginLocationCode", "PriorLocationCode", "CurrentLocationCode", "Description", "OfficeCode"):
        assert columns[column] == "tokenize"
    assert columns["Notes"] == "redact_text"
    assert columns["RecordedDate"] == "date_shift"
    assert columns["LastModifiedDate"] == "date_shift"
    assert columns["AuditTime"] == "time_shift"
    assert columns["ProcessedBy"] == "tokenize"
    assert columns["AgentCode"] == "tokenize"
    assert columns["OfficeCode"] == "tokenize"
    assert columns["Amount"] == "review_required"


def test_auto_policy_classifies_repeated_numeric_values_as_category_not_measure():
    frame = pd.DataFrame({
        "NumericGroup": [1, 2, 3, 1, 2, 3] * 20,
        "ContinuousValue": list(range(120)),
    })

    columns, _, decisions, _ = infer_policy(frame)
    roles = {decision.source_name: decision.role for decision in decisions}

    assert columns["NumericGroup"] == "tokenize"
    assert roles["NumericGroup"] == "category"
    assert columns["ContinuousValue"] == "review_required"
    assert roles["ContinuousValue"] == "unknown_numeric"


def test_auto_policy_assigns_shared_domains_to_related_category_columns():
    from privategateway.policy_generator import infer_token_domains

    frame = pd.DataFrame({
        "SourceSystem": ["A", "B"] * 20,
        "OrganizationCode": ["C1", "C2"] * 20,
        "OriginLocationCode": [1, 2] * 20,
        "PriorLocationCode": [2, 1] * 20,
        "CurrentLocationCode": [1, 1, 2, 2] * 10,
        "Description": ["fee", "refund"] * 20,
    })

    _, _, decisions, _ = infer_policy(frame)
    domains = infer_token_domains(decisions)

    assert domains == {
        "SourceSystem": "SOURCE",
        "OrganizationCode": "ORGANIZATION",
        "OriginLocationCode": "LOCATION",
        "PriorLocationCode": "LOCATION",
        "CurrentLocationCode": "LOCATION",
        "Description": "DESCRIPTION",
    }
