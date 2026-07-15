from privategateway_harness.contracts import SafeArtifactRef, ToolCall, ToolResult
from privategateway_harness.errors import HarnessError


def test_safe_artifact_ref_round_trips_as_a_session_scoped_uri():
    reference = SafeArtifactRef.parse("safe://session-001/a07d1298")

    assert reference.session_id == "session-001"
    assert reference.artifact_id == "a07d1298"
    assert reference.uri == "safe://session-001/a07d1298"


def test_safe_artifact_ref_rejects_malformed_or_encoded_values():
    for value in (
        "safe://session-001",
        "safe://session-001/a07d1298/extra",
        "SAFE://session-001/a07d1298",
        "safe://session-001/%7Bartifact%7D",
    ):
        try:
            SafeArtifactRef.parse(value)
        except HarnessError as error:
            assert error.code == "INVALID_SAFE_ARTIFACT_REF"
        else:
            raise AssertionError(f"expected invalid reference: {value}")


def test_tool_result_uses_stable_error_code_without_exception_details():
    call = ToolCall(
        call_id="call-001",
        tool_name="describe_table",
        arguments={"artifact": "safe://session-001/a07d1298"},
        session_id="session-001",
        actor_id="agent-001",
    )
    result = ToolResult.failure(call, HarnessError("RAW_DATA_REQUIRES_IMPORT", "C:\\secret\\raw.xlsx"))

    assert result.to_dict() == {
        "call_id": "call-001",
        "ok": False,
        "error_code": "RAW_DATA_REQUIRES_IMPORT",
        "output": None,
        "artifact_refs": [],
        "warnings": [],
    }
