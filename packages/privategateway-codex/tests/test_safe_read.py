from __future__ import annotations

from privategateway_protocol import OutputClassification, SanitizedEnvelope

from privategateway_codex.safe_read import SafeFileReader


class _Runtime:
    def __init__(self, client: object) -> None:
        self.client = client
        self.calls = 0

    def ensure_client(self) -> object:
        self.calls += 1
        return self.client


class _Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def read_safe_table(self, path: str, *, offset: int, limit: int):
        self.calls.append(("table", {"path": path, "offset": offset, "limit": limit}))
        return SanitizedEnvelope(
            "req_1",
            OutputClassification.SANITIZED,
            {"rows": [{"email": "EMAIL_001"}], "offset": offset, "limit": limit, "sheet_scope": "default_sheet_only"},
            "policy",
            "source",
            "content",
        )

    def read_safe_text(self, path: str, *, max_chars: int):
        self.calls.append(("text", {"path": path, "max_chars": max_chars}))
        return SanitizedEnvelope(
            "req_2",
            OutputClassification.SANITIZED,
            {"text": "[REDACTED_EMAIL]", "returned_chars": 16, "truncated": False},
            "policy",
            "source",
            "content",
        )


def test_csv_routes_to_existing_safe_table_operation() -> None:
    client = _Client()
    reader = SafeFileReader(_Runtime(client))

    response = reader.read("C:/protected/customers.csv", offset=3, limit=10)

    assert client.calls == [("table", {"path": "C:/protected/customers.csv", "offset": 3, "limit": 10})]
    assert response == {
        "ok": True,
        "kind": "table",
        "file_type": "csv",
        "sheet_scope": "default_sheet_only",
        "rows": [{"email": "EMAIL_001"}],
        "pagination": {"offset": 3, "limit": 10, "returned": 1},
        "redaction_summary": {"sanitized": True},
    }


def test_text_routes_to_existing_safe_text_operation() -> None:
    client = _Client()
    reader = SafeFileReader(_Runtime(client))

    response = reader.read("C:/protected/note.txt", max_chars=123)

    assert client.calls == [("text", {"path": "C:/protected/note.txt", "max_chars": 123})]
    assert response["kind"] == "text"
    assert response["text"] == "[REDACTED_EMAIL]"


def test_unsupported_type_does_not_start_gateway() -> None:
    runtime = _Runtime(_Client())
    reader = SafeFileReader(runtime)

    response = reader.read("C:/protected/customers.parquet")

    assert response == {"ok": False, "error_code": "UNSUPPORTED_SAFE_READ_TYPE"}
    assert runtime.calls == 0
