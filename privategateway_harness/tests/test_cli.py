from privategateway_harness.cli import _schema_from_preview


def test_schema_from_preview_keeps_only_sheet_names_columns_and_types():
    preview = {
        "sheets": [
            {
                "name": "Sheet1",
                "inferred_types": {"email": "object", "amount": "float64"},
                "sample": [{"email": "EMAIL_001", "amount": 10}],
            }
        ]
    }

    assert _schema_from_preview(preview) == {"Sheet1": {"email": "object", "amount": "float64"}}
