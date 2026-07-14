import pytest

from privategateway.file_inputs import normalize_file_type, read_payloads


@pytest.mark.parametrize(
    ("suffix", "input_type"),
    [
        (".csv", "csv"),
        (".tsv", "tsv"),
        (".psv", "psv"),
        (".jsonl", "jsonl"),
        (".yaml", "yaml"),
        (".xml", "xml"),
        (".txt", "text"),
        (".parquet", "parquet"),
        (".zip", "zip"),
        (".gz", "gzip"),
    ],
)
def test_normalize_file_type_accepts_supported_aliases(tmp_path, suffix, input_type):
    path = tmp_path / f"data{suffix}"
    path.touch()
    assert normalize_file_type(path, input_type)


def test_read_payloads_parses_tsv(tmp_path):
    path = tmp_path / "customers.tsv"
    path.write_text("customer_id\temail\nC-1\talice@example.com\n", encoding="utf-8")

    payload = read_payloads(path)[0]

    assert payload.input_type == "dataframe"
    assert payload.data.to_dict("records") == [{"customer_id": "C-1", "email": "alice@example.com"}]


def test_read_payloads_rejects_unsupported_file_without_reading_it(tmp_path):
    path = tmp_path / "raw.pdf"
    path.write_bytes(b"%PDF-secret-content")

    with pytest.raises(ValueError, match="unsupported file type"):
        read_payloads(path)
