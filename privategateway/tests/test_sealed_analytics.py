import pandas as pd
import pytest

from privategateway import import_pipeline
from privategateway.import_pipeline import _sanitize_frame, sanitize_import
from privategateway.key_provider import init_project
from privategateway.policy import Policy, SecurityPolicy
from privategateway.redaction_report import RedactionReport
from privategateway.tokenizer import Tokenizer


def _policy(tmp_path, columns):
    path = tmp_path / "policy.yaml"
    lines = ["security:", "  require_presidio: false", "columns:"]
    lines.extend(f"  {name}: {action}" for name, action in columns.items())
    lines.extend(["default:", "  unknown_column: review_required"])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_sealed_analytics_synthesizes_numeric_values_without_copying_source_values(tmp_path):
    policy = _policy(tmp_path, {"amount": "synthesize"})
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("analytics", key_root=key_root)
    source = pd.DataFrame({"amount": [100.0, 250.0, 900.0, 1200.0, None]})

    result = sanitize_import(
        source,
        "dataframe",
        policy,
        "analytics",
        "synthesis",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    output = result.safe_dataset["amount"]
    assert output.isna().sum() == 1
    assert set(output.dropna()).isdisjoint(set(source["amount"].dropna()))
    assert output.dropna().between(100.0, 1200.0).all()


def test_sealed_analytics_synthesizes_formatted_amount_strings(tmp_path):
    policy = _policy(tmp_path, {"amount": "synthesize"})
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("formatted-amounts", key_root=key_root)
    source = pd.DataFrame({"amount": ["1,200.50", "THB 2,400.00", "(300.00)", "-"]})

    result = sanitize_import(
        source,
        "dataframe",
        policy,
        "formatted-amounts",
        "synthesis",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    output = result.safe_dataset["amount"]
    assert output.notna().sum() == 3
    assert output.dropna().between(-300.0, 2400.0).all()
    assert set(output.dropna()).isdisjoint({1200.5, 2400.0, -300.0})


def test_time_shift_masks_time_of_day_with_a_stable_subject_offset(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join([
            "security:",
            "  require_presidio: false",
            "time_shift:",
            "  subject_column: customer_id",
            "  min_minutes: 60",
            "  max_minutes: 60",
            "  direction: forward",
            "  stability: project",
            "columns:",
            "  customer_id: tokenize",
            "  audit_time: time_shift",
            "default:",
            "  unknown_column: review_required",
        ]),
        encoding="utf-8",
    )
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("time-shift", key_root=key_root)

    result = sanitize_import(
        pd.DataFrame({
            "CustomerID": ["C1", "C1", "C2", None],
            "AuditTime": ["01:15:00", "23:30:00", "08:00:00", None],
        }),
        "dataframe",
        policy,
        "time-shift",
        "time-mask",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    assert result.can_export
    assert result.safe_dataset["AuditTime"].iloc[:3].tolist() == ["02:15:00", "00:30:00", "09:00:00"]
    assert pd.isna(result.safe_dataset["AuditTime"].iloc[3])


def test_sealed_analytics_still_blocks_sensitive_values_in_keep_columns(tmp_path):
    policy = _policy(tmp_path, {"status": "keep"})
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("analytics", key_root=key_root)

    result = sanitize_import(
        pd.DataFrame({"status": ["contact alice@example.com"]}),
        "dataframe",
        policy,
        "analytics",
        "keep_pii",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    assert not result.can_export
    assert result.redaction_report.residual_detections > 0


def test_session_skips_presidio_initialization_when_policy_never_uses_text_detection(tmp_path, monkeypatch):
    policy = _policy(tmp_path, {"customer_id": "tokenize"})
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("analytics", key_root=key_root)

    def unexpected_presidio_load():
        raise AssertionError("Presidio must not initialize for token-only policies")

    monkeypatch.setattr(import_pipeline, "get_presidio_detector", unexpected_presidio_load)
    session = import_pipeline.StreamingSanitizationSession(
        policy_path=policy,
        project_id="analytics",
        job_id="token_only",
        raw_payload=b"test",
        input_type="excel",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    assert not session.presidio.available


def test_redact_text_scans_each_unique_value_once_across_batches():
    policy = Policy(
        columns={"note": "redact_text"},
        fingerprint="test",
        security=SecurityPolicy(require_presidio=False),
    )

    class CountingPresidio:
        available = True

        def __init__(self):
            self.detect_calls = 0

        def detect(self, value):
            self.detect_calls += 1
            return []

        def redact(self, value):
            self.detect(value)
            return str(value), 0

    detector = CountingPresidio()
    report = RedactionReport(
        project_id="analytics",
        job_id="single_scan",
        input_type="dataframe",
        policy_fingerprint=policy.fingerprint,
        presidio_available=True,
        date_shift={},
    )
    text_cache = {}
    _sanitize_frame(
        pd.DataFrame({"note": ["repeat", "repeat", "second"]}),
        policy,
        Tokenizer(b"x" * 32),
        report,
        detector,
        [],
        b"y" * 32,
        "sealed_analytics",
        text_cache,
    )
    _sanitize_frame(
        pd.DataFrame({"note": ["repeat"]}),
        policy,
        Tokenizer(b"x" * 32),
        report,
        detector,
        [],
        b"y" * 32,
        "sealed_analytics",
        text_cache,
    )

    assert detector.detect_calls == 2


def test_redact_text_cache_preserves_missing_values():
    policy = Policy(
        columns={"note": "redact_text"},
        fingerprint="test",
        security=SecurityPolicy(require_presidio=False),
    )

    class CountingPresidio:
        available = True

        def __init__(self):
            self.detect_calls = 0

        def redact(self, value):
            self.detect_calls += 1
            return str(value), 0

    detector = CountingPresidio()
    report = RedactionReport(
        project_id="analytics",
        job_id="missing-text",
        input_type="dataframe",
        policy_fingerprint=policy.fingerprint,
        presidio_available=True,
        date_shift={},
    )

    safe = _sanitize_frame(
        pd.DataFrame({"note": ["repeat", None, ""]}),
        policy,
        Tokenizer(b"x" * 32),
        report,
        detector,
        [],
        b"y" * 32,
        "sealed_analytics",
        {},
    )

    assert detector.detect_calls == 1
    assert safe["note"].isna().sum() == 2


def test_token_domains_preserve_cross_column_category_relationships(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join([
            "security:",
            "  require_presidio: false",
            "columns:",
            "  origin_location_code: tokenize",
            "  current_location_code: tokenize",
            "token_domains:",
            "  origin_location_code: LOCATION",
            "  current_location_code: LOCATION",
            "default:",
            "  unknown_column: review_required",
        ]),
        encoding="utf-8",
    )
    key_root = tmp_path / "keys"
    secure_root = tmp_path / "secure"
    init_project("category-domains", key_root=key_root)

    result = sanitize_import(
        pd.DataFrame({"OriginLocationCode": ["A", "B", None], "CurrentLocationCode": ["A", "A", None]}),
        "dataframe",
        policy,
        "category-domains",
        "domain-test",
        secure_root=secure_root,
        key_root=key_root,
        scan_mode="sealed_analytics",
    )

    safe = result.safe_dataset
    assert safe.loc[0, "OriginLocationCode"] == safe.loc[0, "CurrentLocationCode"]
    assert safe.loc[0, "OriginLocationCode"].startswith("LOCATION_")
    assert safe.loc[1, "OriginLocationCode"] != safe.loc[1, "CurrentLocationCode"]
    assert safe.loc[2, ["OriginLocationCode", "CurrentLocationCode"]].isna().all()
