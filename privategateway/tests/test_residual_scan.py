import pandas as pd

from privategateway.import_pipeline import _count_residual_findings
from privategateway.policy import DateShiftPolicy, Policy, SecurityPolicy


class DateDetectingPresidio:
    available = True

    def detect(self, value):
        if "2026-07-20" in str(value):
            return [{"entity_type": "DATE_TIME"}]
        return []


def test_post_scan_does_not_reject_policy_sanitized_date_column():
    policy = Policy(
        columns={"transaction_date": "date_shift", "status": "keep"},
        fingerprint="test",
        date_shift=DateShiftPolicy(),
        security=SecurityPolicy(require_presidio=False),
    )
    safe = pd.DataFrame([{
        "transaction_date": "2026-07-20",
        "status": "active",
    }])

    residual = _count_residual_findings(
        safe,
        policy,
        DateDetectingPresidio(),
        [],
    )

    assert residual == 0
