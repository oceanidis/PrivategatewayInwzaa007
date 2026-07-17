import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from privategateway import CoreSanitizer
from privategateway.key_provider import init_project


def test_sanitize_table_tokenizes_email_with_fixture_policy(monkeypatch):
    workspace = Path.cwd() / ".core_facade_test"
    shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir()
    try:
        policy = workspace / "policy.yaml"
        policy.write_text(
            """
columns:
  email: tokenize
unknown_column_action: keep
security:
  store_raw_copy: false
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(workspace)
        init_project("core_test")

        result = CoreSanitizer().sanitize_table(
            pd.DataFrame({"email": ["alice@example.com"]}),
            policy_path=policy,
            project_id="core_test",
            job_id="table_test",
        )

        assert result.safe_dataset["email"].iloc[0].startswith("EMAIL_")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_core_facade_does_not_import_langchain_modules():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import privategateway.core; print(any(m == 'langchain' or m.startswith('langchain.') for m in sys.modules))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "False"
