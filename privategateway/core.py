from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from .import_pipeline import sanitize_import


class CoreSanitizer:
    def sanitize_table(
        self,
        table: Any,
        *,
        policy_path: str | Path,
        project_id: str,
        job_id: str | None = None,
        scan_mode: str = "fast",
        secure_root: str | Path = ".privacy_gateway/secure",
        key_root: str | Path = ".privacy_gateway/keys",
    ) -> Any:
        return sanitize_import(
            input_data=table,
            input_type="dataframe",
            policy_path=policy_path,
            project_id=project_id,
            job_id=job_id or f"core_{uuid4().hex}",
            scan_mode=scan_mode,
            secure_root=secure_root,
            key_root=key_root,
        )

    def sanitize_text(
        self,
        text: Any,
        *,
        policy_path: str | Path,
        project_id: str,
        job_id: str | None = None,
        scan_mode: str = "fast",
        secure_root: str | Path = ".privacy_gateway/secure",
        key_root: str | Path = ".privacy_gateway/keys",
    ) -> Any:
        return sanitize_import(
            input_data=text,
            input_type="text",
            policy_path=policy_path,
            project_id=project_id,
            job_id=job_id or f"core_{uuid4().hex}",
            scan_mode=scan_mode,
            secure_root=secure_root,
            key_root=key_root,
        )
