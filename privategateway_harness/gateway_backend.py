from __future__ import annotations

from pathlib import Path
from typing import Any

from privategateway.agent_plugin import sanitize_local_file_to_file
from privategateway.agent_plugin import preview_local_file
from privategateway.agent_plugin import preview_local_file


class LocalPrivateGatewayBackend:
    """Calls the existing gateway in-process; not an OS isolation boundary."""

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        *,
        input_type: str,
        project_id: str,
        policy_path: Path,
    ) -> dict[str, Any]:
        return sanitize_local_file_to_file(
            str(input_path), str(output_path), input_type=input_type,
            project_id=project_id, policy_path=str(policy_path), auto_policy=False,
        )

    def preview(self, input_path: Path, *, input_type: str, project_id: str) -> dict[str, Any]:
        return preview_local_file(str(input_path), input_type=input_type, project_id=project_id)

    def preview(self, input_path: Path, *, input_type: str, project_id: str) -> dict[str, Any]:
        return preview_local_file(str(input_path), input_type=input_type, project_id=project_id)
