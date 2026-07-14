from __future__ import annotations

from .agent_plugin import (
    get_export_job_status as _get_export_job_status,
    preview_local_file as _preview_local_file,
    sanitize_file,
    sanitize_local_file_to_file as _sanitize_local_file_to_file,
    sanitize_records,
    sanitize_text,
)


def build_server():
    """Build the optional MCP server without exposing raw or mapping data."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "MCP support is optional. Install with: pip install 'privategateway[mcp]'"
        ) from exc

    server = FastMCP("privategateway")

    @server.tool()
    def sanitize_local_file(
        path: str,
        input_type: str | None = None,
        project_id: str | None = None,
        policy_path: str | None = None,
    ) -> dict:
        """Sanitize supported data files and return only safe data and reports."""
        return sanitize_file(path, input_type, project_id, policy_path)

    @server.tool()
    def preview_local_file(
        path: str,
        input_type: str | None = None,
        project_id: str | None = None,
        policy_path: str | None = None,
        preview_rows: int = 10,
        auto_policy: bool = True,
    ) -> dict:
        """Return a sanitized bounded sample and inferred structure; no full export."""
        return _preview_local_file(path, input_type, project_id, policy_path, preview_rows, auto_policy)
    @server.tool()
    def sanitize_local_file_to_file(
        input_path: str,
        output_path: str,
        input_type: str | None = None,
        project_id: str | None = None,
        policy_path: str | None = None,
        auto_policy: bool = True,
        scan_mode: str = "fast",
    ) -> dict:
        """Sanitize a file, including every Excel sheet, and write a safe output file."""
        return _sanitize_local_file_to_file(
            input_path, output_path, input_type, project_id, policy_path, auto_policy, scan_mode
        )

    @server.tool()
    def get_export_job_status(job_id: str) -> dict:
        """Return safe status and final safe report for a background file export."""
        return _get_export_job_status(job_id)

    @server.tool()
    def sanitize_text_input(
        text: str,
        project_id: str | None = None,
        policy_path: str | None = None,
    ) -> dict:
        """Auto-init a project and sanitize text before downstream use."""
        return sanitize_text(text, project_id, policy_path)

    @server.tool()
    def sanitize_record_input(
        records: list[dict],
        project_id: str | None = None,
        policy_path: str | None = None,
    ) -> dict:
        """Auto-init a project and sanitize structured records before downstream use."""
        return sanitize_records(records, project_id, policy_path)

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
