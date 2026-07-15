from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .config import HarnessConfig
from .gateway_backend import LocalPrivateGatewayBackend
from .runtime import HarnessRuntime


@dataclass(frozen=True)
class HarnessMcpSettings:
    project_id: str
    sessions_root: Path
    raw_roots: tuple[Path, ...]
    policy_root: Path
    actor: str = 'mcp-user'

    @classmethod
    def from_env(cls) -> 'HarnessMcpSettings':
        project_id = _required_env('PRIVATEGATEWAY_HARNESS_PROJECT_ID')
        sessions_root = Path(_required_env('PRIVATEGATEWAY_HARNESS_SESSIONS_ROOT'))
        policy_root = Path(_required_env('PRIVATEGATEWAY_HARNESS_POLICY_ROOT'))
        raw_roots = tuple(Path(value) for value in _required_env('PRIVATEGATEWAY_HARNESS_RAW_ROOTS').split(';') if value)
        if not raw_roots:
            raise RuntimeError('PRIVATEGATEWAY_HARNESS_RAW_ROOTS is required')
        return cls(project_id, sessions_root, raw_roots, policy_root, os.environ.get('PRIVATEGATEWAY_HARNESS_ACTOR', 'mcp-user'))

    def policy_path(self, name: str) -> Path:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('policy_name must be relative to the configured policy root')
        candidate = (self.policy_root / relative).resolve()
        if not candidate.is_relative_to(self.policy_root.resolve()) or not candidate.is_file():
            raise ValueError('policy_name is not an approved policy file')
        return candidate


def build_server(settings: HarnessMcpSettings | None = None):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError('MCP support is optional. Install with: pip install privategateway[mcp]') from exc
    active = settings or HarnessMcpSettings.from_env()
    server = FastMCP('privategateway-harness')

    def runtime() -> HarnessRuntime:
        return HarnessRuntime(HarnessConfig(active.project_id, active.sessions_root, active.raw_roots), LocalPrivateGatewayBackend())

    @server.tool()
    def import_dataset(session_id: str, input_path: str, input_type: str, policy_name: str, reason: str) -> dict:
        '''Sanitize a file inside configured raw roots and return a safe artifact reference only.'''
        harness = runtime()
        try:
            harness.create_session(session_id)
        except Exception:
            harness.resume_session(session_id)
        try:
            policy = active.policy_path(policy_name)
            schema = harness.preview_schema(Path(input_path), input_type)
            harness.approve_policy(policy, schema, actor=active.actor, reason=reason)
            artifact = harness.import_dataset(Path(input_path), input_type, policy, schema)
            return {'artifact': artifact.uri, 'schema': schema}
        finally:
            harness.close_session()

    @server.tool()
    def describe_table(session_id: str, artifact: str) -> dict:
        '''Return aggregate metadata for a READY safe artifact; raw paths are not accepted.'''
        harness = runtime()
        harness.resume_session(session_id)
        try:
            return harness.describe_table(artifact)
        finally:
            harness.close_session()

    @server.tool()
    def read_safe_rows(session_id: str, artifact: str, offset: int = 0, limit: int = 100) -> dict:
        '''Read only sanitized rows from a READY safe artifact, up to 200 rows per call.'''
        harness = runtime()
        harness.resume_session(session_id)
        try:
            return harness.read_safe_rows(artifact, offset=offset, limit=limit)
        finally:
            harness.close_session()

    return server


def main() -> None:
    build_server().run(transport='stdio')


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required')
    return value


if __name__ == '__main__':
    main()
