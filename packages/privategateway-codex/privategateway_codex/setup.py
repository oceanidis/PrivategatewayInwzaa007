from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path

from privategateway.key_provider import init_project


_DEFAULT_POLICY = """security:
  store_raw_copy: false
  require_presidio: false
columns:
  email: tokenize
  phone: tokenize
  customer_id: hash
  password: drop
  api_key: drop
default:
  unknown_column: review_required
"""


@dataclass(frozen=True)
class GatewaySetupResult:
    config_path: Path


def initialize_gateway(
    protected_root: str | Path,
    *,
    project_id: str = "default",
    state_root: str | Path | None = None,
) -> GatewaySetupResult:
    root = Path(protected_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("PROTECTED_ROOT_MUST_BE_DIRECTORY")
    if not project_id.strip():
        raise ValueError("PROJECT_ID_REQUIRED")
    state = Path(state_root) if state_root is not None else _default_state_root()
    state.mkdir(parents=True, exist_ok=True)
    (state / "safe").mkdir(exist_ok=True)
    policy_path = state / "default-policy.yaml"
    if not policy_path.exists():
        policy_path.write_text(_DEFAULT_POLICY, encoding="utf-8")
    config_path = state / "service.toml"
    config_path.write_text(
        "\n".join(
            [
                "[service]",
                f"project_id = {json.dumps(project_id)}",
                f"protected_roots = [{json.dumps(str(root))}]",
                'safe_root = "safe"',
                'policy_path = "default-policy.yaml"',
                'authkey_path = "gateway.authkey"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    previous = Path.cwd()
    try:
        os.chdir(state)
        init_project(project_id)
    finally:
        os.chdir(previous)
    return GatewaySetupResult(config_path=config_path)


def _default_state_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PrivateGateway"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="privategateway-codex-setup")
    parser.add_argument("--protect", required=True)
    parser.add_argument("--project-id", default="default")
    parser.add_argument("--state-root")
    args = parser.parse_args(argv)
    try:
        result = initialize_gateway(args.protect, project_id=args.project_id, state_root=args.state_root)
    except FileNotFoundError:
        print(json.dumps({"ok": False, "error_code": "PROTECTED_ROOT_NOT_FOUND"}))
        return 1
    except PermissionError:
        print(json.dumps({"ok": False, "error_code": "PROTECTED_ROOT_ACCESS_DENIED"}))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"ok": False, "error_code": "SETUP_FAILED"}))
        return 1
    print(json.dumps({"ok": True, "config_path": str(result.config_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
