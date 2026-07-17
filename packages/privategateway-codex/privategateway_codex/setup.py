from __future__ import annotations

import argparse
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from privategateway.key_provider import init_project

from .service_manager import ensure_gateway_running, stop_gateway
from .startup import install_user_startup


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
    service_starter: Callable[[Path], None] | None = None,
    service_stopper: Callable[[Path], None] | None = None,
    startup_installer: Callable[[Path], object] | None = None,
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
    if config_path.exists():
        (service_stopper or stop_gateway)(config_path)
    config_path.write_text(
        "\n".join(
            [
                "[service]",
                f"project_id = {json.dumps(project_id)}",
                f"protected_roots = [{json.dumps(str(root))}]",
                f"address = {json.dumps(_available_loopback_address())}",
                "auto_policy = true",
                'secure_root = ".privacy_gateway/secure"',
                'key_root = ".privacy_gateway/keys"',
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
    (service_starter or ensure_gateway_running)(config_path)
    (startup_installer or install_user_startup)(config_path)
    return GatewaySetupResult(config_path=config_path)


def _default_state_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PrivateGateway"


def _available_loopback_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{probe.getsockname()[1]}"


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
