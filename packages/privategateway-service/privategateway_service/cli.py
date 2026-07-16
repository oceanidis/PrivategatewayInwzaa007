from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from multiprocessing.connection import AuthenticationError, Client
from pathlib import Path

from privategateway.key_provider import init_project

from .config import ServiceConfig
from .operations import GatewayOperations
from .server import LocalGatewayServer, default_family


def _bootstrap_config(workspace: Path) -> Path:
    workspace = workspace.resolve()
    raw = workspace / "raw"
    state = workspace / ".privategateway"
    raw.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    policy = state / "default-policy.yaml"
    if not policy.exists():
        policy.write_text("security:\n  store_raw_copy: false\n  require_presidio: false\ncolumns:\n  email: tokenize\n  phone: tokenize\n  customer_id: hash\n  password: drop\n  api_key: drop\ndefault:\n  unknown_column: review_required\n", encoding="utf-8")
    config = state / "service.toml"
    if not config.exists():
        config.write_text("[service]\nproject_id = \"default\"\nprotected_roots = [\"../raw\"]\nsafe_root = \"safe\"\npolicy_path = \"default-policy.yaml\"\nauthkey_path = \"gateway.authkey\"\n", encoding="utf-8")
    init_project("default")
    return config

def _load_config(path: str | Path) -> tuple[ServiceConfig, str, bytes, str]:
    config_path = Path(path).resolve(strict=True)
    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    service = payload.get("service")
    if not isinstance(service, dict):
        raise ValueError("INVALID_SERVICE_CONFIG")
    base = config_path.parent
    def resolve(value: str) -> Path:
        item = Path(value)
        return item if item.is_absolute() else base / item
    config = ServiceConfig(tuple(resolve(value) for value in service["protected_roots"]), resolve(service["safe_root"]), resolve(service["policy_path"]), str(service["project_id"]))
    family = default_family()
    address = str(service.get("address") or (rf"\\.\pipe\privategateway-{config.project_id}" if family == "AF_PIPE" else config.safe_root / "gateway.sock"))
    key_path = resolve(str(service.get("authkey_path", "gateway.authkey")))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        authkey = key_path.read_bytes()
    else:
        authkey = os.urandom(32)
        key_path.write_bytes(authkey)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    if len(authkey) < 16:
        raise ValueError("INVALID_AUTHKEY")
    return config, address, authkey, family


def _status(address: str, authkey: bytes, family: str) -> int:
    from privategateway_client import LocalGatewayClient
    try:
        result = LocalGatewayClient(address, authkey, family=family).health()
    except Exception:
        print(json.dumps({"ok": False, "status": "unavailable"}))
        return 1
    print(json.dumps({"ok": True, "status": result.to_dict().get("payload", {}).get("status", "unknown")}))
    return 0


def _stop(address: str, authkey: bytes, family: str) -> int:
    try:
        with Client(address, family=family, authkey=authkey) as connection:
            connection.send_bytes(b'{"control":"shutdown"}')
            connection.recv_bytes()
    except AuthenticationError:
        print(json.dumps({"ok": False, "error_code": "GATEWAY_AUTHENTICATION_FAILED"}))
        return 1
    except OSError:
        print(json.dumps({"ok": False, "status": "unavailable"}))
        return 1
    print(json.dumps({"ok": True, "status": "stopping"}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="privategateway-service")
    parser.add_argument("command", choices=("start", "status", "stop", "doctor"))
    parser.add_argument("--config")
    parser.add_argument("--workspace")
    args = parser.parse_args(argv)
    try:
        config_path = Path(args.config) if args.config else _bootstrap_config(Path(args.workspace or Path.cwd()))
        config, address, authkey, family = _load_config(config_path)
        if args.command == "status":
            return _status(address, authkey, family)
        if args.command == "stop":
            return _stop(address, authkey, family)
        if args.command == "doctor":
            operations = GatewayOperations.from_config(config)
            print(json.dumps({"ok": True, "family": family, "safe_root": str(operations.path_policy.safe_root)}))
            return 0
        server = LocalGatewayServer(GatewayOperations.from_config(config), address=address, authkey=authkey, family=family)
        server.start()
        print(json.dumps({"ok": True, "status": "running"}), flush=True)
        server._thread.join()
        return 0
    except (KeyError, OSError, ValueError):
        print(json.dumps({"ok": False, "error_code": "INVALID_SERVICE_CONFIG"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
