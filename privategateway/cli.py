from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .key_provider import init_project
from .masker import handle_request
from .secure_store import purge_expired_secure_data
from .setup import run_setup
from .audit import verify_audit_log


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return _run_json_request()
    parser = _build_admin_parser()
    args = parser.parse_args(arguments)
    if args.command == "init-project":
        key = init_project(args.project_id, key_root=args.key_root)
        print(json.dumps({"project_id": args.project_id, "key_id": key.key_id}, sort_keys=True))
        return 0
    if args.command == "setup":
        result = run_setup(args.workspace, check=args.check, remove=args.remove)
        print(json.dumps({"installed": result.installed, "drifted": result.drifted, "removed": result.removed}, sort_keys=True))
        return 1 if args.check and result.drifted else 0
    if args.command == "verify-audit":
        result = verify_audit_log(args.secure_root)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["valid"] else 1
    removed = purge_expired_secure_data(secure_root=args.secure_root, key_root=args.key_root)
    print(json.dumps({"removed_artifacts": removed}, sort_keys=True))
    return 0


def _run_json_request() -> int:
    try:
        request = json.load(sys.stdin)
        response = handle_request(request)
        print(json.dumps(response, ensure_ascii=False, default=str))
        return 0
    except Exception as exc:
        # stdout remains a machine-readable response; details are never echoed because input may be raw.
        print(json.dumps({"ok": False, "error": type(exc).__name__}, sort_keys=True))
        return 1


def _build_admin_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privategateway")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init-project")
    init.add_argument("--project-id", required=True)
    init.add_argument("--key-root", default=".privacy_gateway/keys")
    purge = subparsers.add_parser("purge")
    purge.add_argument("--secure-root", default=".privacy_gateway/secure")
    purge.add_argument("--key-root", default=".privacy_gateway/keys")
    verify_audit = subparsers.add_parser("verify-audit")
    verify_audit.add_argument("--secure-root", default=".privacy_gateway/secure")
    setup = subparsers.add_parser("setup")
    setup.add_argument("--workspace", required=True)
    mode = setup.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--remove", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
