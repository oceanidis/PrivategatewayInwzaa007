from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import HarnessConfig
from .gateway_backend import LocalPrivateGatewayBackend
from .runtime import HarnessRuntime, _schema_from_preview


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='privategateway-harness')
    parser.add_argument('--project-id', required=True)
    parser.add_argument('--sessions-root', default='.harness_sessions')
    parser.add_argument('--raw-root', action='append', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    imported = commands.add_parser('import')
    imported.add_argument('--session-id', required=True)
    imported.add_argument('--input', required=True)
    imported.add_argument('--input-type', required=True, choices=('csv', 'excel', 'json'))
    imported.add_argument('--policy', required=True)
    imported.add_argument('--actor', required=True)
    imported.add_argument('--reason', required=True)
    described = commands.add_parser('describe')
    described.add_argument('--session-id', required=True)
    described.add_argument('--artifact', required=True)
    args = parser.parse_args(argv)
    runtime = HarnessRuntime(HarnessConfig(args.project_id, Path(args.sessions_root), tuple(Path(value) for value in args.raw_root)), LocalPrivateGatewayBackend())
    if args.command == 'import':
        try:
            runtime.create_session(args.session_id)
        except Exception:
            runtime.resume_session(args.session_id)
        try:
            schema = runtime.preview_schema(Path(args.input), args.input_type)
            runtime.approve_policy(Path(args.policy), schema, actor=args.actor, reason=args.reason)
            artifact = runtime.import_dataset(Path(args.input), args.input_type, Path(args.policy), schema)
            print(json.dumps({'artifact': artifact.uri, 'schema': schema}, ensure_ascii=False))
        finally:
            runtime.close_session()
        return 0
    runtime.resume_session(args.session_id)
    try:
        print(json.dumps(runtime.describe_table(args.artifact), ensure_ascii=False))
    finally:
        runtime.close_session()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
