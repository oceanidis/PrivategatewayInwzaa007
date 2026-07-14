# Security Policy

## Scope

PrivateGateway v0.1 is a Windows-only local sanitization workflow. It is not a hard isolation boundary when the agent and gateway share a Windows account.

## Reporting a vulnerability

Do not publish sensitive vulnerability details in a public issue. Contact the repository owner privately with the affected version, reproduction steps, impact, and any proof-of-concept needed to reproduce the issue.

## Security-sensitive configuration

- Keep `.privacy_gateway/`, raw imports, mappings, keys, and output directories out of Git.
- Use `store_raw_copy: false` unless a replay requirement is formally approved.
- Treat `synthesize` as experimental.
- Review explicit YAML policies before export.
- Run `python -m privategateway.cli verify-audit` to detect local audit-chain corruption.
- Use `uv sync --all-extras --locked` for the tested dependency set.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the supported threat model and enforced-mode requirements.
