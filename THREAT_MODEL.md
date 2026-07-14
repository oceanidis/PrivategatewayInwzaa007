# Threat Model

## Current mode: convenience mode

PrivateGateway v0.1 reduces accidental disclosure when callers use its sanitization APIs. It protects token mappings from normal API responses and defaults to not retaining a second encrypted raw copy.

It does not protect against a process that runs under the same Windows account and has filesystem, shell, or Python access. Such a process can bypass MCP, open raw input directly, or invoke local package internals. Windows DPAPI does not establish a boundary between processes using the same Windows identity.

## Non-goals

- Defending against a malicious or compromised same-user process.
- Providing compliance-grade immutable audit records. The local hash chain detects accidental corruption but does not protect against a same-user attacker who can replace the log.
- Durable asynchronous execution across process restarts.
- Supporting non-Windows secure storage in v0.1.

## Enforced mode target

An enforced deployment must run the gateway as a separate Windows service account. The agent account must be denied ACL access to raw input, project keys, mappings, and secure artifacts. The agent should call a constrained, authenticated named-pipe or localhost service API that accepts only allowlisted operations and paths. The gateway must never expose raw-data, mapping, key, or decrypt operations through that API.

## Operator requirements

- Treat MCP stdio as convenience mode only.
- Use explicit reviewed policies for every export.
- Keep `store_raw_copy` disabled unless replay is approved.
- Restrict raw-data directory ACLs even in convenience mode.
- Run purge on a schedule when raw-copy retention is enabled.
