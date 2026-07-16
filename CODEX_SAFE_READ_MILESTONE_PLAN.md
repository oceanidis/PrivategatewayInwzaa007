# Codex Safe Read Milestone Plan

## Goal

Make the existing PrivateGateway vertical slice available to Codex as a normal workflow: a user supplies a configured protected file path in conversation, Codex calls one safe file-read tool, and the tool returns only a Gateway-sanitized response. The user does not repeatedly run import, preview, export, service-start, or configuration commands.

## Explicit Scope

This milestone adds only a Codex-facing adapter and the narrow runtime work required to use existing Core, Service, Client, and Protocol packages.

It does not redesign those packages or add LangGraph, new LangChain features, generic sandboxing, a virtual filesystem, VM/container orchestration, capability generalization, or other framework integrations.

## Security Statement

**Workflow guarantee:** Any file content returned through the Codex `read_safe_file` tool has passed through PrivateGateway policy and sanitization.

**Not a hard guarantee:** Codex can still directly read a protected raw path if its process has operating-system permission and bypasses the normal tool workflow. This milestone does not claim otherwise.

## Required One-Time State

Installation/configuration creates a stable local Gateway configuration containing protected roots, a policy path, a project id, an auth key, and a safe root. It is not modified by agent-provided paths.

Files outside configured protected roots fail closed. The runtime must not add a supplied file's parent directory as a protected root, generate a new policy, or alter an existing policy.

## Public Codex Tool

```python
read_safe_file(
    path: str,
    offset: int = 0,
    limit: int = 200,
    max_chars: int = 50_000,
) -> dict
```

The tool is a thin facade. It has no scanner, policy evaluator, DataFrame reader, or transformation logic of its own. It does only the following:

1. Ensure the existing configured Gateway service is healthy, starting it when unavailable.
2. Infer a supported operation from the file extension.
3. Call `LocalGatewayClient.read_safe_table` or `LocalGatewayClient.read_safe_text`.
4. Convert only the existing Gateway envelope/error into a Codex-safe JSON response.

Supported types are exactly those already implemented by `GatewayOperations`:

| Input kind | Extensions | Existing operation |
| --- | --- | --- |
| Table | `.csv`, `.xlsx`, `.xls`, `.json` | `read_safe_table` |
| Text | `.txt`, `.log`, `.md` | `read_safe_text` |

Every other extension returns `UNSUPPORTED_SAFE_READ_TYPE`; it is never opened by the adapter. The Gateway remains the authoritative validator/parser. Extension inference selects an operation only; parser validation within the Gateway determines whether the content is valid.

## Gateway Startup Runtime

Create a Codex-local `GatewayRuntime` with this behavior:

```text
read_safe_file
  -> client.health()
  -> healthy: use it
  -> unavailable: acquire startup lock
      -> client.health() again
      -> healthy: use it
      -> unavailable: start configured privategateway-service child process
      -> poll health with bounded timeout
      -> healthy: use it
      -> failure: return GATEWAY_UNAVAILABLE
```

Rules:

- Startup is separate from bootstrap/configuration. It starts only from pre-existing configuration.
- A startup lock prevents duplicate service launches from concurrent calls.
- Runtime records a process handle/PID only for the service it starts itself.
- Cleanup may stop only that owned child process. It must never stop an already-running externally owned Gateway.
- The runtime never reads raw data and never falls back to a direct filesystem reader.

## Policy and Pagination Semantics

Policy is resolved exclusively by `GatewayOperations` and `CoreSanitizer` using the configured policy. A blocked/review-required/residual-sensitive result remains blocked and is returned as a safe error code. There is no direct-reader fallback.

`offset`, `limit`, and `max_chars` limit the sanitized response payload sent to Codex. They must not reduce the content subject to the configured privacy policy.

Required correction in existing text behavior:

```text
Current: raw text is sliced to max_chars, then sanitized.
Required: source text is sanitized according to policy first, then the safe response is truncated to max_chars.
```

Table behavior already sanitizes the full loaded DataFrame before returning `iloc[offset:offset + limit]`. This must remain true.

## Excel Contract

The current service uses `pandas.read_excel()` and therefore reads the first/default sheet only. The Codex tool must not imply that it analyzes every sheet.

For this milestone, document the response as `sheet_scope: "default_sheet_only"`. Do not add multi-sheet orchestration. A later milestone can add explicit sheet selection and multi-sheet contracts without silently changing this behavior.

## Safe Response Contract

The tool returns bounded JSON only. It must not return raw rows, secrets, mappings, raw/config/key paths, auth material, stack traces, or exception text.

Example table response:

```json
{
  "ok": true,
  "kind": "table",
  "file_type": "excel",
  "sheet_scope": "default_sheet_only",
  "rows": [{"customer_id": "CUSTOMER_ID_001", "amount": "AMOUNT_BUCKET_10K_50K"}],
  "pagination": {"offset": 0, "limit": 200, "returned": 1},
  "redaction_summary": {"sanitized": true}
}
```

The adapter enforces a maximum response-byte budget. If a Gateway response cannot fit after bounded payload formation, it returns `SAFE_RESPONSE_TOO_LARGE`, not partial raw diagnostics.

## Plugin Routing

Create a Codex plugin bundle with MCP registration and a narrowly written skill:

- Directory listing and metadata inspection remain normal allowed operations.
- When a task needs data-file contents, Codex uses `read_safe_file`.
- The skill must not claim interception of native `open`, `Get-Content`, Pandas, or shell reads.
- If the Gateway blocks access, Codex reports the safe error and requests a user-approved policy/configuration change; it does not read directly.

This is normal workflow routing, not non-bypassable enforcement.

## Files and Responsibilities

```text
packages/privategateway-codex/
  pyproject.toml                         Codex adapter package metadata and MCP dependency
  privategateway_codex/__init__.py       Public adapter exports
  privategateway_codex/runtime.py        Existing-service health/startup/ownership lifecycle only
  privategateway_codex/safe_read.py      Thin extension-to-client facade and safe response shaping
  privategateway_codex/mcp_server.py     FastMCP read_safe_file tool registration
  tests/test_runtime.py                  Startup lock, health, ownership, timeout tests
  tests/test_safe_read.py                Type routing, safe errors, response size tests
  tests/test_end_to_end.py               Raw-sentinel Gateway-to-tool flow

codex-plugin/privategateway/
  .codex-plugin/plugin.json              Codex plugin manifest
  skills/privategateway-safe-read/
    SKILL.md                             Normal workflow routing instructions
  mcp.json                               MCP launch registration

packages/privategateway-service/privategateway_service/operations.py
                                       Move text output truncation after Core sanitization
packages/privategateway-service/tests/test_operations.py
                                       Regression test for full-policy text sanitization
pyproject.toml                          Add the new workspace member/source only
README.md                               Install-once usage and security distinction
PROJECT_OVERVIEW.md                     Mark Codex adapter milestone/status accurately
```

## Tasks

### Task 1: Lock service semantics needed by the adapter

- Write a failing service test with sensitive text after `max_chars`.
- Change `_read_safe_text` so Core receives the full text and only the safe result is bounded.
- Keep `read_safe_table` full-sanitize-then-page behavior unchanged.
- Add explicit response metadata for table sheet scope without claiming multi-sheet support.
- Run focused service tests.

### Task 2: Create the Codex runtime

- Write failing tests for healthy reuse, unavailable auto-start, concurrent start race, timeout, and external-service ownership.
- Implement `GatewayRuntime` around the existing `privategateway-service` command/config and `LocalGatewayClient.health()`.
- Use a process-local startup lock and bounded health polling.
- Verify runtime startup does not write/change protected roots or policy files.
- Run runtime tests.

### Task 3: Implement the thin safe-read facade

- Write failing tests for each supported extension, unsupported extension, protected-path denial, safe error translation, table pagination, text safe-output limit, response-size bound, and default-sheet metadata.
- Implement extension routing only to existing client methods.
- Shape envelopes into a small fixed JSON contract and redact all internal diagnostics.
- Run facade tests.

### Task 4: Add the Codex MCP adapter and plugin instructions

- Write a contract test that invokes registered `read_safe_file` and asserts it calls only the facade.
- Register one FastMCP tool; do not expose direct raw reader, service lifecycle, policy mutation, or generic shell operation tools.
- Add plugin manifest and routing skill that directs normal data-content work to the tool and accurately states limitations.
- Run MCP/plugin package tests.

### Task 5: Prove the vertical slice end to end

- Create a protected raw fixture containing a unique sentinel, email, and secret-like value.
- Call the MCP-facing safe-read path with the service initially unavailable.
- Assert service auto-start succeeds and the raw sentinel, email, and secret never occur in the response.
- Assert sanitized replacements/report summary occur instead.
- Repeat with a small `limit`/`max_chars` to prove these are output bounds, not raw-policy scan bounds.
- Run all package tests and the E2E suite.

### Task 6: Documentation and release gate

- Document one-time plugin installation/configuration only; no recurring user command.
- Document supported types exactly and default-sheet-only Excel behavior.
- Document workflow guarantee versus hard OS/process guarantee.
- Run package install/build checks and all focused tests before any commit.

## Definition of Done

- A normal Codex conversation can invoke one path-based safe-read tool.
- The tool starts/checks the existing configured Gateway automatically.
- The tool returns only existing Gateway-sanitized content in a bounded safe response.
- Type support matches the actual service implementation exactly.
- Pagination/output limits never reduce the policy/sanitization scope.
- A raw-sentinel E2E test passes.
- No new recurring user CLI workflow exists.
- Docs make no claim of non-bypassable OS enforcement.
