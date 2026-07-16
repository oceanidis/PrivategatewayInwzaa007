# PrivateGateway: Complete Project Overview

## Purpose

PrivateGateway is a local privacy gateway for imported files and agent workflows. It detects sensitive content, applies policy-driven transformations, and returns safe data while keeping mappings, keys, and optional raw artifacts outside normal agent responses.

The product direction has evolved through three layers:

1. **PrivateGateway Core**: framework-independent detection and sanitization.
2. **Gateway/Capability Layer**: authenticated local service, client, capability broker, and safe artifacts.
3. **Agent Integrations**: LangChain tools/middleware now; Codex installer/harness is the intended next product layer.

This document separates implemented capabilities from planned hard enforcement. Do not treat planned features as available security guarantees.

---

## Security Position

### Current guarantee

When a caller uses PrivateGateway Core, the Gateway service, or one of the safe integration tools, results are sanitized before return. Token mappings are kept in separate secure artifacts rather than normal result payloads.

### Current limitation

A process running under the same Windows identity with direct filesystem, PowerShell, Python, shell, or executable access can read a raw file directly. Skills, prompts, AGENTS.md, MCP tools, and middleware do not remove that OS permission.

### Hard guarantee required for the intended Codex product

```text
Codex process: no read permission to protected raw roots
Gateway service: read permission to protected raw roots
Codex content access: Gateway safe operations only
```

That is the only non-bypassable boundary. A direct `open()`, `Get-Content`, `pd.read_excel()`, shell command, or executable must fail before raw content is loaded.

---

## Current Repository Structure

```text
privategateway/
  __init__.py                 Public Core exports
  core.py                     CoreSanitizer facade
  import_pipeline.py          Main sanitization pipeline
  scanner.py                  Detection orchestration
  secret_scanner.py           Keys/passwords/tokens/connection strings
  schema_detector.py          Sensitive column/key names
  presidio_detector.py        Optional Presidio PII detection
  custom_recognizers.py       Organization-specific identifiers
  policy.py                   YAML policy parsing and actions
  policy_generator.py         Existing policy inference utilities
  tokenizer.py                Stable tokens and mapping creation
  redaction_report.py         Safe report/result model
  secure_store.py             DPAPI-protected artifacts/mappings
  key_provider.py             Project key initialization/loading
  mcp_server.py               Existing convenience MCP server
  cli.py                      Existing Core CLI
  tests/                      Existing Core tests

privategateway_harness/
  Earlier session-oriented prototype
  runtime.py, dispatcher.py, tool_broker.py, data_guard.py,
  artifact_registry.py, session_store.py, policy_review.py
  Status: legacy/prototype; not the planned public product API

packages/
  privategateway-protocol/
    privategateway_protocol/
      enums.py                GatewayOperation, OutputClassification
      requests.py             GatewayRequest
      responses.py            SanitizedEnvelope
      errors.py               GatewayError

  privategateway-service/
    privategateway_service/
      config.py               ServiceConfig
      path_policy.py          Root/output/reparse path enforcement
      operations.py           Fixed service operation allowlist
      audit.py                Safe operation audit records
      working_copies.py       Integrity-checked temporary safe copies
      server.py               Authenticated named-pipe/Unix-socket listener
      cli.py                  Development service lifecycle/bootstrap

  privategateway-client/
    privategateway_client/
      base.py                 GatewayClient protocol
      serialization.py        Allowlisted IPC serialization
      local.py                Authenticated local client

  privategateway-capabilities/
    privategateway_capabilities/
      contracts.py            Capability and authorization types
      registry.py             Host-owned tool registry
      broker.py               ALLOW/DENY/ROUTE_TO_GATEWAY broker

  privategateway-langchain/
    privategateway_langchain/
      tools.py                LangChain safe tools
      middleware.py           Structured tool-call routing middleware
      conversion.py           LangChain request conversion

integration_tests/
  Package dependency-boundary tests

README.md
SECURITY.md
THREAT_MODEL.md
PROJECT_OVERVIEW.md           This document
```

---

## Core Sanitization Flow

```text
Input text / CSV / Excel / JSON / DataFrame
  -> secret scan
  -> schema-aware scan
  -> regex PII scan
  -> Presidio scan when required by policy
  -> custom recognizers
  -> policy action
  -> safe dataset/text + redaction report

Mappings / optional raw copy
  -> separate encrypted secure store
  -> never normal LLM/vector/prompt/tool payload
```

### Detection order

1. Secret scanner: API keys, passwords, JWTs, OAuth tokens, connection strings, private keys.
2. Schema detector: names, email, phone, customer/account/loan/employee IDs, address, ID-card, passport, API-key/password fields.
3. Regex PII: email, phone, Thai ID-like values, card-like values, IP addresses.
4. Presidio general PII.
5. Optional organization recognizers.

### Policy actions

| Action | Meaning |
| --- | --- |
| `drop` | Remove a value or column. Secrets are dropped. |
| `tokenize` | Replace with stable scoped token. |
| `hash` | One-way keyed identifier representation. |
| `bucket` | Replace numeric value with range. |
| `date_shift` / `time_shift` | Consistent bounded shift. |
| `synthesize` | Experimental numeric simulation; explicit opt-in only. |
| `redact` / `redact_text` | Label or sanitize text. |
| `keep` | Preserve only when no residual sensitive detection blocks output. |
| `review_required` | Replace output and block export pending review. |

---

## Gateway Service

### Operations

| Operation | Result |
| --- | --- |
| `browse_directory` | Directory metadata only. |
| `inspect_file` | File metadata only. |
| `read_safe_text` | Gateway reads and sanitizes text. |
| `read_safe_table` | Gateway reads and returns paginated safe rows. |
| `create_safe_working_copy` | Sanitized temporary file with integrity metadata. |
| `safe_export` | Export approved safe copy under safe-root policy. |
| `health` | Safe service metadata. |

Operations are selected through a fixed enum. Request arguments cannot supply arbitrary callables, modules, commands, or handler names.

### Path policy

- Protected inputs must exist below configured protected roots.
- Inputs cannot be directories.
- Canonical resolution prevents traversal outside roots.
- UNC paths, alternate data streams, symlink/reparse escapes, and unsafe outputs are denied.
- Only the configured safe root can receive exports.

### IPC transport

- Windows uses authenticated `AF_PIPE` named pipes.
- Unix uses authenticated `AF_UNIX` sockets.
- Messages are JSON allowlists with a 1 MiB limit.
- Bad auth becomes `GATEWAY_AUTHENTICATION_FAILED` for the client.

### Safe working copies

Working copies contain sanitized content only. The copy store records SHA-256 and expiry metadata. Resolve verifies integrity; revoked, expired, missing, or changed copies fail closed.

---

## Capability Broker

```text
Agent/framework tool call
  -> ExecutionRequest
  -> host-owned CapabilityRegistry
  -> ALLOW / DENY / ROUTE_TO_GATEWAY
```

The model cannot elevate privilege by adding a `capability` field. Capability is derived only from the host registry. Broker routing requires a matching prior authorization with the same request ID and tool name.

Unknown tools, missing resources, absent Gateway client, and unsandboxed execution are denied.

---

## LangChain Integration

### Safe tools

- `browse_protected_directory`
- `inspect_protected_file`
- `read_safe_table`
- `read_safe_text`
- `create_safe_working_copy`
- `safe_export`

The package calls a Gateway client. It does not directly depend on Core, Pandas, Presidio, or spaCy.

### Middleware

`PrivateGatewayMiddleware` converts structured LangChain tool calls into broker requests.

- `DENY`: returns safe error and does not invoke the original handler.
- `ROUTE_TO_GATEWAY`: calls Gateway and does not invoke the original handler.
- `ALLOW`: invokes the registered handler.
- `audit_only`: intentionally non-enforcing and warns at construction.

Middleware is not an OS boundary.

---

## Test Evidence On Current Branch

| Area | Recent result |
| --- | --- |
| Core facade | 2 passed |
| Protocol contracts | 6 passed |
| Service paths, operations, working copies | 16 passed, 1 skipped |
| IPC protocol/client/service | 22 passed, 1 skipped |
| LangChain tools/middleware | 5 passed |
| Automatic workspace bootstrap smoke test | Passed |

The skip is a Windows symlink case when symlink creation is unavailable.

---

## Current Developer Bootstrap

The current service can bootstrap a development workspace automatically. This is not final product UX.

It creates:

```text
raw/
.privategateway/
  safe/
  default-policy.yaml
  service.toml
  gateway.authkey
```

This behavior exists to test service primitives. A public Codex integration must hide it behind one-time installation.

---

## Desired Product UX

```powershell
pg install --protect <folder>
codex
```

No recurring TOML editing, service startup, Python snippets, or separate chat app.

`pg install` should install/enable a Codex plugin, register the Gateway integration, create protected-root state, generate policy/key material, and run a self-test.

---

## Codex Integration Reality

Codex plugin, skill, AGENTS.md, MCP, and middleware can guide or constrain structured workflows. They cannot themselves remove native file-read permission from a same-user Codex process.

Therefore there are two product modes:

### Workflow Guard

- Codex plugin and safe MCP tools.
- Strong protection against accidental disclosure through normal agent workflow.
- Not a hard boundary against direct same-user shell/Python/filesystem access.

### Hard Harness

```text
Controlled Codex execution environment
  -> no raw-root filesystem access
  -> safe Gateway tools available
Trusted Gateway service
  -> raw-root access
  -> Core sanitization
```

A hard harness must be based on one of:

1. Separate Windows identities and ACLs. Recommended local hard mode.
2. Container/VM where raw roots are not mounted into Codex.
3. Sanitized virtual filesystem for transparent arbitrary `open()` behavior.

The virtual-filesystem option is the only way to transparently make arbitrary `pd.read_excel()` or `open()` return sanitized content. It is substantially more complex and typically needs elevated setup.

---

## Product Roadmap

### No-admin work remaining

1. Productize `pg install`, `pg uninstall`, `pg doctor`, and `pg status`.
2. Build a Codex plugin bundle containing durable workflow instructions, safe tools, and MCP registration.
3. Hide service/key/policy bootstrap behind the installer.
4. Create a Codex-facing safe-read facade and auto-start Gateway lifecycle.
5. Add end-to-end raw-sentinel tests for tool results, transcripts, and exports.
6. Finish safe-copy client/export coverage.
7. Reconcile or retire legacy harness/session APIs.
8. Add CI matrix, lockfile verification, release build checks, README, security docs, and package publishing flow.
9. Keep LangGraph optional and outside synchronous read path.

### Hard-enforcement work

1. Select isolation model.
2. Ensure direct Python, shell, PowerShell, Pandas, and executable reads fail.
3. Verify Gateway still safely reads the same protected source.
4. Document setup, limitations, and support matrix.

---

## Operator Decisions Required Later

No immediate action is required for current development.

Before claiming non-bypassable enforcement, an operator must choose:

- Separate Windows Gateway and agent accounts with ACLs.
- Container/VM agent environment.
- Virtual sanitized filesystem.

The recommended first hard mode is separate Windows identities and ACLs because it is simpler and auditable without command parsing.

## Codex Safe-Read Milestone

Implemented on the feature branch:

```text
Codex plugin MCP tool: read_safe_file(path)
  -> GatewayRuntime health check / owned child startup
  -> LocalGatewayClient
  -> GatewayOperations read_safe_table or read_safe_text
  -> Core sanitization
  -> bounded safe response
```

The adapter supports only CSV, XLS/XLSX, JSON, TXT, LOG, and Markdown because
those are the types currently implemented by Gateway operations. It performs
extension routing only and delegates parsing, path validation, policy
resolution, and sanitization to the Gateway. Unsupported types fail closed.

A raw-sentinel integration test starts a Gateway from unavailable state and
asserts that the raw sentinel and secret-like value never occur in the
Codex-safe response.

This is a workflow guarantee only. It is not a hard OS/process enforcement
boundary.
