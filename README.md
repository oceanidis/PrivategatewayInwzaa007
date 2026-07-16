# PrivateGateway

PrivateGateway is a local privacy gateway for imported data. It sanitizes a file or record **before** that data reaches an AI agent, vector database, memory system, prompt log, or tool trace.

It is intended to reduce accidental disclosure when a local workflow sends imported data to AI tools. It is not an OS-enforced data-loss-prevention boundary.

## What It Protects

```text
Raw file or record
  -> PrivateGateway
  -> detection and policy actions
  -> safe dataset / safe export + redaction report

Internal only: encrypted token mapping, project key, operational access metadata
```

The caller receives only safe output and a safe report. It never receives raw input or the token-to-original mapping table.

## Features

- Stable input support: text, CSV/TSV/PSV, Excel (`xlsx`, `xls`, `xlsm`), JSON, and DataFrame.
- Excel support: processes every sheet and writes a data-only sanitized workbook.
- Detection order: secret scanner, schema detector, regex PII scanner, Presidio where needed, and optional custom recognizers.
- Stable actions: `drop`, `tokenize`, `hash`, `bucket`, `date_shift`, `time_shift`, `redact_text`, `redact`, `keep`, and `review_required`.
- Experimental: `synthesize`.
- Storage: project keys and token mappings are encrypted and separated from safe output. Raw-copy retention is disabled by default.

## Security Model

PrivateGateway protects only the path that uses PrivateGateway. It does not stop a process running as the same Windows user from opening the raw file, key material, or secure directory directly.

The bundled stdio MCP server is therefore a convenience integration, not a hard boundary. Enforced mode requires a separate gateway service account, Windows ACLs that deny the agent account access to raw/key/mapping directories, and authenticated IPC. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Quick Start

### 1. Clone and create a virtual environment

```powershell
git clone https://github.com/oceanidis/PrivategatewayInwzaa007.git
cd PrivategatewayInwzaa007
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[mcp,dev]"
```

v0.1 is Windows-only because secure storage uses Windows DPAPI.

For a reproducible developer/test environment, install the committed lock file instead:

```powershell
uv sync --all-extras --locked
```

### 2. Sanitize an Excel file

```python
from privategateway.agent_plugin import sanitize_local_file_to_file

result = sanitize_local_file_to_file(
    input_path="./data/input.xlsx",
    output_path="./output/input_safe.xlsx",
    input_type="xlsx",
    project_id="loan_ai",
    policy_path="./privacy-policy.yaml",
    auto_policy=False,
    scan_mode="sealed_analytics",
)

print(result)
```

Exports run synchronously. A durable queue is intentionally out of scope for v0.1.

### 3. Preview safely before export

```python
from privategateway.agent_plugin import preview_local_file

preview = preview_local_file(
    path="./data/input.xlsx",
    input_type="xlsx",
    project_id="loan_ai",
    preview_rows=10,
    auto_policy=True,
)
```

Preview returns a bounded sample that has already been sanitized. Each sheet also includes `suggested_policy`: a complete YAML-equivalent policy draft containing security defaults, actions, token domains, and date/time-shift settings. Review it, save it as YAML, and pass that file as `policy_path` for full export. The preview does not permit raw full-file access.

## MCP Setup

PrivateGateway can run as an MCP stdio server for Codex or another MCP host.

```toml
[mcp_servers.privategateway]
type = "stdio"
command = "/absolute/path/to/PrivategatewayInwzaa007/.venv/Scripts/python.exe"
args = ["-m", "privategateway.mcp_server"]
cwd = "/absolute/path/to/PrivategatewayInwzaa007"
startup_timeout_ms = 30000
tool_timeout_ms = 300000
```

The MCP host starts this process. Running `python -m privategateway.mcp_server` in a terminal appears to hang because it waits for the MCP host handshake over standard input/output.

Available MCP tools:

- `sanitize_local_file`
- `sanitize_local_file_to_file`
- `preview_local_file`
- `sanitize_text_input`
- `sanitize_record_input`

Restart the MCP host after changing gateway code, dependencies, or MCP configuration.

### Codex CLI: install, enable, and disable

On Windows, register the local server once. Codex starts the server only when a tool is called; do not run the MCP module in a separate terminal.

```powershell
# Set this to the folder that contains the cloned PrivateGateway repository.
$gatewayRoot = "C:\path\to\privategateway"
$gatewayPython = Join-Path $gatewayRoot ".venv\Scripts\python.exe"

# Check registered MCP servers.
codex mcp list

# Register or enable PrivateGateway.
codex mcp add privategateway -- $gatewayPython -m privategateway.mcp_server

# Confirm the registered command and working directory.
codex mcp get privategateway
```

The `get` command must show the folder where you cloned PrivateGateway as its working directory:

```text
cwd: <PRIVATEGATEWAY_ROOT>
```

If `cwd` is missing, open `%USERPROFILE%\.codex\config.toml` and add it below the `privategateway` server entry:

```toml
[mcp_servers.privategateway]
command = '<PRIVATEGATEWAY_ROOT>\\.venv\\Scripts\\python.exe'
args = ["-m", "privategateway.mcp_server"]
cwd = '<PRIVATEGATEWAY_ROOT>'
```

To disable the server, remove its Codex registration:

```powershell
codex mcp remove privategateway
```

To enable it again, run the registration command above, restore `cwd` if needed, and verify with `codex mcp get privategateway`. Start a new Codex session after any enable, disable, or configuration change so its MCP tool list is refreshed.

## Auto Policy

With `auto_policy=True`, PrivateGateway produces a sanitized preview and policy draft. It is preview-only: a full export requires an explicit reviewed YAML `policy_path`.

| Field pattern | Default action |
| --- | --- |
| API key, password, private key, connection string | `drop` |
| Name, email, phone, loan/account/business ID | `tokenize` |
| Customer ID | `tokenize` to retain safe joins |
| Numeric measure / amount | `review_required` |
| Date with a detected subject ID | `date_shift` |
| Time of day with a detected subject ID | `time_shift` |
| Boolean or low-risk public category such as status/province | `keep`, but findings still block export |
| Repeated internal category or numeric code | stable domain `tokenize` |
| Repeated description | stable category `tokenize` |
| Remark, note, or other free text | `redact_text`; repeated values are scanned once per import |
| Unknown text/code | `review_required` |
| Ambiguous field | `review_required` |

Related fields can share a token domain. For example, `OriginLocationCode`, `PriorLocationCode`, and `CurrentLocationCode` can use the same `LOCATION` domain, so equal source values remain equal after sanitization without exposing the original code. Review the generated draft, make the actions explicit in YAML, then use that YAML for export.

## Policy Example

```yaml
security:
  require_presidio: true
  store_raw_copy: false
  raw_ttl_hours: 24
  mapping_ttl_days: 30
  reject_duplicate_job_id: true

date_shift:
  subject_column: customer_id
  min_days: 1
  max_days: 30
  direction: both
  stability: project

time_shift:
  subject_column: customer_id
  min_minutes: 1
  max_minutes: 720
  direction: both
  stability: project

columns:
  customer_name: tokenize
  email: tokenize
  customer_id: hash
  amount: bucket
  transaction_date: date_shift
  updated_time: time_shift
  note: redact_text
  api_key: drop
  password: drop

token_domains:
  organization_code: ORGANIZATION
  origin_location_code: LOCATION
  prior_location_code: LOCATION
  current_location_code: LOCATION

default:
  unknown_column: review_required
```

Pass a reviewed custom file with `policy_path`. Policy changes take effect on the next import; a new project key is not required. `synthesize` is experimental and must be explicitly selected in policy.

`time_shift` shifts each valid time within the configured minute range using a deterministic offset derived from the project and subject ID. The same subject therefore keeps the same shifted time relationship in every import for that project. Output stays in `HH:MM:SS`; midnight wraparound is expected. Missing values remain missing, while invalid times or rows without a subject are redacted rather than exposed. Column matching treats `AuditTime`, `audit_time`, and `audit time` as the same policy name.

## Scan Modes

- `fast`: default file-export mode. It reserves expensive value-level checks for fields that remain visible or require text analysis.
- `sealed_analytics`: optimized for analysis. It does not change policy actions; numeric synthesis remains explicit opt-in.
- `strict`: uses the full detector boundary when latency is less important than maximum inspection.

## Outputs and Storage

Every import produces:

- `safe_dataset` or a sanitized output file
- `redaction_report` with detector counts, actions, block reasons, and `utility_impact` per column
- an internal encrypted mapping reference when tokenization is used

Local secure state is stored in `.privacy_gateway/`:

```text
.privacy_gateway/
  keys/       project keys
  secure/     encrypted mapping artifacts and operational access metadata
```

Raw copies are disabled by default. Set `security.store_raw_copy: true` only for an approved replay workflow; expiry requires a purge process to run. Do not commit this directory. Purge expired artifacts with:

```powershell
python -m privategateway.cli purge
```

`utility_impact` explains the intended analytical effect of each applied action. For example, tokenization preserves stable joins, bucketing preserves only ranges, and date/time shifting preserves relative timing per subject. It is an action-level disclosure, not a statistical-quality guarantee; `synthesize` remains experimental and requires separate validation for the analysis being performed.

Operational events are stored in `audit.v1.jsonl` with a per-entry SHA-256 hash chain. Check its internal consistency with:

```powershell
python -m privategateway.cli verify-audit
```

This detects accidental corruption or edits made without rebuilding the chain. It is not an immutable compliance audit trail because a process running as the same Windows identity can replace both the log and its hashes.

## Performance

The Excel path uses:

- OpenPyXL read-only input batches
- XlsxWriter constant-memory output
- no repeated safe-frame scan after transformed fields
- synchronous exports by default

Run a synthetic benchmark without customer data:

```powershell
python tools\benchmark_synthetic_excel.py --rows-per-sheet 2000 --sheets 2
```

The benchmark reports policy-preview, secure-store, transform, finalize, write, total time, and throughput. It creates only synthetic data and cleans its work directory by default.

## Development and Verification

```powershell
python -m pip check
python -m py_compile privategateway\agent_plugin.py privategateway\import_pipeline.py privategateway\mcp_server.py
python -m pytest privategateway\tests -q
uv lock --check
python tools\benchmark_synthetic_excel.py --rows-per-sheet 2000 --sheets 2
```

Tests and benchmarks must use synthetic fixtures only. Never commit customer files, raw exports, credentials, project keys, token mappings, or secure artifacts.

## Current Limitations

- Excel export is data-only; formatting, charts, formulas, filters, merged cells, and column widths are not preserved.
- MCP review approval is not yet an interactive workflow.
- Presidio's bundled analysis is English-oriented. Add organization-specific recognizers for Thai or business identifiers.
- A process with direct filesystem access can bypass MCP unless a separate harness or OS boundary blocks it.

## Codex Safe-Read Plugin (Experimental)

The repository now includes `plugins/privategateway-safe-read` and the
`privategateway-codex` package. It exposes one MCP tool, `read_safe_file`.
For a supported path below a previously configured protected root, the tool
checks Gateway health, starts the configured local Gateway when it is not
running, and returns only the Gateway-sanitized response.

Supported input types are exactly:

- Tables: `.csv`, `.xlsx`, `.xls`, `.json`
- Text: `.txt`, `.log`, `.md`

For Excel, the current service reads the default sheet only. The safe result
contains `sheet_scope: "default_sheet_only"`; it does not claim multi-sheet
analysis.

`offset`, `limit`, and `max_chars` bound the safe payload returned to Codex.
They do not reduce the content evaluated by the privacy policy. Text is
sanitized before its safe output is truncated; table data is sanitized before
its safe page is selected.

This is normal workflow routing, not hard enforcement. Content returned by
`read_safe_file` is sanitized, but Codex can still bypass the tool if its
process has direct operating-system permission to read the raw source. A hard
guarantee requires a separate process or OS permission boundary.

The runtime starts only from an existing Gateway configuration. It does not
silently add a protected root from an agent-supplied path or create/change a
policy. Paths outside configured protected roots fail closed.
