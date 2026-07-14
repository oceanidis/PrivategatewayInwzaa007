# PrivateGateway

PrivateGateway is a local privacy gateway for imported data. It sanitizes a file or record **before** that data reaches an AI agent, vector database, memory system, prompt log, or tool trace.

It is intended for teams that need to let agents analyze imported data without exposing raw values, secrets, or token mappings outside a controlled local process.

## What It Protects

```text
Raw file or record
  -> PrivateGateway
  -> detection and policy actions
  -> safe dataset / safe export + redaction report

Internal only: encrypted raw input, encrypted token mapping, project key, audit metadata
```

The caller receives only safe output and a safe report. It never receives raw input or the token-to-original mapping table.

## Features

- Input support: text, CSV/TSV/PSV, Excel (`xlsx`, `xls`, `xlsm`), JSON, DataFrame, Parquet, Feather, ORC, XML, YAML, ZIP, and GZip.
- Excel support: processes every sheet and writes a data-only sanitized workbook.
- Detection order: secret scanner, schema detector, regex PII scanner, Presidio where needed, and optional custom recognizers.
- Actions: `drop`, `tokenize`, `hash`, `bucket`, `synthesize`, `date_shift`, `time_shift`, `redact_text`, `redact`, `keep`, and `review_required`.
- Large export jobs: background execution, progress status, and duplicate-request reuse.
- Storage: project keys, raw input, and token mappings are encrypted and separated from safe output.

## Security Model

PrivateGateway protects the path through PrivateGateway. It does not stop a separate process with filesystem permission from opening the raw file directly.

For a hard agent boundary, configure the agent or its harness so that it can call the PrivateGateway MCP server but cannot access the raw-data directory through shell, Python, or file tools.

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

For macOS/Linux, activate with:

```bash
source .venv/bin/activate
python -m pip install -e '.[mcp,dev]'
```

### 2. Sanitize an Excel file

```python
from privategateway.agent_plugin import sanitize_local_file_to_file

result = sanitize_local_file_to_file(
    input_path="./data/input.xlsx",
    output_path="./output/input_safe.xlsx",
    input_type="xlsx",
    project_id="loan_ai",
    auto_policy=True,
    scan_mode="sealed_analytics",
)

print(result)
```

For exports smaller than 25 MB, the call returns output metadata and a redaction report. For larger files it immediately returns a background job:

```python
from privategateway.agent_plugin import get_export_job_status

status = get_export_job_status(result["job_id"])
print(status)
# queued/running: stage, rows_processed, sheets_processed, elapsed_seconds
# completed: output metadata and redaction report
# failed: safe error code/type/stage only
```

Do not submit the same export repeatedly while it is running. The gateway reuses the active job when source, target, policy, project, and scan mode are identical.

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

Preview returns a bounded sample that has already been sanitized. It is useful for inspecting structure and the suggested policy, but it does not permit raw full-file access.

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

On macOS/Linux, use the virtual environment interpreter at `.venv/bin/python`.

The MCP host starts this process. Running `python -m privategateway.mcp_server` in a terminal appears to hang because it waits for the MCP host handshake over standard input/output.

Available MCP tools:

- `sanitize_local_file`
- `sanitize_local_file_to_file`
- `preview_local_file`
- `get_export_job_status`
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

With `auto_policy=True`, PrivateGateway infers a safe baseline in this order: schema/name semantics, value patterns, cardinality ratio, then dtype. This prevents repeated numeric codes from being mistaken for measures and prevents identifiers from being treated as harmless categories.

| Field pattern | Default action |
| --- | --- |
| API key, password, private key, connection string | `drop` |
| Name, email, phone, loan/account/business ID | `tokenize` |
| Customer ID | `tokenize` to retain safe joins |
| Numeric measure / amount | `synthesize` |
| Date with a detected subject ID | `date_shift` |
| Time of day with a detected subject ID | `time_shift` |
| Boolean or low-risk public category such as status/province | `keep`, but findings still block export |
| Repeated internal category or numeric code | stable domain `tokenize` |
| Repeated description | stable category `tokenize` |
| Remark, note, or other free text | `redact_text`; repeated values are scanned once per import |
| Unknown text/code | `tokenize` |
| Ambiguous field | `review_required` |

Related fields can share a token domain. For example, `OriginLocationCode`, `PriorLocationCode`, and `CurrentLocationCode` can use the same `LOCATION` domain, so equal source values remain equal after sanitization without exposing the original code. `auto_policy` is a baseline. Use a YAML policy when the organization needs exact business-ID rules, public category allowlists, custom recognizers, bucketing rules, or formal review decisions.

## Policy Example

```yaml
security:
  require_presidio: true
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
  amount: synthesize
  transaction_date: date_shift
  updated_time: time_shift
  note: redact_text
  api_key: drop
  password: drop

token_domains:
  company_id: COMPANY
  port_no: PORT
  port_no_2: PORT
  port_current: PORT

default:
  unknown_column: review_required
```

Pass a custom file with `policy_path`. Policy changes take effect on the next import; a new project key is not required.

`time_shift` shifts each valid time within the configured minute range using a deterministic offset derived from the project and subject ID. The same subject therefore keeps the same shifted time relationship in every import for that project. Output stays in `HH:MM:SS`; midnight wraparound is expected. Missing values remain missing, while invalid times or rows without a subject are redacted rather than exposed. Column matching treats `AuditTime`, `audit_time`, and `audit time` as the same policy name.

## Scan Modes

- `fast`: default file-export mode. It reserves expensive value-level checks for fields that remain visible or require text analysis.
- `sealed_analytics`: optimized for analysis. Identifiers and text are tokenized, numeric measures can be synthesized, and visible fields remain gated.
- `strict`: uses the full detector boundary when latency is less important than maximum inspection.

## Outputs and Storage

Every import produces:

- `safe_dataset` or a sanitized output file
- `redaction_report` with detector counts, actions, and block reasons
- an internal encrypted mapping reference when tokenization is used

Local secure state is stored in `.privacy_gateway/`:

```text
.privacy_gateway/
  keys/       project keys
  secure/     encrypted raw and mapping artifacts plus safe audit metadata
```

Do not commit this directory. Purge expired artifacts with:

```powershell
python -m privategateway.cli purge
```

## Performance

The Excel path uses:

- one bounded auto-policy preview per sheet
- OpenPyXL read-only input batches
- XlsxWriter constant-memory output
- no repeated safe-frame scan after transformed fields
- background jobs for files at or above 25 MB

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
python tools\benchmark_synthetic_excel.py --rows-per-sheet 2000 --sheets 2
```

Tests and benchmarks must use synthetic fixtures only. Never commit customer files, raw exports, credentials, project keys, token mappings, or secure artifacts.

## Current Limitations

- Excel export is data-only; formatting, charts, formulas, filters, merged cells, and column widths are not preserved.
- MCP review approval is not yet an interactive workflow.
- Presidio's bundled analysis is English-oriented. Add organization-specific recognizers for Thai or business identifiers.
- A process with direct filesystem access can bypass MCP unless a separate harness or OS boundary blocks it.
