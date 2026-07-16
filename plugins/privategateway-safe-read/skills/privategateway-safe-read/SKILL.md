---
name: privategateway-safe-read
description: Read contents of configured protected data files only through PrivateGateway.
---

# PrivateGateway Safe Read

When a task needs the contents of a supported protected data file, call
`read_safe_file` with the path before analyzing its values.

Supported types are CSV, XLS/XLSX, JSON, TXT, LOG, and Markdown. The tool
returns sanitized content only. Use the result returned by the tool for all
analysis, summaries, code examples, and follow-up reasoning.

Directory listings and file metadata may be used normally. Do not use shell
commands, Python readers, spreadsheet readers, or direct file APIs to read
protected data-file contents in the normal workflow.

If the tool returns a privacy, policy, path, or Gateway error, report the safe
error and request user direction. Do not fall back to direct reading.

This plugin provides normal workflow routing. It does not provide an
operating-system enforcement boundary: a process with direct filesystem
permission can still bypass this tool.
