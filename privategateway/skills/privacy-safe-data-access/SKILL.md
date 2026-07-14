---
name: privacy-safe-data-access
description: Sanitize local data files with PrivateGateway before reading, analyzing, summarizing, exporting, or passing their values to tools. Use for tabular, structured, text, and supported archive files.
---

Call the PrivateGateway MCP tool before accessing file contents. Use only its `safe_dataset` and `redaction_report`. Treat blocked or review-required responses as a stop condition and request an explicit user override with actor and reason. Never expose raw values, mapping tables, secret values, or secure-store paths.
