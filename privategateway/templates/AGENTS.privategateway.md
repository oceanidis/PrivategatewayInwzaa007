<!-- privategateway:start -->
## PrivateGateway data-access rule
Before reading a data file's content, call the `privategateway` MCP server and use only its sanitized result. This includes CSV/TSV/PSV, Excel, Parquet/Feather/ORC, JSON/JSONL/XML/YAML, TXT/LOG, ZIP, and GZip. Do not use direct filesystem, shell, Python, or spreadsheet readers for raw data. Config/schema/manifest JSON may be read directly only when it is clearly not a dataset. If the gateway blocks a file or needs review, stop and request a user-approved override.
<!-- privategateway:end -->
