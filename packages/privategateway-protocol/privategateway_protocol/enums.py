from enum import StrEnum


class GatewayOperation(StrEnum):
    BROWSE_DIRECTORY = "browse_directory"
    INSPECT_FILE = "inspect_file"
    READ_SAFE_TABLE = "read_safe_table"
    READ_SAFE_TEXT = "read_safe_text"
    CREATE_SAFE_WORKING_COPY = "create_safe_working_copy"
    SAFE_EXPORT = "safe_export"
    HEALTH = "health"


class OutputClassification(StrEnum):
    METADATA = "metadata"
    SANITIZED = "sanitized"
    SAFE_WORKING_COPY = "safe_working_copy"
    SAFE_EXPORT = "safe_export"
