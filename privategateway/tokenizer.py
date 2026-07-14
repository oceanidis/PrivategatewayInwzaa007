from __future__ import annotations

import base64
import hmac
import re
from hashlib import sha256

from .secure_store import derive_project_key


class Tokenizer:
    def __init__(self, project_key: bytes) -> None:
        if len(project_key) < 32:
            raise ValueError("project_key must contain at least 32 bytes")
        self._token_key = derive_project_key(project_key, "tokenization")
        self.mapping_table: dict[str, str] = {}
        self._value_to_token: dict[tuple[str, str], str] = {}

    def token_for(self, value: object, token_type: str) -> str:
        original = "" if value is None else str(value)
        normalized_type = token_type.strip().upper().replace(" ", "_")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", normalized_type):
            raise ValueError("token_type must be a safe uppercase identifier")
        key = (normalized_type, original)
        if key in self._value_to_token:
            return self._value_to_token[key]
        digest = hmac.new(
            self._token_key,
            normalized_type.encode("utf-8") + b"\0" + original.encode("utf-8"),
            sha256,
        ).digest()[:10]
        suffix = base64.b32encode(digest).decode("ascii").rstrip("=")
        token = f"{normalized_type}_{suffix}"
        existing = self.mapping_table.get(token)
        if existing is not None and existing != original:
            raise RuntimeError("token collision detected")
        self._value_to_token[key] = token
        self.mapping_table[token] = original
        return token
