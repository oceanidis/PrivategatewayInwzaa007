from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .key_provider import DpapiKeyProvider, ProjectKey, _restrict_permissions, validate_identifier


_MAGIC = b"PGW1"
_ARTIFACT_ID = re.compile(r"[0-9a-f]{32}")
_KEY_ID = re.compile(r"[0-9a-f]{16}")


class SecureArtifactError(RuntimeError):
    pass


class SecureJobExistsError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecureMappingReference:
    project_id: str
    job_id: str
    artifact_id: str
    key_id: str


class LocalSecureStore:
    def __init__(
        self,
        project_id: str,
        job_id: str,
        secure_root: str | Path = ".privacy_gateway/secure",
        key_root: str | Path = ".privacy_gateway/keys",
        reserve_job: bool = False,
    ) -> None:
        self.project_id = validate_identifier(project_id, "project_id")
        self.job_id = validate_identifier(job_id, "job_id")
        self.secure_root = Path(secure_root)
        self.key_provider = DpapiKeyProvider(key_root)
        self.project_key = self.key_provider.load(self.project_id)
        project_root = self.secure_root / self.project_id
        self.job_root = project_root / self.job_id
        for directory in (self.secure_root, project_root, self.job_root):
            directory.mkdir(parents=True, exist_ok=True)
            _restrict_permissions(directory, is_directory=True)
        if reserve_job:
            marker = self.job_root / ".reserved"
            try:
                descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError as exc:
                raise SecureJobExistsError(f"Secure job already exists: {self.job_id}") from exc
            else:
                os.close(descriptor)
                _restrict_permissions(marker, is_directory=False)

    def write_raw(self, payload: bytes, input_type: str, ttl: timedelta) -> str:
        metadata = self._write_artifact(payload, "raw", input_type, ttl, "artifact_encryption")
        return str(metadata["artifact_id"])

    def write_mapping(self, mapping: dict[str, str], ttl: timedelta) -> SecureMappingReference:
        payload = json.dumps(mapping, ensure_ascii=False, sort_keys=True).encode("utf-8")
        metadata = self._write_artifact(
            payload, "mapping", "application/json", ttl, "mapping_encryption"
        )
        return SecureMappingReference(
            project_id=self.project_id,
            job_id=self.job_id,
            artifact_id=str(metadata["artifact_id"]),
            key_id=self.project_key.key_id,
        )

    def _write_artifact(
        self,
        payload: bytes,
        kind: str,
        content_type: str,
        ttl: timedelta,
        purpose: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        artifact_id = uuid4().hex
        metadata: dict[str, Any] = {
            "algorithm": "AES-256-GCM",
            "artifact_id": artifact_id,
            "content_type": content_type,
            "created_at": now.isoformat(),
            "expires_at": (now + ttl).isoformat(),
            "job_id": self.job_id,
            "key_id": self.project_key.key_id,
            "kind": kind,
            "project_id": self.project_id,
            "version": 1,
        }
        aad = _canonical_json(metadata)
        nonce = os.urandom(12)
        ciphertext = AESGCM(derive_project_key(self.project_key.master_key, purpose)).encrypt(
            nonce, payload, aad
        )
        _atomic_write(self.job_root / f"{artifact_id}.pgenc", _MAGIC + nonce + ciphertext)
        _atomic_write(self.job_root / f"{artifact_id}.json", aad)
        return metadata


def open_secure_mapping(
    reference: SecureMappingReference,
    project_id: str,
    purpose: str,
    secure_root: str | Path = ".privacy_gateway/secure",
    key_root: str | Path = ".privacy_gateway/keys",
) -> dict[str, str]:
    project_id = validate_identifier(project_id, "project_id")
    _validate_reference(reference)
    if project_id != reference.project_id:
        raise ValueError("project_id does not match the secure mapping reference")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError("purpose is required when opening a secure mapping")
    root = Path(secure_root)
    artifact_root = root / reference.project_id / reference.job_id
    metadata_path = artifact_root / f"{reference.artifact_id}.json"
    artifact_path = artifact_root / f"{reference.artifact_id}.pgenc"
    try:
        metadata_bytes = metadata_path.read_bytes()
        metadata = json.loads(metadata_bytes)
        encrypted = artifact_path.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise SecureArtifactError("secure mapping artifact is missing or invalid") from exc
    expected = {
        "artifact_id": reference.artifact_id,
        "job_id": reference.job_id,
        "key_id": reference.key_id,
        "kind": "mapping",
        "project_id": reference.project_id,
    }
    if any(metadata.get(name) != value for name, value in expected.items()):
        raise SecureArtifactError("secure mapping metadata does not match its reference")
    project_key = DpapiKeyProvider(key_root).load(project_id)
    plaintext = _decrypt_artifact(encrypted, metadata_bytes, project_key, "mapping_encryption")
    try:
        expires_at = datetime.fromisoformat(str(metadata["expires_at"]))
    except (KeyError, ValueError) as exc:
        raise SecureArtifactError("secure mapping expiry metadata is invalid") from exc
    if expires_at <= datetime.now(UTC):
        raise SecureArtifactError("secure mapping has expired")
    try:
        mapping = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise SecureArtifactError("decrypted mapping is not valid JSON") from exc
    lowered_purpose = purpose.casefold()
    if any(str(original).strip() and str(original).casefold() in lowered_purpose for original in mapping.values()):
        raise ValueError("purpose must not contain an original mapping value")
    _append_audit_event(root, reference, purpose)
    return {str(token): str(original) for token, original in mapping.items()}


def purge_expired_secure_data(
    secure_root: str | Path = ".privacy_gateway/secure",
    key_root: str | Path = ".privacy_gateway/keys",
    now: datetime | None = None,
) -> int:
    root = Path(secure_root)
    comparison_time = now or datetime.now(UTC)
    removed = 0
    if not root.exists():
        return removed
    for metadata_path in root.glob("*/*/*.json"):
        try:
            metadata_bytes = metadata_path.read_bytes()
            metadata = json.loads(metadata_bytes)
            expires_at = datetime.fromisoformat(str(metadata["expires_at"]))
            if expires_at > comparison_time:
                continue
            project_id = validate_identifier(str(metadata["project_id"]), "project_id")
            validate_identifier(str(metadata["job_id"]), "job_id")
            artifact_id = str(metadata["artifact_id"])
            if not _ARTIFACT_ID.fullmatch(artifact_id) or metadata_path.stem != artifact_id:
                continue
            encrypted = metadata_path.with_suffix(".pgenc").read_bytes()
            project_key = DpapiKeyProvider(key_root).load(project_id)
            purpose = "mapping_encryption" if metadata.get("kind") == "mapping" else "artifact_encryption"
            _decrypt_artifact(encrypted, metadata_bytes, project_key, purpose)
        except (OSError, KeyError, ValueError, json.JSONDecodeError, SecureArtifactError):
            continue
        metadata_path.with_suffix(".pgenc").unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        removed += 1
    return removed


def derive_project_key(master_key: bytes, purpose: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"privacy_gateway:v1",
        info=purpose.encode("ascii"),
    ).derive(master_key)


def _validate_reference(reference: SecureMappingReference) -> None:
    validate_identifier(reference.project_id, "project_id")
    validate_identifier(reference.job_id, "job_id")
    if not _ARTIFACT_ID.fullmatch(reference.artifact_id):
        raise ValueError("artifact_id must be 32 lowercase hexadecimal characters")
    if not _KEY_ID.fullmatch(reference.key_id):
        raise ValueError("key_id must be 16 lowercase hexadecimal characters")


def _decrypt_artifact(
    encrypted: bytes,
    metadata_bytes: bytes,
    project_key: ProjectKey,
    purpose: str,
) -> bytes:
    if not encrypted.startswith(_MAGIC) or len(encrypted) < len(_MAGIC) + 13:
        raise SecureArtifactError("secure artifact has an invalid format")
    nonce = encrypted[len(_MAGIC) : len(_MAGIC) + 12]
    ciphertext = encrypted[len(_MAGIC) + 12 :]
    try:
        return AESGCM(derive_project_key(project_key.master_key, purpose)).decrypt(
            nonce, ciphertext, metadata_bytes
        )
    except InvalidTag as exc:
        raise SecureArtifactError("secure artifact authentication failed") from exc


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}-{uuid4().hex}")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
        _restrict_permissions(path, is_directory=False)
    finally:
        temporary.unlink(missing_ok=True)


def _append_audit_event(root: Path, reference: SecureMappingReference, purpose: str) -> None:
    event = {
        "artifact_id": reference.artifact_id,
        "event": "mapping_opened",
        "job_id": reference.job_id,
        "project_id": reference.project_id,
        "purpose": purpose.strip(),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    root.mkdir(parents=True, exist_ok=True)
    with (root / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
