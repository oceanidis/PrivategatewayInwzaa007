from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import subprocess
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4


class KeyProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProjectKey:
    key_id: str
    master_key: bytes = field(repr=False)


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def validate_identifier(value: str, field_name: str) -> str:
    import re

    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError(f"{field_name} must contain only letters, digits, '.', '_' or '-'")
    return value


class DpapiKeyProvider:
    def __init__(self, key_root: str | Path = ".privacy_gateway/keys") -> None:
        if os.name != "nt":
            raise KeyProviderError("Windows DPAPI key provider is available only on Windows")
        self.key_root = Path(key_root)

    def initialize(self, project_id: str) -> ProjectKey:
        project_id = validate_identifier(project_id, "project_id")
        self.key_root.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self.key_root, is_directory=True)
        path = self.key_root / f"{project_id}.dpapi"
        if not path.exists():
            protected = _dpapi_protect(os.urandom(32), project_id.encode("utf-8"))
            temporary = path.with_suffix(f".tmp-{os.getpid()}-{uuid4().hex}")
            try:
                temporary.write_bytes(protected)
                _restrict_permissions(temporary, is_directory=False)
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
                _restrict_permissions(path, is_directory=False)
            finally:
                temporary.unlink(missing_ok=True)
        return self.load(project_id)

    def load(self, project_id: str) -> ProjectKey:
        project_id = validate_identifier(project_id, "project_id")
        path = self.key_root / f"{project_id}.dpapi"
        if not path.exists():
            raise KeyProviderError(
                f"No key exists for project '{project_id}'. Run init-project before importing data."
            )
        master_key = _dpapi_unprotect(path.read_bytes(), project_id.encode("utf-8"))
        if len(master_key) != 32:
            raise KeyProviderError("Decrypted project key has an invalid length")
        key_id = hashlib.sha256(master_key).hexdigest()[:16]
        return ProjectKey(key_id=key_id, master_key=master_key)


def init_project(project_id: str, key_root: str | Path = ".privacy_gateway/keys") -> ProjectKey:
    return DpapiKeyProvider(key_root).initialize(project_id)


def _to_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _dpapi_protect(data: bytes, entropy: bytes) -> bytes:
    return _call_dpapi("CryptProtectData", data, entropy)


def _dpapi_unprotect(data: bytes, entropy: bytes) -> bytes:
    return _call_dpapi("CryptUnprotectData", data, entropy)


def _call_dpapi(function_name: str, data: bytes, entropy: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = getattr(crypt32, function_name)
    input_blob, input_buffer = _to_blob(data)
    entropy_blob, entropy_buffer = _to_blob(entropy)
    output_blob = _DataBlob()
    description = wintypes.LPWSTR()
    flags = 0x1
    if function_name == "CryptProtectData":
        ok = function(
            ctypes.byref(input_blob), None, ctypes.byref(entropy_blob), None, None, flags,
            ctypes.byref(output_blob),
        )
    else:
        ok = function(
            ctypes.byref(input_blob), ctypes.byref(description), ctypes.byref(entropy_blob),
            None, None, flags, ctypes.byref(output_blob),
        )
    _ = input_buffer, entropy_buffer
    if not ok:
        raise KeyProviderError(f"DPAPI operation failed with Windows error {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        if description:
            kernel32.LocalFree(description)


def _restrict_permissions(path: Path, is_directory: bool) -> None:
    if os.name != "nt":
        mode = stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if is_directory else 0)
        os.chmod(path, mode)
        return
    identity_result = subprocess.run(
        ["whoami"], capture_output=True, text=True, check=False, creationflags=0x08000000
    )
    identity = identity_result.stdout.strip()
    if identity_result.returncode != 0 or not identity:
        raise KeyProviderError("Unable to identify the Windows account for secure ACL setup")
    rights = "(OI)(CI)F" if is_directory else "F"
    acl_result = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:{rights}"],
        capture_output=True,
        text=True,
        check=False,
        creationflags=0x08000000,
    )
    if acl_result.returncode != 0:
        raise KeyProviderError(f"Unable to restrict ACL for secure path: {path}")
