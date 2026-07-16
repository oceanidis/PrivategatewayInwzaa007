from __future__ import annotations

import os
from pathlib import Path

import pytest

from privategateway_service.path_policy import PathPolicy, ServicePathError


@pytest.fixture
def policy(tmp_path: Path) -> tuple[PathPolicy, Path, Path]:
    protected = tmp_path / "protected"
    safe = tmp_path / "safe"
    outside = tmp_path / "outside"
    protected.mkdir()
    safe.mkdir()
    outside.mkdir()
    (protected / "input.txt").write_text("input", encoding="ascii")
    (outside / "outside.txt").write_text("outside", encoding="ascii")
    return PathPolicy((protected,), safe), protected, outside


def test_resolve_valid_protected_file(policy: tuple[PathPolicy, Path, Path]) -> None:
    path_policy, protected, _ = policy

    assert path_policy.resolve_input(protected / "input.txt") == protected / "input.txt"


def test_resolve_directory_requires_protected_directory(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, protected, _ = policy

    assert path_policy.resolve_directory(protected) == protected


def test_rejects_traversal_and_outside_input(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, protected, outside = policy

    for candidate in (protected / ".." / "outside" / "outside.txt", outside / "outside.txt"):
        with pytest.raises(ServicePathError) as error:
            path_policy.resolve_input(candidate)
        assert error.value.code == "RAW_PATH_DENIED"
        assert str(error.value) == "RAW_PATH_DENIED"
        assert str(candidate) not in str(error.value)


def test_rejects_directory_and_nonexistent_input(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, protected, _ = policy

    for candidate in (protected, protected / "missing.txt"):
        with pytest.raises(ServicePathError) as error:
            path_policy.resolve_input(candidate)
        assert error.value.code == "RAW_PATH_DENIED"


def test_rejects_output_outside_safe_root(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, _, outside = policy

    with pytest.raises(ServicePathError) as error:
        path_policy.resolve_output(outside / "created.txt")
    assert error.value.code == "OUTPUT_PATH_DENIED"
    assert str(error.value) == "OUTPUT_PATH_DENIED"


def test_allows_new_output_file_under_safe_root(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, _, _ = policy

    output = path_policy.resolve_output(path_policy.safe_root / "created.txt")

    assert output == path_policy.safe_root / "created.txt"


def test_initializes_absent_safe_root_and_allows_output(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    safe = tmp_path / "new" / "safe"
    protected.mkdir()

    path_policy = PathPolicy((protected,), safe)

    assert safe.is_dir()
    assert path_policy.resolve_output(safe / "created.txt") == safe / "created.txt"


@pytest.mark.skipif(os.name != "nt", reason="Windows path syntax")
def test_rejects_windows_unc_and_ads_paths(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, _, _ = policy

    for candidate in (r"\\server\share\file.txt", path_policy.safe_root / "file.txt:stream"):
        with pytest.raises(ServicePathError):
            path_policy.resolve_input(candidate)


def test_rejects_symlink_escape(
    policy: tuple[PathPolicy, Path, Path],
) -> None:
    path_policy, protected, outside = policy
    link = protected / "link.txt"
    try:
        link.symlink_to(outside / "outside.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ServicePathError) as error:
        path_policy.resolve_input(link)
    assert error.value.code == "RAW_PATH_DENIED"
