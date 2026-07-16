from pathlib import Path

from privategateway.secure_store import _atomic_write


def test_atomic_write_uses_short_temporary_artifact_name(tmp_path, monkeypatch):
    target_dir = tmp_path / "nested" / "temporary" / "artifacts"
    target_dir.mkdir(parents=True)
    target = target_dir / ("artifact-" + "a" * 80 + ".pgenc")
    payload = b"secure payload"
    replaced = {}

    real_replace = __import__("os").rename

    def capture_replace(temporary, final):
        replaced["temporary"] = Path(temporary)
        real_replace(temporary, final)

    monkeypatch.setattr("privategateway.secure_store.os.replace", capture_replace)

    _atomic_write(target, payload)

    temporary = replaced["temporary"]
    assert target.read_bytes() == payload
    assert temporary.parent == target.parent
    assert temporary.name.startswith(".tmp-")
    assert len(temporary.name) < 64
    assert len(temporary.name) < len(target.name)
