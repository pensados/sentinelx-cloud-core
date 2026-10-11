"""A finished upload/transfer lands even when the destination is on another filesystem.

sxrep_XW9FTRHAH0H7: a transfer to a WSL host writing under /mnt/... moved every
byte and then failed with "[Errno 18] Invalid cross-device link": the staging
area and the destination were on different filesystems, and a rename can't
cross them. The rename is simulated to fail with EXDEV here.
"""

from __future__ import annotations

import errno
import hashlib
from pathlib import Path

import pytest

from sentinelx_core.handlers import upload


@pytest.fixture
def cross_device(monkeypatch):
    real = Path.replace

    def replace(self, target):
        if ".sentinelx_uploads" in str(self):        # leaving staging = crossing devices
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real(self, target)
    monkeypatch.setattr(Path, "replace", replace)


def test_finalize_copies_across_filesystems_and_leaves_nothing_behind(tmp_path, cross_device):
    staging = tmp_path / ".sentinelx_uploads" / "abc"; staging.mkdir(parents=True)
    tmp = staging / "assembled"; tmp.write_bytes(b"payload" * 1000)
    dest = tmp_path / "mnt" / "c" / "file.bin"; dest.parent.mkdir(parents=True)
    upload._finalize(tmp, dest)
    assert dest.read_bytes() == b"payload" * 1000
    assert not tmp.exists()
    assert [p.name for p in dest.parent.iterdir()] == ["file.bin"]   # no .part left


def test_other_errors_are_not_swallowed(tmp_path, monkeypatch):
    def replace(self, target):
        raise OSError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(Path, "replace", replace)
    tmp = tmp_path / "a"; tmp.write_bytes(b"x")
    with pytest.raises(OSError) as exc:
        upload._finalize(tmp, tmp_path / "b")
    assert exc.value.errno == errno.EACCES


async def test_a_chunked_upload_completes_across_filesystems(tmp_path, cross_device):
    base = tmp_path / "base"; base.mkdir()
    data = b"0123456789" * 5000
    init = upload.make_upload_init_handler(base)
    chunk = upload.make_upload_chunk_handler(base)
    done = upload.make_upload_complete_handler(base)
    r = await init({"target_path": str(base / "f.bin"), "total_size": len(data)})
    uid = r["upload_id"]
    import base64
    await chunk({"upload_id": uid, "index": 0, "content_base64": base64.b64encode(data).decode()})
    out = await done({"upload_id": uid, "sha256": hashlib.sha256(data).hexdigest()})
    assert Path(out["target_path"]).read_bytes() == data         # landed, intact, across "devices"
