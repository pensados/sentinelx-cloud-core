"""A refused rename or copy names the destination, not the staging file (0.23.35).

sxrep_0XCP6WETXRRH: an upload to /home/alex/Downloads failed with "permission denied:
'/var/lib/sentinelx/uploads/.sentinelx_uploads/<id>/assembled.bin'". The agent's own
staging file was fine; its OS user couldn't write into /home/alex/Downloads. A refused
os.replace carries the source in .filename and the destination in .filename2, and the
message used only the first.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from sentinelx_core import executor as EX
from sentinelx_core.executor import Executor
from sentinelx_protocol import RequestMessage

pytestmark = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                reason="needs POSIX permissions enforced (not root)")


def _real_refused_rename():
    root = Path(tempfile.mkdtemp())
    staging = root / "uploads" / ".sentinelx_uploads" / "abc"
    staging.mkdir(parents=True)
    tmp = staging / "assembled.bin"
    tmp.write_bytes(b"x" * 64)
    locked = root / "home" / "alex" / "Downloads"
    locked.mkdir(parents=True)
    os.chmod(locked, 0o555)
    try:
        os.replace(tmp, locked / "ci.tar.gz")
    except PermissionError as exc:
        return exc, str(tmp), str(locked / "ci.tar.gz"), str(locked)
    raise AssertionError("the rename should have been refused")


def _executor_raising(err, monkeypatch, op="upload_complete"):
    ex = Executor.__new__(Executor)

    async def boom(payload):
        raise err

    ex._handlers = {op: boom}
    monkeypatch.setattr(EX.local_audit, "record", lambda *a, **k: None)
    return ex


async def test_a_refused_move_names_the_destination_folder(monkeypatch):
    err, src, dest, folder = _real_refused_rename()
    assert err.filename == src and err.filename2 == dest   # what Python gives us
    ex = _executor_raising(err, monkeypatch)
    resp = await ex.dispatch(RequestMessage(id="r1", op="upload_complete", payload={}))
    e = resp["error"]
    assert e["code"] == "permission_denied"
    assert folder in e["message"] and "assembled.bin" not in e["message"]
    assert e["details"] == {"path": dest, "source": src}


async def test_a_single_path_error_is_reported_as_before(monkeypatch):
    err = PermissionError(13, "Permission denied", "/var/lib/x/y.sh")
    ex = _executor_raising(err, monkeypatch, op="delete")
    resp = await ex.dispatch(RequestMessage(id="r2", op="delete", payload={}))
    assert resp["error"]["details"] == {"path": "/var/lib/x/y.sh"}
    assert "parent directories" in resp["error"]["message"]
