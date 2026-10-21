"""An upload to another drive works on Windows (0.23.30).

When the destination is on another filesystem (Windows: staging on C:, target
on G:), _finalize copies the file and fsyncs the copy before the rename. It
opened the copy read-only; Windows' fsync (_commit) needs a handle open for
writing and failed with "[Errno 9] Bad file descriptor" after every byte had
arrived. The test applies Windows' rule on any OS.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from sentinelx_core.handlers import upload

fcntl = pytest.importorskip("fcntl")  # emulates Windows' rule on POSIX


def _windows_fsync(real):
    def fsync(fd):
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
            raise OSError(errno.EBADF, "Bad file descriptor")
        return real(fd)
    return fsync


def test_a_cross_drive_finalize_fsyncs_a_writable_handle(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "staging" / "assembled.bin"
    src.parent.mkdir()
    src.write_bytes(b"x" * 4096)
    dest = tmp_path / "other-drive" / "video.webm"
    dest.parent.mkdir()

    real_replace = Path.replace

    def cross_device(self, target):
        if self == src:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", cross_device)
    monkeypatch.setattr(upload.os, "fsync", _windows_fsync(os.fsync))
    upload._finalize(src, dest)
    assert dest.read_bytes() == b"x" * 4096
    assert not src.exists()
    assert not list(dest.parent.glob(".*.part"))


def test_other_errors_still_raise(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "a"
    src.write_bytes(b"1")

    def boom(self, target):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "replace", boom)
    with pytest.raises(OSError):
        upload._finalize(src, tmp_path / "b")
