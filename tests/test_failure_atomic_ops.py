"""Failure-atomic file operations (agent 0.23.43), from Jan's audit of 2026-10-31.

#10 edit(create=true) left a zero-byte file after a failed validation
#11 move(overwrite=true) replaced the destination and still reported failure
#12 copy(overwrite=true) destroyed the old destination before the copy could finish
#13 upload_file(overwrite=false) overwrote a file created during the upload
#18 chunked upload accepted a sparse chunk set and reused stale parts
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import sys

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import fsmutate as FM
from sentinelx_core.handlers import upload as U
from sentinelx_core.policy import FileOpsPath, Policy
from sentinelx_core.vendored import pensa_safe_edit as pse

posix_user = pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0,
                                reason="needs POSIX permissions enforced")


def _pol(tmp_path):
    return dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))


def _leftovers(d):
    return [p.name for p in d.iterdir() if ".sentinelx-" in p.name]


@posix_user
async def test_a_move_that_cant_remove_its_source_leaves_the_destination_intact(tmp_path):
    srcdir = tmp_path / "srcdir"; srcdir.mkdir()
    src = srcdir / "a.txt"; src.write_text("SOURCE")
    dst = tmp_path / "b.txt"; dst.write_text("DESTINATION")
    os.chmod(srcdir, 0o555)
    try:
        with pytest.raises(HandlerError):
            await FM.make_move_handler(_pol(tmp_path))({"src": str(src), "dst": str(dst), "overwrite": True})
    finally:
        os.chmod(srcdir, 0o755)
    assert dst.read_text() == "DESTINATION" and src.read_text() == "SOURCE"
    assert not _leftovers(tmp_path)


@posix_user
async def test_across_filesystems_a_failed_source_removal_undoes_the_move(tmp_path, monkeypatch):
    monkeypatch.setattr(FM, "_same_filesystem", lambda s, d: False)
    srcdir = tmp_path / "srcdir"; srcdir.mkdir()
    src = srcdir / "a.txt"; src.write_text("SOURCE")
    dst = tmp_path / "b.txt"; dst.write_text("DESTINATION")
    os.chmod(srcdir, 0o555)
    try:
        with pytest.raises(HandlerError):
            await FM.make_move_handler(_pol(tmp_path))({"src": str(src), "dst": str(dst), "overwrite": True})
    finally:
        os.chmod(srcdir, 0o755)
    assert dst.read_text() == "DESTINATION" and src.read_text() == "SOURCE"
    assert not _leftovers(tmp_path)


async def test_a_successful_move_and_copy_replace_cleanly(tmp_path):
    a = tmp_path / "a"; a.write_text("NEW")
    b = tmp_path / "b"; b.write_text("OLD")
    await FM.make_move_handler(_pol(tmp_path))({"src": str(a), "dst": str(b), "overwrite": True})
    assert b.read_text() == "NEW" and not a.exists()
    c = tmp_path / "c"; c.write_text("OLD")
    await FM.make_copy_handler(_pol(tmp_path))({"src": str(b), "dst": str(c), "overwrite": True})
    assert c.read_text() == "NEW" and b.read_text() == "NEW"
    assert not _leftovers(tmp_path)


@posix_user
async def test_a_failed_directory_copy_keeps_the_old_destination(tmp_path):
    src = tmp_path / "src"; src.mkdir()
    (src / "a").write_text("a"); locked = src / "b"; locked.write_text("b"); os.chmod(locked, 0)
    dst = tmp_path / "dst"; dst.mkdir(); (dst / "old.txt").write_text("OLD")
    try:
        with pytest.raises(HandlerError):
            await FM.make_copy_handler(_pol(tmp_path))({"src": str(src), "dst": str(dst), "overwrite": True})
    finally:
        os.chmod(locked, 0o644)
    assert (dst / "old.txt").read_text() == "OLD" and not (dst / "a").exists()
    assert not _leftovers(tmp_path)


async def test_overwrite_false_upload_keeps_a_file_created_meanwhile(tmp_path, monkeypatch):
    base = tmp_path / "uploads"; base.mkdir()
    dest = base / "out.txt"           # upload_file writes under upload_base
    real = U._decode_base64_to

    def decode_then_someone_creates_dest(content_b64, tmp):
        r = real(content_b64, tmp)
        dest.write_text("CONCURRENT")
        return r
    monkeypatch.setattr(U, "_decode_base64_to", decode_then_someone_creates_dest)
    h = U.make_upload_file_handler(_pol(tmp_path), base)
    with pytest.raises(HandlerError) as e:
        await h({"target_path": "out.txt", "overwrite": False,
                 "content_base64": base64.b64encode(b"UPLOAD").decode()})
    assert e.value.code == "conflict" and dest.read_text() == "CONCURRENT"


def _uid(s):
    return hashlib.sha256(s.encode()).hexdigest()[:32]


async def _chunked(tmp_path, uid, chunks, dest):
    base = tmp_path / "uploads"; base.mkdir(exist_ok=True)
    pol = _pol(tmp_path)
    await U.make_upload_init_handler(base, pol)({"target_path": str(dest), "upload_id": uid,
                                                "overwrite": True, "land_in_place": True})
    for i, data in chunks:
        await U.make_upload_chunk_handler(base)({"upload_id": uid, "index": i,
                                                 "content_base64": base64.b64encode(data).decode()})
    return await U.make_upload_complete_handler(base, pol)({"upload_id": uid})


async def test_a_sparse_chunk_set_is_not_a_complete_upload(tmp_path):
    with pytest.raises(HandlerError) as e:
        await _chunked(tmp_path, _uid("sparse"), [(0, b"A"), (2, b"C")], tmp_path / "x.bin")
    assert e.value.code == "incomplete_upload" and e.value.details["missing"] == [1]


async def test_a_reused_upload_id_starts_a_fresh_session(tmp_path):
    uid = _uid("reused")
    base = tmp_path / "uploads"; base.mkdir()
    pol = _pol(tmp_path)
    await U.make_upload_init_handler(base, pol)({"target_path": str(tmp_path / "x.bin"), "upload_id": uid,
                                                "overwrite": True, "land_in_place": True})
    for i in range(3):
        await U.make_upload_chunk_handler(base)({"upload_id": uid, "index": i,
                                                 "content_base64": base64.b64encode(b"OLD").decode()})
    await _chunked(tmp_path, uid, [(0, b"NEW")], tmp_path / "x.bin")
    assert (tmp_path / "x.bin").read_bytes() == b"NEW"


def test_a_failed_create_leaves_no_file(tmp_path):
    target = tmp_path / "new.json"
    with pytest.raises(pse.SafeEditError):
        pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="{not json",
                                    create=True, validator_preset="json"))
    assert not target.exists(), "a zero-byte file was left behind"
