"""Jan's follow-ups on 0.23.43-0.23.51 (agent 0.23.52).

sxrep_NBEA83P4PV36  SHELLOPTS=xtrace + PS4 ran code before the allowlist prelude
sxrep_1SAMMGP269VG  through HTTPS_PROXY the tunnel went to the name, not the validated address
sxrep_YEKEFZ56TWY3  edit(create=true) created the target before validating, racing other writers
sxrep_F27ESHNWMPNF  without hard links, overwrite=false was exists() then replace()
sxrep_J68YSRS109FY  the missing-chunk check allocated a set the size of the largest index
sxrep_V0B3A89CJ4YV  script_run with a cwd left the agent's PWD in the child's environment
"""
from __future__ import annotations

import base64
import dataclasses
import errno
import hashlib
import os
import sys
import tracemalloc

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import exec as ex
from sentinelx_core.handlers import script as S
from sentinelx_core.handlers import upload as U
from sentinelx_core.policy import FileOpsPath, Policy
from sentinelx_core.vendored import pensa_safe_edit as pse

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")


def _rw(tmp_path):
    return dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))


@posix
async def test_shellopts_and_ps4_inherited_by_the_agent_run_nothing(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("SHELLOPTS", "xtrace")
    monkeypatch.setenv("PS4", f"$(printf SHELLOPTS_BYPASS > {marker}) TRACE> ")
    r = await ex.make_exec_handler(Policy(allowed_commands=("ls",)))({"command": "ls /"})
    assert not marker.exists(), "inherited shell state ran code before the allowlisted command"
    assert "usr" in r["output"].split()


def test_through_a_proxy_the_tunnel_goes_to_the_validated_address(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    conn = U._fetch_connection("trusted.example", 443, "8.8.8.8", 5)
    assert (conn.host, conn.port) == ("proxy.example", 8443)
    assert conn._tunnel_host == "8.8.8.8", f"CONNECT went to {conn._tunnel_host}, not the validated address"
    assert conn._sx_host == "trusted.example"


def _edit(target, new):
    return pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new=new, create=True))


@posix
def test_a_create_never_replaces_a_file_that_appeared_meanwhile(tmp_path, monkeypatch):
    target = tmp_path / "new.conf"
    real_link = os.link

    def someone_creates_first(src, dst, *a, **k):
        if os.fspath(dst) == str(target) and not target.exists():
            target.write_text("CONCURRENT")
        return real_link(src, dst, *a, **k)
    monkeypatch.setattr(pse.os, "link", someone_creates_first)
    with pytest.raises(pse.SafeEditError) as e:
        _edit(target, "SENTINEL\n")
    assert e.value.code == "target_exists"
    assert target.read_text() == "CONCURRENT"
    assert not [p for p in tmp_path.iterdir() if p.name != "new.conf"], "a temp file was left behind"


@posix
def test_a_failed_create_does_not_delete_a_file_that_appeared_meanwhile(tmp_path, monkeypatch):
    target = tmp_path / "new.json"
    real_ensure = pse.ensure_parent

    def ensure_then_someone_creates(path):
        real_ensure(path)
        target.write_text("")          # an empty file, created by someone else
    monkeypatch.setattr(pse, "ensure_parent", ensure_then_someone_creates)
    with pytest.raises(pse.SafeEditError):
        pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="{not json",
                                    create=True, validator_preset="json"))
    assert target.exists(), "the failure cleanup deleted a file it did not create"


@posix
def test_a_plain_create_still_works_with_the_usual_mode(tmp_path):
    target = tmp_path / "sub" / "fresh.txt"
    _edit(target, "hello\n")
    mask = os.umask(0)
    os.umask(mask)
    assert target.read_text() == "hello\n"
    assert (target.stat().st_mode & 0o777) == (0o666 & ~mask)


@posix
async def test_without_hard_links_overwrite_false_never_overwrites(tmp_path, monkeypatch):
    base = tmp_path / "uploads"
    base.mkdir()
    dest = base / "out.txt"

    def no_hard_links(*a, **k):
        raise OSError(errno.EPERM, "hard links not supported here")
    monkeypatch.setattr(U.os, "link", no_hard_links)
    real_replace = os.replace
    created = []

    def a_concurrent_creator_tries_first(src, dst, *a, **k):
        if os.fspath(dst) == str(dest):
            try:
                fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, b"CONCURRENT")
                os.close(fd)
                created.append(True)
            except FileExistsError:
                pass
        return real_replace(src, dst, *a, **k)
    monkeypatch.setattr(U.os, "replace", a_concurrent_creator_tries_first)
    h = U.make_upload_file_handler(_rw(tmp_path), base)
    try:
        await h({"target_path": "out.txt", "overwrite": False,
                 "content_base64": base64.b64encode(b"UPLOAD").decode()})
    except HandlerError:
        pass
    assert not (created and dest.read_bytes() != b"CONCURRENT"), "a concurrently created file was overwritten"


async def test_a_sparse_chunk_set_costs_no_memory_proportional_to_its_index(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    uid = hashlib.sha256(b"sparse-big").hexdigest()[:32]
    pol = _rw(tmp_path)
    await U.make_upload_init_handler(base, pol)({"target_path": str(tmp_path / "x.bin"), "upload_id": uid,
                                                "overwrite": True, "land_in_place": True})
    for i in (0, U.MAX_CHUNK_INDEX - 1):
        await U.make_upload_chunk_handler(base)({"upload_id": uid, "index": i,
                                                 "content_base64": base64.b64encode(b"A").decode()})
    tracemalloc.start()
    try:
        with pytest.raises(HandlerError) as e:
            await U.make_upload_complete_handler(base, pol)({"upload_id": uid})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert e.value.code == "incomplete_upload" and e.value.details["missing"][:3] == [1, 2, 3]
    assert peak < 8 * 1024 * 1024, f"{peak} bytes to report the missing chunks"
    with pytest.raises(HandlerError) as e2:
        await U.make_upload_chunk_handler(base)({"upload_id": uid, "index": U.MAX_CHUNK_INDEX,
                                                 "content_base64": base64.b64encode(b"A").decode()})
    assert e2.value.code == "invalid_payload"


@posix
async def test_a_script_with_a_cwd_sees_that_cwd_as_pwd(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    base = tmp_path / "uploads"
    base.mkdir()
    r = await S.make_script_run_handler(_rw(tmp_path), base)({
        "interpreter": "python3", "cwd": str(work), "timeout": 30,
        "content": "import os\nprint(os.environ.get('PWD'))"})
    assert r["output"].strip() == str(work), r["output"]
