"""Findings of sx-review on 0.23.43-0.23.52 (agent 0.23.53).

From the backtest of 0.23.43..0.23.51: git, project_snapshot, the local_api relay and
icacls dropped left_running on a timeout; the edit helper under sudo was killed without
sudo; a file_url cancelled during the TCP connect went on afterwards; service ran with a
login shell; move across bind mounts failed with EXDEV. From the review of 0.23.52: the
O_EXCL reservation was left behind when the replace failed (upload and create), and a
failed create left the directories it made.
"""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import errno
import os
import socket
import sys
import types

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core import local_api as LA
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import edit as ED
from sentinelx_core.handlers import fsmutate as FM
from sentinelx_core.handlers import git_ops as GO
from sentinelx_core.handlers import project_snapshot as PSN
from sentinelx_core.handlers import upload as U
from sentinelx_core.policy import FileOpsPath, Policy
from sentinelx_core.vendored import pensa_safe_edit as pse

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")
ORPHAN = "(setsid sh -c 'echo $$ > {pid}; sleep 8' &); sleep 30"


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 1.0)


def _fake_bin(tmp_path, monkeypatch, name, body):
    d = tmp_path / "fakebin"
    d.mkdir(exist_ok=True)
    (d / name).write_text("#!/bin/bash\n" + body + "\n")
    (d / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")


def _kill(pidfile):
    try:
        os.killpg(int(pidfile.read_text().strip()), 9)
    except (OSError, ValueError):
        pass


@posix
@pytest.mark.parametrize("which", ["git_ops", "project_snapshot"])
async def test_a_git_timeout_says_when_something_outlived_it(which, tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    _fake_bin(tmp_path, monkeypatch, "git", ORPHAN.format(pid=pid))
    try:
        with pytest.raises(HandlerError) as e:
            if which == "git_ops":
                await GO._run_git(tmp_path, "status", timeout=1)
            else:
                monkeypatch.setattr(PSN, "_GIT_CMD_TIMEOUT", 1)
                await PSN._run_git(tmp_path, "status")
        assert e.value.code == "git_timeout" and (e.value.details or {}).get("left_running") is True
    finally:
        _kill(pid)


@posix
async def test_a_relay_timeout_says_the_relay_is_still_running(tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    monkeypatch.setattr(LA, "_relay_command", lambda ep: ["bash", "-c", ORPHAN.format(pid=pid)])
    ep = types.SimpleNamespace(timeout_s=-4.0, name="x", run_as="svcuser", path="/x")
    try:
        with pytest.raises(LA.LocalApiError) as e:
            await LA._call_via_run_as(ep, b"{}")
        assert e.value.code == "timeout" and "still running" in e.value.message
    finally:
        _kill(pid)


@posix
async def test_icacls_timeout_says_when_something_outlived_it(tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    monkeypatch.setattr(FM, "ICACLS_TIMEOUT_SECONDS", 1)
    _fake_bin(tmp_path, monkeypatch, "icacls", ORPHAN.format(pid=pid))
    try:
        with pytest.raises(HandlerError) as e:
            await FM._icacls_setowner(tmp_path, "someone")
        assert (e.value.details or {}).get("left_running") is True
    finally:
        _kill(pid)


async def test_the_edit_helper_under_sudo_gets_an_elevated_kill(monkeypatch):
    seen = []

    async def fake(argv, **kw):
        seen.append(kw.get("elevated"))
        return EE.ProcResult(0, b"", b"")
    monkeypatch.setattr(ED, "run_process", fake)
    await ED._run_argv(["sudo", "-n", "python3", "-m", "x"], timeout=5)
    await ED._run_argv(["python3", "-m", "x"], timeout=5)
    assert seen == [True, False]


async def test_a_fetch_cancelled_during_the_connect_sends_nothing(tmp_path, monkeypatch):
    for k in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(U.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])
    ours, server = socket.socketpair()
    ours.settimeout(10)

    def slow_connect(*a, **k):
        import time
        time.sleep(1.0)
        return ours
    monkeypatch.setattr(U.socket, "create_connection", slow_connect)
    task = asyncio.create_task(U._fetch_url("https://files.example.com/x", tmp_path / "d",
                                            trusted_hosts=("files.example.com",), timeout=30))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(1.5)
    server.settimeout(2)
    try:
        assert server.recv(65536) == b"", "the worker sent the TLS hello after being cancelled"
    finally:
        server.close()


@posix
async def test_service_commands_get_a_clean_startup(tmp_path, monkeypatch):
    marker = tmp_path / "hook"
    (tmp_path / "env.sh").write_text(f"printf x > {marker}\n")
    monkeypatch.setenv("BASH_ENV", str(tmp_path / "env.sh"))
    await EE.run_shell_split("true", timeout=10)
    assert not marker.exists(), "BASH_ENV ran before a service command"


def _rw(tmp_path):
    return dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))


@posix
async def test_move_across_bind_mounts_falls_back_to_a_copy(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_text("SOURCE")
    dst = tmp_path / "b.txt"
    monkeypatch.setattr(FM, "_same_filesystem", lambda s, d: True)
    real_rename = os.rename

    def exdev_for_the_source(a, b, *args, **kw):
        if os.fspath(a) == str(src):
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_rename(a, b, *args, **kw)
    monkeypatch.setattr(FM.os, "rename", exdev_for_the_source)
    await FM.make_move_handler(_rw(tmp_path))({"src": str(src), "dst": str(dst)})
    assert dst.read_text() == "SOURCE" and not src.exists()


def _no_links_and_failing_replace(monkeypatch, mod):
    monkeypatch.setattr(mod.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EPERM, "no links")))
    monkeypatch.setattr(mod.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EIO, "replace failed")))


async def test_a_failed_upload_replace_leaves_no_reservation(tmp_path, monkeypatch):
    base = tmp_path / "uploads"
    base.mkdir()
    _no_links_and_failing_replace(monkeypatch, U)
    with pytest.raises(Exception):
        await U.make_upload_file_handler(_rw(tmp_path), base)(
            {"target_path": "out.txt", "overwrite": False, "content_base64": base64.b64encode(b"X").decode()})
    assert not (base / "out.txt").exists(), "an empty reservation was left at the destination"


@posix
def test_a_failed_create_replace_leaves_no_reservation(tmp_path, monkeypatch):
    target = tmp_path / "new.txt"
    _no_links_and_failing_replace(monkeypatch, pse)
    with pytest.raises(Exception):
        pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="x\n", create=True))
    assert not target.exists(), "an empty reservation was left at the target"


@posix
def test_a_failed_create_removes_the_directories_it_made(tmp_path):
    target = tmp_path / "a" / "b" / "c.json"
    with pytest.raises(pse.SafeEditError):
        pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="{not json",
                                    create=True, validator_preset="json"))
    assert not (tmp_path / "a").exists(), "the directories made for the target were left"


def test_the_chunk_index_limit_is_the_file_name_width():
    assert U.MAX_CHUNK_INDEX == 100_000_000 and len(f"{U.MAX_CHUNK_INDEX - 1:08d}") == 8
