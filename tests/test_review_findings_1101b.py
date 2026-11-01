"""Findings of sx-review on 0.23.53 (agent 0.23.54).

A cancellation that went through run_process lost left_running: the total budgets of
project_snapshot, git diff and git apply_patch answered without it, and clone_timeout
dropped it and called dest clean. Through a proxy, a fetch cancelled during the TCP
connect still sent CONNECT.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import socket
import sys

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import git_ops as GO
from sentinelx_core.handlers import project_snapshot as PSN
from sentinelx_core.handlers import upload as U
from sentinelx_core.policy import FileOpsPath, Policy

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")
ORPHAN = "(setsid sh -c 'echo $$ > {pid}; sleep 8' &); sleep 30"


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 1.0)


def _kill(pidfile):
    try:
        os.killpg(int(pidfile.read_text().strip()), 9)
    except (OSError, ValueError):
        pass


def _rw(tmp_path):
    return dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))


@posix
async def test_a_budget_around_run_process_learns_what_outlived_the_kill(tmp_path):
    pid = tmp_path / "pid"
    try:
        with pytest.raises(asyncio.TimeoutError) as e:
            await asyncio.wait_for(EE.run_process(["bash", "-c", ORPHAN.format(pid=pid)], timeout=30), 1)
        assert EE.left_running_from(e.value), "the cancel lost left_running"
    finally:
        _kill(pid)


@posix
async def test_project_snapshot_budget_reports_left_running(tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    d = tmp_path / "bin"
    d.mkdir()
    (d / "git").write_text("#!/bin/bash\n" + ORPHAN.format(pid=pid) + "\n")
    (d / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(PSN, "_TOTAL_TIMEOUT", 2)
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        with pytest.raises(HandlerError) as e:
            await PSN.make_project_snapshot_handler(_rw(tmp_path))({"path": str(repo)})
        assert e.value.code == "timeout" and (e.value.details or {}).get("left_running") is True
    finally:
        _kill(pid)


async def test_clone_timeout_keeps_left_running_and_does_not_call_dest_clean(tmp_path, monkeypatch):
    async def wedged(*a, **k):
        raise HandlerError("git_timeout", "git clone timed out", {"left_running": True})
    monkeypatch.setattr(GO, "_run_git", wedged)
    with pytest.raises(HandlerError) as e:
        await GO._op_clone(_rw(tmp_path), {"url": "https://example.com/r.git", "dest": str(tmp_path / "c")})
    assert e.value.code == "clone_timeout" and (e.value.details or {}).get("left_running") is True
    assert "is clean" not in str(e.value)


async def test_a_proxy_fetch_cancelled_during_the_connect_sends_no_connect(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(U.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])
    ours, proxy = socket.socketpair()
    ours.settimeout(10)

    def slow(*a, **k):
        import time
        time.sleep(1.0)
        return ours
    monkeypatch.setattr(U.socket, "create_connection", slow)
    task = asyncio.create_task(U._fetch_url("https://files.example.com/x", tmp_path / "d",
                                            trusted_hosts=("files.example.com",), timeout=30))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(1.5)
    proxy.settimeout(2)
    try:
        assert proxy.recv(65536) == b"", "CONNECT reached the proxy after the cancel"
    finally:
        proxy.close()
