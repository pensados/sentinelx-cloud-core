"""Windows chown: icacls runs through run_process (agent 0.23.52; 0.23.44 used a thread).

A wedged icacls is cut off at the timeout, and a cancelled request kills it instead of
letting it change the owner afterwards (sxrep_1N5VN9Z8NNHG). Exercised on POSIX with a
fake `icacls` on PATH, which is what run_process would start on Windows.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import sys

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import fsmutate as FM
from sentinelx_core.policy import FileOpsPath, Policy

posix = pytest.mark.skipif(sys.platform == "win32", reason="fake icacls is a shell script")


def _fake_icacls(tmp_path, monkeypatch, body):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "icacls").write_text("#!/bin/sh\n" + body)
    (bindir / "icacls").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


@posix
async def test_cancelling_the_request_kills_icacls(tmp_path, monkeypatch):
    marker = tmp_path / "changed"
    _fake_icacls(tmp_path, monkeypatch, f"sleep 1; printf x > {marker}\n")
    task = asyncio.create_task(FM._icacls_setowner(tmp_path, "someone"))
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(1.5)
    assert not marker.exists(), "icacls kept running after the request was cancelled"


@posix
async def test_a_wedged_icacls_is_cut_off_with_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(FM, "ICACLS_TIMEOUT_SECONDS", 1)
    _fake_icacls(tmp_path, monkeypatch, "sleep 30\n")
    with pytest.raises(HandlerError) as e:
        await FM._icacls_setowner(tmp_path, "someone")
    assert e.value.code == "chown_failed" and "did not finish" in str(e.value)


async def test_the_windows_branch_uses_it(tmp_path, monkeypatch):
    calls = []

    async def fake(target, owner):
        calls.append((str(target), owner))
    monkeypatch.setattr(FM.sys, "platform", "win32")
    monkeypatch.setattr(FM, "_icacls_setowner", fake)
    target = tmp_path / "f.txt"
    target.write_text("x")
    pol = dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))
    res = await FM.make_chown_handler(pol)({"path": str(target), "owner": "someone"})
    assert res["ok"] and res["backend"] == "icacls" and calls and calls[0][1] == "someone"
