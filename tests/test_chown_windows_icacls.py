"""Windows chown: icacls runs in a thread with a timeout (agent 0.23.44, Jan's audit #16).

It ran as a blocking subprocess.run with no timeout inside the async handler, so a slow
or wedged icacls froze the whole agent. Exercised on any OS by faking the platform.
"""
from __future__ import annotations

import asyncio
import dataclasses
import subprocess
import time

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import fsmutate as FM
from sentinelx_core.policy import FileOpsPath, Policy


def _handler(tmp_path, monkeypatch, fake_run):
    monkeypatch.setattr(FM.sys, "platform", "win32")
    monkeypatch.setattr(FM.subprocess, "run", fake_run)
    target = tmp_path / "f.txt"
    target.write_text("x")
    pol = dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))
    return FM.make_chown_handler(pol), target


async def test_icacls_does_not_block_the_event_loop(tmp_path, monkeypatch):
    def slow_icacls(argv, **kw):
        time.sleep(0.6)
        return subprocess.CompletedProcess(argv, 0, "", "")
    h, target = _handler(tmp_path, monkeypatch, slow_icacls)
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.05)
            ticks += 1

    t = asyncio.create_task(ticker())
    res = await h({"path": str(target), "owner": "someone"})
    t.cancel()
    assert res["ok"] and res["backend"] == "icacls"
    assert ticks >= 5, f"the event loop was blocked while icacls ran ({ticks} ticks)"


async def test_a_wedged_icacls_is_cut_off_with_a_clear_error(tmp_path, monkeypatch):
    def wedged(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
    h, target = _handler(tmp_path, monkeypatch, wedged)
    with pytest.raises(HandlerError) as e:
        await h({"path": str(target), "owner": "someone"})
    assert e.value.code == "chown_failed" and "did not finish" in str(e.value)
