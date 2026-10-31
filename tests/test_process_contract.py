"""The process-lifecycle contract every caller that starts a child must meet.

run_process (executor_engine) is the one implementation. Each RUNNER below drives a
real caller with a bash script; stage 2 of the lifecycle unification adds edit, git
and the local_api relay here. A caller that rolls its own lifecycle fails this file.

  1. cancelling the call kills the whole tree: nothing it started keeps running;
  2. a timeout kills the tree and comes back within the timeout plus the grace;
  3. a descendant that left the group with setsid is killed too;
  4. a process already orphaned out of the tree is reported as left_running;
  5. input reaches the child's stdin (where the caller takes input).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time

import pytest

from sentinelx_core import executor_engine as EE

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setsid") is None,
    reason="the tree guarantees are checked on Linux (/proc, setsid)",
)


async def _via_run_process(script, timeout, input=None):
    r = await EE.run_process(["bash", "-c", script], timeout=timeout, input=input)
    return {"timed_out": r.timed_out, "left_running": r.left_running, "out": r.stdout.decode()}


async def _via_run_shell(script, timeout, input=None):
    r = await EE.run_shell(script, timeout=timeout)
    return {"timed_out": r.get("timed_out", False), "left_running": r.get("left_running", False),
            "out": r.get("output", "")}


async def _via_run_shell_split(script, timeout, input=None):
    r = await EE.run_shell_split(script, timeout=timeout)
    return {"timed_out": r.get("timed_out", False), "left_running": r.get("left_running", False),
            "out": r.get("stdout", "")}


RUNNERS = {
    "run_process": (_via_run_process, True),
    "run_shell": (_via_run_shell, False),
    "run_shell_split": (_via_run_shell_split, False),
}
NAMES = list(RUNNERS)


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 1.0)


def _killpg_from(pidfile):
    try:
        os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
    except (OSError, ValueError):
        pass


@pytest.mark.parametrize("name", NAMES)
async def test_cancelling_kills_the_whole_tree(name, tmp_path):
    runner, _ = RUNNERS[name]
    marker = tmp_path / "marker"
    task = asyncio.create_task(runner(f"(sleep 2; printf x > {marker}) & sleep 30", 20))
    await asyncio.sleep(0.4)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: a child kept running after cancellation"


@pytest.mark.parametrize("name", NAMES)
async def test_a_timeout_kills_the_tree_and_returns_in_time(name, tmp_path):
    runner, _ = RUNNERS[name]
    marker = tmp_path / "marker"
    t0 = time.monotonic()
    res = await runner(f"(sleep 2; printf x > {marker}) & sleep 30", 1)
    assert res["timed_out"] and time.monotonic() - t0 < 4, (name, res)
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: a child outlived the timeout"


@pytest.mark.parametrize("name", NAMES)
async def test_a_setsid_descendant_is_killed_too(name, tmp_path):
    runner, _ = RUNNERS[name]
    marker = tmp_path / "marker"
    res = await runner(f"setsid sh -c 'sleep 2; printf x > {marker}' & sleep 30", 1)
    assert res["timed_out"] and not res["left_running"], (name, res)
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: an escaped descendant kept running"


@pytest.mark.parametrize("name", NAMES)
async def test_an_orphan_holding_the_pipes_is_reported(name, tmp_path):
    runner, _ = RUNNERS[name]
    pidfile = tmp_path / "pid"
    try:
        res = await runner(f"(setsid sh -c 'echo $$ > {pidfile}; sleep 8' &); sleep 30", 1)
        assert res["timed_out"] and res["left_running"], (name, res)
    finally:
        _killpg_from(pidfile)


@pytest.mark.parametrize("name", [n for n in NAMES if RUNNERS[n][1]])
async def test_input_reaches_stdin(name):
    runner, _ = RUNNERS[name]
    res = await runner("cat", 5, input=b"through stdin")
    assert res["out"] == "through stdin" and not res["timed_out"]
