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


async def _via_edit_helper(script, timeout, input=None):
    from sentinelx_core.handlers import edit as ED
    r = await ED._run_argv(["bash", "-c", script], timeout=timeout)
    return {"timed_out": r["returncode"] == -1 and r["output"].startswith("⏱"),
            "left_running": r.get("left_running", False), "out": r["output"]}


def _fake_git_on_path(tmp_path, monkeypatch, script):
    """A `git` on PATH that runs the case's script: git_ops and project_snapshot only
    ever run git, so this drives them through their real code."""
    bindir = tmp_path / "fakegit"
    bindir.mkdir(exist_ok=True)
    (bindir / "git").write_text('#!/bin/bash\nexec bash -c "$SX_CONTRACT_SCRIPT"\n')
    (bindir / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SX_CONTRACT_SCRIPT", script)


async def _via_git_ops(script, timeout, input=None, *, tmp_path, monkeypatch):
    from sentinelx_core.executor import HandlerError
    from sentinelx_core.handlers import git_ops as GO
    _fake_git_on_path(tmp_path, monkeypatch, script)
    try:
        rc, out, _ = await GO._run_git(tmp_path, "status", stdin=input, timeout=timeout)
    except HandlerError as e:
        assert e.code == "git_timeout"
        return {"timed_out": True, "left_running": False, "out": ""}
    return {"timed_out": False, "left_running": False, "out": out.decode()}


async def _via_project_snapshot(script, timeout, input=None, *, tmp_path, monkeypatch):
    from sentinelx_core.executor import HandlerError
    from sentinelx_core.handlers import project_snapshot as PS
    _fake_git_on_path(tmp_path, monkeypatch, script)
    monkeypatch.setattr(PS, "_GIT_CMD_TIMEOUT", timeout)
    try:
        rc, out = await PS._run_git(tmp_path, "status")
    except HandlerError as e:
        assert e.code == "git_timeout"
        return {"timed_out": True, "left_running": False, "out": ""}
    return {"timed_out": False, "left_running": False, "out": out.decode()}


async def _via_local_api_relay(script, timeout, input=None, *, tmp_path, monkeypatch):
    import types

    from sentinelx_core import local_api as LA
    monkeypatch.setattr(LA, "_relay_command", lambda endpoint: ["bash", "-c", script])
    ep = types.SimpleNamespace(timeout_s=timeout - 5, name="contract", run_as="nobody", path="/x")
    try:
        out = await LA._call_via_run_as(ep, input if input is not None else b"")
    except LA.LocalApiError as e:
        if e.code == "timeout":
            return {"timed_out": True, "left_running": False, "out": ""}
        raise
    return {"timed_out": False, "left_running": False, "out": out.decode()}


async def _via_script_run(script, timeout, input=None, *, tmp_path, monkeypatch, sudo=False):
    from sentinelx_core.handlers import script as S
    from sentinelx_core.policy import Policy
    if sudo:
        bindir = tmp_path / "fakesudo"
        bindir.mkdir(exist_ok=True)
        # Like the real sudo: -n accepted, the command started with a reset
        # environment. It also runs `sudo -n kill`, the elevated tree kill.
        (bindir / "sudo").write_text('#!/bin/sh\n[ "$1" = "-n" ] && shift\nexec env -i PATH="$PATH" "$@"\n')
        (bindir / "sudo").chmod(0o755)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    base = tmp_path / "uploads"
    base.mkdir(exist_ok=True)
    r = await S.make_script_run_handler(Policy.empty(), base)(
        {"interpreter": "bash", "content": script, "timeout": max(1, int(timeout)), "sudo": sudo})
    return {"timed_out": r.get("timed_out", False), "left_running": r.get("left_running", False),
            "out": r.get("output", "")}


async def _via_script_run_sudo(script, timeout, input=None, *, tmp_path, monkeypatch):
    return await _via_script_run(script, timeout, input, tmp_path=tmp_path, monkeypatch=monkeypatch, sudo=True)


# name: (runner, takes input, reports left_running, needs tmp_path/monkeypatch)
RUNNERS = {
    "run_process": (_via_run_process, True, True, False),
    "run_shell": (_via_run_shell, False, True, False),
    "run_shell_split": (_via_run_shell_split, False, True, False),
    "edit_helper": (_via_edit_helper, False, True, False),
    "git_ops": (_via_git_ops, True, False, True),
    "project_snapshot": (_via_project_snapshot, False, False, True),
    "local_api_relay": (_via_local_api_relay, True, False, True),
    "script_run": (_via_script_run, False, True, True),
    "script_run_sudo": (_via_script_run_sudo, False, True, True),
}
NAMES = list(RUNNERS)


def _runner(name, tmp_path, monkeypatch):
    fn, _, _, needs = RUNNERS[name]
    if needs:
        return lambda script, timeout, input=None: fn(script, timeout, input,
                                                      tmp_path=tmp_path, monkeypatch=monkeypatch)
    return fn


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 1.0)


def _killpg_from(pidfile):
    try:
        os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
    except (OSError, ValueError):
        pass


@pytest.mark.parametrize("name", NAMES)
async def test_cancelling_kills_the_whole_tree(name, tmp_path, monkeypatch):
    runner = _runner(name, tmp_path, monkeypatch)
    marker = tmp_path / "marker"
    task = asyncio.create_task(runner(f"(sleep 2; printf x > {marker}) & sleep 30", 20))
    await asyncio.sleep(0.4)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: a child kept running after cancellation"


@pytest.mark.parametrize("name", NAMES)
async def test_a_timeout_kills_the_tree_and_returns_in_time(name, tmp_path, monkeypatch):
    runner = _runner(name, tmp_path, monkeypatch)
    marker = tmp_path / "marker"
    t0 = time.monotonic()
    res = await runner(f"(sleep 2; printf x > {marker}) & sleep 30", 1)
    assert res["timed_out"] and time.monotonic() - t0 < 4, (name, res)
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: a child outlived the timeout"


@pytest.mark.parametrize("name", NAMES)
async def test_a_setsid_descendant_is_killed_too(name, tmp_path, monkeypatch):
    runner = _runner(name, tmp_path, monkeypatch)
    marker = tmp_path / "marker"
    res = await runner(f"setsid sh -c 'sleep 2; printf x > {marker}' & sleep 30", 1)
    assert res["timed_out"] and not res["left_running"], (name, res)
    await asyncio.sleep(2.5)
    assert not marker.exists(), f"{name}: an escaped descendant kept running"


@pytest.mark.parametrize("name", [n for n in NAMES if RUNNERS[n][2]])
async def test_an_orphan_holding_the_pipes_is_reported(name, tmp_path, monkeypatch):
    runner = _runner(name, tmp_path, monkeypatch)
    pidfile = tmp_path / "pid"
    try:
        res = await runner(f"(setsid sh -c 'echo $$ > {pidfile}; sleep 8' &); sleep 30", 1)
        assert res["timed_out"] and res["left_running"], (name, res)
    finally:
        _killpg_from(pidfile)


@pytest.mark.parametrize("name", [n for n in NAMES if RUNNERS[n][1]])
async def test_input_reaches_stdin(name, tmp_path, monkeypatch):
    runner = _runner(name, tmp_path, monkeypatch)
    res = await runner("cat", 5, input=b"through stdin")
    assert res["out"] == "through stdin" and not res["timed_out"]


async def test_script_run_with_sudo_asks_run_process_for_an_elevated_kill(tmp_path, monkeypatch):
    """The fake sudo above runs as the same user, so an elevated kill and a plain one
    look alike there; this checks the wiring itself. The real thing (root-owned
    tree, sudo kill) was exercised end to end on the dev agent for 0.23.47."""
    from sentinelx_core.handlers import script as S
    from sentinelx_core.policy import Policy
    seen = {}

    async def fake_run_process(argv, **kw):
        seen.update(kw)
        return EE.ProcResult(0, b"ok", b"")
    monkeypatch.setattr(S, "run_process", fake_run_process)
    base = tmp_path / "uploads"
    base.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
    (bindir / "sudo").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    await S.make_script_run_handler(Policy.empty(), base)(
        {"interpreter": "bash", "content": "true", "timeout": 5, "sudo": True})
    assert seen.get("elevated") is True
    seen.clear()
    await S.make_script_run_handler(Policy.empty(), base)(
        {"interpreter": "bash", "content": "true", "timeout": 5})
    assert seen.get("elevated") is False
