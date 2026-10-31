"""exec timeout/cancellation must not leak descendants from bash -lc."""

from __future__ import annotations

import asyncio
import shlex
import subprocess
import sys
import time

import pytest

from sentinelx_core.executor_engine import run_shell, run_shell_split

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


def _group_members(pgid: int) -> list[str]:
    out = subprocess.run(
        ["ps", "-eo", "pgid=,stat=,pid=,comm="], capture_output=True, text=True, check=True
    ).stdout
    members = []
    for line in out.splitlines():
        fields = line.split()
        if fields and fields[0] == str(pgid) and not fields[1].startswith("Z"):
            members.append(line.strip())
    return members


def _wait_group_gone(pgid: int, timeout: float = 3.0) -> list[str]:
    deadline = time.monotonic() + timeout
    members = _group_members(pgid)
    while members and time.monotonic() < deadline:
        time.sleep(0.05)
        members = _group_members(pgid)
    return members


def _tree_command(pidfile) -> str:
    return (
        f"printf '%s' \"$$\" > {shlex.quote(str(pidfile))}; "
        "sleep 30 & sleep 30"
    )


@pytest.mark.parametrize("runner", [run_shell, run_shell_split])
async def test_exec_timeout_kills_the_whole_shell_process_group(tmp_path, runner):
    pidfile = tmp_path / "pgid"
    # 2 s, not 0.25: on a slow CI runner the shell sometimes hadn't written the
    # pidfile before the timeout, and reading it failed (CI 2026-10-26, -29).
    result = await runner(_tree_command(pidfile), timeout=2)

    assert result.get("returncode") == -1
    pgid = int(pidfile.read_text())
    assert _wait_group_gone(pgid) == []


async def test_exec_cancellation_kills_the_whole_shell_process_group(tmp_path):
    pidfile = tmp_path / "pgid"
    task = asyncio.create_task(run_shell(_tree_command(pidfile), timeout=30))

    deadline = time.monotonic() + 3
    while not pidfile.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert pidfile.exists(), "shell did not start"
    pgid = int(pidfile.read_text())
    assert _group_members(pgid), "fixture should have a live process group"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert _wait_group_gone(pgid) == []


# --- the actual children, not the process group --------------------------------
# The tests above look up the shell's PID as a process group. Without the fix
# no such group exists, so they pass against the old code too. These follow the
# children's real PIDs and fail without the fix, in both of the defect's forms.

def _alive(pid: int) -> bool:
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return bool(out.strip()) and not out.strip().startswith("Z")


async def test_children_that_detach_from_output_do_not_survive_a_timeout(tmp_path):
    # The production case: a child that doesn't hold the pipes. The call
    # returned on time, and the child kept running, reparented to PID 1.
    pids = tmp_path / "pids"
    q = shlex.quote(str(pids))
    cmd = f"sleep 60 >/dev/null 2>&1 & echo $! >> {q}; sleep 60 >/dev/null 2>&1 & echo $! >> {q}; wait"
    result = await run_shell(cmd, timeout=0.5)
    assert result.get("returncode") == -1
    time.sleep(0.5)
    survivors = [p for p in map(int, pids.read_text().split()) if _alive(p)]
    for p in survivors:  # don't leave them behind if this ever regresses
        subprocess.run(["kill", "-9", str(p)], check=False)
    assert survivors == []


async def test_the_timeout_holds_when_children_keep_the_pipes():
    # The second form: children holding the output pipes kept the old code
    # waiting until they exited on their own (a 0.5 s timeout returned after 20 s).
    started = time.monotonic()
    result = await run_shell("sleep 20 & sleep 20 & wait", timeout=0.5)
    assert result.get("returncode") == -1
    assert time.monotonic() - started < 5


def test_windows_tree_kill_opens_no_console_window(monkeypatch):
    from types import SimpleNamespace

    from sentinelx_core import executor_engine as E
    from sentinelx_core.winspawn import CREATE_NO_WINDOW

    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw, argv=argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(E.subprocess, "run", fake_run)
    E._kill_process_tree(SimpleNamespace(pid=4321, kill=lambda: None))
    assert seen["argv"][:3] == ["taskkill", "/T", "/F"]
    assert seen["creationflags"] & CREATE_NO_WINDOW
