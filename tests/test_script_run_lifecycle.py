"""script_run process lifecycle (agent 0.23.36), from Jan's reports of 2026-10-30.

sxrep_E7RCC1FKQC7P  a cancelled script kept running after the handler returned
sxrep_9GWKAWPTXZWM  a timeout waited for a descendant that escaped the group
sxrep_5CE1B15G691J  payload.env silently dropped with sudo=true
sxrep_69N1GEHNAN1K  cleanup=false kept workdirs without saying where; a missing
                    interpreter escaped as a raw FileNotFoundError
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import script as S
from sentinelx_core.policy import Policy

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups and sudo")


def _handler(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    return S.make_script_run_handler(Policy.empty(), base), base


def _fake_sudo(tmp_path, monkeypatch):
    """A sudo that, like the real one, starts the command with a reset environment."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sudo = bindir / "sudo"
    sudo.write_text('#!/bin/sh\nexec env -i PATH="$PATH" "$@"\n')
    sudo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


async def test_cancelling_a_script_run_stops_the_script(tmp_path):
    h, _ = _handler(tmp_path)
    marker = tmp_path / "marker"
    task = asyncio.create_task(h({"interpreter": "bash", "timeout": 20,
                                  "content": f"sleep 2; printf survived > {marker}"}))
    await asyncio.sleep(0.35)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(2.5)
    assert not marker.exists(), "the cancelled script kept running"


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid")
async def test_a_timeout_does_not_wait_for_an_escaped_descendant(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "STOP_GRACE_SECONDS", 1.0)
    h, _ = _handler(tmp_path)
    pidfile = tmp_path / "escaped.pid"
    t0 = time.monotonic()
    res = await h({"interpreter": "bash", "timeout": 1,
                   # An ORPHAN: the subshell exits at once, so the setsid'd process is
                   # reparented out of our tree and can't be found or killed (0.23.38
                   # kills escaped descendants still in the tree). It holds the pipes:
                   # that is what left_running is for.
                   "content": f"(setsid sh -c 'echo $$ > {pidfile}; sleep 8' &); sleep 30"})
    elapsed = time.monotonic() - t0
    try:
        assert res["timed_out"] and res.get("left_running") is True, res
        assert elapsed < 5, f"took {elapsed:.1f}s"
    finally:
        try:
            os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


async def test_env_reaches_a_script_run_with_sudo_and_never_the_command_line(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch)
    h, base = _handler(tmp_path)
    value = "a b $HOME 'single' \"double\" ;rm -rf x\nsecond line"
    wd = tmp_path / "wd"
    wd.mkdir()
    res = await h({"interpreter": "bash", "sudo": True, "cwd": str(wd), "timeout": 10,
                   "env": {"SENTINELX_ENV_PROBE": value},
                   "content": 'printf "%s|%s" "$SENTINELX_ENV_PROBE" "$(pwd -P)"'})
    assert res["ok"], res
    assert res["output"] == f"{value}|{os.path.realpath(wd)}"
    assert value not in " ".join(res["command"])
    assert not list(base.rglob("sentinelx_env.sh")), "the env file was left behind"


async def test_the_env_file_goes_even_when_cleanup_false_keeps_the_rest(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch)
    h, _ = _handler(tmp_path)
    res = await h({"interpreter": "bash", "sudo": True, "cleanup": False, "timeout": 10,
                   "env": {"TOKEN": "s3cret"}, "content": 'printf "%s" "$TOKEN"'})
    assert res["ok"] and res["output"] == "s3cret", res
    assert Path(res["script_path"]).is_file()
    assert not (Path(res["workdir"]) / "sentinelx_env.sh").exists()


async def test_env_names_with_sudo_must_be_shell_identifiers(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch)
    h, _ = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "sudo": True, "timeout": 5, "env": {"BAD-NAME": "x"}, "content": "true"})
    assert e.value.code == "invalid_payload" and "BAD-NAME" in str(e.value)


async def test_a_missing_interpreter_is_named_and_the_kept_workdir_returned(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(S.shutil, "which", lambda *a, **k: None)
    h, base = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "powershell", "content": "Write-Output x", "cleanup": False, "timeout": 5})
    assert e.value.code == "interpreter_missing"
    assert Path(e.value.details["workdir"]).is_dir()
    with pytest.raises(HandlerError) as e2:
        await h({"interpreter": "powershell", "content": "Write-Output x", "timeout": 5})
    assert e2.value.code == "interpreter_missing" and "workdir" not in e2.value.details


async def test_a_timed_out_script_kept_with_cleanup_false_returns_its_paths(tmp_path):
    h, _ = _handler(tmp_path)
    res = await h({"interpreter": "bash", "content": "sleep 5", "cleanup": False, "timeout": 1})
    assert res["timed_out"] and Path(res["workdir"]).is_dir() and Path(res["script_path"]).is_file()
