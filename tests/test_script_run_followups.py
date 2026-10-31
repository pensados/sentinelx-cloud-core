"""Jan's follow-ups on 0.23.36 (agent 0.23.38).

sxrep_E7RCC1FKQC7P  a setsid descendant survived cancellation; a second cancel
                    interrupted the cleanup
sxrep_5CE1B15G691J  the env-file cleanup could raise over the result and leave the
                    secret behind
sxrep_69N1GEHNAN1K  an invalid sudo env name, checked after staging, left an
                    undiscoverable workdir with cleanup=false
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import script as S
from sentinelx_core.policy import Policy

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")
linux_setsid = pytest.mark.skipif(not sys.platform.startswith("linux") or shutil.which("setsid") is None,
                                  reason="needs Linux /proc and setsid")


def _handler(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    return S.make_script_run_handler(Policy.empty(), base), base


def _fake_sudo(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sudo = bindir / "sudo"
    sudo.write_text('#!/bin/sh\nexec env -i PATH="$PATH" "$@"\n')
    sudo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


async def _cancel_after(task, *delays):
    for d in delays:
        await asyncio.sleep(d)
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@linux_setsid
async def test_cancelling_script_run_kills_a_descendant_that_escaped_with_setsid(tmp_path):
    h, _ = _handler(tmp_path)
    marker = tmp_path / "marker"
    task = asyncio.create_task(h({"interpreter": "bash", "timeout": 20,
                                  "content": f"setsid sh -c 'sleep 2; printf survived > {marker}' & sleep 30"}))
    await _cancel_after(task, 0.35)
    await asyncio.sleep(2.5)
    assert not marker.exists(), "the escaped descendant kept running"


@linux_setsid
async def test_a_second_cancel_still_leaves_nothing_running(tmp_path):
    h, _ = _handler(tmp_path)
    marker = tmp_path / "marker"
    task = asyncio.create_task(h({"interpreter": "bash", "timeout": 20,
                                  "content": f"setsid sh -c 'sleep 2; printf survived > {marker}' & sleep 30"}))
    await _cancel_after(task, 0.35, 0.2)
    await asyncio.sleep(2.5)
    assert not marker.exists()


@linux_setsid
async def test_cancelling_exec_kills_a_descendant_that_escaped_with_setsid(tmp_path):
    marker = tmp_path / "marker"
    task = asyncio.create_task(EE.run_shell(f"setsid sh -c 'sleep 2; printf survived > {marker}' & sleep 30", timeout=20))
    await _cancel_after(task, 0.35)
    await asyncio.sleep(2.5)
    assert not marker.exists()


async def test_finish_cleanup_survives_repeated_cancellation():
    done = asyncio.Event()

    async def cleanup():
        await asyncio.sleep(0.3)
        done.set()

    async def cancelled_caller():
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await EE.finish_cleanup(cleanup())
            raise

    task = asyncio.create_task(cancelled_caller())
    await _cancel_after(task, 0.05, 0.05, 0.05)
    assert done.is_set(), "the cleanup was cut short by the second cancel"


@posix
async def test_a_script_that_locks_its_workdir_keeps_its_result_and_leaves_no_secret(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch)
    h, base = _handler(tmp_path)
    res = await h({"interpreter": "bash", "sudo": True, "timeout": 10, "env": {"SECRET_PROBE": "secret-value"},
                   "content": 'chmod 000 "$(dirname "$0")"; printf done'})
    assert res["ok"] and res["output"] == "done", res
    for d in base.rglob("*"):
        if d.is_dir():
            os.chmod(d, 0o700)
    leftovers = [p for p in base.rglob("sentinelx_env.sh")]
    assert not leftovers, leftovers


@posix
async def test_an_invalid_sudo_env_name_stages_nothing(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch)
    h, base = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "sudo": True, "cleanup": False, "timeout": 5,
                 "env": {"BAD-NAME": "x"}, "content": "true"})
    assert e.value.code == "invalid_payload"
    assert not list(base.rglob("script_job_*")), "a workdir was created before validation"


@posix
async def test_every_failure_after_staging_says_where_a_kept_workdir_is(tmp_path):
    h, _ = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "cleanup": False, "timeout": 5,
                 "cwd": str(tmp_path / "does-not-exist"), "content": "true"})
    assert e.value.code == "not_found"
    assert Path(e.value.details["workdir"]).is_dir() and Path(e.value.details["script_path"]).is_file()


@linux_setsid
async def test_a_timeout_kills_a_setsid_descendant_still_in_the_tree(tmp_path):
    h, _ = _handler(tmp_path)
    marker = tmp_path / "marker"
    res = await h({"interpreter": "bash", "timeout": 1,
                   "content": f"setsid sh -c 'sleep 2; printf survived > {marker}' & sleep 30"})
    assert res["timed_out"] and "left_running" not in res, res
    await asyncio.sleep(2.5)
    assert not marker.exists(), "the escaped descendant outlived the timeout"
