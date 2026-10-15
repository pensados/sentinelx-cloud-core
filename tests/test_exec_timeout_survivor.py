"""A command's time limit holds even when something it started can't be stopped.

sxrep_64T9VXZEVC61: exec with a 300 s limit ran `sudo python3 bridge.py`. At 300 s the
agent killed the shell, but bridge.py ran as root, so the unprivileged agent couldn't
signal it, and it still held the shell's stdout. asyncio's proc.wait() also waits for
the pipes to close, so the call came back only when bridge.py exited on its own, at
900 s. Here a grandchild in its own session (setsid) stands in for the root process:
the group kill doesn't reach it, and it keeps stdout open.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time

import pytest

from sentinelx_core import executor_engine as ee

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not shutil.which("setsid"), reason="POSIX setsid needed"
)

SURVIVOR = "setsid sleep 25.31 & echo started; sleep 100"


@pytest.fixture(autouse=True)
def _reap_survivor():
    yield
    subprocess.run(["pkill", "-f", "sleep 25.31"], check=False)


def _bound():
    return 1 + ee.STOP_GRACE_SECONDS + 3


async def test_run_shell_returns_on_time_and_says_something_is_still_running():
    t0 = time.monotonic()
    r = await ee.run_shell(SURVIVOR, timeout=1)
    assert time.monotonic() - t0 < _bound()
    assert r["timed_out"] and r["returncode"] == -1 and r.get("left_running") is True
    assert r["output"].startswith("⏱️ Timeout") and "started" in r["output"]
    assert ee.LEFT_RUNNING_NOTE in r["output"]


async def test_run_shell_split_returns_on_time_too():
    t0 = time.monotonic()
    r = await ee.run_shell_split(SURVIVOR, timeout=1)
    assert time.monotonic() - t0 < _bound()
    assert r["timed_out"] and r.get("left_running") is True and "started" in r["stdout"]
    assert ee.LEFT_RUNNING_NOTE in r["stderr"]


async def test_an_ordinary_timeout_has_no_note():
    t0 = time.monotonic()
    r = await ee.run_shell("echo started; sleep 100", timeout=1)
    assert time.monotonic() - t0 < 4
    assert r["timed_out"] and "left_running" not in r and ee.LEFT_RUNNING_NOTE not in r["output"]
