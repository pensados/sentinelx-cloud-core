"""left_running survives Python 3.14's Process.wait() (agent 0.23.37, sxrep_9GWKAWPTXZWM).

On 3.12 Process.wait() also waits for the pipes; on 3.14 it returns when the process
exits. A descendant that escaped the group and still held stdout was then missed by
both exec and script_run. Runs on whatever Python the suite runs on (CI: 3.12 and 3.14).
"""
from __future__ import annotations

import os
import shutil
import signal
import sys
import time

import pytest

from sentinelx_core import executor_engine as EE

pytestmark = [
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups"),
    pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid"),
]


async def test_exec_reports_a_descendant_that_escaped_and_holds_the_pipes(tmp_path, monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 1.0)
    pidfile = tmp_path / "escaped.pid"
    t0 = time.monotonic()
    res = await EE.run_shell(f"setsid sh -c 'echo $$ > {pidfile}; sleep 8' & sleep 30", timeout=1)
    elapsed = time.monotonic() - t0
    try:
        assert res.get("timed_out") and res.get("left_running") is True, res
        assert elapsed < 5, f"took {elapsed:.1f}s"
    finally:
        try:
            os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


async def test_a_normal_timeout_is_not_reported_as_left_running(tmp_path):
    res = await EE.run_shell("sleep 30", timeout=1)
    assert res.get("timed_out") and "left_running" not in res, res
