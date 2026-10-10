"""What a process wrote before its timeout comes back with the timeout (sxrep_AY8JPBQKSAXR).

exec, the service ops and script_run ran communicate() inside wait_for(), so on
a timeout everything already written was thrown away and only "Timeout" came
back, even from a script that flushed its progress precisely to leave a trace.
"""

from __future__ import annotations

import sys
import time

import pytest

from sentinelx_core.executor_engine import run_shell, run_shell_split
from sentinelx_core.handlers.script import make_script_run_handler
from sentinelx_core.policy import Policy

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell commands")

SLOW = "printf 'step1\\n'; echo err1 >&2; sleep 5"


async def test_exec_returns_the_partial_output_with_the_timeout():
    t0 = time.time()
    r = await run_shell(SLOW, timeout=1)
    assert r["timed_out"] is True and r["returncode"] == -1
    assert r["output"].startswith("⏱️ Timeout. Output written before the timeout:")
    assert "step1" in r["output"] and "err1" in r["output"]
    assert time.time() - t0 < 4          # still stops at the timeout


async def test_without_output_the_timeout_text_is_unchanged():
    r = await run_shell("sleep 5", timeout=1)
    assert r["output"] == "⏱️ Timeout" and r["timed_out"] is True


async def test_service_ops_keep_both_streams_and_say_they_timed_out():
    r = await run_shell_split(SLOW, timeout=1)
    assert r["timed_out"] is True and r["returncode"] == -1
    assert r["stdout"] == "step1"
    assert r["stderr"].startswith("⏱️ Timeout") and "err1" in r["stderr"]


async def test_a_command_that_finishes_is_unaffected():
    r = await run_shell("printf 'a\\n'; echo b >&2", timeout=5)
    assert "timed_out" not in r and r["returncode"] == 0
    assert "a" in r["output"] and "b" in r["output"]


@pytest.fixture
def script(tmp_path):
    return make_script_run_handler(Policy.empty(), tmp_path / "uploads")


async def test_script_run_returns_the_flushed_progress(script):
    r = await script({
        "interpreter": "python3",
        "content": "import time\nprint('reached step 1', flush=True)\ntime.sleep(5)\n",
        "timeout": 1,
    })
    assert r["timed_out"] is True and "reached step 1" in r["output"]
    assert r["output"].startswith("⏱️ Timeout")
