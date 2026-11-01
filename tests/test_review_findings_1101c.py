"""Finding of sx-review on 0.23.54 (agent 0.23.55): a cancel that arrived while
run_process waited for the kill of its own timeout lost left_running."""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

from sentinelx_core import executor_engine as EE

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")


@posix
async def test_a_budget_expiring_during_the_timeout_kill_keeps_left_running(tmp_path, monkeypatch):
    monkeypatch.setattr(EE, "STOP_GRACE_SECONDS", 3.0)
    pid = tmp_path / "pid"
    cmd = f"(setsid sh -c 'echo $$ > {pid}; sleep 12' &); sleep 30"
    try:
        with pytest.raises(asyncio.TimeoutError) as e:
            # own timeout at 1 s, then up to 3 s waiting for the kill; the budget ends at 2 s
            await asyncio.wait_for(EE.run_process(["bash", "-c", cmd], timeout=1), 2)
        assert EE.left_running_from(e.value), "the cancel during the kill wait lost left_running"
    finally:
        try:
            os.killpg(int(pid.read_text().strip()), 9)
        except (OSError, ValueError):
            pass


def test_the_agent_uses_protocol_1_13_4_or_later():
    import sentinelx_protocol as p
    assert tuple(int(x) for x in p.PROTOCOL_VERSION.split(".")) >= (1, 13, 4)
