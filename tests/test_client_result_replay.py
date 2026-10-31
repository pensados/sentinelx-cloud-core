"""The client's own replay path, not just the storage under it.

test_pending_results covers the file layer. This drives the two places in the
client that use it: the emit path that records before sending and clears after,
and the reconnect path that re-sends what is left. Those are where the loss
actually happened, so they are what has to be exercised.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


from sentinelx_core import pending_results as pr
from sentinelx_core.client import HubClient

EVENT = {"kind": "job_completed", "data": {"job_id": "job_abc", "status": "failed"}}


def _client(tmp_path: Path) -> HubClient:
    """A client with only the pieces the replay path touches."""
    c = HubClient.__new__(HubClient)
    up = tmp_path / "uploads"
    up.mkdir()
    ex = MagicMock()
    ex.upload_base = up
    c._executor = ex
    return c


async def test_a_held_result_is_sent_on_the_next_connection(tmp_path):
    c = _client(tmp_path)
    pr.record(c._executor.upload_base, "job_abc", EVENT)

    ws = AsyncMock()
    await c._replay_pending_results(ws)

    ws.send.assert_awaited_once()
    assert json.loads(ws.send.await_args[0][0]) == EVENT


async def test_a_replayed_result_is_not_sent_twice(tmp_path):
    c = _client(tmp_path)
    pr.record(c._executor.upload_base, "job_abc", EVENT)

    await c._replay_pending_results(AsyncMock())
    second = AsyncMock()
    await c._replay_pending_results(second)

    second.send.assert_not_awaited()


async def test_nothing_held_sends_nothing(tmp_path):
    ws = AsyncMock()
    await _client(tmp_path)._replay_pending_results(ws)
    ws.send.assert_not_awaited()


async def test_a_failed_replay_keeps_the_result_for_later(tmp_path):
    """The socket died again; the answer must not be dropped with it."""
    c = _client(tmp_path)
    pr.record(c._executor.upload_base, "job_abc", EVENT)

    failing = AsyncMock()
    failing.send.side_effect = ConnectionError("gone")
    await c._replay_pending_results(failing)

    assert len(list(pr.drain(c._executor.upload_base))) == 1


async def test_a_failed_replay_does_not_raise_into_the_session(tmp_path):
    """A replay problem must never stop a connection from being established."""
    c = _client(tmp_path)
    pr.record(c._executor.upload_base, "job_abc", EVENT)
    failing = AsyncMock()
    failing.send.side_effect = ConnectionError("gone")
    await c._replay_pending_results(failing)  # must not raise


async def test_replay_stops_at_the_first_failure(tmp_path):
    """No point hammering a socket that just refused; keep the rest."""
    c = _client(tmp_path)
    for i in range(4):
        pr.record(c._executor.upload_base, f"job_{i}", EVENT)

    ws = AsyncMock()
    ws.send.side_effect = ConnectionError("gone")
    await c._replay_pending_results(ws)

    assert ws.send.await_count == 1
    assert len(list(pr.drain(c._executor.upload_base))) == 4


async def test_several_held_results_are_all_delivered(tmp_path):
    c = _client(tmp_path)
    for i in range(3):
        pr.record(c._executor.upload_base, f"job_{i}", EVENT)

    ws = AsyncMock()
    await c._replay_pending_results(ws)

    assert ws.send.await_count == 3
    assert list(pr.drain(c._executor.upload_base)) == []


async def test_an_unreadable_store_does_not_break_connecting(tmp_path):
    c = _client(tmp_path)
    c._executor.upload_base = Path("/proc/nonexistent/deep")
    ws = AsyncMock()
    await c._replay_pending_results(ws)  # must not raise
    ws.send.assert_not_awaited()


# --- the emit path: recording happens BEFORE the send is attempted -----------
# Sabotage found this gap: deleting the record() call from _run_job_and_report
# left every test above passing, because they all start from an already-written
# file. The write is the half that matters -- without it there is nothing to
# replay.


def _emit_client(tmp_path: Path, dispatch_result=None) -> HubClient:
    c = _client(tmp_path)
    c._executor.dispatch = AsyncMock(
        return_value=dispatch_result or {"ok": False, "exit_code": 1, "output": "x"}
    )
    ident = MagicMock()
    ident.host_id = "host_test"
    c._identity = ident
    return c


def _request():
    r = MagicMock()
    r.id = "req_1"
    r.op = "exec"
    r.payload = {"background": True, "job_id": "job_emit"}
    return r


async def test_a_result_survives_a_send_that_fails(tmp_path):
    """The exact reported loss: work finishes, socket is gone, answer kept."""
    from datetime import datetime, timezone

    c = _emit_client(tmp_path)
    ws = AsyncMock()
    ws.send.side_effect = ConnectionError("socket gone")

    await c._run_job_and_report(ws, _request(), "job_emit", datetime.now(timezone.utc))

    held = list(pr.drain(c._executor.upload_base))
    assert len(held) == 1, "a result whose send failed must remain on disk"
    assert held[0][1]["data"]["job_id"] == "job_emit"


async def test_a_delivered_result_is_not_kept(tmp_path):
    """The common case must not leave litter behind to be re-sent forever."""
    from datetime import datetime, timezone

    c = _emit_client(tmp_path)
    ws = AsyncMock()

    await c._run_job_and_report(ws, _request(), "job_emit", datetime.now(timezone.utc))

    ws.send.assert_awaited_once()
    assert list(pr.drain(c._executor.upload_base)) == []


async def test_the_held_result_is_the_one_that_gets_replayed(tmp_path):
    """End to end: send fails, next connection carries the same answer."""
    from datetime import datetime, timezone

    c = _emit_client(tmp_path)
    dead = AsyncMock()
    dead.send.side_effect = ConnectionError("socket gone")
    await c._run_job_and_report(dead, _request(), "job_emit", datetime.now(timezone.utc))

    fresh = AsyncMock()
    await c._replay_pending_results(fresh)

    fresh.send.assert_awaited_once()
    sent = json.loads(fresh.send.await_args[0][0])
    assert sent["kind"] == "job_completed"
    assert sent["data"]["job_id"] == "job_emit"
