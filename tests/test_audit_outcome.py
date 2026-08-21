"""Issue #30: a failed child must not be audited as a plain success.

`ok` in the local audit has always meant "the handler returned without
raising" — dispatch-level completion. But `script_run` reports a failed
child as a perfectly normal result, {"ok": false, "returncode": 7}, so the
caller saw a failed script while `read_audit` showed the same operation as
ok=true with nothing to indicate otherwise.

The repair is additive on purpose: `ok` keeps its meaning, and the nested
outcome travels in optional `result_ok` / `result_returncode` fields. These
tests pin all four acceptance criteria, including the two negative ones —
old entries stay readable, and no result body leaks into the log.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sentinelx_protocol import RequestMessage

from sentinelx_core import local_audit
from sentinelx_core.executor import Executor, HandlerError


@pytest.fixture(autouse=True)
def _audit_in_tmp(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(local_audit, "AUDIT_PATH", tmp_path / "audit.jsonl")
    local_audit._reset_retention_state()
    yield
    local_audit._reset_retention_state()


def _executor_returning(result, monkeypatch, op: str = "script_run") -> Executor:
    """An Executor whose only handler hands back `result` (or raises it)."""

    async def fake_handler(payload):
        if isinstance(result, Exception):
            raise result
        return result

    ex = Executor(config_path=Path("/nonexistent/config.yaml"))
    monkeypatch.setattr(ex, "_get_handlers", lambda: {op: fake_handler})
    return ex


def _entries() -> list[dict]:
    raw = local_audit.AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in raw if line.strip()]


async def _dispatch(ex: Executor, op: str = "script_run", payload=None):
    return await ex.dispatch(
        RequestMessage(id="req-1", op=op, payload=payload or {"script": "x.sh"})
    )


@pytest.mark.asyncio
async def test_failed_child_is_distinguishable_in_the_audit(monkeypatch):
    """The reproduction: a harmless child exits 7."""
    ex = _executor_returning({"ok": False, "returncode": 7}, monkeypatch)

    response = await _dispatch(ex)

    assert response["ok"] is True  # dispatch succeeded; the child did not
    entry = _entries()[0]
    assert entry["op"] == "script_run"
    assert entry["ok"] is True, "historical meaning of ok must not change"
    assert entry["result_ok"] is False
    assert entry["result_returncode"] == 7


@pytest.mark.asyncio
async def test_successful_child_records_its_outcome_too(monkeypatch):
    ex = _executor_returning({"ok": True, "returncode": 0}, monkeypatch)

    await _dispatch(ex)

    entry = _entries()[0]
    assert entry["ok"] is True
    assert entry["result_ok"] is True
    assert entry["result_returncode"] == 0


@pytest.mark.asyncio
async def test_dispatch_failure_stays_distinct_from_a_failed_child(monkeypatch):
    """Acceptance #1: three outcomes, three shapes."""
    ex = _executor_returning(
        HandlerError("script_not_allowed", "nope"), monkeypatch
    )

    response = await _dispatch(ex)

    assert response["ok"] is False
    entry = _entries()[0]
    assert entry["ok"] is False
    assert entry["error"]
    assert "result_ok" not in entry
    assert "result_returncode" not in entry


@pytest.mark.asyncio
async def test_no_result_body_reaches_the_audit(monkeypatch):
    """Acceptance #3: only the two scalars are lifted."""
    ex = _executor_returning(
        {
            "ok": False,
            "returncode": 7,
            "stdout": "SENSITIVE-STDOUT",
            "stderr": "SENSITIVE-STDERR",
            "artifacts": ["/tmp/whatever"],
        },
        monkeypatch,
    )

    await _dispatch(ex)

    line = local_audit.AUDIT_PATH.read_text(encoding="utf-8")
    assert "SENSITIVE-STDOUT" not in line
    assert "SENSITIVE-STDERR" not in line
    entry = _entries()[0]
    assert set(entry) == {
        "timestamp", "op", "payload", "ok", "error", "duration_ms",
        "result_ok", "result_returncode",
    }


@pytest.mark.asyncio
async def test_results_without_a_nested_outcome_add_no_fields(monkeypatch):
    """A read/list result has no child, so nothing is invented for it."""
    ex = _executor_returning(
        {"path": "/etc/hosts", "content": "x"}, monkeypatch, op="read"
    )

    await _dispatch(ex, op="read", payload={"path": "/etc/hosts"})

    entry = _entries()[0]
    assert "result_ok" not in entry
    assert "result_returncode" not in entry


@pytest.mark.asyncio
async def test_a_bool_is_not_mistaken_for_a_returncode(monkeypatch):
    """bool is an int in Python; it must not land in result_returncode."""
    ex = _executor_returning({"ok": True, "returncode": True}, monkeypatch)

    await _dispatch(ex)

    entry = _entries()[0]
    assert entry["result_ok"] is True
    assert "result_returncode" not in entry


def test_legacy_entries_without_the_new_fields_stay_readable():
    """Acceptance #4: nothing about the old shape is required."""
    legacy = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "op": "script_run",
        "payload": {"script": "old.sh"},
        "ok": True,
        "error": None,
        "duration_ms": 12,
    }
    local_audit.AUDIT_PATH.write_text(
        json.dumps(legacy) + "\n", encoding="utf-8"
    )

    entries = local_audit.read_recent(limit=10)

    assert len(entries) == 1
    assert entries[0]["op"] == "script_run"
    assert "result_ok" not in entries[0]
