"""Issue #31: local audit I/O must not scale with the whole JSONL file.

Two costs, both O(file size) and both paid on routine operations:

  * every audited write rescanned the entire log to count lines before
    deciding whether retention should trim it;
  * read_audit(limit=N) loaded the whole log with readlines() and sliced
    the tail afterwards — synchronously, on the event loop.

With full payloads retained for 5000 entries, that file is measured in
megabytes. These tests pin the repaired behaviour: a bounded retention
cadence, a bounded tail read, and unchanged retention/read semantics.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path

import pytest

from sentinelx_core import local_audit
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy
from tests.loop_probe import run_with_loop_probe


@pytest.fixture(autouse=True)
def _audit_in_tmp(tmp_path: Path, monkeypatch):
    """Point the audit at a temp file and forget the write cadence."""
    monkeypatch.setattr(local_audit, "AUDIT_PATH", tmp_path / "audit.jsonl")
    local_audit._reset_retention_state()
    yield
    local_audit._reset_retention_state()


def _write_entries(path: Path, count: int, payload: str = "x") -> None:
    with path.open("w", encoding="utf-8") as f:
        for i in range(count):
            f.write(json.dumps({"op": "exec", "n": i, "payload": payload}) + "\n")


# ---------------------------------------------------------------------------
# Repair A — retention is checked at a bounded cadence
# ---------------------------------------------------------------------------


def test_retention_is_checked_on_first_write_then_periodically(monkeypatch):
    """Once per process start, then once every RETENTION_CHECK_EVERY writes —
    not on every single audited op."""
    monkeypatch.setattr(local_audit, "RETENTION_CHECK_EVERY", 100)
    calls = []
    monkeypatch.setattr(local_audit, "_maybe_trim", lambda: calls.append(1))

    for _ in range(250):
        local_audit.record("exec", {"command": "ls"}, ok=True)

    # write 1 (process start), write 101, write 201.
    assert len(calls) == 3


def test_oversized_pre_existing_log_is_repaired_on_the_first_write(monkeypatch):
    """A log left oversized by an earlier run must not wait for the cadence."""
    monkeypatch.setattr(local_audit, "MAX_LINES", 50)
    monkeypatch.setattr(local_audit, "TRIM_TRIGGER", 60)
    monkeypatch.setattr(local_audit, "RETENTION_CHECK_EVERY", 100)
    _write_entries(local_audit.AUDIT_PATH, 200)

    local_audit.record("exec", {"command": "ls"}, ok=True)

    lines = local_audit.AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 50


def test_overshoot_between_checks_is_bounded(monkeypatch):
    """Between checks the log may drift past the trigger, but only by the
    cadence — the existing hysteresis is otherwise untouched."""
    monkeypatch.setattr(local_audit, "MAX_LINES", 50)
    monkeypatch.setattr(local_audit, "TRIM_TRIGGER", 60)
    monkeypatch.setattr(local_audit, "RETENTION_CHECK_EVERY", 10)

    for _ in range(120):
        local_audit.record("exec", {"command": "ls"}, ok=True)
        count = len(local_audit.AUDIT_PATH.read_text(encoding="utf-8").splitlines())
        assert count <= 60 + 10


def test_external_truncation_is_tolerated(monkeypatch):
    """Rotation/truncation by something else must not confuse the cadence —
    which is exactly why the count is never cached to disk."""
    monkeypatch.setattr(local_audit, "RETENTION_CHECK_EVERY", 5)
    for _ in range(7):
        local_audit.record("exec", {"command": "ls"}, ok=True)

    local_audit.AUDIT_PATH.unlink()
    local_audit.record("exec", {"command": "ls"}, ok=True)

    assert len(local_audit.read_recent(limit=10)) == 1


# ---------------------------------------------------------------------------
# Repair B — the tail read is bounded
# ---------------------------------------------------------------------------


def test_read_recent_returns_the_newest_physical_lines_newest_first():
    _write_entries(local_audit.AUDIT_PATH, 500)

    entries = local_audit.read_recent(limit=50)

    assert len(entries) == 50
    assert [e["n"] for e in entries] == list(range(499, 449, -1))


def test_read_recent_skips_a_malformed_newest_line_without_backfilling():
    """Historical semantics: inspect the newest N physical lines and skip
    what does not parse — do NOT reach further back for a replacement."""
    _write_entries(local_audit.AUDIT_PATH, 3)
    with local_audit.AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write("{ this is not json\n")

    entries = local_audit.read_recent(limit=3)

    assert [e["n"] for e in entries] == [2, 1]


def test_read_recent_handles_a_record_larger_than_one_block(monkeypatch):
    monkeypatch.setattr(local_audit, "_TAIL_BLOCK_SIZE", 512)
    _write_entries(local_audit.AUDIT_PATH, 5)
    big = "z" * 4096
    with local_audit.AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"op": "exec", "n": 99, "payload": big}) + "\n")

    entries = local_audit.read_recent(limit=2)

    assert [e["n"] for e in entries] == [99, 4]
    assert entries[0]["payload"] == big


def test_small_read_does_not_load_the_whole_log():
    """The point of the fix: a 50-entry request must not allocate the file."""
    _write_entries(local_audit.AUDIT_PATH, 4000, payload="p" * 2048)
    size = local_audit.AUDIT_PATH.stat().st_size
    assert size > 8_000_000, "fixture should be big enough to matter"

    tracemalloc.start()
    try:
        entries = local_audit.read_recent(limit=50)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(entries) == 50
    assert peak < size // 4, f"peak {peak} bytes for a 50-entry tail read"


def test_read_recent_on_a_missing_log_is_empty():
    assert local_audit.read_recent(limit=10) == []


# ---------------------------------------------------------------------------
# read_audit does its disk work off the event loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_audit_does_not_block_event_loop(monkeypatch):
    def slow_read_recent(limit: int = 200):
        time.sleep(0.25)
        return [{"op": "exec"}]

    monkeypatch.setattr(local_audit, "read_recent", slow_read_recent)
    handlers = build_registry(policy=Policy.empty())

    result, max_gap = await run_with_loop_probe(handlers["read_audit"]({"limit": 5}))

    assert result["count"] == 1
    assert max_gap < 0.10, f"event loop stalled for {max_gap:.3f}s during read_audit"
