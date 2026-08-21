"""On-host audit log: append each executed op (with payload) to a local JSONL file.

This is the host-side counterpart to the hub's metadata ring buffer. Unlike the
hub — which deliberately stores only metadata (op, host, time, status) and never
the payload — this log keeps the full payload of each operation, on the host
itself. It is the only place the actual command/script/content is retained, it
never leaves the host except in response to a `read_audit` op, and it is the host
owner's own record.

Format: JSON Lines (one JSON object per line), append-only, at AUDIT_PATH.
Retention: capped at MAX_LINES; when exceeded, the file is trimmed to the most
recent MAX_LINES entries. Per-host, so this is far more history than the hub's
shared buffer holds for any one user.

Design constraints:
- Writing must NEVER break the operation being audited. Every failure here is
  swallowed (best-effort) — a broken log is not worth failing a real op over.
- No redaction: entries are stored as-is. The payload may contain secrets the
  user themselves passed; that is their record on their own machine.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default location, resolved cross-platform. An explicit SENTINELX_AUDIT_PATH
# always wins (installers set it per mode). Otherwise: on Linux, /var/lib is the
# canonical home for variable application state and is owned by the agent user;
# on macOS there is no /var/lib, so fall back to the user's Library/Logs, which
# is writable for user-mode installs. System-mode (LaunchDaemon) installs point
# SENTINELX_AUDIT_PATH at a path their service user owns.
def _default_audit_path() -> Path:
    override = os.environ.get("SENTINELX_AUDIT_PATH")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "SentinelX" / "audit.jsonl"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "sentinelx" / "audit.jsonl"
    return Path("/var/lib/sentinelx/audit.jsonl")


AUDIT_PATH = _default_audit_path()

# Retention: keep the most recent N entries. Matches the hub ring buffer size
# for conceptual consistency, but because this is per-host it represents far
# more real history than 5000 shared entries ever would.
MAX_LINES = 5000

# Only trim once we've drifted a bit past the cap, so we're not rewriting the
# whole file on every single append once it's full. Amortizes the trim cost.
TRIM_TRIGGER = MAX_LINES + 500

# How often the retention CHECK itself runs. Counting the log's lines means
# reading the whole file, and 5000 retained rows of full payloads is several
# megabytes — paid on every single audited op if checked every time (issue
# #31). Instead the count is taken on the first audited write after process
# start (so an oversized log left behind by an earlier run is repaired
# promptly) and then once every RETENTION_CHECK_EVERY writes.
#
# Deliberately NOT a persisted line-count cache: re-reading the real file is
# what keeps us tolerant of external rotation or truncation. The existing
# TRIM_TRIGGER hysteresis is unchanged; this cadence only adds a bounded
# overshoot of at most RETENTION_CHECK_EVERY - 1 further rows.
RETENTION_CHECK_EVERY = 100

# Block size for reading the log's tail backwards. One block covers a typical
# read_audit(limit=50) comfortably; a single record larger than a block is
# handled by reading further blocks, never by truncating the record.
_TAIL_BLOCK_SIZE = 64 * 1024

# Guarded because record() can be called from more than one thread (handlers
# now run in the default executor).
_retention_lock = threading.Lock()
_writes_since_check = 0
_checked_this_process = False

# Ops we never record, to avoid noise / recursion. read_audit reads this very
# log; auditing the read would grow the log every time someone views it.
SKIP_OPS = frozenset({"read_audit", "ping"})


def record(op: str, payload: dict[str, Any], ok: bool,
           error: str | None = None, duration_ms: int | None = None,
           result_ok: bool | None = None,
           result_returncode: int | None = None) -> None:
    """Append one entry to the local audit log. Best-effort; never raises.

    `ok` keeps its historical meaning: the handler completed without raising
    (dispatch-level success). It is NOT the outcome of whatever the handler
    ran. An op like script_run reports a failed child as a normal nested
    result — {"ok": false, "returncode": 7} — so an audit that only carried
    `ok` showed a failed script as ok=true with nothing to say otherwise
    (issue #30).

    `result_ok` / `result_returncode` carry that nested outcome when the
    handler's result has one. Both are optional and omitted when absent, so
    entries written before this existed stay valid and readers that ignore
    the fields keep working. Only these two scalars are lifted — never
    stdout, stderr or any other result body.
    """
    if op in SKIP_OPS:
        return
    try:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "op": op,
            "payload": payload,
            "ok": ok,
            "error": error,
            "duration_ms": duration_ms,
        }
        if result_ok is not None:
            entry["result_ok"] = bool(result_ok)
        if result_returncode is not None:
            entry["result_returncode"] = int(result_returncode)
        line = json.dumps(entry, ensure_ascii=False, default=str)

        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        if _should_check_retention():
            _maybe_trim()
    except Exception as exc:  # never let auditing break the op
        logger.warning("local_audit_write_failed: %s", exc)


def _should_check_retention() -> bool:
    """True on this process's first audited write and every
    RETENTION_CHECK_EVERY writes after that.

    The append itself is O(1); it was the retention CHECK that read the
    whole log on every op (issue #31). Keeping the cadence in memory —
    rather than caching a line count on disk — means every check still
    measures the real file, so external rotation or truncation is picked
    up at the next check instead of being masked by a stale cache.
    """
    global _writes_since_check, _checked_this_process
    with _retention_lock:
        if not _checked_this_process:
            _checked_this_process = True
            _writes_since_check = 0
            return True
        _writes_since_check += 1
        if _writes_since_check >= RETENTION_CHECK_EVERY:
            _writes_since_check = 0
            return True
        return False


def _reset_retention_state() -> None:
    """Forget the cadence, as if the process had just started. Test-only."""
    global _writes_since_check, _checked_this_process
    with _retention_lock:
        _writes_since_check = 0
        _checked_this_process = False


def _maybe_trim() -> None:
    """If the log has grown past TRIM_TRIGGER lines, rewrite it keeping the
    most recent MAX_LINES. Atomic replace so a crash mid-trim can't corrupt or
    truncate the live file."""
    try:
        # Cheap line count without loading the whole file into memory.
        with AUDIT_PATH.open("rb") as f:
            count = sum(1 for _ in f)
        if count <= TRIM_TRIGGER:
            return

        with AUDIT_PATH.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        keep = lines[-MAX_LINES:]

        # Write to a temp file in the same dir, then atomically replace.
        fd, tmp = tempfile.mkstemp(dir=str(AUDIT_PATH.parent), prefix=".audit-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.writelines(keep)
            os.replace(tmp, AUDIT_PATH)
        except Exception:
            # Clean up the temp file if the replace didn't happen.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as exc:
        logger.warning("local_audit_trim_failed: %s", exc)


def _read_tail_lines(path: Path, limit: int) -> list[bytes]:
    """Return at most the last `limit` physical lines of `path`, oldest first.

    Reads backwards from EOF in _TAIL_BLOCK_SIZE blocks and stops as soon as
    enough newlines have been seen, so a 50-entry request touches kilobytes
    instead of the whole retained log (issue #31). A record longer than one
    block simply costs another block — records are never split.
    """
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        # `<= limit` rather than `< limit`: the log normally ends with a
        # newline, so N complete lines carry N newlines and the first one
        # seen going backwards closes the newest line rather than opening it.
        while pos > 0 and buf.count(b"\n") <= limit:
            step = min(_TAIL_BLOCK_SIZE, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf

    return buf.splitlines()[-limit:]


def read_recent(limit: int = 200) -> list[dict[str, Any]]:
    """Return the most recent `limit` entries, newest first. Best-effort:
    returns whatever parses; a malformed line is skipped, not fatal.

    Only the newest `limit` PHYSICAL lines are ever inspected. A malformed
    line among them is skipped and NOT backfilled from further back in the
    log — the caller asked for the last N rows, not for N parseable rows.
    That is the historical behaviour, kept deliberately.
    """
    limit = max(1, min(int(limit), MAX_LINES))
    try:
        if not AUDIT_PATH.exists():
            return []
        tail = _read_tail_lines(AUDIT_PATH, limit)
    except Exception as exc:
        logger.warning("local_audit_read_failed: %s", exc)
        return []

    out: list[dict[str, Any]] = []
    for raw in reversed(tail):
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except (json.JSONDecodeError, TypeError):
            continue
    return out
