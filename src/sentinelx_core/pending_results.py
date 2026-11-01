"""Results that outlive the connection that was meant to carry them.

A background job's completion goes back over the very websocket the request
arrived on. If that socket is gone by the time the work finishes -- our own
deployment, the operator's network, anything -- the send fails and the result is
simply lost. The agent did the work, built the answer, and wrote it to a
connection nobody was reading.

Three users reported the same shape of loss in one day, and 98 job records were
sitting at "running" fleet-wide with nothing ever coming back for them.

So: write the event down before attempting to send it, delete it once the send
succeeds, and replay whatever is still on disk the next time we connect. The hub
accepts a completion from any connection belonging to the same user, and
applying one twice yields the same record, so a replay is safe.

Deliberately NOT a job registry. The work still runs inside the agent process
and still dies with it -- what survives here is the ANSWER, not the job. That is
the failure everyone actually hit; surviving an agent restart is a separate and
much larger change.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Old enough that the hub has expired the job anyway: replaying it would land on
# an unknown id and be discarded, so there is nothing to gain by keeping it.
PENDING_TTL_SECONDS = 24 * 3600

# A stuck or offline agent must not fill the disk with results nobody will read.
MAX_PENDING_FILES = 500


def pending_dir(upload_base: Path) -> Path:
    """Where unsent results live. A sibling of the upload base, not inside it:
    that directory is user-facing, and these are ours."""
    return upload_base.parent / "pending-results"


def _safe_name(job_id: str) -> str:
    """job_id comes from the hub, but it reaches disk, so treat it as input."""
    keep = "".join(c for c in job_id if c.isalnum() or c in "-_")
    return keep[:64] or "unnamed"


def record(upload_base: Path, job_id: str, event: dict[str, Any]) -> Path | None:
    """Write `event` down before it is sent. Returns the path, or None if we
    could not write -- in which case the caller still tries to send, because a
    result that might reach the hub beats one we refuse to attempt."""
    try:
        d = pending_dir(upload_base)
        d.mkdir(parents=True, exist_ok=True)

        existing = sorted(d.glob("*.json"))
        if len(existing) >= MAX_PENDING_FILES:
            # Drop the oldest rather than refuse the newest: a recent result is
            # the one someone is still waiting on.
            for stale in existing[: len(existing) - MAX_PENDING_FILES + 1]:
                stale.unlink(missing_ok=True)

        path = d / f"{_safe_name(job_id)}.json"
        # Write-then-rename: a crash mid-write must not leave a half file that
        # the next startup tries to parse and re-send.
        fd, tmp = tempfile.mkstemp(dir=str(d), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"at": time.time(), "event": event}, fh)
            os.replace(tmp, path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise
        return path
    except Exception as exc:  # noqa: BLE001
        logger.warning("pending_result_write_failed job=%s: %s", job_id, exc)
        return None


def clear(path: Path | None) -> None:
    """Forget a result once it is on its way."""
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pending_result_clear_failed %s: %s", path, exc)


def drain(upload_base: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield (path, event) for every result still waiting, oldest first.

    Expired and unreadable entries are removed as they are met rather than
    yielded: a file we cannot parse will never parse, and one the hub has
    forgotten cannot be applied.
    """
    d = pending_dir(upload_base)
    if not d.is_dir():
        return
    now = time.time()
    for path in sorted(d.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            event = data.get("event")
            if not isinstance(event, dict):
                raise ValueError("no event object")
            if now - float(data.get("at") or 0) > PENDING_TTL_SECONDS:
                logger.info("pending_result_expired %s", path.name)
                path.unlink(missing_ok=True)
                continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("pending_result_unreadable %s: %s", path.name, exc)
            path.unlink(missing_ok=True)
            continue
        yield path, event
