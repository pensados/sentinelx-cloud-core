"""Background job helpers for the agent side of the async-jobs feature.

This is a leaf module (stdlib only) so the handlers and the WS client can all
import it without a cycle. It owns two things:

1. The background execution limits (timeout ceiling, event output cap).
2. Building the ``job_completed`` event payload from an executor dispatch
   response — the payload the agent emits over the existing ``EventMessage``
   channel (kind="job_completed") when a background op finishes.

See sentinelx-notifications-integration-spec.md §2e (schema) and §3b (frame).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# When an op runs with background=true its wall-clock ceiling is raised from
# the interactive default (script_run's 600s / exec's policy max) to this, so
# genuinely long jobs — the whole point of the feature — aren't rejected. The
# handler still enforces it via its own asyncio.wait_for; the hub keeps a §3d
# hard-timeout / agent-disconnect reaper as the backstop.
BACKGROUND_TIMEOUT_MAX = 3600  # 1 hour

# The job_completed event carries the output inline. Cap it well under the
# protocol frame limit (sentinelx_protocol.MAX_FRAME_BYTES = 1 MiB); the hub
# stores this copy and serves it via notifications(get). Larger real outputs
# are truncated here with a flag so the caller knows the tail was dropped.
MAX_EVENT_OUTPUT_BYTES = 256 * 1024  # 256 KiB


def _truncate_output(text: str | None) -> tuple[str, bool]:
    """Return (possibly-truncated text, was_truncated). Byte-bounded so a
    multibyte tail can't push us over the frame cap; splits on a char
    boundary via errors='replace' on decode."""
    if not text:
        return "", False
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= MAX_EVENT_OUTPUT_BYTES:
        return text, False
    clipped = raw[:MAX_EVENT_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return clipped, True


def build_completed_event_data(
    *,
    job_id: str,
    op: str,
    host: str,
    dispatch_response: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, Any]:
    """Translate an ``Executor.dispatch`` response into the job_completed
    event ``data`` payload.

    ``dispatch_response`` is the dict returned by Executor.dispatch (or the
    client's internal-error fallback):
      - success:  {"ok": True,  "result": {<handler result>}, ...}
      - handler error / crash: {"ok": False, "error": {"code", "message", ...}}

    Status mapping:
      - ok False                         -> "failed"   (handler raised)
      - ok True + result.timed_out       -> "timeout"  (wall-clock exceeded)
      - ok True + returncode == 0        -> "succeeded"
      - ok True + returncode != 0        -> "failed"

    The handler result shapes vary (script_run vs exec vs others) but all the
    executing ops expose ``returncode`` and ``output``; ``timed_out`` is set by
    the handlers' timeout branch (see script.py / executor_engine.run_shell).
    """
    ok = bool(dispatch_response.get("ok"))
    result = dispatch_response.get("result") or {}
    error = dispatch_response.get("error") or {}
    duration_s = round((finished_at - started_at).total_seconds(), 2)

    if not ok:
        status = "failed"
        exit_code: int | None = None
        output = ""
        error_msg: str | None = (
            error.get("message") if isinstance(error, dict) else str(error)
        ) or "operation failed"
    else:
        returncode = result.get("returncode")
        if result.get("timed_out"):
            status = "timeout"
        elif returncode == 0:
            status = "succeeded"
        else:
            status = "failed"
        exit_code = returncode if isinstance(returncode, int) else None
        output = result.get("output") or ""
        error_msg = None

    clipped_output, output_truncated = _truncate_output(output)

    return {
        "job_id": job_id,
        "tool": op,
        "host": host,
        "status": status,
        "exit_code": exit_code,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_s": duration_s,
        "output": clipped_output,
        "output_truncated": output_truncated,
        "error": error_msg,
    }
