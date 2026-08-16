"""Tests for the background-job helpers (sentinelx_core.jobs) and the
background timeout-ceiling behaviour of the executing handlers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.jobs import (
    BACKGROUND_TIMEOUT_MAX,
    MAX_EVENT_OUTPUT_BYTES,
    build_completed_event_data,
)
from sentinelx_core.policy import Policy

_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_T1 = _T0 + timedelta(seconds=5)


def _build(dispatch_response: dict) -> dict:
    return build_completed_event_data(
        job_id="job_test123456",
        op="script_run",
        host="host_abc",
        dispatch_response=dispatch_response,
        started_at=_T0,
        finished_at=_T1,
    )


def test_background_timeout_max_is_one_hour() -> None:
    assert BACKGROUND_TIMEOUT_MAX == 3600


def test_common_fields_and_duration() -> None:
    data = _build({"ok": True, "result": {"returncode": 0, "output": "hi"}})
    assert data["job_id"] == "job_test123456"
    assert data["tool"] == "script_run"
    assert data["host"] == "host_abc"
    assert data["started_at"] == _T0.isoformat()
    assert data["finished_at"] == _T1.isoformat()
    assert data["duration_s"] == 5.0


def test_status_succeeded() -> None:
    data = _build({"ok": True, "result": {"returncode": 0, "output": "done"}})
    assert data["status"] == "succeeded"
    assert data["exit_code"] == 0
    assert data["output"] == "done"
    assert data["output_truncated"] is False
    assert data["error"] is None


def test_status_failed_nonzero_exit() -> None:
    data = _build({"ok": True, "result": {"returncode": 7, "output": "boom"}})
    assert data["status"] == "failed"
    assert data["exit_code"] == 7
    assert data["output"] == "boom"


def test_status_timeout_from_timed_out_flag() -> None:
    data = _build(
        {"ok": True, "result": {"returncode": -1, "output": "⏱️ Timeout",
                                 "timed_out": True}}
    )
    assert data["status"] == "timeout"
    assert data["exit_code"] == -1


def test_status_failed_on_handler_error() -> None:
    data = _build(
        {"ok": False, "error": {"code": "command_not_allowed",
                                "message": "nope"}}
    )
    assert data["status"] == "failed"
    assert data["exit_code"] is None
    assert data["output"] == ""
    assert data["error"] == "nope"


def test_handler_error_without_message_has_fallback() -> None:
    data = _build({"ok": False})
    assert data["status"] == "failed"
    assert data["error"]  # non-empty fallback string


def test_output_truncation() -> None:
    big = "a" * (MAX_EVENT_OUTPUT_BYTES + 5000)
    data = _build({"ok": True, "result": {"returncode": 0, "output": big}})
    assert data["output_truncated"] is True
    assert len(data["output"].encode("utf-8")) <= MAX_EVENT_OUTPUT_BYTES


def test_output_at_cap_not_truncated() -> None:
    exact = "a" * MAX_EVENT_OUTPUT_BYTES
    data = _build({"ok": True, "result": {"returncode": 0, "output": exact}})
    assert data["output_truncated"] is False


# --- handler ceiling behaviour -------------------------------------------------

@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    p = Policy()
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def test_script_run_rejects_over_600_without_background(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["script_run"]({
            "interpreter": "bash",
            "content": "echo hi",
            "timeout": 700,
        })
    assert exc.value.code == "invalid_payload"


async def test_script_run_accepts_over_600_with_background(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    # 700s is rejected interactively but allowed under background; the script
    # itself returns immediately, we're only exercising the timeout gate.
    result = await handlers["script_run"]({
        "interpreter": "bash",
        "content": "echo hi",
        "timeout": 700,
        "background": True,
    })
    assert result["ok"] is True
    assert "hi" in result["output"]


async def test_script_run_rejects_over_3600_even_with_background(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["script_run"]({
            "interpreter": "bash",
            "content": "echo hi",
            "timeout": 4000,
            "background": True,
        })
    assert exc.value.code == "invalid_payload"
