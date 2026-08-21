"""Executor: receives a RequestMessage, runs the right handler, returns a response dict.

This is the integration seam with the legacy core code. Each handler in
`handlers/` is a thin wrapper that calls into the proven execution logic.

Right now the handlers are stubs. The plan is to copy the implementations from
the legacy `agent.py` (at /home/carlos/projects/sentinelx/agent.py) one by one
as the new core gets validated end-to-end.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from sentinelx_protocol import RequestMessage

from sentinelx_core import local_audit

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def _nested_outcome(result: Any) -> tuple[bool | None, int | None]:
    """Lift a handler result's OWN outcome, when it reports one.

    Dispatch-level success ("the handler returned") is not the same thing as
    the outcome of what the handler ran. `script_run` reports a failed child
    as a perfectly normal result — {"ok": false, "returncode": 7} — so an
    audit that recorded only dispatch success showed a failed script as
    ok=true with nothing to contradict it (issue #30).

    Exactly two scalars are lifted, and only when present and of the right
    type: nothing here reaches into stdout, stderr or any other body. A bool
    is not accepted as a returncode (in Python it would pass an int check).
    """
    if not isinstance(result, dict):
        return None, None

    nested_ok = result.get("ok")
    if not isinstance(nested_ok, bool):
        nested_ok = None

    returncode = result.get("returncode")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        returncode = None

    return nested_ok, returncode


class Executor:
    def __init__(self, config_path: Path) -> None:
        self._config_path = config_path
        # Lazy-loaded
        self._handlers: dict[str, Handler] | None = None
        self._upload_base: Path | None = None

    def capability_names(self) -> list[str]:
        """Names of supported ops, used in the `hello` capabilities list."""
        return list(self._get_handlers().keys())

    def config_summary(self) -> dict[str, int]:
        """Policy counts for the hello's ConfigSummary — aggregates only.

        Loads the policy and returns how many commands/paths/services/etc.
        are configured, never the actual values. Best-effort: if the policy
        can't be loaded, returns an empty dict and the hello omits the
        summary rather than failing the connection.
        """
        try:
            from sentinelx_core.policy import Policy

            p = Policy.from_file(self._config_path)
        except Exception:
            logger.warning("config_summary: policy load failed", exc_info=True)
            return {}

        rw = sum(
            1
            for entry in getattr(p, "file_ops_paths", ())
            if getattr(entry, "access", "r") == "rw"
        )
        return {
            "allowed_command_count": len(p.allowed_commands),
            "file_ops_path_count": len(p.file_ops_paths),
            "file_ops_rw_count": rw,
            "service_count": len(p.services),
            "playbook_count": len(p.playbooks),
            "trusted_fetch_host_count": len(p.trusted_fetch_hosts),
            "exec_timeout_default": p.exec_timeout_default,
            "exec_timeout_max": p.exec_timeout_max,
        }

    def preferred_profile(self) -> str | None:
        """The host's advertised MCP toolset-profile preference for the hello.

        Loads the policy and returns its (already-sanitized) preferred_profile
        ('compact' | 'full' | None). Best-effort: on any load failure returns
        None, so a bad policy makes the host advertise no preference rather
        than failing the connection.
        """
        try:
            from sentinelx_core.policy import Policy

            return Policy.from_file(self._config_path).preferred_profile
        except Exception:
            logger.warning("preferred_profile: policy load failed", exc_info=True)
            return None

    def _get_upload_base(self) -> Path:
        if self._upload_base is None:
            from sentinelx_core.policy import Policy

            self._upload_base = Policy.from_file(self._config_path).upload_base
        return self._upload_base

    async def ingest_transfer_chunk(self, upload_id: str, index: int, data: bytes) -> int:
        """Write one inbound binary transfer chunk into the upload staging dir.

        Called by the client's binary-frame read path on the DESTINATION side.
        Reuses the staging layout that `upload_complete` reassembles/verifies.
        """
        from sentinelx_core.handlers.upload import write_transfer_part

        return await asyncio.to_thread(
            write_transfer_part, self._get_upload_base(), upload_id, index, data
        )

    def _get_handlers(self) -> dict[str, Handler]:
        if self._handlers is None:
            from sentinelx_core.handlers import build_registry

            self._handlers = build_registry(config_path=self._config_path)
        return self._handlers

    async def dispatch(self, request: RequestMessage) -> dict[str, Any]:
        """Run the handler for `request.op` and build a response dict ready to send."""
        handlers = self._get_handlers()
        handler = handlers.get(request.op)

        if handler is None:
            return {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {
                    "code": "unsupported_op",
                    "message": f"agent does not support op: {request.op}",
                },
            }

        try:
            start = time.perf_counter()
            result = await handler(request.payload)
            duration_ms = int((time.perf_counter() - start) * 1000)
            nested_ok, nested_returncode = _nested_outcome(result)
            local_audit.record(
                request.op, request.payload, ok=True, duration_ms=duration_ms,
                result_ok=nested_ok, result_returncode=nested_returncode,
            )
            return {
                "type": "response",
                "id": request.id,
                "ok": True,
                "result": result,
            }
        except HandlerError as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            local_audit.record(
                request.op, request.payload, ok=False,
                error=str(exc), duration_ms=duration_ms,
            )
            return {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": str(exc),
                    "details": exc.details,
                },
            }


class HandlerError(Exception):
    """A handler explicitly rejected a request (e.g. policy violation)."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}
