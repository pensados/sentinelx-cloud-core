"""Preflight: ask the hub whether this enrollment token is accepted.

The hub verifies the token during the WebSocket handshake, BEFORE any hello,
and on refusal it sends an error frame and closes with 1008. So a probe only
has to open the connection and see whether it survives: no hello, no session,
nothing that could disturb a running agent.

This exists because a rejected token is otherwise invisible at install time.
The agent retries in the background every few minutes and the reason only
reaches the system journal, so a token that was altered on the way to the
server can go unnoticed for days. Verifying once, in front of whoever is
installing, turns that into an immediate answer.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus, InvalidStatusCode

# The hub accepts, then waits for our hello. If nothing arrives in this window,
# the token was accepted -- a rejection is immediate, not slow.
_ACCEPT_WINDOW_SECONDS = 6.0


@dataclass
class PreflightResult:
    ok: bool
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return self.reason if not self.detail else f"{self.reason}: {self.detail}"


def _ws_url(hub_url: str) -> str:
    if hub_url.startswith("http://"):
        return "ws://" + hub_url[7:]
    if hub_url.startswith("https://"):
        return "wss://" + hub_url[8:]
    return hub_url


async def verify_enrollment(hub_url: str, token: str) -> PreflightResult:
    """Open one connection and report whether the hub accepted the token.

    Never raises: every failure mode is returned as a result, and network
    problems are reported separately from a refused token so they are not
    confused for one another.
    """
    url = f"{_ws_url(hub_url)}/agent/connect"
    hdr_kw = (
        "additional_headers"
        if int(websockets.__version__.split(".")[0]) >= 14
        else "extra_headers"
    )
    try:
        async with websockets.connect(
            url,
            **{hdr_kw: {"Authorization": f"Bearer {token}"}},
            open_timeout=15,
            ping_interval=None,
        ) as ws:
            try:
                raw = await asyncio.wait_for(
                    ws.recv(), timeout=_ACCEPT_WINDOW_SECONDS
                )
            except asyncio.TimeoutError:
                # Hub is waiting for our hello: the token verified.
                return PreflightResult(True, "accepted")
            except ConnectionClosed as exc:
                return _closed(exc)
            # Anything sent before our hello is a refusal.
            try:
                msg = json.loads(raw)
                code = str(msg.get("code") or "rejected")
                detail = str(msg.get("message") or "")
            except Exception:  # noqa: BLE001 - unparseable is still a refusal
                code, detail = "rejected", ""
            return PreflightResult(False, code, detail)
    except ConnectionClosed as exc:
        return _closed(exc)
    except (InvalidStatus, InvalidStatusCode) as exc:
        # HTTP-level refusal (e.g. 403 before the upgrade completes).
        return PreflightResult(False, "rejected_by_hub", str(exc))
    except (OSError, asyncio.TimeoutError) as exc:
        # Cannot reach the hub. NOT a token problem -- saying so keeps whoever
        # is installing from re-running enrollment to fix a network fault.
        return PreflightResult(False, "unreachable", str(exc))
    except Exception as exc:  # noqa: BLE001
        return PreflightResult(False, "error", str(exc))


def _closed(exc: ConnectionClosed) -> PreflightResult:
    reason = _reason(exc)
    if exc.code == 1008:
        return PreflightResult(
            False, "enrollment_rejected", reason or "policy violation"
        )
    return PreflightResult(False, "closed", f"{exc.code}: {reason}".strip())


def _reason(exc: ConnectionClosed) -> str:
    """``.reason`` is deprecated since websockets 13.1; ``.rcvd`` is absent on
    older releases the agent still runs on. Prefer the new one, fall back."""
    rcvd = getattr(exc, "rcvd", None)
    if rcvd is not None and getattr(rcvd, "reason", None):
        return str(rcvd.reason)
    try:
        return str(exc.reason or "")
    except Exception:  # noqa: BLE001
        return ""
