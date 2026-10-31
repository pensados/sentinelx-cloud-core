"""The hub URL the agent is configured with, as the two bases it needs.

SENTINELX_HUB_URL (and --hub-url) may be http(s):// or ws(s)://, with or without
/agent/connect. The README used to show the full connect URL, which the client
then doubled (wss://host/agent/connect/agent/connect), and credential rotation
posted to wss://host/agent/connect/agent/rotate (sxrep_C8GHQR7WEGKS,
sxrep_058HW8X403G3). Both bases come from here.
"""
from __future__ import annotations

_CONNECT = "/agent/connect"


def hub_bases(hub_url: str) -> tuple[str, str]:
    """Return (http_base, ws_base) for a configured hub URL."""
    u = (hub_url or "").strip().rstrip("/")
    if u.endswith(_CONNECT):
        u = u[: -len(_CONNECT)].rstrip("/")
    if u.startswith("ws://"):
        return "http://" + u[5:], u
    if u.startswith("wss://"):
        return "https://" + u[6:], u
    if u.startswith("http://"):
        return u, "ws://" + u[7:]
    if u.startswith("https://"):
        return u, "wss://" + u[8:]
    return u, u
