"""A hub name with two addresses, the first unreachable, still connects (0.23.32).

mcp-direct.sentinelx.app has two relays since 2026-10-23 (orion and venus). Some
networks can't reach one of them: packets are dropped, so the TCP connect hangs.
Without happy eyeballs, create_connection tries the addresses one by one and the
whole websockets open_timeout runs out on the first; with it, the next address is
raced after HAPPY_EYEBALLS_DELAY.
"""

from __future__ import annotations

import asyncio
import socket
import time

import pytest
import websockets

from sentinelx_core import client as client_module

BLACKHOLE = "192.0.2.1"  # TEST-NET-1: routed nowhere; a SYN to it is usually just dropped


async def _serve():
    async def echo(ws):
        async for m in ws:
            await ws.send(m)
    return await websockets.serve(echo, "127.0.0.1", 0)


def _fake_getaddrinfo(port):
    async def getaddrinfo(host, p, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (BLACKHOLE, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    return getaddrinfo


async def _blackhole_hangs() -> bool:
    try:
        await asyncio.wait_for(asyncio.open_connection(BLACKHOLE, 9), timeout=1.0)
    except (asyncio.TimeoutError, TimeoutError):
        return True
    except OSError:
        return False  # this network rejects it at once: nothing to race
    return False


async def _connect(port, **extra):
    async with websockets.connect(f"ws://relay.test:{port}", open_timeout=3, **extra) as ws:
        await ws.send("ping")
        return await ws.recv()


async def test_the_second_address_wins_when_the_first_never_answers(monkeypatch):
    server = await _serve()
    port = server.sockets[0].getsockname()[1]
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", _fake_getaddrinfo(port))
    try:
        t0 = time.monotonic()
        got = await _connect(port, happy_eyeballs_delay=client_module.HAPPY_EYEBALLS_DELAY, interleave=1)
        assert got == "ping" and time.monotonic() - t0 < 2.0
        if await _blackhole_hangs():
            # The behaviour this fixes: without racing, the first address eats the timeout.
            with pytest.raises((asyncio.TimeoutError, TimeoutError)):
                await _connect(port)
    finally:
        server.close()
        await server.wait_closed()
