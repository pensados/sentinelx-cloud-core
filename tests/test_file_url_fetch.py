"""file_url fetching (agent 0.23.48), from Jan's audit of 2026-10-31.

#14 the address validated against SSRF was looked up again by urllib, so a DNS server
    answering differently the second time (rebinding) passed validation;
#15 cancelling a fetch abandoned the worker thread, which kept downloading.
"""
from __future__ import annotations

import asyncio
import socket
import time

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import upload as U

PUBLIC, PRIVATE = "93.184.216.34", "10.0.0.5"


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)


def _rebinding_dns(monkeypatch):
    calls = []

    def fake_getaddrinfo(host, *a, **k):
        calls.append(host)
        ip = PUBLIC if len(calls) == 1 else PRIVATE
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    monkeypatch.setattr(U.socket, "getaddrinfo", fake_getaddrinfo)
    return calls


async def test_the_connection_goes_to_the_address_that_was_validated(tmp_path, monkeypatch):
    lookups = _rebinding_dns(monkeypatch)
    dialled = []

    def fake_create_connection(address, *a, **k):
        dialled.append(address)
        raise ConnectionRefusedError("test stops here")
    monkeypatch.setattr(U.socket, "create_connection", fake_create_connection)
    with pytest.raises(HandlerError) as e:
        await U._fetch_url("https://files.example.com/x", tmp_path / "d",
                           trusted_hosts=("files.example.com",))
    assert e.value.code == "fetch_failed"
    assert dialled == [(PUBLIC, 443)], f"connected to {dialled}, not the validated address"
    assert len(lookups) == 1, "the name was looked up again after validation"


async def test_cancelling_a_fetch_stops_the_worker_and_removes_the_partial(tmp_path, monkeypatch):
    _rebinding_dns(monkeypatch)
    ours, server = socket.socketpair()   # a "server" that never answers the TLS hello
    ours.settimeout(10)                  # a regression fails in seconds instead of hanging
    monkeypatch.setattr(U.socket, "create_connection", lambda *a, **k: ours)
    dest = tmp_path / "partial.bin"
    dest.write_bytes(b"half")            # as if the transfer had started
    task = asyncio.create_task(U._fetch_url("https://files.example.com/big", dest,
                                            trusted_hosts=("files.example.com",), timeout=30))
    await asyncio.sleep(0.4)
    t0 = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - t0 < 3, "cancelling waited for the transfer"
    server.settimeout(2)
    try:
        while server.recv(65536):
            pass                         # the ClientHello, then EOF once our side is shut
    except socket.timeout:
        pytest.fail("the worker's socket was still open after the cancel")
    finally:
        server.close()
    assert not dest.exists(), "the partial file was left behind"
