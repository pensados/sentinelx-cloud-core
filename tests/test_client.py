"""Focused tests for the WebSocket connection lifecycle."""

from __future__ import annotations

import asyncio
import json
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from sentinelx_protocol import HEARTBEAT_INTERVAL_SECONDS, MAX_BINARY_FRAME_BYTES, WelcomeMessage
from websockets import frames
from websockets.exceptions import ConnectionClosed

from sentinelx_core.client import BACKOFF_SCHEDULE, HubClient


class _ConnectionContext:
    def __init__(self, websocket: AsyncMock) -> None:
        self.websocket = websocket

    async def __aenter__(self) -> AsyncMock:
        return self.websocket

    async def __aexit__(self, *_args: object) -> None:
        return None


class HubClientReconnectTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.client = object.__new__(HubClient)
        self.client._stop = asyncio.Event()
        self.client._session_established = False

    async def _run_actions(self, actions: list[str]) -> list[float]:
        remaining = list(actions)
        delays: list[float] = []

        async def connect_and_serve() -> None:
            action = remaining.pop(0)
            if action == "pre_welcome_failure":
                raise OSError("connection failed before welcome")
            if action == "established_1006":
                self.client._session_established = True
                raise ConnectionClosed(None, None)
            if action == "established_1012":
                self.client._session_established = True
                raise ConnectionClosed(frames.Close(1012, "hub restart"), None)
            if action == "stop":
                self.client._stop.set()
                return
            raise AssertionError(f"unknown action: {action}")

        async def record_wait(awaitable: object, timeout: float) -> None:
            close = getattr(awaitable, "close", None)
            if close is not None:
                close()
            delays.append(timeout)
            raise TimeoutError

        with (
            patch.object(self.client, "_connect_and_serve", new=connect_and_serve),
            patch("sentinelx_core.client.asyncio.wait_for", new=record_wait),
        ):
            await self.client.run()

        self.assertEqual(remaining, [])
        return delays

    async def test_established_session_resets_old_backoff_before_1006(self) -> None:
        delays = await self._run_actions(
            ["pre_welcome_failure"] * 6 + ["established_1006", "stop"]
        )

        self.assertEqual(delays, BACKOFF_SCHEDULE[1:] + [1])

    async def test_pre_welcome_failures_keep_escalating(self) -> None:
        delays = await self._run_actions(["pre_welcome_failure"] * 7 + ["stop"])

        self.assertEqual(delays, BACKOFF_SCHEDULE[1:] + [BACKOFF_SCHEDULE[-1]])

    async def test_1012_remains_prompt_after_old_failures(self) -> None:
        delays = await self._run_actions(
            ["pre_welcome_failure"] * 6 + ["established_1012", "stop"]
        )

        self.assertEqual(delays, BACKOFF_SCHEDULE[1:])


class HubClientKeepaliveTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_enables_native_keepalive(self) -> None:
        client = object.__new__(HubClient)
        client._ws_url = "wss://hub.example"
        client._identity = SimpleNamespace(token="test-token", host_id="host-test")
        client._executor = SimpleNamespace(
            config_summary=dict,
            capability_names=list,
            preferred_profile=lambda: None,
        )
        client._session_established = False

        welcome = WelcomeMessage(
            session_id="session-test",
            server_time=datetime.now(UTC),
        )
        websocket = AsyncMock()
        websocket.recv.return_value = welcome.model_dump_json()
        connect = Mock(return_value=_ConnectionContext(websocket))

        with (
            patch("sentinelx_core.client.websockets.connect", new=connect),
            patch.object(client, "_read_loop", new=AsyncMock(return_value=None)),
            patch.object(client, "_heartbeat_loop", new=AsyncMock(return_value=None)),
        ):
            await client._connect_and_serve()

        connect.assert_called_once_with(
            "wss://hub.example/agent/connect?token=test-token",
            ping_interval=30,
            ping_timeout=60,
            max_size=MAX_BINARY_FRAME_BYTES,
        )
        self.assertTrue(client._session_established)

    async def test_application_ping_heartbeat_remains_active(self) -> None:
        class EndHeartbeat(Exception):
            pass

        client = object.__new__(HubClient)
        websocket = AsyncMock()
        intervals: list[float] = []

        async def sleep_then_stop(interval: float) -> None:
            intervals.append(interval)
            if len(intervals) > 1:
                raise EndHeartbeat

        with (
            patch("sentinelx_core.client.asyncio.sleep", new=sleep_then_stop),
            self.assertRaises(EndHeartbeat),
        ):
            await client._heartbeat_loop(websocket)

        self.assertEqual(intervals, [HEARTBEAT_INTERVAL_SECONDS] * 2)
        websocket.send.assert_awaited_once()
        payload = json.loads(websocket.send.await_args.args[0])
        self.assertEqual(payload["type"], "ping")
        self.assertIn("timestamp", payload)


if __name__ == "__main__":
    unittest.main()
