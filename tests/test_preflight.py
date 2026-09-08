"""Preflight and enrollment-rejection classification.

A rejected token used to be invisible: the agent retried in the background and
the cause only reached the journal. These cover the two halves of the fix --
asking the hub once, and never again treating a refusal as a network blip.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock

from websockets.exceptions import ConnectionClosed
from websockets.frames import Close

from sentinelx_core import preflight
from sentinelx_core.client import EnrollmentRejected, FatalProtocolError


def _closed(code: int, reason: str = "") -> ConnectionClosed:
    # .code/.reason are read-only properties derived from the received Close
    # frame, so build a real one rather than assigning to the exception.
    return ConnectionClosed(Close(code, reason), None)


class _FakeWS:
    """Stands in for the hub side of one probe connection."""

    def __init__(self, *, frame=None, closed=None, hang=False):
        self._frame, self._closed, self._hang = frame, closed, hang

    async def recv(self):
        if self._closed:
            raise self._closed
        if self._hang:  # hub is waiting for our hello
            await asyncio.sleep(60)
        return self._frame

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _connect(ws=None, raises=None):
    def _factory(*a, **kw):
        if raises:
            raise raises
        return ws
    return _factory


class PreflightTests(unittest.IsolatedAsyncioTestCase):
    async def test_silence_means_the_token_was_accepted(self):
        preflight._ACCEPT_WINDOW_SECONDS = 0.05
        with mock.patch.object(
            preflight.websockets, "connect", _connect(_FakeWS(hang=True))
        ):
            res = await preflight.verify_enrollment("https://h", "tok")
        self.assertTrue(res.ok)
        self.assertEqual(res.reason, "accepted")

    async def test_error_frame_reports_the_hub_reason(self):
        frame = json.dumps(
            {"type": "error", "code": "enrollment_rejected",
             "message": "enrollment rejected: bad_signature"}
        )
        with mock.patch.object(
            preflight.websockets, "connect", _connect(_FakeWS(frame=frame))
        ):
            res = await preflight.verify_enrollment("https://h", "tok")
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "enrollment_rejected")
        self.assertIn("bad_signature", res.detail)

    async def test_1008_close_without_a_frame_is_still_a_rejection(self):
        # The hub closes right after sending the frame, so reading it is a race.
        with mock.patch.object(
            preflight.websockets,
            "connect",
            _connect(_FakeWS(closed=_closed(1008, "invalid token"))),
        ):
            res = await preflight.verify_enrollment("https://h", "tok")
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "enrollment_rejected")
        self.assertIn("invalid token", res.detail)

    async def test_unreachable_hub_is_not_reported_as_a_token_problem(self):
        with mock.patch.object(
            preflight.websockets, "connect",
            _connect(raises=OSError("Name or service not known")),
        ):
            res = await preflight.verify_enrollment("https://nope.invalid", "tok")
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "unreachable")

    async def test_never_raises_on_an_unexpected_failure(self):
        with mock.patch.object(
            preflight.websockets, "connect", _connect(raises=RuntimeError("boom"))
        ):
            res = await preflight.verify_enrollment("https://h", "tok")
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "error")

    def test_ws_scheme_mapping(self):
        self.assertEqual(preflight._ws_url("https://h"), "wss://h")
        self.assertEqual(preflight._ws_url("http://h"), "ws://h")
        self.assertEqual(preflight._ws_url("wss://h"), "wss://h")


class RejectionClassificationTests(unittest.TestCase):
    def test_enrollment_rejection_is_retryable_not_fatal(self):
        # Retrying is the point: a disabled host that is re-enabled, or a
        # hub-side fix, must heal without touching this machine.
        self.assertFalse(issubclass(EnrollmentRejected, FatalProtocolError))

    def test_the_operator_message_names_both_causes_and_the_fix(self):
        with self.assertLogs("sentinelx_core.client", level="ERROR") as cm:
            from sentinelx_core.client import _log_enrollment_rejected

            _log_enrollment_rejected("bad_signature")
        text = "\n".join(cm.output).lower()
        for expected in ("re-run enrollment", "disabled", "retrying"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
