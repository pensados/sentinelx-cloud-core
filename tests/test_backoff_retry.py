"""Reconnect timing: a gentler curve, jitter, and a hub-supplied hint.

Three problems, one place. The curve jumped 5 -> 30 seconds, so a momentary
break on a healthy path cost close to a minute offline. Every agent waited the
identical delay, so a hub restart brought ~1700 of them back in one spike. And
the hub, which is the only party that knows how many are reconnecting at once,
had no way to say so.
"""

from __future__ import annotations

import pytest

from sentinelx_core.client import (
    BACKOFF_SCHEDULE,
    MAX_RETRY_AFTER_SECONDS,
    apply_jitter,
    parse_retry_after,
)


# --- the curve -------------------------------------------------------------

def test_the_early_steps_recover_in_seconds():
    # The first four attempts must stay inside ten seconds: that is the window
    # where a transient break is still worth retrying eagerly.
    assert sum(BACKOFF_SCHEDULE[:4]) <= 10


def test_no_step_more_than_triples_the_previous_one():
    # The old 5 -> 30 jump is what put a healthy host offline for a minute.
    steps = [s for s in BACKOFF_SCHEDULE if s > 0]
    for before, after in zip(steps, steps[1:]):
        assert after <= before * 3, f"{before}s -> {after}s is too steep"


def test_the_tail_is_a_minute():
    # Long enough that a hub that is genuinely down isn't hammered: with full
    # jitter, ~3100 agents spread over 60 s is the wave every deploy absorbs (the
    # hub can still ask for longer with Retry-After). Short enough that a host
    # whose network comes back reconnects within a minute: at 300 s, hosts sat
    # out up to 5 more minutes after an outage (returns at 12-17 min, 0.23.26).
    assert max(BACKOFF_SCHEDULE) == 60
    assert MAX_RETRY_AFTER_SECONDS >= 300   # the hub keeps its brake


# --- jitter ----------------------------------------------------------------

def test_jitter_stays_within_the_window():
    for _ in range(200):
        assert 0.0 <= apply_jitter(30) <= 30


def test_jitter_actually_spreads():
    # The point is that agents stop choosing the same instant.
    values = {round(apply_jitter(30), 3) for _ in range(50)}
    assert len(values) > 40


def test_an_immediate_retry_stays_immediate():
    # The first attempt after a clean disconnect should not be delayed.
    assert apply_jitter(0) == 0.0


# --- the hub's hint --------------------------------------------------------

def test_a_hint_is_read_from_the_close_reason():
    assert parse_retry_after("hub_shutdown;retry_after=37") == 37


def test_a_hint_survives_other_fields_and_spacing():
    assert parse_retry_after("hub_shutdown; retry_after = 12 ; foo=bar") == 12


def test_no_hint_means_no_hint():
    for reason in ("hub_shutdown", "", None, "retry_after"):
        assert parse_retry_after(reason) is None


def test_a_malformed_hint_falls_back_rather_than_breaking():
    # Reconnection must not depend on the hub formatting this correctly.
    for reason in ("retry_after=soon", "retry_after=", "retry_after=1e999"):
        assert parse_retry_after(reason) is None


def test_the_agent_caps_what_the_hub_can_ask_for():
    # A buggy or hostile hub must not be able to silence the fleet.
    assert parse_retry_after("retry_after=86400") == MAX_RETRY_AFTER_SECONDS
    assert MAX_RETRY_AFTER_SECONDS <= 300


def test_a_negative_hint_is_clamped_to_zero():
    assert parse_retry_after("retry_after=-5") == 0.0
