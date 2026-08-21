"""Shared probe: how long did the event loop go unscheduled?

Used by the regressions for issues #25 and #31. The idea is the one the
reporter used: run an independent ticker at a fixed interval while the
operation under test is in flight, and record the largest gap between
consecutive ticks. If the operation does its blocking work on the loop,
the ticker cannot run for its duration and the gap approaches that
duration; if the work is handed to a worker thread, the gap stays close
to the tick interval.

This measures scheduling latency, not throughput — an operation is
allowed to take exactly as long as it always did.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable
from typing import Any

TICK_SECONDS = 0.01


async def run_with_loop_probe(
    awaitable: Awaitable[Any],
    tick: float = TICK_SECONDS,
) -> tuple[Any, float]:
    """Await `awaitable` while ticking, returning (result, max_gap_seconds)."""
    gaps: list[float] = []
    stop = asyncio.Event()

    async def ticker() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(tick)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    probe = asyncio.create_task(ticker())
    # Let the ticker take its first sample before the work starts, so the
    # measured window covers the operation rather than task startup.
    await asyncio.sleep(tick * 2)
    try:
        result = await awaitable
    finally:
        stop.set()
        await probe

    return result, max(gaps) if gaps else 0.0
