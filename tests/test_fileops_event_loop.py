"""Issue #25: read/list/search must not monopolize the asyncio loop.

The three ops are async, but their filesystem work is blocking. Run on the
loop, a slow open, a deep enumeration or a recursive scan stalls everything
else the agent is doing — including the WebSocket control plane — for the
duration of the filesystem work.

Each test injects a deterministic delay into one filesystem primitive and
runs the op while an independent 10 ms ticker measures scheduling gaps.
Against the pre-fix implementation these fail with a gap of about the
injected delay; with the work handed to the default executor the gap stays
near the tick interval. The assertions also check the RESULT, because the
point of the fix is that only the thread changed.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import FileOpsPath, Policy
from tests.loop_probe import run_with_loop_probe

# Long enough to dwarf the tick interval, short enough to keep the suite fast.
INJECTED_DELAY = 0.25
# The reporter's threshold: anything at or above this means the loop was held.
MAX_ACCEPTABLE_GAP = 0.10


def _policy(tmp_path: Path) -> Policy:
    pol = Policy(file_ops_paths=(FileOpsPath(path=str(tmp_path), access="r"),))
    object.__setattr__(pol, "upload_base", tmp_path)
    return pol


def _slow_path_method(monkeypatch, name: str, target: Path) -> None:
    """Make one Path method sleep, but only for `target`."""
    original = getattr(Path, name)

    def slow(self, *args, **kwargs):
        if self == target:
            time.sleep(INJECTED_DELAY)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, name, slow)


@pytest.mark.asyncio
async def test_read_file_io_does_not_block_event_loop(tmp_path, monkeypatch):
    target = tmp_path / "slow.txt"
    target.write_text("payload line\n")
    _slow_path_method(monkeypatch, "open", target)

    handlers = build_registry(policy=_policy(tmp_path))
    result, max_gap = await run_with_loop_probe(
        handlers["read"]({"path": str(target)})
    )

    assert "payload line" in result["content"]
    assert max_gap < MAX_ACCEPTABLE_GAP, (
        f"event loop stalled for {max_gap:.3f}s during a slow read"
    )


@pytest.mark.asyncio
async def test_recursive_list_keeps_event_loop_responsive(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "leaf.txt").write_text("x")
    (root / "top.txt").write_text("y")
    _slow_path_method(monkeypatch, "iterdir", root)

    handlers = build_registry(policy=_policy(tmp_path))
    result, max_gap = await run_with_loop_probe(
        handlers["list"]({"path": str(root), "depth": 3})
    )

    names = {e["name"] for e in result["entries"]}
    assert "top.txt" in names
    assert max_gap < MAX_ACCEPTABLE_GAP, (
        f"event loop stalled for {max_gap:.3f}s during a recursive list"
    )


@pytest.mark.asyncio
async def test_recursive_search_keeps_event_loop_responsive(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "hit.txt").write_text("needle here\n")
    _slow_path_method(monkeypatch, "iterdir", root)

    handlers = build_registry(policy=_policy(tmp_path))
    result, max_gap = await run_with_loop_probe(
        handlers["search"]({"path": str(root), "pattern": "needle"})
    )

    assert [m["line"] for m in result["matches"]] == [1]
    assert max_gap < MAX_ACCEPTABLE_GAP, (
        f"event loop stalled for {max_gap:.3f}s during a recursive search"
    )


@pytest.mark.asyncio
async def test_handler_errors_still_propagate_from_the_worker(tmp_path):
    """The offload must not swallow or reshape HandlerError."""
    from sentinelx_core.executor import HandlerError

    handlers = build_registry(policy=_policy(tmp_path))
    with pytest.raises(HandlerError) as exc:
        await handlers["read"]({"path": "/etc/shadow"})
    assert exc.value.code == "path_not_allowed"
