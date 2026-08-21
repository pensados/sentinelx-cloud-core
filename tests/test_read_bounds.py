"""Issue #27: `read` bounds — max_bytes as a real ceiling, reachable ranges.

Both defects came from one coupling: the 8 KiB binary probe was also the
buffer handed back as content, and `view_range` was applied to that buffer
afterwards. So a request for 257 bytes got 8192, and a range past the
response prefix could not be reached at all — the documented "range in the
file" behaved as "range in the prefix". The prefix's line count was also
reported as if it were the file's total.

The repair keeps three concerns apart: the probe classifies, the ceiling
bounds returned content, and a ranged read may scan as far as the request
needs — but no further than one line past a finite range.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from sentinelx_core.handlers import build_registry, fileops
from sentinelx_core.policy import FileOpsPath, Policy
from tests.loop_probe import run_with_loop_probe

LINE_BYTES = 102  # "line NNNN " + padding + "\n"
TOTAL_LINES = 1200  # 122,400 bytes: comfortably past the 64 KiB policy cap


def _policy(tmp_path: Path) -> Policy:
    pol = Policy(file_ops_paths=(FileOpsPath(path=str(tmp_path), access="r"),))
    object.__setattr__(pol, "upload_base", tmp_path)
    return pol


def _handlers(tmp_path: Path):
    return build_registry(policy=_policy(tmp_path))


def _big_text_file(tmp_path: Path, lines: int = TOTAL_LINES) -> Path:
    p = tmp_path / "big.txt"
    body = "".join(
        f"line {i:04d} ".ljust(LINE_BYTES - 1, "x") + "\n" for i in range(1, lines + 1)
    )
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# max_bytes is a hard ceiling, independent of the probe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_max_bytes_below_the_binary_probe_is_a_hard_ceiling(tmp_path):
    """Reproduction A: 14,000-byte file, max_bytes=257 used to return 8192."""
    target = tmp_path / "fourteen_k.txt"
    target.write_text("a" * 14_000, encoding="utf-8")

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "max_bytes": 257}
    )

    assert len(result["content"].encode("utf-8")) == 257
    assert result["size_bytes"] == 14_000
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_max_bytes_above_the_probe_still_bounded(tmp_path):
    target = tmp_path / "fourteen_k.txt"
    target.write_text("a" * 14_000, encoding="utf-8")

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "max_bytes": 10_000}
    )

    assert len(result["content"].encode("utf-8")) == 10_000
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_small_file_read_whole_is_exact_and_untruncated(tmp_path):
    target = tmp_path / "small.txt"
    target.write_text("one\ntwo\nthree\n", encoding="utf-8")

    result = await _handlers(tmp_path)["read"]({"path": str(target)})

    assert result["content"] == "one\ntwo\nthree\n"
    assert result["truncated"] is False
    assert result["total_lines"] == 3
    assert result["total_lines_exact"] is True


@pytest.mark.asyncio
async def test_prefix_line_count_is_marked_inexact(tmp_path):
    """Reproduction C: a prefix count must not pose as the file's total."""
    target = _big_text_file(tmp_path)

    result = await _handlers(tmp_path)["read"]({"path": str(target)})

    assert result["truncated"] is True
    assert result["total_lines"] < TOTAL_LINES
    assert result["total_lines_exact"] is False


# ---------------------------------------------------------------------------
# view_range reaches into the file, not just the prefix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_late_view_range_beyond_the_prefix_cap(tmp_path):
    """Reproduction B: [900, 905] in a 122 KiB file, 64 KiB policy cap."""
    target = _big_text_file(tmp_path)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [900, 905]}
    )

    lines = result["content"].splitlines()
    assert len(lines) == 6
    assert lines[0].startswith("line 0900")
    assert lines[-1].startswith("line 0905")
    assert result["view_range"] == [900, 905]
    assert result["lines_returned"] == 6
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_finite_range_scans_one_line_past_the_end_and_no_further(
    tmp_path, monkeypatch
):
    """Acceptance #4: the remainder is not scanned just to produce a total."""
    target = _big_text_file(tmp_path)
    real_iter = fileops._iter_lines
    consumed: list[int] = []

    def counting_iter(f, encoding):
        for i, line in enumerate(real_iter(f, encoding), start=1):
            consumed.append(i)
            yield line

    monkeypatch.setattr(fileops, "_iter_lines", counting_iter)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [900, 905]}
    )

    assert max(consumed) == 906, "scanned past the one-line lookahead"
    assert result["total_lines"] == 906
    assert result["total_lines_exact"] is False


@pytest.mark.asyncio
async def test_open_ended_range_reports_an_exact_total(tmp_path):
    target = _big_text_file(tmp_path)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [1195, -1]}
    )

    lines = result["content"].splitlines()
    assert len(lines) == 6
    assert lines[0].startswith("line 1195")
    assert result["total_lines"] == TOTAL_LINES
    assert result["total_lines_exact"] is True
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_open_ended_range_stays_byte_bounded(tmp_path):
    """Acceptance #3: ranged content obeys the ceiling; the count still runs
    to EOF, so the total stays exact."""
    target = _big_text_file(tmp_path)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [1, -1], "max_bytes": 257}
    )

    assert len(result["content"].encode("utf-8")) <= 257
    assert result["truncated"] is True
    assert result["total_lines"] == TOTAL_LINES
    assert result["total_lines_exact"] is True


@pytest.mark.asyncio
async def test_range_past_eof_returns_empty_without_error(tmp_path):
    target = _big_text_file(tmp_path)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [5000, 5010]}
    )

    assert result["content"] == ""
    assert result["lines_returned"] == 0
    assert result["total_lines"] == TOTAL_LINES
    assert result["total_lines_exact"] is True
    assert result["view_range"] == [5000, 4999]


@pytest.mark.asyncio
async def test_utf16_bom_file_supports_late_ranges(tmp_path):
    """Acceptance #6: BOM handling survives the streaming scanner."""
    target = tmp_path / "utf16.txt"
    body = "".join(f"linea {i:04d} ñ\n" for i in range(1, 301))
    target.write_text(body, encoding="utf-16")

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "view_range": [250, 252]}
    )

    assert result["encoding"] == "utf-16"
    assert result["content"].splitlines() == [
        "linea 0250 ñ",
        "linea 0251 ñ",
        "linea 0252 ñ",
    ]


@pytest.mark.asyncio
async def test_binary_file_is_still_classified_by_the_probe(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00\x01\x02" * 4000)

    result = await _handlers(tmp_path)["read"](
        {"path": str(target), "max_bytes": 257}
    )

    assert result["encoding"] == "binary"
    assert "content" not in result
    assert result["preview_hex"].startswith("000102")


@pytest.mark.asyncio
async def test_malformed_view_range_is_rejected(tmp_path):
    from sentinelx_core.executor import HandlerError

    target = _big_text_file(tmp_path, lines=5)
    with pytest.raises(HandlerError) as exc:
        await _handlers(tmp_path)["read"](
            {"path": str(target), "view_range": ["900", 905]}
        )
    assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_ranged_scan_runs_off_the_event_loop(tmp_path, monkeypatch):
    """The scan must stay in the worker thread the #25 fix put it in."""
    target = _big_text_file(tmp_path)
    original_open = Path.open

    def slow_open(self, *args, **kwargs):
        if self == target:
            time.sleep(0.25)
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", slow_open)

    result, max_gap = await run_with_loop_probe(
        _handlers(tmp_path)["read"]({"path": str(target), "view_range": [900, 905]})
    )

    assert result["lines_returned"] == 6
    assert max_gap < 0.10, f"event loop stalled for {max_gap:.3f}s during a ranged read"
