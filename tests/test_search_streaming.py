"""Issue #29: search must not load each candidate file whole.

The old path read the probe, then the rest, concatenated them, decoded the
result and split it into a line list — four whole-file representations
alive at once, which is how a 20 MiB file cost ~90 MiB of peak allocation.
Streaming replaces that with one block plus at most one in-progress line.

The guard here is the reporter's: wrap the file object and fail the test if
`search` ever calls an unbounded `.read()`. Everything else pins semantics
that must NOT move — line numbering above all, since renumbering someone's
search results is the quiet way this "optimisation" could go wrong.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from sentinelx_core.handlers import build_registry, fileops
from sentinelx_core.policy import FileOpsPath, Policy


def _policy(tmp_path: Path) -> Policy:
    pol = Policy(file_ops_paths=(FileOpsPath(path=str(tmp_path), access="r"),))
    object.__setattr__(pol, "upload_base", tmp_path)
    return pol


def _handlers(tmp_path: Path):
    return build_registry(policy=_policy(tmp_path))


class _BoundedReadFile:
    """A file object that refuses an unbounded read()."""

    def __init__(self, real):
        self._real = real

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError("search attempted an unbounded read()")
        return self._real.read(size)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)


@pytest.fixture
def forbid_unbounded_reads(monkeypatch):
    original_open = Path.open

    def guarded_open(self, *args, **kwargs):
        handle = original_open(self, *args, **kwargs)
        if "b" in (args[0] if args else kwargs.get("mode", "r")):
            return _BoundedReadFile(handle)
        return handle

    monkeypatch.setattr(Path, "open", guarded_open)


@pytest.mark.asyncio
async def test_search_never_reads_a_whole_file_and_still_finds_late_matches(
    tmp_path, forbid_unbounded_reads
):
    """The reporter's regression: guard the read, put the match near EOF."""
    target = tmp_path / "big.log"
    filler = "".join(f"line {i} nothing to see here\n" for i in range(1, 40_000))
    target.write_text(filler + "the NEEDLE is here\n", encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "NEEDLE"}
    )

    assert len(result["matches"]) == 1
    match = result["matches"][0]
    assert match["line"] == 40_000
    assert match["column"] == 5
    assert match["text"] == "the NEEDLE is here"
    assert result["files_searched"] == 1


@pytest.mark.asyncio
async def test_search_memory_is_bounded(tmp_path):
    """Acceptance #1: a no-match scan of a large file allocates ~nothing."""
    target = tmp_path / "huge.txt"
    with target.open("w", encoding="utf-8") as f:
        for i in range(220_000):
            f.write(f"line {i:06d} " + "y" * 80 + "\n")
    size = target.stat().st_size
    assert size > 20_000_000, "fixture should be big enough to matter"

    handlers = _handlers(tmp_path)
    tracemalloc.start()
    try:
        result = await handlers["search"](
            {"path": str(tmp_path), "pattern": "NOTHING-MATCHES-THIS"}
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result["matches"] == []
    assert result["files_searched"] == 1
    assert peak < size // 10, f"peak {peak} bytes scanning a {size}-byte file"


# ---------------------------------------------------------------------------
# Semantics that must not move
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_line_numbering_matches_the_whole_file_path(tmp_path):
    """Every break str.splitlines() recognises still starts a new line."""
    body = "alpha\r\nbeta\rgamma\nd\x0celta\nTARGET here\n"
    (tmp_path / "mixed.txt").write_text(body, encoding="utf-8", newline="")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    expected_line = body.splitlines().index("TARGET here") + 1
    assert result["matches"][0]["line"] == expected_line == 6


@pytest.mark.asyncio
async def test_crlf_split_across_a_block_boundary(tmp_path, monkeypatch):
    """A "\\r\\n" straddling two reads must stay one line break."""
    monkeypatch.setattr(fileops, "_READ_BLOCK_BYTES", 64)
    # 63 bytes, then "\r" lands at byte 64 and "\n" opens the next block.
    body = "a" * 63 + "\r\n" + "TARGET\r\n" + "tail\r\n"
    (tmp_path / "crlf.txt").write_text(body, encoding="utf-8", newline="")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    assert result["matches"][0]["line"] == 2
    assert result["matches"][0]["text"] == "TARGET"


@pytest.mark.asyncio
async def test_line_longer_than_one_block(tmp_path, monkeypatch):
    monkeypatch.setattr(fileops, "_READ_BLOCK_BYTES", 128)
    long_line = "z" * 5000 + "TARGET" + "z" * 5000
    (tmp_path / "long.txt").write_text(f"first\n{long_line}\nlast\n", encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    match = result["matches"][0]
    assert match["line"] == 2
    assert match["column"] == 5001
    assert match["text"].endswith("…"), "preview stays capped"
    assert len(match["text"]) == 201


@pytest.mark.asyncio
async def test_match_on_a_final_line_without_a_newline(tmp_path):
    (tmp_path / "no_eol.txt").write_text("one\ntwo\nTARGET", encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    assert result["matches"][0]["line"] == 3


@pytest.mark.asyncio
async def test_multibyte_columns_are_character_offsets(tmp_path):
    (tmp_path / "utf8.txt").write_text("ñañá TARGET\n", encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    assert result["matches"][0]["column"] == 6


@pytest.mark.asyncio
async def test_regex_case_and_glob_are_unchanged(tmp_path):
    (tmp_path / "a.py").write_text("def Handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("def Handler():\n", encoding="utf-8")
    handlers = _handlers(tmp_path)

    hits = await handlers["search"](
        {
            "path": str(tmp_path),
            "pattern": r"def\s+handler",
            "regex": True,
            "file_glob": "*.py",
        }
    )
    assert [m["file"] for m in hits["matches"]] == ["a.py"]

    sensitive = await handlers["search"](
        {"path": str(tmp_path), "pattern": "def handler", "case_sensitive": True}
    )
    assert sensitive["matches"] == []


@pytest.mark.asyncio
async def test_result_cap_still_truncates(tmp_path):
    (tmp_path / "many.txt").write_text("TARGET\n" * 50, encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET", "max_results": 5}
    )

    assert len(result["matches"]) == 5
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_binary_files_are_still_skipped(tmp_path):
    """Acceptance #4."""
    (tmp_path / "blob.dat").write_bytes(b"TARGET\x00" + b"\x00\x01" * 5000)
    (tmp_path / "ok.txt").write_text("TARGET\n", encoding="utf-8")

    result = await _handlers(tmp_path)["search"](
        {"path": str(tmp_path), "pattern": "TARGET"}
    )

    assert [m["file"] for m in result["matches"]] == ["ok.txt"]
    assert result["files_searched"] == 1
