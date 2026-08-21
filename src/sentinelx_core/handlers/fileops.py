"""fileops handlers: read-only filesystem primitives.

Three ops, each constrained by the unified `policy.file_ops_paths`
allowlist (read/list/search resolve under any entry, r or rw):

  - read    -> read a file with optional line range
  - list    -> list a directory, structured (entries with type/size/mtime)
  - search  -> recursive grep-like search across an allowed subtree

Why separate primitives instead of letting the LLM call `cat`, `ls`, `grep`
via `exec`? Three reasons:

  1. SHAPE. `exec` returns stdout/stderr/return-code as opaque strings.
     A primitive can return structured data (a list of files with metadata,
     a list of matches with file+line+text) that the LLM consumes natively
     without parsing.

  2. SAFETY. `exec` requires command-by-command allowlisting; the operator
     must enable `cat`, `head`, `tail`, `find`, `grep`, etc. Each one is
     a shell command with its own quoting quirks and option flags. The
     read/list/search primitives have one shape, one set of options, one
     allowlist (paths instead of commands).

  3. PERFORMANCE. `search` can bail out at max_results without rendering
     the rest. A `grep | head -n 200` pipeline can't always do that.

Security model — read-only and bounded
=======================================

These primitives are STRICTLY read-only. They never write, never sudo,
never escalate. The agent runs as user `sentinelx` (or in dev as carlos)
and inherits its unix permissions:

  - The agent can only read files it has the unix bits to read.
  - For files only readable by root, the primitives return
    "permission_denied" — they do NOT try `sudo cat`. That decision is
    deliberate: a primitive that escalates is harder to reason about
    and easier to misuse.

  - The handler enforces a PATH allowlist (`policy.file_ops_paths`)
    BEFORE filesystem access. Even if the agent user can read `/etc/shadow`
    (it can't, but as a hypothetical), the primitive refuses unless `/etc`
    is in the allowlist. Path resolution canonicalizes symlinks, so
    /workspace/escape -> /etc/shadow does NOT bypass the check.

  - Output is bounded by policy: max bytes per read, max entries per list,
    max results per search. Beyond these limits the response carries a
    `truncated=true` flag so the caller knows to narrow the query.

Error codes
===========

  invalid_payload     missing/bad-type required field
  path_not_allowed    path falls outside allowed_read_paths
  not_found           path doesn't exist
  is_directory        `read` was called on a directory
  is_file             `list` was called on a non-directory
  permission_denied   unix bits prevent reading
  too_many_results    only returned if EXPLICITLY requested (we prefer
                      to set truncated=true and return what we have)

Concurrency — filesystem work never runs on the event loop
==========================================================

The three ops are exposed as async handlers, but the filesystem work
itself is blocking: opening a file on a slow disk, enumerating a deep
tree, or scanning a subtree for content takes as long as it takes. Run
directly in the coroutine, that time is time the agent's event loop is
NOT scheduling anything else — including the WebSocket control plane
(issue #25).

So each op is written as a plain synchronous `_*_blocking` function
holding all of the policy, traversal and bounding logic, and the async
handler is a thin wrapper that hands it to `asyncio.to_thread`. That is
the default executor: a bounded, shared thread pool, so no dedicated
thread is created per request. Semantics are unchanged — the same
function body, the same HandlerError propagation, the same response
shape — only the thread it runs on differs.
"""

from __future__ import annotations

import asyncio
import codecs
import fnmatch
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core import platform_guidance as _pg
from sentinelx_core.policy import Policy


# Directories we always skip during recursive list/search, regardless of
# show_hidden. These contain build artifacts, VCS internals, or
# pip/npm caches — never useful to walk for the LLM, and walking them
# wastes time and can blow past the result cap on a real repo.
_ALWAYS_SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".tox", ".eggs",
})

# Files we always skip for search (binary or noisy). list still shows them.
_SEARCH_SKIP_FILES = frozenset({
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".class",
    ".jar", ".war", ".o", ".a", ".bin",
})

# Probe size for binary detection. Reading the first 8KB and looking
# for NUL bytes is the same heuristic git uses.
_BINARY_PROBE_BYTES = 8192

# Max characters of the matched line returned by `search`. Keeps results
# compact even when matched lines are long minified JS or similar.
_SEARCH_LINE_PREVIEW_CHARS = 200


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_str(payload: dict[str, Any], key: str) -> str:
    """Pull a required string from payload or raise HandlerError."""
    val = payload.get(key)
    if not isinstance(val, str) or not val.strip():
        raise HandlerError(
            "invalid_payload",
            f"missing or non-string {key!r}",
        )
    return val


def _resolve_or_reject(policy: Policy, path: str) -> Path:
    """Resolve `path` against the unified file_ops allowlist or raise
    path_not_allowed.

    read/list/search are non-mutating, so they resolve under ANY
    file_ops entry regardless of access level (r or rw) — we pass
    need_write=False. The access level only gates mutation (edit and
    the destructive ops); reading an rw path is obviously fine.

    Returns the canonical Path on success. Raises HandlerError with
    a helpful message on failure — we surface both "the allowlist is
    empty" and "this path isn't in your list" as the same error code
    but with distinct messages, so the operator knows which it is.
    """
    if not policy.file_ops_paths:
        raise HandlerError(
            "path_not_allowed",
            "file_ops has no paths configured in this agent's "
            "config.yaml. Add at least one entry under file_ops.paths "
            "(or the legacy file_ops.allowed_read_paths) to enable "
            "read/list/search.",
            details={"path": path, "configured_paths": []},
        )

    resolved = policy.resolve_path(path, need_write=False)
    if resolved is None:
        raise HandlerError(
            "path_not_allowed",
            f"path {path!r} (or its target after resolving symlinks) is not "
            "under any configured file_ops path. To allow reading here, add "
            f"an entry under file_ops.paths (with the operator's approval, via "
            f"{_pg.edit_config_via()}) covering a parent directory, with "
            "access 'r' for read-only or 'rw' to also allow edits, then "
            f"{_pg.reload_agent()}.",
            details={
                "path": path,
                "configured_paths": [
                    {"path": e.path, "access": e.access}
                    for e in policy.file_ops_paths
                ],
            },
        )
    return resolved


def _stat_safe(p: Path) -> os.stat_result | None:
    """stat() that returns None instead of raising for missing/EACCES."""
    try:
        return p.lstat()
    except (OSError, PermissionError):
        return None


def _file_type(st: os.stat_result) -> str:
    """Map stat mode to a short label."""
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block"
    if stat.S_ISCHR(mode):
        return "char"
    return "other"


def _looks_binary(data: bytes) -> bool:
    """Same heuristic git uses: any NUL byte in the probe = binary."""
    return b"\x00" in data


def _bom_encoding(data: bytes) -> str | None:
    """Detect a Unicode BOM at the start of the probe and return the codec to
    decode with, else None. Windows tools frequently emit UTF-16, whose ASCII
    bytes are XX 00 -- the NUL heuristic would misflag those as binary. The
    'utf-16' codec auto-detects endianness from the BOM and strips it."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return None


# ---------------------------------------------------------------------------
# read handler
# ---------------------------------------------------------------------------


# Block size for the streaming line scanner used by ranged reads. Big
# enough that a range near the start of a huge file costs one or two
# reads, small enough that nothing large is held in memory.
_READ_BLOCK_BYTES = 64 * 1024


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _clip_utf8(text: str, max_bytes: int) -> str:
    """Trim `text` to at most `max_bytes` UTF-8 bytes.

    A multi-byte character straddling the boundary is dropped rather than
    returned as a mangled fragment.
    """
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore")


def _count_lines(text: str) -> int:
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def _iter_lines(f, encoding: str):
    """Yield decoded lines from an open binary file, in bounded blocks.

    A line is what ends in "\\n" — the same definition `total_lines` has
    always used, applied now to `view_range` too. The file is never
    materialized: scanning to line 900 of a multi-gigabyte log costs
    blocks, not the file. An incremental decoder handles the BOM and, for
    UTF-16, the endianness and code units split across block edges.
    """
    decoder = codecs.getincrementaldecoder(encoding)("replace")
    buf = ""
    while True:
        chunk = f.read(_READ_BLOCK_BYTES)
        if not chunk:
            buf += decoder.decode(b"", final=True)
            if buf:
                yield buf
            return
        buf += decoder.decode(chunk)
        if "\n" not in buf:
            continue
        parts = buf.split("\n")
        buf = parts.pop()
        for part in parts:
            yield part + "\n"


def _scan_range(f, encoding: str, cap: int, start: int, end: int):
    """Stream `f` and collect lines [start, end], 1-indexed, end=-1 = EOF.

    Returns (text, lines_seen, total_is_exact, truncated, last_line).

    Two ceilings, deliberately independent (issue #27):

      * returned content never exceeds `cap` UTF-8 bytes;
      * a FINITE range stops one line past `end` — that lookahead is all
        that is needed to know the file continues, and it avoids scanning
        the remainder of a huge log purely to produce a total. When the
        scan stops that way, lines_seen is a lower bound and
        total_is_exact is False.

    `end=-1` scans to EOF, so the total is exact; the content stays
    bounded because collection stops once `cap` is reached while the
    counting continues.
    """
    to_eof = end == -1
    pieces: list[str] = []
    used = 0
    truncated = False
    lines_seen = 0
    last = start - 1
    exact = True

    for line in _iter_lines(f, encoding):
        lines_seen += 1
        if lines_seen < start:
            continue
        if not to_eof and lines_seen > end:
            # The one-line lookahead: the file continues past the range.
            exact = False
            break
        if truncated:
            continue
        room = cap - used
        if _utf8_len(line) <= room:
            pieces.append(line)
            used += _utf8_len(line)
            last = lines_seen
        else:
            clipped = _clip_utf8(line, room)
            if clipped:
                pieces.append(clipped)
                used += _utf8_len(clipped)
                last = lines_seen
            truncated = True

    return "".join(pieces), lines_seen, exact, truncated, last


def make_read_handler(policy: Policy):
    """Return an async handler for the `read` op bound to the policy."""

    def _read_blocking(payload: dict[str, Any]) -> dict[str, Any]:
        """Read a file's contents. BLOCKING — runs in a worker thread.

        Payload:
          path:        str (required)
          view_range:  [int, int] optional (1-indexed, inclusive). Either
                       end can be -1 to mean "to the end of file". If
                       omitted, the file's prefix is returned (subject to
                       max_bytes truncation).
          max_bytes:   int optional. Hard ceiling on the returned content,
                       in UTF-8 bytes. Defaults to
                       policy.file_ops_max_read_bytes and is clamped to it.

        Returns:
          {
            "ok": true,
            "path": "<resolved-path>",
            "encoding": "utf-8" | "utf-16" | "binary",
            "content": "<file content as string>",
            "total_lines": N,            # only when text
            "total_lines_exact": bool,   # false => N is a LOWER BOUND
            "lines_returned": N,         # only when text
            "view_range": [start, end],  # if view_range was used
            "size_bytes": N,
            "truncated": true|false,
            "modified_at": "<iso>",
          }

        Three concerns kept separate (issue #27): the binary/BOM probe may
        inspect up to _BINARY_PROBE_BYTES no matter how small max_bytes is,
        but that buffer is never the returned content; the returned content
        obeys max_bytes; and a ranged read may scan as far into the file as
        the requested lines require without materializing it.
        """
        path_str = _require_str(payload, "path")
        resolved = _resolve_or_reject(policy, path_str)

        st = _stat_safe(resolved)
        if st is None:
            # Could be not-found OR permission to stat the parent. Probe
            # to give a clearer error.
            if not resolved.exists():
                raise HandlerError("not_found", f"path does not exist: {path_str!r}")
            raise HandlerError(
                "permission_denied",
                f"cannot access {path_str!r}: the agent's OS user lacks "
                "Unix permission on it or a parent directory (read/list/"
                "search never use sudo by design). Ask the operator to "
                "grant the agent's user read+execute on the directory "
                "(chmod/chown or an ACL), or run the agent as a user that "
                "can access it.",
            )

        if stat.S_ISDIR(st.st_mode):
            raise HandlerError(
                "is_directory",
                f"{path_str!r} is a directory. Use `list` instead.",
            )
        if not stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            raise HandlerError(
                "invalid_payload",
                f"{path_str!r} is not a regular file (type={_file_type(st)}).",
            )

        # Clamp max_bytes to policy cap. Don't let the caller request more
        # than we're configured to give. (If they want more, the operator
        # can raise the policy cap.)
        cap = policy.file_ops_max_read_bytes
        requested = payload.get("max_bytes")
        if isinstance(requested, int) and requested > 0:
            cap = min(cap, requested)

        # Validated up front: a malformed range is the caller's mistake and
        # should not depend on whether the file happens to be readable.
        view_range = payload.get("view_range")
        start = end = None
        if view_range is not None:
            if (
                not isinstance(view_range, (list, tuple))
                or len(view_range) != 2
                or not all(isinstance(x, int) for x in view_range)
            ):
                raise HandlerError(
                    "invalid_payload",
                    "view_range must be a [start, end] pair of integers "
                    "(1-indexed). Use -1 for end to mean 'to the end'.",
                )
            start = max(1, view_range[0])
            end = view_range[1]

        size = st.st_size
        modified_at = time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.gmtime(st.st_mtime)
        )

        try:
            with resolved.open("rb") as f:
                # Classification probe. It may read up to 8KB even when the
                # caller asked for less, because BOM/binary detection needs
                # it — but this buffer is never handed back as content.
                head = f.read(_BINARY_PROBE_BYTES)
                bom_enc = _bom_encoding(head)
                # A Unicode BOM means text even when UTF-16 trips the NUL
                # heuristic; only apply the binary check when there's no BOM.
                if bom_enc is None and _looks_binary(head):
                    # Don't return binary content as a "string" — that's
                    # never useful to the LLM. Return metadata + a hex
                    # preview of the first 256 bytes.
                    return {
                        "ok": True,
                        "path": str(resolved),
                        "encoding": "binary",
                        "size_bytes": size,
                        "preview_hex": head[:256].hex(),
                        "modified_at": modified_at,
                        "truncated": True,
                    }

                enc = bom_enc or "utf-8"
                enc_label = "utf-16" if bom_enc == "utf-16" else "utf-8"

                if view_range is None:
                    # Prefix read. `cap` bounds the content, so a request
                    # below the probe size is honoured by trimming the probe
                    # buffer rather than returning all 8KB of it.
                    if cap <= len(head):
                        data = head[:cap]
                    else:
                        data = head + f.read(cap - len(head))
                    text = data.decode(enc, errors="replace")
                    # UTF-16 source can expand when re-encoded as UTF-8, so
                    # enforce the ceiling on the OUTPUT as well.
                    clipped = _clip_utf8(text, cap)
                    truncated = size > len(data) or clipped != text
                    text = clipped
                    total_lines = _count_lines(text)
                    total_exact = not truncated
                    used_range = None
                else:
                    # The probe consumed the first bytes; the scanner needs
                    # the file from the top (its decoder handles the BOM).
                    f.seek(0)
                    text, total_lines, total_exact, truncated, last = _scan_range(
                        f, enc, cap, start, end
                    )
                    used_range = [start, last]
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot read {path_str!r}: the agent's OS user lacks Unix "
                f"read permission ([Errno {exc.errno}]). The path is "
                "allowed by policy, so this is a filesystem-permission "
                "issue, not an allowlist one, and read/list/search never "
                "use sudo by design. For a privileged read, use "
                f"sentinel_exec with 'sudo cat {path_str}' if 'sudo cat' "
                "is in allowed_commands; otherwise ask the operator to "
                "grant the agent's user read access (chmod/chown or an ACL "
                "on the file or its parent directory), or run the agent as "
                "a user that can read it.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "io_error",
                f"failed to read {path_str!r}: {exc}.",
            ) from exc

        result: dict[str, Any] = {
            "ok": True,
            "path": str(resolved),
            "encoding": enc_label,
            "content": text,
            "total_lines": total_lines,
            "total_lines_exact": total_exact,
            "lines_returned": _count_lines(text),
            "size_bytes": size,
            "truncated": truncated,
            "modified_at": modified_at,
        }
        if used_range is not None:
            result["view_range"] = used_range
        return result

    async def handle_read(payload: dict[str, Any]) -> dict[str, Any]:
        """Run the blocking read off the event loop (issue #25).

        See _read_blocking for the payload and response contract. The
        default executor is a bounded, shared pool, so a slow open/read
        costs a worker thread rather than the agent's whole control
        plane, and no per-request thread is created. HandlerError raised
        in the worker propagates unchanged.
        """
        return await asyncio.to_thread(_read_blocking, payload)

    return handle_read


# ---------------------------------------------------------------------------
# list handler
# ---------------------------------------------------------------------------


def make_list_handler(policy: Policy):
    """Return an async handler for the `list` op bound to the policy."""

    def _list_blocking(payload: dict[str, Any]) -> dict[str, Any]:
        """List directory contents. BLOCKING — runs in a worker thread.

        Payload:
          path:        str (required) — directory to list
          depth:       int optional (default 1). 1 = direct children only.
                       Capped at 5 to prevent absurd recursion.
          glob:        str optional. fnmatch-style pattern applied to
                       basenames ("*.py", "config.*", etc.).
          show_hidden: bool optional (default False). Hidden files start
                       with '.'.

        Returns:
          {
            "ok": true,
            "path": "<resolved>",
            "entries": [{"name", "type", "size", "mtime"}, ...],
            "total": N,
            "truncated": true|false,
          }

        Notes:
          - Entries are relative to `path` when depth=1, or contain a
            relative-to-`path` slash-separated key when depth>1.
          - Always skips noise dirs (.git, __pycache__, etc.) regardless
            of show_hidden.
        """
        path_str = _require_str(payload, "path")
        resolved = _resolve_or_reject(policy, path_str)

        st = _stat_safe(resolved)
        if st is None:
            if not resolved.exists():
                raise HandlerError("not_found", f"path does not exist: {path_str!r}")
            raise HandlerError(
                "permission_denied",
                f"cannot access {path_str!r}: the agent's OS user lacks "
                "Unix permission on it or a parent directory (read/list/"
                "search never use sudo by design). Ask the operator to "
                "grant read+execute on the directory, or run the agent as "
                "a user that can access it.",
            )
        if not stat.S_ISDIR(st.st_mode):
            raise HandlerError(
                "is_file",
                f"{path_str!r} is not a directory. Use `read` instead.",
            )

        depth = payload.get("depth", 1)
        if not isinstance(depth, int) or depth < 1:
            depth = 1
        depth = min(depth, 5)  # hard cap

        glob_pat = payload.get("glob")
        if glob_pat is not None and not isinstance(glob_pat, str):
            raise HandlerError("invalid_payload", "glob must be a string")

        show_hidden = bool(payload.get("show_hidden", False))

        cap = policy.file_ops_max_list_entries
        entries: list[dict[str, Any]] = []
        truncated = False

        def add_entry(entry_path: Path, depth_remaining: int) -> bool:
            """Walk one level. Returns True if cap reached (stop)."""
            nonlocal truncated
            try:
                children = sorted(
                    entry_path.iterdir(),
                    key=lambda p: (not p.is_dir(), p.name.lower()),
                )
            except PermissionError:
                # Can't list this dir — skip it silently (the parent
                # already showed it as type=dir; the LLM can ask for it
                # specifically if needed).
                return False
            except OSError:
                return False

            for child in children:
                name = child.name
                if not show_hidden and name.startswith("."):
                    continue
                if name in _ALWAYS_SKIP_DIRS and child.is_dir():
                    continue

                child_st = _stat_safe(child)
                if child_st is None:
                    continue

                # Glob match applies to the basename only.
                if glob_pat is None or fnmatch.fnmatch(name, glob_pat):
                    rel = str(child.relative_to(resolved))
                    entries.append({
                        "name": rel,
                        "type": _file_type(child_st),
                        "size": child_st.st_size,
                        "mtime": time.strftime(
                            "%Y-%m-%dT%H:%M:%S%z",
                            time.gmtime(child_st.st_mtime),
                        ),
                    })
                    if len(entries) >= cap:
                        truncated = True
                        return True

                if depth_remaining > 1 and stat.S_ISDIR(child_st.st_mode):
                    if add_entry(child, depth_remaining - 1):
                        return True

            return False

        add_entry(resolved, depth)

        return {
            "ok": True,
            "path": str(resolved),
            "entries": entries,
            "total": len(entries),
            "truncated": truncated,
        }

    async def handle_list(payload: dict[str, Any]) -> dict[str, Any]:
        """Run the blocking enumeration off the event loop (issue #25).

        See _list_blocking for the payload and response contract. A deep
        or slow recursive walk now costs a worker thread from the default
        bounded pool instead of stalling every other coroutine for the
        duration of the traversal.
        """
        return await asyncio.to_thread(_list_blocking, payload)

    return handle_list


# ---------------------------------------------------------------------------
# search handler
# ---------------------------------------------------------------------------


def make_search_handler(policy: Policy):
    """Return an async handler for the `search` op bound to the policy."""

    def _search_blocking(payload: dict[str, Any]) -> dict[str, Any]:
        """Recursive content search. BLOCKING — runs in a worker thread.

        Payload:
          path:           str (required) — root of the search
          pattern:        str (required) — what to look for
          regex:          bool optional (default False). If True, pattern
                          is a Python regex; else a literal substring.
          case_sensitive: bool optional (default False).
          file_glob:      str optional. fnmatch on basename ("*.py").
          max_results:    int optional. Capped at policy max.

        Returns:
          {
            "ok": true,
            "path": "<resolved>",
            "pattern": "...",
            "matches": [
              {"file": "<relpath>", "line": N, "column": N, "text": "..."},
              ...
            ],
            "files_searched": N,
            "truncated": true|false,
          }

        Notes:
          - Skips _ALWAYS_SKIP_DIRS and _SEARCH_SKIP_FILES extensions.
          - Skips files that look binary (first 8KB has NUL).
          - The `text` field is truncated to 200 chars.
        """
        path_str = _require_str(payload, "path")
        pattern_str = _require_str(payload, "pattern")
        resolved = _resolve_or_reject(policy, path_str)

        st = _stat_safe(resolved)
        if st is None or not stat.S_ISDIR(st.st_mode):
            # Allow search on a single file too — treat as a one-file walk.
            if st is None:
                raise HandlerError("not_found", f"path does not exist: {path_str!r}")
            # Single-file search: handled in the walk below.

        is_regex = bool(payload.get("regex", False))
        case_sensitive = bool(payload.get("case_sensitive", False))
        file_glob = payload.get("file_glob")
        if file_glob is not None and not isinstance(file_glob, str):
            raise HandlerError("invalid_payload", "file_glob must be a string")

        cap = policy.file_ops_max_search_results
        requested_cap = payload.get("max_results")
        if isinstance(requested_cap, int) and requested_cap > 0:
            cap = min(cap, requested_cap)

        # Compile the matcher once.
        if is_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                regex = re.compile(pattern_str, flags)
            except re.error as exc:
                raise HandlerError(
                    "invalid_payload",
                    f"pattern is not a valid regex: {exc}",
                ) from exc
            matcher = lambda line: regex.search(line)  # noqa: E731
        else:
            needle = pattern_str if case_sensitive else pattern_str.lower()

            def matcher(line: str):
                hay = line if case_sensitive else line.lower()
                idx = hay.find(needle)
                if idx < 0:
                    return None
                # Mimic regex.search()'s interface for downstream code:
                # we only need .start().
                class _M:
                    def __init__(self, i: int) -> None:
                        self._i = i

                    def start(self) -> int:
                        return self._i

                return _M(idx)

        matches: list[dict[str, Any]] = []
        files_searched = 0
        truncated = False

        def walk(p: Path) -> bool:
            """Walk a directory or single file. Returns True when cap reached."""
            nonlocal files_searched, truncated

            try:
                p_st = _stat_safe(p)
                if p_st is None:
                    return False

                if stat.S_ISDIR(p_st.st_mode):
                    try:
                        children = sorted(p.iterdir(), key=lambda c: c.name)
                    except (PermissionError, OSError):
                        return False
                    for child in children:
                        if child.name in _ALWAYS_SKIP_DIRS and child.is_dir():
                            continue
                        if walk(child):
                            return True
                    return False

                # File path.
                if not stat.S_ISREG(p_st.st_mode):
                    return False
                if file_glob is not None and not fnmatch.fnmatch(p.name, file_glob):
                    return False
                if p.suffix in _SEARCH_SKIP_FILES:
                    return False

                # Read + check binary.
                try:
                    with p.open("rb") as f:
                        head = f.read(_BINARY_PROBE_BYTES)
                        if _looks_binary(head):
                            return False
                        # Read the rest (text files only).
                        rest = f.read()
                    blob = head + rest
                except (PermissionError, OSError):
                    return False

                text = blob.decode("utf-8", errors="replace")
                files_searched += 1

                for lineno, line in enumerate(text.splitlines(), start=1):
                    m = matcher(line)
                    if m is None:
                        continue
                    rel = (
                        str(p.relative_to(resolved))
                        if p != resolved
                        else p.name
                    )
                    preview = line.strip()
                    if len(preview) > _SEARCH_LINE_PREVIEW_CHARS:
                        preview = preview[:_SEARCH_LINE_PREVIEW_CHARS] + "…"
                    matches.append({
                        "file": rel,
                        "line": lineno,
                        "column": m.start() + 1,
                        "text": preview,
                    })
                    if len(matches) >= cap:
                        truncated = True
                        return True
                return False
            except Exception:
                # Defensive — never let a single weird file kill the whole
                # search. Skip and continue.
                return False

        walk(resolved)

        return {
            "ok": True,
            "path": str(resolved),
            "pattern": pattern_str,
            "matches": matches,
            "files_searched": files_searched,
            "truncated": truncated,
        }

    async def handle_search(payload: dict[str, Any]) -> dict[str, Any]:
        """Run the blocking scan off the event loop (issue #25).

        See _search_blocking for the payload and response contract. A
        recursive content scan is the longest-running of the three ops,
        so this is where loop monopolization hurt most; it now runs in
        the default bounded executor.
        """
        return await asyncio.to_thread(_search_blocking, payload)

    return handle_search
