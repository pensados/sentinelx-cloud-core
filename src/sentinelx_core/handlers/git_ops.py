"""git_ops handler: structured Git operations (the `sentinel_git` tool).

ONE agent op ``git`` with an internal ``operation`` selector:

  - ``diff``        (read-only) : one bounded, structured view of a repo's
                                  current changes — replaces a chain of
                                  status / diff --stat / diff <file> exec calls.
  - ``apply_patch`` (rw mutation): apply one unified diff touching several
                                  files, all-or-nothing.

Why one op with an internal selector (not two agent ops)? It keeps the agent
surface small and mirrors how the hub presents compute/notifications as one
tool with an ``operation`` — adapted to the agent side.

GIT QUARANTINE (spec §0/§1): every git-specific concept lives in THIS module.
Nothing here bleeds into ``edit`` or the agnostic core primitives. A non-coding
operator sees one ``git`` tool they can ignore; ``edit`` stays pure.

Security substrate is copied verbatim from ``project_snapshot.py`` (the
canonical template): a fixed ``_GIT_ENV``, a fixed-argv ``_run_git`` that never
uses a shell, per-command and total timeouts, and — critically — the git-root
REVALIDATION against the file_ops allowlist. Path validation reuses
``fileops`` (``_resolve_or_reject`` for the read op) and, for the mutation,
``policy.resolve_path(path, need_write=True)`` exactly like ``edit``/``fsmutate``.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers.fileops import _require_str, _resolve_or_reject
from sentinelx_core.policy import Policy

# --- Hard caps (server ceilings ALWAYS win over any request-provided value) --
_MAX_FILES_CEILING = 50            # max file entries returned by diff
_MAX_PATCH_BYTES_CEILING = 131072  # 128 KiB: per-file patch byte cap
_MAX_TOTAL_PATCH_BYTES = 524288    # 512 KiB: whole-response patch budget
_MAX_CONTEXT_LINES = 10            # clamp for unified context
_DEFAULT_CONTEXT_LINES = 3
_MAX_APPLY_PATCH_BYTES = 5 * 1024 * 1024  # 5 MiB: reject absurd patches early

_GIT_CMD_TIMEOUT = 15  # seconds, per git invocation
_TOTAL_TIMEOUT = 45    # seconds, whole operation

# Copied verbatim from project_snapshot.py — do not diverge.
_GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",   # never prompt for credentials
    "GIT_OPTIONAL_LOCKS": "0",    # don't take optional locks
    "GIT_PAGER": "cat",           # no pager
    "GIT_CONFIG_NOSYSTEM": "1",   # ignore /etc/gitconfig quirks
}


async def _run_git(
    root: Path, *args: str, stdin: bytes | None = None
) -> tuple[int, bytes, bytes]:
    """Run a fixed git argv under ``root``. Returns (rc, stdout, stderr).

    NEVER a shell. Optional ``stdin`` bytes are fed to the process (used by
    apply_patch to pass the patch without a temp file).
    """
    env = {**os.environ, **_GIT_ENV}
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(root), "-c", "core.fsmonitor=false", *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin), timeout=_GIT_CMD_TIMEOUT
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        raise HandlerError("git_timeout", f"git {args[0] if args else '?'} timed out")
    return proc.returncode or 0, out, err


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        return default
    return max(lo, min(value, hi))


async def _revalidate_git_root(policy: Policy, root: Path, path: str) -> Path:
    """Confirm ``root`` is inside a git repo AND the repo root is STILL inside
    the file_ops allowlist (read access). A repo whose real root sits ABOVE an
    allowed path is rejected — we never silently climb out of the sandbox."""
    rc, out, _ = await _run_git(root, "rev-parse", "--show-toplevel")
    if rc != 0 or not out.strip():
        raise HandlerError(
            "not_a_git_repo",
            f"{path!r} is not inside a git repository. (git diff/apply operate "
            "on a working tree; use project_snapshot for a plain directory.)",
        )
    git_root_str = out.decode("utf-8", "replace").strip()
    try:
        return _resolve_or_reject(policy, git_root_str)
    except HandlerError:
        raise HandlerError(
            "git_root_outside_allowlist",
            f"the repository root ({git_root_str!r}) resolves OUTSIDE the "
            "file_ops allowlist; refusing to operate on it.",
            details={"git_root": git_root_str},
        )


# ---------------------------------------------------------------------------
# diff (read-only)
# ---------------------------------------------------------------------------


def _sum_numstat(raw: bytes) -> tuple[int, int, int]:
    """Sum insertions/deletions from ``git diff --numstat -z``.

    Returns (files, ins, dels). Robust to ``-`` (binary) markers and to the
    rename form where the path is NUL-split after the ins/dels header.
    """
    files = ins = dels = 0
    for token in raw.split(b"\x00"):
        if not token.strip():
            continue
        parts = token.decode("utf-8", "replace").split("\t")
        if len(parts) >= 2 and (parts[0].isdigit() or parts[0] == "-"):
            files += 1
            try:
                ins += int(parts[0]) if parts[0] != "-" else 0
                dels += int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                pass
    return files, ins, dels


def _file_numstat(raw: bytes) -> tuple[int, int, bool]:
    """Parse a single-file ``git diff --numstat -z`` into (ins, dels, binary)."""
    for token in raw.split(b"\x00"):
        if not token.strip():
            continue
        parts = token.decode("utf-8", "replace").split("\t")
        if len(parts) >= 2:
            if parts[0] == "-" and parts[1] == "-":
                return 0, 0, True
            try:
                return int(parts[0]), int(parts[1]), False
            except ValueError:
                return 0, 0, False
    return 0, 0, False


_STATUS_LABEL = {
    "A": "added", "M": "modified", "D": "deleted", "R": "renamed",
    "C": "copied", "T": "typechange", "U": "unmerged",
}


def _parse_name_status(raw: bytes) -> list[dict[str, Any]]:
    """Parse ``git diff --name-status -z`` into ordered change records.

    Under ``-z`` each field is NUL-separated: a status token, then the path
    token(s). Renames/copies (status starting with R/C) carry a similarity
    score and TWO paths (old, new); we key on the NEW path.
    """
    tokens = [t for t in raw.split(b"\x00")]
    out: list[dict[str, Any]] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i].decode("utf-8", "replace")
        if not tok:
            i += 1
            continue
        letter = tok[0]
        if letter in ("R", "C"):
            old = tokens[i + 1].decode("utf-8", "replace") if i + 1 < n else ""
            new = tokens[i + 2].decode("utf-8", "replace") if i + 2 < n else ""
            out.append({
                "path": new, "old_path": old,
                "status": _STATUS_LABEL.get(letter, letter.lower()),
            })
            i += 3
        else:
            path = tokens[i + 1].decode("utf-8", "replace") if i + 1 < n else ""
            out.append({
                "path": path, "old_path": None,
                "status": _STATUS_LABEL.get(letter, letter.lower()),
            })
            i += 2
    return out


def _diff_selector(base_ref: str, staged: bool, unstaged: bool) -> list[str]:
    """Return the base ``git diff`` argv for the requested view."""
    if staged and unstaged:
        return ["diff", base_ref]
    if staged:
        return ["diff", "--cached", base_ref]
    return ["diff"]


async def _op_diff(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    path = _require_str(payload, "path")
    root = _resolve_or_reject(policy, path)  # read-only allowlist (r or rw)
    if not root.exists():
        raise HandlerError("not_found", f"path does not exist: {path!r}")
    if not root.is_dir():
        raise HandlerError(
            "is_file", "git diff expects a directory (a path inside the repo)."
        )

    base_ref = payload.get("base_ref") or "HEAD"
    if not isinstance(base_ref, str):
        raise HandlerError("invalid_payload", "base_ref must be a string")
    staged = _as_bool(payload.get("staged"), True)
    unstaged = _as_bool(payload.get("unstaged"), True)
    include_untracked = _as_bool(payload.get("include_untracked"), True)
    if not staged and not unstaged:
        raise HandlerError(
            "invalid_payload",
            "at least one of staged / unstaged must be true.",
        )
    ctx = _clamp_int(
        payload.get("context_lines"), _DEFAULT_CONTEXT_LINES, 0, _MAX_CONTEXT_LINES
    )
    max_files = _clamp_int(
        payload.get("max_files"), _MAX_FILES_CEILING, 1, _MAX_FILES_CEILING
    )
    max_patch_bytes = _clamp_int(
        payload.get("max_patch_bytes"), _MAX_PATCH_BYTES_CEILING,
        1024, _MAX_PATCH_BYTES_CEILING,
    )

    async def _work() -> dict[str, Any]:
        git_root = await _revalidate_git_root(policy, root, path)
        selector = _diff_selector(base_ref, staged, unstaged)

        _, ns_all, _ = await _run_git(
            git_root, *selector, "--no-ext-diff", "--numstat", "-z"
        )
        files_total, ins_total, dels_total = _sum_numstat(ns_all)

        _, nstat, _ = await _run_git(
            git_root, *selector, "--no-ext-diff", "--name-status", "-z"
        )
        changed = _parse_name_status(nstat)

        untracked: list[str] = []
        if include_untracked:
            _, uo, _ = await _run_git(
                git_root, "ls-files", "--others", "--exclude-standard", "-z"
            )
            untracked = [p for p in uo.decode("utf-8", "replace").split("\x00") if p]

        files_out: list[dict[str, Any]] = []
        truncated_files = False
        truncated_patch = False
        budget = _MAX_TOTAL_PATCH_BYTES

        kept = changed[:max_files]
        if len(changed) > max_files:
            truncated_files = True

        for c in kept:
            fpath = c["path"]
            old_path = c.get("old_path")
            pathspec = [old_path, fpath] if old_path else [fpath]

            _, fns, _ = await _run_git(
                git_root, *selector, "--no-ext-diff", "--numstat", "-z",
                "--", *pathspec,
            )
            fi, fd, binary = _file_numstat(fns)

            entry: dict[str, Any] = {
                "path": fpath,
                "status": c["status"],
                "insertions": fi,
                "deletions": fd,
                "binary": binary,
                "patch": None,
            }
            if old_path:
                entry["old_path"] = old_path

            if not binary:
                _, praw, _ = await _run_git(
                    git_root, *selector, "--no-ext-diff", f"--unified={ctx}",
                    "--", *pathspec,
                )
                if len(praw) > max_patch_bytes or len(praw) > budget:
                    truncated_patch = True
                else:
                    entry["patch"] = praw.decode("utf-8", "replace")
                    budget -= len(praw)
            files_out.append(entry)

        if include_untracked:
            room = max_files - len(files_out)
            if room > 0:
                for up in untracked[:room]:
                    files_out.append({
                        "path": up,
                        "status": "untracked",
                        "insertions": 0,
                        "deletions": 0,
                        "binary": False,
                        "patch": None,
                    })
                if len(untracked) > room:
                    truncated_files = True
            elif untracked:
                truncated_files = True

        return {
            "ok": True,
            "version": 1,
            "root": str(git_root),
            "base_ref": base_ref,
            "summary": {
                "files": files_total,
                "insertions": ins_total,
                "deletions": dels_total,
                "untracked": len(untracked),
            },
            "files": files_out,
            "truncated": {"files": truncated_files, "patch": truncated_patch},
        }

    try:
        return await asyncio.wait_for(_work(), timeout=_TOTAL_TIMEOUT)
    except asyncio.TimeoutError:
        raise HandlerError("timeout", "git diff exceeded its time budget")


# ---------------------------------------------------------------------------
# apply_patch (rw mutation)
# ---------------------------------------------------------------------------


def _extract_patch_paths(patch: str) -> list[str]:
    """Enumerate the repo-relative file paths a unified diff targets.

    We parse the ``--- ``/``+++ `` headers (stripping the git ``a/``/``b/``
    prefix and any trailing tab-timestamp) plus ``rename/copy from|to`` lines.
    ``/dev/null`` (add/delete side) is ignored. Best-effort but conservative:
    anything we cannot make sense of is surfaced by the subsequent
    ``git apply --check`` rather than silently applied. The extracted paths are
    then validated against the repo root + rw allowlist BEFORE any mutation.
    """
    def _strip(rest: str) -> str | None:
        p = rest.split("\t", 1)[0].strip()
        if not p or p == "/dev/null":
            return None
        if p.startswith(("a/", "b/")):
            p = p[2:]
        return p or None

    out: list[str] = []
    seen: set[str] = set()

    def _add(p: str | None) -> None:
        if p and p not in seen:
            seen.add(p)
            out.append(p)

    for raw in patch.splitlines():
        if raw.startswith("--- ") or raw.startswith("+++ "):
            _add(_strip(raw[4:]))
        elif raw.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            _add(raw.split(" ", 2)[2].strip())
    return out


def _validate_patch_paths(policy: Policy, git_root: Path, paths: list[str]) -> None:
    """Reject absolute / ``..`` / symlink-escape / out-of-rw target paths BEFORE
    any git invocation. Each path is canonicalized (symlinks included) via
    ``policy.resolve_path(need_write=True)`` and must land inside the repo root
    AND under an rw entry."""
    rw_paths = [e.path for e in policy.file_ops_paths if e.access == "rw"]
    for p in paths:
        if p.startswith('"'):
            raise HandlerError(
                "patch_unsafe_path",
                f"quoted/escaped path is not supported in V1: {p!r}",
            )
        if os.path.isabs(p):
            raise HandlerError(
                "patch_unsafe_path", f"absolute path in patch is not allowed: {p!r}"
            )
        if ".." in Path(p).parts:
            raise HandlerError(
                "patch_unsafe_path", f"'..' in patch path is not allowed: {p!r}"
            )
        candidate = git_root / p
        resolved = policy.resolve_path(str(candidate), need_write=True)
        if resolved is None:
            raise HandlerError(
                "path_not_allowed",
                f"patch touches a path outside the rw allowlist: {p!r}. "
                "apply_patch requires every target under a file_ops rw entry.",
                details={"writable_paths": rw_paths, "path": p},
            )
        if resolved != git_root and not resolved.is_relative_to(git_root):
            raise HandlerError(
                "patch_unsafe_path",
                f"patch path escapes the repository root: {p!r}",
                details={"git_root": str(git_root)},
            )


def _parse_apply_numstat(raw: bytes) -> tuple[int, int, int]:
    """Parse ``git apply --numstat`` (newline-separated ins\\tdels\\tpath)."""
    files = ins = dels = 0
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            files += 1
            try:
                ins += int(parts[0]) if parts[0] != "-" else 0
                dels += int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                pass
    return files, ins, dels


def _scrub(text: str, git_root: Path) -> str:
    """Strip the absolute repo-root prefix from git stderr (don't leak host
    paths) and bound the length."""
    gr = str(git_root)
    return text.replace(gr + os.sep, "").replace(gr, "").strip()[:1000]


async def _op_apply_patch(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    req = payload.get("root") or payload.get("path")
    if not isinstance(req, str) or not req.strip():
        raise HandlerError(
            "invalid_payload", "apply_patch requires 'root' (the repository path)."
        )
    patch = payload.get("patch")
    if not isinstance(patch, str) or not patch.strip():
        raise HandlerError(
            "invalid_payload",
            "apply_patch requires a non-empty 'patch' (a unified diff).",
        )
    if len(patch.encode("utf-8")) > _MAX_APPLY_PATCH_BYTES:
        raise HandlerError(
            "invalid_payload",
            f"patch exceeds the {_MAX_APPLY_PATCH_BYTES // (1024*1024)} MiB ceiling.",
        )
    dry_run = _as_bool(payload.get("dry_run"), False)

    # The target repo MUST be under an rw entry (mutation). Mirrors edit/fsmutate.
    resolved = policy.resolve_path(req, need_write=True)
    if resolved is None:
        raise HandlerError(
            "path_not_allowed",
            "apply_patch requires the repository under a file_ops entry with "
            f"access: rw. {req!r} is not within any rw path.",
            details={
                "writable_paths": [
                    e.path for e in policy.file_ops_paths if e.access == "rw"
                ]
            },
        )
    if not resolved.exists():
        raise HandlerError("not_found", f"path does not exist: {req!r}")
    if not resolved.is_dir():
        raise HandlerError("is_file", "apply_patch expects the repository directory.")

    async def _work() -> dict[str, Any]:
        # Revalidate the git root AND require it under rw (not just readable).
        rc, out, _ = await _run_git(resolved, "rev-parse", "--show-toplevel")
        if rc != 0 or not out.strip():
            raise HandlerError(
                "not_a_git_repo", f"{req!r} is not inside a git repository."
            )
        git_root_str = out.decode("utf-8", "replace").strip()
        git_root = policy.resolve_path(git_root_str, need_write=True)
        if git_root is None:
            raise HandlerError(
                "git_root_outside_allowlist",
                f"the repository root ({git_root_str!r}) is not under a file_ops "
                "rw entry; refusing to apply.",
                details={"git_root": git_root_str},
            )

        patch_bytes = patch.encode("utf-8")

        # Enumerate + validate every target path BEFORE any git that could mutate.
        paths = _extract_patch_paths(patch)
        if not paths:
            raise HandlerError(
                "invalid_payload",
                "could not find any target file paths in the patch (expected a "
                "unified diff with --- / +++ headers).",
            )
        _validate_patch_paths(policy, git_root, paths)

        # Summary from a query-only numstat (never mutates).
        rc_ns, ns_out, _ = await _run_git(
            git_root, "apply", "--numstat", "--no-3way", "-", stdin=patch_bytes
        )
        files = ins = dels = 0
        if rc_ns == 0:
            files, ins, dels = _parse_apply_numstat(ns_out)

        # --check first: validate without mutating. On failure, mutate nothing.
        rc_chk, _, chk_err = await _run_git(
            git_root, "apply", "--check", "--no-3way", "-", stdin=patch_bytes
        )
        if rc_chk != 0:
            raise HandlerError(
                "patch_does_not_apply",
                _scrub(chk_err.decode("utf-8", "replace"), git_root)
                or "git apply --check rejected the patch.",
                details={"root": str(git_root), "dry_run": dry_run},
            )

        if dry_run:
            return {
                "ok": True, "version": 1, "applied": False, "dry_run": True,
                "root": str(git_root),
                "summary": {"files": files, "insertions": ins, "deletions": dels},
            }

        # Apply for real. No --reject: all-or-nothing (git apply is atomic —
        # it verifies all hunks before touching the working tree).
        rc_app, _, app_err = await _run_git(
            git_root, "apply", "--no-3way", "-", stdin=patch_bytes
        )
        if rc_app != 0:
            raise HandlerError(
                "patch_does_not_apply",
                _scrub(app_err.decode("utf-8", "replace"), git_root)
                or "git apply failed after a passing --check.",
                details={"root": str(git_root), "dry_run": False},
            )

        return {
            "ok": True, "version": 1, "applied": True, "dry_run": False,
            "root": str(git_root),
            "summary": {"files": files, "insertions": ins, "deletions": dels},
        }

    try:
        return await asyncio.wait_for(_work(), timeout=_TOTAL_TIMEOUT)
    except asyncio.TimeoutError:
        raise HandlerError("timeout", "git apply_patch exceeded its time budget")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def make_git_handler(policy: Policy):
    """Return the async handler for the single agent op ``git``.

    Dispatches on ``payload['operation']`` in {"diff", "apply_patch"}.
    """
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        operation = payload.get("operation")
        if operation == "diff":
            return await _op_diff(policy, payload)
        if operation == "apply_patch":
            return await _op_apply_patch(policy, payload)
        raise HandlerError(
            "invalid_payload",
            "git: 'operation' must be 'diff' or 'apply_patch' "
            f"(got {operation!r}).",
        )

    return handle
