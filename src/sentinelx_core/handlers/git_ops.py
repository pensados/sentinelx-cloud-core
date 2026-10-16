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
import shutil
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers.fileops import _require_str, _resolve_or_reject
from sentinelx_core.policy import Policy
from sentinelx_core.winspawn import spawn_kwargs

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
    # Pin the language of git's own diagnostics. We branch on the text of
    # stderr -- the --recount retry looks for "corrupt patch" -- and git
    # translates that text, so on a host with a localized LANG the branch never
    # fired and the recovery silently stopped existing. Reported from a
    # pl_PL.UTF-8 host where git says "uszkodzona łatka".
    #
    # LC_ALL wins over LANG and LC_MESSAGES, so one key is enough. C rather
    # than C.UTF-8 because C.UTF-8 is not present everywhere (musl, older
    # glibc) and we only need the messages untranslated: paths still travel as
    # bytes and are never decoded through the locale.
    "LC_ALL": "C",
}


async def _run_git(
    root: Path,
    *args: str,
    stdin: bytes | None = None,
    timeout: float | None = None,
) -> tuple[int, bytes, bytes]:
    """Run a fixed git argv under ``root``. Returns (rc, stdout, stderr).

    NEVER a shell. Optional ``stdin`` bytes are fed to the process (used by
    apply_patch to pass the patch without a temp file).
    """
    env = {**os.environ, **_GIT_ENV}
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(root), "-c", "core.fsmonitor=false", *args,
        **spawn_kwargs(
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        ),
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin),
            # Local git is fast and 15s is a generous ceiling for it. A network
            # operation is a different animal: cloning a real repository over a
            # slow link legitimately takes minutes, so those pass their own.
            timeout=timeout if timeout is not None else _GIT_CMD_TIMEOUT,
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


def _dubious_ownership(stderr: bytes) -> bool:
    """Did git refuse because the repo belongs to another user?

    Git returns a non-zero rc for this, exactly as it does for "no repo here",
    so without reading stderr the two are indistinguishable -- and we reported
    both as not_a_git_repo. That message is actively wrong here: the checkout is
    a perfectly good one, sitting right where the caller said it was. Reported
    by a user whose /var/www checkout git handled fine over exec (running as the
    owner) and refused under the agent's own account.

    Matched on the stable token rather than the whole sentence, which git has
    reworded across versions and translates under a localized LANG. _GIT_ENV
    pins LC_ALL=C so this sees English, but the narrower match costs nothing.
    """
    return b"dubious ownership" in stderr


def _agent_user() -> str:
    """Name the account this agent runs as.

    The operator has to act on the permission error below, and the first thing
    they need is which user to grant. Windows has no geteuid, hence the guard.
    """
    try:
        import getpass

        name = getpass.getuser()
    except (KeyError, OSError):
        # No passwd entry for this uid, or the environment has nothing to read.
        # Rare, and never worth failing the caller's git operation over.
        name = "unknown"
    geteuid = getattr(os, "geteuid", None)
    return f"{name} (uid {geteuid()})" if geteuid is not None else name


def _permission_denied(stderr: bytes) -> bool:
    """Did the OS refuse, rather than there being no repository here?

    The same mistake _dubious_ownership fixes, with a different cause. git exits
    128 for `cannot change to '<path>': Permission denied` exactly as it does
    for "no repo here", so reading only the rc reported an EACCES as
    not_a_git_repo -- a message that states the directory is not a checkout and
    that retrying is pointless. The first half is false, and the second is true
    for entirely the wrong reason: the checkout is fine, this agent's user
    simply cannot traverse the path.

    Found on a host where /home/<user> is 0750 and the agent runs as its own
    account: every repository under it answered "not a git repository" while
    sentinel_read on a file inside said "Permission denied". Two tools, one
    cause, contradictory diagnoses -- and the git one sent the caller looking
    for a repo that was never missing.

    "Permission denied (publickey)" is a transport failure from the network
    operations and means something else entirely. It cannot reach this helper
    today; excluding it keeps that true if the call sites ever move.
    """
    low = stderr.lower()
    return b"permission denied" in low and b"publickey" not in low


async def _revalidate_git_root(policy: Policy, root: Path, path: str) -> Path:
    """Confirm ``root`` is inside a git repo AND the repo root is STILL inside
    the file_ops allowlist (read access). A repo whose real root sits ABOVE an
    allowed path is rejected — we never silently climb out of the sandbox."""
    rc, out, err = await _run_git(root, "rev-parse", "--show-toplevel")
    if rc != 0 and _dubious_ownership(err):
        raise HandlerError(
            "git_dubious_ownership",
            f"{path!r} IS a git checkout, but git refuses to read it because the "
            "repository is owned by a different user than the one this agent runs "
            "as. This is git's own safety check, not a SentinelX restriction, and "
            "it is why the same commands succeed over sentinel_exec when that runs "
            "as the owner. Retrying will not change it. Two ways out, both for the "
            "operator to decide on the host: give the agent's user ownership of the "
            "checkout, or declare the exception deliberately with "
            "`git config --global --add safe.directory <path>` as the agent's user. "
            "Until then, git through sentinel_exec is the working route.",
        )
    if rc != 0 and _permission_denied(err):
        raise HandlerError(
            "permission_denied",
            f"{path!r} exists, but the account this agent runs as "
            f"({_agent_user()}) cannot read it. This is the HOST's file "
            "permissions, not SentinelX's allowlist: naming a path under "
            "file_ops permits the agent to work there, it does not grant "
            "access the kernel refuses. Retrying will not change it. The "
            "operator can add the agent's user to the group owning the "
            "directory, or widen its mode. Until then git through "
            "sentinel_exec, running as the owner, is the working route.",
        )
    if rc != 0 or not out.strip():
        raise HandlerError(
            "not_a_git_repo",
            # TERMINAL BY DESIGN. Measured over 14 days: 5,523 failures here,
            # and 46% of them came from retry loops on the SAME path, worst case
            # 65 attempts. The old text said what was wrong but never that the
            # answer would not change, so models read it as transient. Only 10
            # of 4,780 had a repo in a subdirectory, so "look harder nearby" is
            # not the fix either: usually there is simply no repo.
            f"{path!r} is not inside a git repository, and retrying this same "
            "path will keep returning this. Either the directory is not a "
            "checkout, or the repository is elsewhere. To read a plain "
            "directory use project_snapshot; to locate a checkout, run "
            "sentinel_exec with something like "
            "`find <dir> -maxdepth 3 -name .git -printf '%h\\n'`.",
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
        rc, out, err = await _run_git(resolved, "rev-parse", "--show-toplevel")
        if rc != 0 and _dubious_ownership(err):
            raise HandlerError(
                "git_dubious_ownership",
                f"{req!r} IS a git checkout, but git refuses to read it because "
                "the repository is owned by a different user than the one this "
                "agent runs as. Git's own safety check, not a SentinelX "
                "restriction. The operator can either give the agent's user "
                "ownership of the checkout, or declare the exception with "
                "`git config --global --add safe.directory <path>` as that user.",
            )
        if rc != 0 and _permission_denied(err):
            raise HandlerError(
                "permission_denied",
                f"{req!r} exists, but the account this agent runs as "
                f"({_agent_user()}) cannot read it. The host's own file "
                "permissions, not SentinelX's allowlist, and retrying will "
                "not change it. The operator can add the agent's user to the "
                "group owning the directory, or widen its mode.",
            )
        if rc != 0 or not out.strip():
            raise HandlerError(
                "not_a_git_repo",
                f"{req!r} is not inside a git repository, and retrying this "
                "same path will keep returning this. To locate a checkout, run "
                "sentinel_exec with something like "
                "`find <dir> -maxdepth 3 -name .git -printf '%h\\n'`.",
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

        # Try the patch as given, and only if git rejects it as CORRUPT, try
        # again letting git recount the hunk headers.
        #
        # WHY. Measured over 14 days: ~3,100 apply_patch calls from 240 users
        # failed with "corrupt patch at line N", clustered on lines 10-22, which
        # is the first hunk. That is the signature of wrong @@ -a,b +c,d @@
        # counts, the classic failure of a model writing a unified diff by hand.
        # Verified against git: a patch whose only fault is its counts fails
        # plainly and applies with --recount.
        #
        # NOT ALWAYS ON. --recount tells git to trust the hunk BODY and redo the
        # arithmetic, so it accepts patches that are currently rejected. A patch
        # that is wrong in some other way could then apply as something slightly
        # different from what was intended. Keeping it to the second attempt
        # means everything that works today behaves exactly as it does today,
        # and the result says plainly when a recount happened.
        #
        # It does not rescue a TRUNCATED hunk: that still fails, though with
        # "patch failed: <file>:<line>", which at least points into the file
        # rather than into the patch.
        recounted = False

        async def _apply(*args: str, **kw: Any) -> tuple[int, bytes, bytes]:
            """Run git apply, retrying once with --recount on a corrupt patch."""
            nonlocal recounted
            rc, out, err = await _run_git(git_root, "apply", *args, **kw)
            if rc == 0 or b"corrupt patch" not in err:
                return rc, out, err
            rc2, out2, err2 = await _run_git(
                git_root, "apply", "--recount", *args, **kw
            )
            if rc2 == 0:
                recounted = True
                return rc2, out2, err2
            return rc, out, err  # keep the FIRST error: it names the real fault

        # Summary from a query-only numstat (never mutates).
        rc_ns, ns_out, _ = await _apply(
            "--numstat", "--no-3way", "-", stdin=patch_bytes
        )
        files = ins = dels = 0
        if rc_ns == 0:
            files, ins, dels = _parse_apply_numstat(ns_out)

        # --check first: validate without mutating. On failure, mutate nothing.
        rc_chk, _, chk_err = await _apply(
            "--check", "--no-3way", "-", stdin=patch_bytes
        )
        if rc_chk != 0:
            detail = _scrub(chk_err.decode("utf-8", "replace"), git_root)
            if b"corrupt patch" in chk_err:
                # Say what to fix. "corrupt patch at line 11" alone tells a model
                # nothing actionable, and the audit shows them retrying blind.
                detail = (
                    f"{detail} The hunk header counts were recomputed and it "
                    "still did not parse, so the hunk body itself is "
                    "incomplete: check that every line carries a leading "
                    "space, + or -, and that no context lines are missing."
                )
            raise HandlerError(
                "patch_does_not_apply",
                detail or "git apply --check rejected the patch.",
                details={"root": str(git_root), "dry_run": dry_run},
            )

        if dry_run:
            return {
                "ok": True, "version": 1, "applied": False, "dry_run": True,
                "root": str(git_root),
                "summary": {"files": files, "insertions": ins, "deletions": dels},
                # Present only when it happened, so its absence is not noise and
                # its presence is a real signal that the patch as written was
                # malformed even though the result is correct.
                **({"recounted": True} if recounted else {}),
            }

        # Apply for real. No --reject: all-or-nothing (git apply is atomic —
        # it verifies all hunks before touching the working tree).
        rc_app, _, app_err = await _apply("--no-3way", "-", stdin=patch_bytes)
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
            **({"recounted": True} if recounted else {}),
        }

    try:
        return await asyncio.wait_for(_work(), timeout=_TOTAL_TIMEOUT)
    except asyncio.TimeoutError:
        raise HandlerError("timeout", "git apply_patch exceeded its time budget")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Network operations
#
# diff and apply_patch never touch the network. These four do, which is why
# sentinel_git's openWorldHint changes with them.
#
# WHAT IS DELIBERATELY ABSENT: `pull`. It is fetch plus merge, and a merge can
# conflict, leave a dirty tree, or move HEAD somewhere the caller did not
# intend. Exposing it as one operation would hide all of that behind a verb that
# sounds atomic. fetch, then an explicit merge or rebase, is honest about what
# is happening; pull is merely convenient.
#
# CREDENTIALS ARE NEVER OURS. Every one of these runs git on the host, using
# whatever that machine already has: ssh-agent, a credential helper, a deploy
# key. SentinelX does not see, store or forward any of it, exactly as it does
# not when the same command goes through exec.
# ---------------------------------------------------------------------------

# The hub cuts a tool call at 60s by default, so anything longer here is time
# the caller never sees: git would still be running on the host while the answer
# was already lost. 50s leaves room for the reply to get back inside that
# budget. A clone that needs more than this needs --depth, or a background job,
# not a bigger number on the agent side.
_NET_TIMEOUT = 50


def _remote_hint(err: str) -> str:
    """Turn git's transport errors into something a caller can act on.

    git's own wording assumes a human with a terminal and an ssh config. A model
    reading "Permission denied (publickey)" cannot tell whether to retry, ask
    for a different URL, or stop. Each of these says which, because the audit
    shows what happens otherwise: the not_a_git_repo message never said retrying
    was pointless and models retried the same path up to 65 times.
    """
    low = err.lower()
    if "permission denied (publickey)" in low or "authentication failed" in low:
        return (
            " This host has no usable credential for that remote, and retrying "
            "will not change that. Credentials belong to the host, not to "
            "SentinelX: someone with access needs to add an SSH key, a deploy "
            "key or a credential helper there."
        )
    if "could not resolve host" in low or "name or service not known" in low:
        return (
            " The remote host name did not resolve from this machine. Check the "
            "URL, or whether this host has DNS and egress to it."
        )
    if "connection refused" in low or "connection timed out" in low:
        return (
            " The remote refused or did not answer. This may be transient, but "
            "it may equally be a firewall on this host; do not retry more than "
            "once without checking."
        )
    if "repository not found" in low or "does not appear to be a git repo" in low:
        return (
            " The remote exists but does not expose that repository to this "
            "host's credential. Often a private repo the key cannot see, which "
            "looks identical to a missing one."
        )
    if "shallow" in low:
        return " The local clone is shallow; a full history operation needs --unshallow."
    return ""


def _net_error(code: str, action: str, rc: int, err: bytes, root: Path) -> HandlerError:
    text = _scrub(err.decode("utf-8", "replace"), root).strip()
    return HandlerError(
        code,
        f"{action} failed (exit {rc}): {text or 'no output'}{_remote_hint(text)}",
    )


def _reject_option_like(value: str, field: str) -> str:
    """A remote/ref/pattern passed to git must not look like an option.

    git treats a value such as --upload-pack=<cmd> as a flag and runs <cmd>
    (reported privately, GHSA-r2h3-76g7-m95x). We reject a leading '-' and rely on
    '--' before positionals as a second line of defence.
    """
    v = (value or "").strip()
    if v.startswith("-"):
        raise HandlerError(
            "invalid_payload",
            f"{field} must not start with '-': {v!r} looks like a git option, not a "
            "remote or ref.",
        )
    return v


async def _op_ls_remote(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    """Read refs from a remote. Touches no working tree at all.

    The safest thing here, and the one that answers "what SHA is that branch on
    right now", which is what a compare-and-swap publish needs before it starts.
    """
    remote = _reject_option_like(str(payload.get("remote") or "origin"), "remote")
    pattern = payload.get("ref_pattern")
    if pattern is not None:
        pattern = _reject_option_like(str(pattern), "ref_pattern")
    path = payload.get("path")

    root = _resolve_or_reject(policy, str(path)) if path else None
    if root is not None:
        root = await _revalidate_git_root(policy, root, str(path))

    args = ["ls-remote", "--", remote]
    if pattern:
        args.append(str(pattern))
    rc, out, err = await _run_git(root or Path.cwd(), *args, timeout=_NET_TIMEOUT)
    if rc != 0:
        raise _net_error("remote_failed", f"git ls-remote {remote}", rc, err,
                         root or Path("/"))

    refs = []
    for line in out.decode("utf-8", "replace").splitlines():
        if "\t" in line:
            sha, ref = line.split("\t", 1)
            refs.append({"sha": sha.strip(), "ref": ref.strip()})
    return {"ok": True, "version": 1, "operation": "ls_remote",
            "remote": remote, "refs": refs[:200], "count": len(refs)}


async def _op_fetch(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    """Bring objects down without touching the working tree.

    Safe by construction: fetch updates remote-tracking refs and nothing the
    caller can lose. It is the honest half of what `pull` does.
    """
    # Validate the option-like inputs before resolving paths, so a bad remote/ref
    # is rejected the same way regardless of the path.
    remote = _reject_option_like(str(payload.get("remote") or "origin"), "remote")
    ref = payload.get("ref")
    if ref is not None:
        ref = _reject_option_like(str(ref), "ref")
    path = payload.get("path")
    if not path:
        raise HandlerError("invalid_payload", "fetch needs `path`: the repository.")
    root = await _revalidate_git_root(
        policy, _resolve_or_reject(policy, str(path)), str(path)
    )
    args = ["fetch", "--prune", "--", remote]
    if ref:
        args.append(ref)
    rc, out, err = await _run_git(root, *args, timeout=_NET_TIMEOUT)
    if rc != 0:
        raise _net_error("remote_failed", f"git fetch {remote}", rc, err, root)
    return {"ok": True, "version": 1, "operation": "fetch", "root": str(root),
            "remote": remote,
            "output": _scrub(err.decode("utf-8", "replace"), root).strip()[:2000]}


def _discard_partial_clone(target: Path, created_by_us: bool) -> None:
    """Remove a checkout that git did not finish writing.

    ONLY when git itself created the directory in this call. The caller has
    already been told the destination must be empty, but "empty" is not "ours",
    and deleting a directory we merely found empty is not a risk worth taking
    for a tidier error message.
    """
    if not created_by_us or not target.exists():
        return
    try:
        shutil.rmtree(target)
    except OSError:
        # Swallowed on purpose. This runs while an error is already being
        # raised, and a cleanup failure must not replace the real reason the
        # clone failed with a confusing second one. The caller learns about it
        # anyway: the next attempt says dest_not_empty.
        pass


async def _op_clone(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    """Create a checkout where there was none.

    Writes, but cannot destroy: it refuses a destination that already exists
    rather than merging into it or emptying it.
    """
    url = str(payload.get("url") or "").strip()
    dest = str(payload.get("dest") or "").strip()
    if not url or not dest:
        raise HandlerError("invalid_payload", "clone needs `url` and `dest`.")

    # clone CREATES a tree, so the destination needs rw, not just readability.
    # Same check apply_patch makes, through the same policy API.
    try:
        target = Path(policy.resolve_path(dest, need_write=True))
    except Exception as exc:
        rw_paths = [e.path for e in policy.file_ops_paths if e.access == "rw"]
        raise HandlerError(
            "path_not_allowed",
            f"clone writes a new tree, so {dest!r} must sit under a file_ops "
            f"entry with access: rw. Writable paths on this host: {rw_paths}.",
            details={"writable_paths": rw_paths, "dest": dest},
        ) from exc
    if target.exists() and any(target.iterdir()):
        raise HandlerError(
            "dest_not_empty",
            f"{dest!r} already exists and is not empty. clone refuses to write "
            "into an existing tree; choose an empty or new directory, or use "
            "fetch if this is already a checkout.",
        )
    args = ["clone"]
    if payload.get("depth"):
        args += ["--depth", str(_clamp_int(payload["depth"], 1, 1, 1000))]
    if payload.get("branch"):
        args += ["--branch", str(payload["branch"])]
    args += [url, str(target)]

    created = not target.exists()
    try:
        rc, _, err = await _run_git(target.parent, *args, timeout=_NET_TIMEOUT)
    except HandlerError as exc:
        if exc.code != "git_timeout":
            raise
        # LEAVE NOTHING HALF-WRITTEN. git was killed mid-clone, so the
        # destination holds a partial tree. Without this the next attempt hits
        # dest_not_empty, which reads as a different problem entirely and sends
        # the caller looking in the wrong place.
        _discard_partial_clone(target, created)
        # Two rungs, in order. depth keeps the caller inside this tool, where
        # the destination is validated and a failure cleans up after itself.
        # Only when that has already been tried is it worth leaving, and then
        # the escape hatch is spelled out rather than described: a model told
        # to "use another tool" will invent a command line, and the whole point
        # of this operation is that it does not have to.
        if not payload.get("depth"):
            depth_hint = (
                " Try again with depth (for example depth: 1), which fetches "
                "only the latest commit and turns minutes into seconds on a "
                "large repository. Most work on a checkout does not need the "
                "full history."
            )
        else:
            depth_hint = (
                " A shallow clone still did not arrive in time, so this one is "
                "too large for a single tool call. Run it as a background job "
                "instead, which has an hour rather than a minute:\n"
                "  sentinel_script_run(\n"
                "      background=True,\n"
                f"      content='git clone --depth 1 {url} {target}',\n"
                "  )\n"
                "then collect the result with notifications(operation='check'). "
                "Note that path is not validated on that route, so check the "
                "destination yourself."
            )
        raise HandlerError(
            "clone_timeout",
            f"The clone did not finish within {_NET_TIMEOUT}s and the partial "
            f"checkout was removed, so {dest!r} is clean for another attempt."
            + depth_hint,
        ) from exc

    if rc != 0:
        _discard_partial_clone(target, created)
        raise _net_error("remote_failed", "git clone", rc, err, target.parent)
    return {"ok": True, "version": 1, "operation": "clone",
            "root": str(target), "url": url}


async def _op_push(policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    """Publish a branch. A forced push MUST carry the SHA it expects to replace.

    NO BARE FORCE, EVER. Measured over 7 days: 189 users force-pushed through
    exec without a lease against 56 who used one. A bare force silently discards
    whatever someone else pushed in the meantime, and an assistant has no way to
    notice. Requiring the expected SHA turns it into a compare-and-swap: if the
    remote moved, the push fails and says so instead of overwriting.

    Anyone who genuinely wants an unconditional force can still reach for exec.
    That is deliberately the less convenient path.
    """
    path = payload.get("path")
    if not path:
        raise HandlerError("invalid_payload", "push needs `path`: the repository.")
    root = await _revalidate_git_root(
        policy, _resolve_or_reject(policy, str(path)), str(path)
    )
    remote = str(payload.get("remote") or "origin").strip()
    branch = str(payload.get("branch") or "").strip()
    if not branch:
        raise HandlerError("invalid_payload", "push needs `branch`.")

    expected = payload.get("expected_remote_sha")
    force = _as_bool(payload.get("force"), False)
    if force and not expected:
        raise HandlerError(
            "force_requires_lease",
            "A forced push must carry `expected_remote_sha`: the commit you "
            "believe the remote branch is on right now. Without it the push "
            "would silently discard anything pushed since you last looked. "
            "Use ls_remote to read the current SHA, then pass it here. If you "
            "truly need an unconditional force, that is only available through "
            "sentinel_exec.",
        )

    args = ["push"]
    if force:
        args.append(f"--force-with-lease={branch}:{expected}")
    args += [remote, branch]

    rc, _, err = await _run_git(root, *args, timeout=_NET_TIMEOUT)
    text = _scrub(err.decode("utf-8", "replace"), root).strip()
    if rc != 0:
        if "stale info" in text.lower():
            raise HandlerError(
                "lease_stale",
                f"The remote branch is no longer at {expected!r}, so the push "
                "was refused and nothing was overwritten. Someone pushed since "
                "you read it. Re-read with ls_remote, reconcile, and try again.",
            )
        raise _net_error("remote_failed", f"git push {remote} {branch}", rc,
                         err, root)
    return {"ok": True, "version": 1, "operation": "push", "root": str(root),
            "remote": remote, "branch": branch, "forced": force,
            "output": text[:2000]}


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
        if operation == "ls_remote":
            return await _op_ls_remote(policy, payload)
        if operation == "fetch":
            return await _op_fetch(policy, payload)
        if operation == "clone":
            return await _op_clone(policy, payload)
        if operation == "push":
            return await _op_push(policy, payload)
        raise HandlerError(
            "invalid_payload",
            "git: 'operation' must be one of diff, apply_patch, ls_remote, "
            f"fetch, clone, push (got {operation!r}). Note there is no 'pull': "
            "it is fetch plus a merge, and the merge is worth doing explicitly.",
        )

    return handle
