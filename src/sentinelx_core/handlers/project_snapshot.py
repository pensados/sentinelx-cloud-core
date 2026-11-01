"""project_snapshot handler: deterministic, read-only project orientation.

One op that aggregates git + filesystem facts into a single bounded response,
so the model doesn't need several list/read/search/exec(git...) round-trips to
orient in a repo. V1 is strictly deterministic: git plumbing + extension counts.
No AST, embeddings, semantic ranking, or manifest curation (the model infers the
project type from extension counts itself).

Security: reuses the same read-path validation as read/list/search
(`_resolve_or_reject` against `policy.file_ops_paths`, read-only). The git root
reported by `git rev-parse --show-toplevel` is RE-validated against the
allowlist — if the repo root sits above an allowed path, we do NOT operate on
it (we fall back to a plain directory summary of the requested path). Fixed git
argv only, never a shell; paging/prompts/locks disabled; per-command and total
timeouts; hard caps win over request values.
"""
from __future__ import annotations

import asyncio
import os
from collections import Counter
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.executor_engine import left_running_from, run_process
from sentinelx_core.handlers.fileops import _require_str, _resolve_or_reject
from sentinelx_core.policy import Policy

# Hard caps (always win over any request-provided value).
_MAX_CHANGED_FILES = 50
_MAX_RECENT_COMMITS = 10
_MAX_TOP_DIRS = 40
_MAX_EXTENSIONS = 40
_GIT_CMD_TIMEOUT = 10  # seconds, per git invocation
_TOTAL_TIMEOUT = 25  # seconds, whole snapshot

_GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",   # never prompt for credentials
    "GIT_OPTIONAL_LOCKS": "0",    # read-only: don't take optional locks
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


async def _git_toplevel(root: Path) -> tuple[int, bytes, bytes]:
    """`rev-parse --show-toplevel`, keeping stderr. Returns (rc, stdout, stderr).

    A separate probe rather than widening _run_git: every other caller here
    wants stdout only, and stderr matters for exactly one question -- whether a
    non-zero rc means "no repo" or means git refusing a perfectly good checkout
    because it belongs to another user. Without it both look identical and the
    snapshot silently downgrades a real repository to kind=directory.
    """
    env = {**os.environ, **_GIT_ENV}
    r = await run_process(
        ["git", "-C", str(root), "-c", "core.fsmonitor=false", "rev-parse", "--show-toplevel"],
        timeout=_GIT_CMD_TIMEOUT, input=b"", env=env,
    )
    if r.timed_out:
        if r.left_running:
            raise HandlerError("git_timeout", "git rev-parse timed out", {"left_running": True})
        return 1, b"", b""
    return r.returncode or 0, r.stdout, r.stderr


async def _run_git(root: Path, *args: str) -> tuple[int, bytes]:
    """Run a fixed git argv under `root`. Returns (returncode, stdout). Never shell."""
    env = {**os.environ, **_GIT_ENV}
    # Same lifecycle as git_ops._run_git: run_process (Jan's audit #9).
    r = await run_process(
        ["git", "-C", str(root), "-c", "core.fsmonitor=false", *args],
        timeout=_GIT_CMD_TIMEOUT, input=b"", env=env,
    )
    if r.timed_out:
        raise HandlerError("git_timeout", f"git {args[0]} timed out", {"left_running": True} if r.left_running else None)
    return r.returncode or 0, r.stdout


def _top_and_extensions(rel_paths: list[str]) -> tuple[list[str], dict[str, int], bool]:
    """From a list of repo-relative file paths derive top-level dirs + extension counts."""
    top: Counter[str] = Counter()
    exts: Counter[str] = Counter()
    for rp in rel_paths:
        head = rp.split("/", 1)[0]
        if "/" in rp:
            top[head] += 1
        # extension (lowercased, no dot); files with no extension counted as "<none>"
        name = rp.rsplit("/", 1)[-1]
        if "." in name and not name.startswith(".") or (name.startswith(".") and name.count(".") > 1):
            ext = name.rsplit(".", 1)[-1].lower()
        elif name.startswith(".") and "." not in name[1:]:
            ext = "<dotfile>"
        else:
            ext = "<none>"
        exts[ext] += 1
    top_dirs = [d for d, _ in top.most_common(_MAX_TOP_DIRS)]
    ext_counts = dict(exts.most_common(_MAX_EXTENSIONS))
    top_truncated = len(top) > _MAX_TOP_DIRS
    return top_dirs, ext_counts, top_truncated


def _parse_status_v2(raw: bytes) -> dict[str, Any]:
    """Parse `git status --porcelain=v2 --branch -z` output."""
    branch = None
    detached = False
    head = None
    ahead = behind = 0
    staged = unstaged = untracked = 0
    # -z: records are NUL-separated; header lines start with '#'
    records = raw.split(b"\x00")
    i = 0
    while i < len(records):
        rec = records[i]
        if not rec:
            i += 1
            continue
        try:
            line = rec.decode("utf-8", "replace")
        except Exception:
            i += 1
            continue
        if line.startswith("# branch.head "):
            name = line[len("# branch.head "):].strip()
            if name == "(detached)":
                detached = True
            else:
                branch = name
        elif line.startswith("# branch.oid "):
            oid = line[len("# branch.oid "):].strip()
            head = None if oid == "(initial)" else oid[:12]
        elif line.startswith("# branch.ab "):
            parts = line[len("# branch.ab "):].split()
            for p in parts:
                if p.startswith("+"):
                    ahead = int(p[1:] or 0)
                elif p.startswith("-"):
                    behind = int(p[1:] or 0)
        elif line.startswith("1 ") or line.startswith("2 "):
            # changed/renamed entry: field 1 is XY (staged=X, unstaged=Y)
            xy = line.split(" ", 2)[1] if len(line.split(" ", 2)) > 1 else ".."
            x, y = (xy + "..")[0], (xy + "..")[1]
            if x != ".":
                staged += 1
            if y != ".":
                unstaged += 1
            # renamed (type 2) consumes the next NUL record (the origin path)
            if line.startswith("2 "):
                i += 1
        elif line.startswith("? "):
            untracked += 1
        i += 1
    return {
        "branch": branch,
        "detached": detached,
        "head": head,
        "ahead": ahead,
        "behind": behind,
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
        "dirty": bool(staged or unstaged or untracked),
    }


def _sum_numstat(raw: bytes) -> tuple[int, int, int]:
    """Sum insertions/deletions from `git diff --numstat -z`. Returns (files, ins, dels)."""
    files = ins = dels = 0
    for line in raw.split(b"\x00"):
        if not line.strip():
            continue
        parts = line.decode("utf-8", "replace").split("\t")
        if len(parts) >= 2:
            files += 1
            try:
                ins += int(parts[0]) if parts[0] != "-" else 0
                dels += int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                pass
    return files, ins, dels


async def _git_snapshot(root: Path) -> dict[str, Any]:
    status = await _run_git(root, "status", "--porcelain=v2", "--branch", "-z")
    st = _parse_status_v2(status[1]) if status[0] == 0 else {}

    # head fallback
    if not st.get("head"):
        rc, out = await _run_git(root, "rev-parse", "--short=12", "HEAD")
        if rc == 0 and out.strip():
            st["head"] = out.decode().strip()

    # diff stats (unstaged + staged)
    _, un = await _run_git(root, "diff", "--no-ext-diff", "--numstat", "-z")
    _, stg = await _run_git(root, "diff", "--cached", "--no-ext-diff", "--numstat", "-z")
    uf, ui, ud = _sum_numstat(un)
    sf, si, sd = _sum_numstat(stg)

    # tracked files -> count, top dirs, extensions
    rc, files_raw = await _run_git(root, "ls-files", "-z")
    rel = [p for p in files_raw.decode("utf-8", "replace").split("\x00") if p] if rc == 0 else []
    tracked = len(rel)
    top_dirs, ext_counts, top_trunc = _top_and_extensions(rel)

    # recent commits (bounded)
    rc, log_raw = await _run_git(
        root, "log", f"-{_MAX_RECENT_COMMITS}", "--no-color",
        "--pretty=format:%h%x1f%s%x1f%an%x1f%ad", "--date=short",
    )
    commits = []
    if rc == 0 and log_raw.strip():
        for ln in log_raw.decode("utf-8", "replace").split("\n"):
            f = ln.split("\x1f")
            if len(f) == 4:
                commits.append({"hash": f[0], "subject": f[1][:120], "author": f[2], "date": f[3]})

    return {
        "ok": True,
        "version": 1,
        "root": str(root),
        "kind": "git",
        "git": {
            "branch": st.get("branch"),
            "detached": st.get("detached", False),
            "head": st.get("head"),
            "ahead": st.get("ahead", 0),
            "behind": st.get("behind", 0),
            "dirty": st.get("dirty", False),
        },
        "changes": {
            "staged": st.get("staged", 0),
            "unstaged": st.get("unstaged", 0),
            "untracked": st.get("untracked", 0),
            "insertions": ui + si,
            "deletions": ud + sd,
        },
        "repository": {
            "tracked_files": tracked,
            "top_directories": top_dirs,
            "extensions": ext_counts,
        },
        "recent_commits": commits,
        "truncated": {
            "top_directories": top_trunc,
            "recent_commits": False,  # log capped at request time, not a partial view
        },
    }


async def _directory_snapshot(root: Path) -> dict[str, Any]:
    """Non-git readable directory: deterministic fs summary, no git fields."""
    top: Counter[str] = Counter()
    exts: Counter[str] = Counter()
    total = 0
    truncated = False
    try:
        with os.scandir(root) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    top[entry.name] += 1
                else:
                    total += 1
                    name = entry.name
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else "<none>"
                    exts[ext] += 1
                if total > 5000:
                    truncated = True
                    break
    except PermissionError:
        raise HandlerError("permission_denied", f"cannot read directory: {root}")
    return {
        "ok": True,
        "version": 1,
        "root": str(root),
        "kind": "directory",
        "repository": {
            "top_directories": [d for d, _ in top.most_common(_MAX_TOP_DIRS)],
            "extensions": dict(exts.most_common(_MAX_EXTENSIONS)),
            "file_count": total,
        },
        "truncated": {"file_count": truncated},
    }


def make_project_snapshot_handler(policy: Policy):
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        path = _require_str(payload, "path")
        root = _resolve_or_reject(policy, path)  # canonical, allowlisted, read-only
        if not root.exists():
            raise HandlerError("not_found", f"path does not exist: {path}")
        if not root.is_dir():
            raise HandlerError("is_file", "project_snapshot expects a directory")

        async def _work() -> dict[str, Any]:
            # git repo?
            rc, out, err = await _git_toplevel(root)
            if rc != 0 and b"dubious ownership" in err:
                # A real checkout that git will not read as this user. Saying
                # "directory" here is not merely incomplete, it is wrong, and it
                # sends the caller looking for a repo that is already there.
                res = await _directory_snapshot(root)
                res["git_unavailable"] = (
                    "This IS a git checkout, but git refuses to read it as the "
                    "user this agent runs as, because the repository is owned by "
                    "someone else. Git's own safety check, not a SentinelX "
                    "restriction -- which is why git over sentinel_exec works "
                    "when that runs as the owner. The operator can give the "
                    "agent's user ownership, or declare the exception with "
                    "`git config --global --add safe.directory <path>` as that "
                    "user. The directory summary below is still accurate."
                )
                return res
            if rc == 0 and out.strip():
                git_root_str = out.decode("utf-8", "replace").strip()
                # SECURITY: the repo root may sit ABOVE an allowed path.
                # Re-validate it; if it escapes the allowlist, fall back to a
                # plain directory summary of the requested (allowed) path.
                try:
                    git_root = _resolve_or_reject(policy, git_root_str)
                except HandlerError:
                    return await _directory_snapshot(root)
                return await _git_snapshot(git_root)
            return await _directory_snapshot(root)

        try:
            return await asyncio.wait_for(_work(), timeout=_TOTAL_TIMEOUT)
        except asyncio.TimeoutError as exc:
            raise HandlerError("timeout", "project_snapshot exceeded its time budget", {"left_running": True} if left_running_from(exc) else None) from exc

    return handle
