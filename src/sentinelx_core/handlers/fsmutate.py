"""fsmutate handlers: the destructive filesystem ops.

Five ops, every one gated by the unified file_ops r/rw model — the
resolved path (and, for move/copy, BOTH source and destination) must
fall under a file_ops entry whose access is "rw":

  - move    -> rename/move a file or directory
  - copy    -> copy a file or directory
  - delete  -> delete a file or (with explicit recursive) a directory
  - chmod   -> change mode bits
  - chown   -> change owner/group

Why a separate module from fileops.py? fileops is STRICTLY read-only
(read/list/search). Mixing destructive ops into it would blur the one
property that makes fileops easy to reason about. fsmutate is the
explicit, auditable home for mutation.

Security model
==============

  1. PATH ENFORCE (rw). Every path argument is resolved via
     policy.resolve_path(p, need_write=True). For move/copy that means
     BOTH endpoints — you cannot move a file out of an rw subtree into
     a place you don't control, nor copy from outside in by tricking
     the destination check. Canonicalization resolves symlinks BEFORE
     the prefix check, so `../` traversal and symlink-escape are
     defeated (same load-bearing check as read/edit). This is the
     A1/A2 defense: a compromised hub or LLM cannot reach outside the
     operator's declared writable surface.

  2. MANDATORY BACKUP BEFORE DELETE. delete always makes a backup
     first. A single file -> copy via make_backup (the same helper the
     editor uses, so backups look identical). A directory -> a
     timestamped .tar.gz next to it. If the backup can't be made, the
     delete is REFUSED (backup_failed) — we never destroy without a
     recovery path.

  3. EXPLICIT RECURSION. Deleting a directory requires
     recursive=true in the payload. Without it, a directory delete is
     refused (is_directory). This makes "rm -rf"-shaped mistakes
     impossible to trigger implicitly.

  4. NO SILENT PRIVILEGE FAILURES. chown typically needs root. When
     the agent isn't privileged enough, chown reports
     permission_denied with the errno detail rather than pretending
     it worked — consistent with the editor's copy_metadata refusing
     to swallow chown EPERM.

  5. BEST-EFFORT AUDIT LOG. Every successful mutation appends one
     JSON line to /var/log/sentinelx/mutations.log. This is
     best-effort: if the log can't be written (perms, disk), the op
     STILL succeeds — an audit-log failure must not make a destructive
     op fail half-way. The agent-side log is a partial mitigation
     (THREAT_MODEL §5.5): the authoritative audit trail is still the
     hub's, but a local record helps post-incident on a compromised
     hub.

All error codes are English and structured (HandlerError), matching
fileops.py style: invalid_payload / path_not_allowed / not_found /
is_directory / not_a_directory / exists / permission_denied /
backup_failed / move_failed / copy_failed / delete_failed /
chmod_failed / chown_failed.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# grp/pwd are POSIX-only (used by chown-by-name). On Windows they don't
# exist; guard the import so the module loads and chown degrades to a
# clear "unsupported" error rather than crashing agent startup.
try:
    import grp
    import pwd
except ModuleNotFoundError:  # Windows
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy
from sentinelx_core.vendored.pensa_safe_edit import make_backup

MUTATION_LOG = (
    Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    / "SentinelX" / "logs" / "mutations.log"
    if sys.platform == "win32"
    else Path("/var/log/sentinelx/mutations.log")
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_str(payload: dict[str, Any], key: str) -> str:
    val = payload.get(key)
    if not isinstance(val, str) or not val.strip():
        raise HandlerError(
            "invalid_payload", f"missing or non-string {key!r}"
        )
    return val


def _resolve_rw(policy: Policy, path: str, *, label: str = "path") -> Path:
    """Resolve `path` requiring rw access, or raise path_not_allowed.

    This is the fsmutate equivalent of fileops._resolve_or_reject, but
    with need_write=True: destructive ops only operate inside subtrees
    the operator explicitly declared access: rw.
    """
    if not policy.file_ops_paths:
        raise HandlerError(
            "path_not_allowed",
            "file_ops has no paths configured. Destructive ops require "
            "an entry with access: rw.",
            details={label: path, "writable_paths": []},
        )
    resolved = policy.resolve_path(path, need_write=True)
    if resolved is None:
        rw_paths = [
            e.path for e in policy.file_ops_paths if e.access == "rw"
        ]
        raise HandlerError(
            "path_not_allowed",
            f"{label} {path!r} (or its target after resolving "
            "symlinks) is not under any file_ops entry with access: rw. "
            "Mutating ops need a writable path. Add or update an entry "
            "under file_ops.paths in /etc/sentinelx/config.yaml with "
            "access: rw covering a parent directory (with the operator's "
            "approval, via sentinel_edit sudo=true and "
            "validator_preset='yaml'), then reload the agent.",
            details={label: path, "writable_paths": rw_paths},
        )
    return resolved


def _audit(op: str, detail: dict[str, Any]) -> None:
    """Append one JSON line to the mutation log. Best-effort: never
    raises. An audit-log failure must not fail the operation."""
    try:
        MUTATION_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "op": op,
            **detail,
        }
        with MUTATION_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Intentionally swallowed: see module docstring point 5.
        pass


import re as _re

# A backup this agent created: "<name>.bak.<YYYYMMDD-HHMMSS>" for a file (make_backup
# adds -%f microseconds), or "...bak.<ts>.tar.gz" for a directory. Matched exactly so
# a user's own file like "config.bak" or "notes.bak.txt" is NOT treated as ours.
_OWN_BACKUP_RE = _re.compile(r"\.bak\.\d{8}-\d{6}(-\d+)?(\.tar\.gz)?$")


def _is_own_backup(target: Path) -> bool:
    """True if target is a backup artifact this agent created (see the pattern
    make_backup / _dir_backup_targz produce)."""
    return bool(_OWN_BACKUP_RE.search(target.name))


def _dir_backup_targz(src: Path) -> Path:
    """Make a timestamped .tar.gz of a directory next to it."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    archive = src.parent / f"{src.name}.bak.{ts}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src, arcname=src.name)
    return archive


# ---------------------------------------------------------------------------
# move
# ---------------------------------------------------------------------------



# move/copy with overwrite=true used to delete the destination first and only then
# find out whether the operation could finish: a failed copy of a directory left
# half the new tree and none of the old one; a move that couldn't remove its source
# had already replaced the destination (Jan's audit #11, #12, 2026-10-31). Now the
# new content is staged beside the destination, the old one is renamed aside, and it
# is only removed once the new one is in place, or put back if anything fails.
def _sibling(path: Path, tag: str) -> Path:
    return path.with_name(f".{path.name}.sentinelx-{tag}-{os.urandom(4).hex()}")


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_tree(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif _exists(path):
        path.unlink()


def _discard(path: Path) -> None:
    try:
        _remove_tree(path)
    except OSError:
        pass


def _same_filesystem(src: Path, dst: Path) -> bool:
    try:
        return os.lstat(src).st_dev == os.stat(dst.parent).st_dev
    except OSError:
        return False


def _put_in_place(staged: Path, dst: Path, *, replace: bool) -> None:
    """Rename staged (beside dst, so atomic) to dst; an old dst waits aside until then."""
    old = None
    if _exists(dst):
        if not replace:
            raise FileExistsError(errno.EEXIST, "the destination appeared meanwhile", str(dst))
        old = _sibling(dst, "old")
        os.rename(dst, old)
    try:
        os.rename(staged, dst)
    except BaseException:
        if old is not None:
            os.rename(old, dst)
        raise
    if old is not None:
        _discard(old)


def _copy_failure_atomic(src: Path, dst: Path, *, replace: bool, symlinks: bool = False) -> str:
    staged = _sibling(dst, "new")
    try:
        if src.is_dir() and not src.is_symlink():
            shutil.copytree(src, staged, symlinks=symlinks)
            kind = "dir"
        elif symlinks and src.is_symlink():
            os.symlink(os.readlink(src), staged)
            kind = "symlink"
        else:
            shutil.copy2(src, staged)
            kind = "file"
        _put_in_place(staged, dst, replace=replace)
    except BaseException:
        _discard(staged)
        raise
    return kind


def _move_failure_atomic(src: Path, dst: Path, *, replace: bool) -> None:
    if _same_filesystem(src, dst):
        # A rename is atomic; keep the old destination aside until it has happened.
        old = None
        if _exists(dst):
            if not replace:
                raise FileExistsError(errno.EEXIST, "the destination appeared meanwhile", str(dst))
            old = _sibling(dst, "old")
            os.rename(dst, old)
        try:
            os.rename(src, dst)
        except BaseException:
            if old is not None:
                os.rename(old, dst)
            raise
        if old is not None:
            _discard(old)
        return
    # Across filesystems: copy beside the destination, put it in place, then remove
    # the source. The old destination waits aside until the source is gone.
    staged = _sibling(dst, "new")
    old = None
    try:
        if src.is_dir() and not src.is_symlink():
            shutil.copytree(src, staged, symlinks=True)
        elif src.is_symlink():
            os.symlink(os.readlink(src), staged)
        else:
            shutil.copy2(src, staged)
        if _exists(dst):
            if not replace:
                raise FileExistsError(errno.EEXIST, "the destination appeared meanwhile", str(dst))
            old = _sibling(dst, "old")
            os.rename(dst, old)
        os.rename(staged, dst)
    except BaseException:
        _discard(staged)
        if old is not None:
            os.rename(old, dst)
        raise
    try:
        _remove_tree(src)
    except OSError as exc:
        if not (src.is_dir() and not src.is_symlink()):
            # A file isn't half-removed: undo the whole move.
            _discard(dst)
            if old is not None:
                os.rename(old, dst)
            raise
        # A directory removed part way: the destination is complete, keep it and say so.
        if old is not None:
            _discard(old)
        raise HandlerError(
            "partial_move",
            f"{src} was copied to {dst} in full, but removing the source failed part way "
            f"({exc}); the destination is complete and part of the source is left behind",
            {"src": str(src), "dst": str(dst)},
        ) from exc
    if old is not None:
        _discard(old)

def make_move_handler(policy: Policy):
    async def handle_move(payload: dict[str, Any]) -> dict[str, Any]:
        """Move/rename a file or directory.

        Payload: src (str, required), dst (str, required),
                 overwrite (bool, default False)
        BOTH src and dst must resolve under an rw entry.
        """
        src_str = _require_str(payload, "src")
        dst_str = _require_str(payload, "dst")
        overwrite = bool(payload.get("overwrite", False))

        src = _resolve_rw(policy, src_str, label="src")
        dst = _resolve_rw(policy, dst_str, label="dst")

        if not src.exists():
            raise HandlerError(
                "not_found", f"src does not exist: {src_str!r}"
            )
        if dst.exists() and not overwrite:
            raise HandlerError(
                "exists",
                f"dst already exists: {dst_str!r} (pass overwrite=true "
                "to replace it)",
            )

        try:
            _move_failure_atomic(src, dst, replace=overwrite)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot move: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "move_failed", f"move failed: {exc}"
            ) from exc

        _audit("move", {"src": str(src), "dst": str(dst)})
        return {
            "ok": True,
            "op": "move",
            "src": str(src),
            "dst": str(dst),
        }

    return handle_move


# ---------------------------------------------------------------------------
# copy
# ---------------------------------------------------------------------------


def make_copy_handler(policy: Policy):
    async def handle_copy(payload: dict[str, Any]) -> dict[str, Any]:
        """Copy a file or directory.

        Payload: src (str, required), dst (str, required),
                 overwrite (bool, default False)
        BOTH src and dst must resolve under an rw entry — copy is a
        write at the destination, so the destination must be writable.
        """
        src_str = _require_str(payload, "src")
        dst_str = _require_str(payload, "dst")
        overwrite = bool(payload.get("overwrite", False))

        src = _resolve_rw(policy, src_str, label="src")
        dst = _resolve_rw(policy, dst_str, label="dst")

        if not src.exists():
            raise HandlerError(
                "not_found", f"src does not exist: {src_str!r}"
            )
        if dst.exists() and not overwrite:
            raise HandlerError(
                "exists",
                f"dst already exists: {dst_str!r} (pass overwrite=true "
                "to replace it)",
            )

        try:
            kind = _copy_failure_atomic(src, dst, replace=overwrite)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot copy: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "copy_failed", f"copy failed: {exc}"
            ) from exc

        _audit("copy", {"src": str(src), "dst": str(dst), "kind": kind})
        return {
            "ok": True,
            "op": "copy",
            "src": str(src),
            "dst": str(dst),
            "kind": kind,
        }

    return handle_copy


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def make_delete_handler(policy: Policy):
    async def handle_delete(payload: dict[str, Any]) -> dict[str, Any]:
        """Delete a file or (with explicit recursive) a directory.

        Payload: path (str, required), recursive (bool, default False)

        ALWAYS backs up first:
          - file      -> sibling .bak.<ts> copy (make_backup)
          - directory -> sibling .bak.<ts>.tar.gz
        If the backup can't be made the delete is refused — we never
        destroy without a recovery path. A directory delete without
        recursive=true is refused (is_directory).

        EXCEPTION: deleting one of our OWN backup artifacts
        (name.bak.<ts> / .bak.<ts>.tar.gz) is TERMINAL — no backup of a
        backup is made, or the user could never reclaim the space. The
        result carries terminal=true and a note. User files that merely
        contain ".bak" do not match the pattern and keep the mandatory
        backup.
        """
        path_str = _require_str(payload, "path")
        recursive = bool(payload.get("recursive", False))

        target = _resolve_rw(policy, path_str, label="path")

        if not target.exists() and not target.is_symlink():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        is_dir = target.is_dir() and not target.is_symlink()
        if is_dir and not recursive:
            raise HandlerError(
                "is_directory",
                f"{path_str!r} is a directory; pass recursive=true to "
                "delete it (and its contents) — this is deliberate so a "
                "directory is never removed implicitly.",
            )

        # Deleting one of OUR OWN backups is terminal: backing up a backup just
        # creates another .bak, so the user can never reclaim the space (reported
        # in a feature request -- 5.2 GB of stranded .bak files). For a backup
        # artifact we skip the copy and delete it directly. Everything else keeps
        # the mandatory-backup guarantee unchanged.
        own_backup = _is_own_backup(target)
        backup = None
        if not own_backup:
            # Mandatory backup BEFORE destruction.
            try:
                if is_dir:
                    backup = _dir_backup_targz(target)
                else:
                    backup = make_backup(target, None)
            except Exception as exc:
                raise HandlerError(
                    "backup_failed",
                    f"refusing to delete: could not back up {path_str!r} "
                    f"first ({exc})",
                ) from exc

        try:
            if is_dir:
                shutil.rmtree(target)
            else:
                target.unlink()
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot delete: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "delete_failed", f"delete failed: {exc}"
            ) from exc

        # backup is None only when we deliberately skipped it for our own .bak
        # artifact -- report that clearly rather than the string "None", so the
        # caller knows this delete was terminal (no recovery copy) by design.
        backup_str = str(backup) if backup is not None else None
        _audit(
            "delete",
            {
                "path": str(target),
                "kind": "dir" if is_dir else "file",
                "backup": backup_str,
                "terminal": own_backup,
            },
        )
        result = {
            "ok": True,
            "op": "delete",
            "path": str(target),
            "kind": "dir" if is_dir else "file",
            "backup": backup_str,
        }
        if own_backup:
            result["terminal"] = True
            result["note"] = (
                "This was a SentinelX backup artifact, so it was deleted "
                "permanently without making a backup of the backup. Space is "
                "reclaimed; there is no recovery copy."
            )
        return result

    return handle_delete


# ---------------------------------------------------------------------------
# chmod
# ---------------------------------------------------------------------------


def make_chmod_handler(policy: Policy):
    async def handle_chmod(payload: dict[str, Any]) -> dict[str, Any]:
        """Change mode bits.

        Payload: path (str, required),
                 mode (str octal like "644" or "0755", required)
        """
        path_str = _require_str(payload, "path")
        mode_str = _require_str(payload, "mode")

        try:
            mode = int(mode_str, 8)
        except ValueError as exc:
            raise HandlerError(
                "invalid_payload",
                f"mode must be octal (e.g. '644', '0755'): "
                f"{mode_str!r}",
            ) from exc

        target = _resolve_rw(policy, path_str, label="path")
        if not target.exists():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        try:
            target.chmod(mode)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot chmod: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "chmod_failed", f"chmod failed: {exc}"
            ) from exc

        _audit("chmod", {"path": str(target), "mode": oct(mode)})
        return {
            "ok": True,
            "op": "chmod",
            "path": str(target),
            "mode": oct(mode),
        }

    return handle_chmod


# ---------------------------------------------------------------------------
# chown
# ---------------------------------------------------------------------------


def make_chown_handler(policy: Policy):
    async def handle_chown(payload: dict[str, Any]) -> dict[str, Any]:
        """Change owner and/or group.

        Payload: path (str, required),
                 owner (str username, optional),
                 group (str group name, optional)
        At least one of owner/group is required. chown typically needs
        root; when the agent isn't privileged the op fails LOUD with
        permission_denied (never a silent no-op).
        """
        path_str = _require_str(payload, "path")
        owner = payload.get("owner")
        group = payload.get("group")
        if not owner and not group:
            raise HandlerError(
                "invalid_payload",
                "at least one of 'owner' or 'group' is required",
            )

        target = _resolve_rw(policy, path_str, label="path")
        if not target.exists():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        if sys.platform == "win32":
            # Windows has no POSIX uid/gid. Map `owner` to the NTFS object
            # owner via icacls; `group` has no Windows analogue. The agent
            # runs as LocalSystem (admin), which can assign ownership.
            if group:
                raise HandlerError(
                    "invalid_payload",
                    "'group' has no Windows equivalent; on Windows chown sets "
                    "the owner only (pass 'owner').",
                )
            proc = subprocess.run(
                ["icacls", str(target), "/setowner", str(owner)],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise HandlerError(
                    "chown_failed",
                    "icacls /setowner failed: "
                    f"{(proc.stderr or proc.stdout or '').strip()}",
                )
            _audit(
                "chown",
                {"path": str(target), "owner": owner, "backend": "icacls"},
            )
            return {
                "ok": True,
                "op": "chown",
                "path": str(target),
                "owner": owner,
                "group": None,
                "backend": "icacls",
            }

        uid = -1
        gid = -1
        if owner:
            try:
                uid = pwd.getpwnam(str(owner)).pw_uid
            except KeyError as exc:
                raise HandlerError(
                    "invalid_payload",
                    f"unknown user: {owner!r}",
                ) from exc
        if group:
            try:
                gid = grp.getgrnam(str(group)).gr_gid
            except KeyError as exc:
                raise HandlerError(
                    "invalid_payload",
                    f"unknown group: {group!r}",
                ) from exc

        try:
            os.chown(target, uid, gid)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                "cannot chown (this usually requires root; the agent "
                f"is not privileged enough): {exc.strerror or exc}",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "chown_failed", f"chown failed: {exc}"
            ) from exc

        _audit(
            "chown",
            {
                "path": str(target),
                "owner": owner or None,
                "group": group or None,
            },
        )
        return {
            "ok": True,
            "op": "chown",
            "path": str(target),
            "owner": owner or None,
            "group": group or None,
        }

    return handle_chown
