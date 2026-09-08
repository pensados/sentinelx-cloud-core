"""edit handlers: structured file editing via the `pensa-safe-edit` binary.

Ported from legacy SentinelX 0.3.5. Three ops:

  - edit                         -> single-call edit (small/medium changes)
  - edit_upload_init             -> begin a multi-step edit (large content)
  - edit_upload_file             -> upload a role file (new/old) to that step
  - edit_upload_complete         -> run the edit using uploaded files

Why this complexity? `pensa-safe-edit` accepts content via `--old-file` and
`--new-file`. For large content, transmitting it inline would be unwieldy.
The chunked path lets the caller stage files up front, then run the edit.

The agent ENFORCES `path` against the unified file_ops r/rw allowlist:
`edit` and `edit_upload_complete` are mutating ops, so the resolved
path must fall under a file_ops entry whose access is "rw" (see
Policy.resolve_path(need_write=True)). This is a hardening over legacy
SentinelX 0.3.5, where edit did NO path validation and relied purely
on filesystem permissions + sudo policy — meaning a compromised hub
(A1) or LLM (A2) could ask the agent to edit any path the service
user could write. Now the writable surface is exactly what the
operator declared rw, and symlink-escape / `../` traversal are
defeated by canonicalization before the prefix check.

What the agent ALSO guarantees:

  - Only the configured `pensa-safe-edit` binary is called.
  - Mode/argument validation happens before exec.
  - Workdirs are created in the upload base, never elsewhere.
  - Each request gets a fresh workdir and is cleaned up after.

Modes:
  - replace        literal old -> new_text (count, multiline, dotall)
  - regex          pattern -> new_text (count, multiline, dotall)
  - replace-block  start_marker..end_marker -> new_text
  - append         append new_text to file
  - prepend        prepend new_text to file
  - write          overwrite file with new_text
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy
from sentinelx_core.staging import staging_root

VALID_MODES = ("replace", "regex", "replace-block", "append", "prepend", "write")
VALID_PRESETS = ("nginx", "json", "python", "sh", "yaml", "systemd", "toml")

# pensa-safe-edit binary resolution.
#
# We support three locations, in this priority:
#   1. The bundled entry point alongside the agent. When sentinelx-cloud-core
#      is installed via pip, pyproject.toml registers a console script named
#      `sentinelx-pensa-safe-edit` in the same bin/ as `sentinelx-cloud-core`.
#      We compute its path from sys.executable so it works in any venv layout.
#   2. The legacy system-wide install at /usr/local/bin/pensa-safe-edit.
#      Kept for backward compat with pensa-orion, which still has it there.
#   3. Whatever `pensa-safe-edit` resolves to on $PATH.
#
# The caller is the per-request handler so this is dirt cheap to evaluate.

LEGACY_SAFE_EDIT_BIN = "/usr/local/bin/pensa-safe-edit"
BUNDLED_SCRIPT_NAME = "sentinelx-pensa-safe-edit"


def _resolve_safe_edit_bin() -> str:
    """Find the pensa-safe-edit binary at request time.

    Returns an absolute path when we can resolve one. Falls back to the bare
    name `pensa-safe-edit` (relying on $PATH) only as a last resort.
    """
    # 1. Bundled entry point next to sentinelx-cloud-core. On Windows the pip
    #    console script is a `.exe` in the venv's Scripts/ dir, so check that
    #    variant first.
    bin_dir = Path(sys.executable).parent
    if sys.platform == "win32":
        win_bundled = bin_dir / f"{BUNDLED_SCRIPT_NAME}.exe"
        if win_bundled.exists():
            return str(win_bundled)
    bundled = bin_dir / BUNDLED_SCRIPT_NAME
    if bundled.exists():
        return str(bundled)

    # 2. Legacy system path
    if Path(LEGACY_SAFE_EDIT_BIN).exists():
        return LEGACY_SAFE_EDIT_BIN

    # 3. Bare name — let exec do the lookup
    return "pensa-safe-edit"


# Public name the rest of the module reads.
DEFAULT_SAFE_EDIT_BIN = LEGACY_SAFE_EDIT_BIN  # kept for backward compat with old refs


def _validate_mode_payload(mode: str, payload: dict[str, Any]) -> None:
    """Mirror the legacy EditRequest validators."""
    if mode not in VALID_MODES:
        raise HandlerError(
            "invalid_payload",
            f"mode must be one of: {', '.join(VALID_MODES)}",
        )

    validator = payload.get("validator")
    validator_preset = payload.get("validator_preset")
    if validator and validator_preset:
        raise HandlerError(
            "invalid_payload",
            "cannot use 'validator' and 'validator_preset' together",
        )
    if validator_preset and validator_preset not in VALID_PRESETS:
        raise HandlerError(
            "invalid_payload",
            f"validator_preset must be one of: {', '.join(VALID_PRESETS)}",
        )

    count = int(payload.get("count", 0) or 0)
    if count < 0:
        raise HandlerError("invalid_payload", "count cannot be negative")

    if mode == "replace":
        if payload.get("old") is None:
            raise HandlerError("invalid_payload", "mode=replace requires 'old'")
        if payload.get("new_text") is None:
            raise HandlerError("invalid_payload", "mode=replace requires 'new_text'")

    elif mode == "regex":
        if not payload.get("pattern"):
            raise HandlerError("invalid_payload", "mode=regex requires 'pattern'")
        if payload.get("new_text") is None:
            raise HandlerError("invalid_payload", "mode=regex requires 'new_text'")

    elif mode == "replace-block":
        if not payload.get("start_marker") or not payload.get("end_marker"):
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'start_marker' and 'end_marker'",
            )
        if payload.get("new_text") is None:
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'new_text'",
            )

    elif mode in ("append", "prepend", "write"):
        if payload.get("new_text") is None:
            raise HandlerError(
                "invalid_payload",
                f"mode={mode} requires 'new_text'",
            )


def _build_argv(
    *,
    binary: str,
    workdir: Path,
    path: str,
    sudo: bool,
    mode: str,
    old: str | None = None,
    new_text: str | None = None,
    pattern: str | None = None,
    start_marker: str | None = None,
    end_marker: str | None = None,
    count: int = 0,
    multiline: bool = False,
    dotall: bool = False,
    interpret_escapes: bool = False,
    backup_dir: str | None = None,
    validator: str | None = None,
    validator_preset: str | None = None,
    diff: bool = False,
    dry_run: bool = False,
    allow_no_change: bool = False,
    create: bool = False,
    old_file_path: Path | None = None,
    new_file_path: Path | None = None,
) -> list[str]:
    """Build the argv list for pensa-safe-edit. Faithful port of legacy."""
    argv: list[str] = []
    if sudo:
        argv.append("sudo")
    argv.extend([binary, path, "--mode", mode])

    # Old content: prefer file path, fall back to writing inline content
    if old_file_path is not None:
        argv.extend(["--old-file", str(old_file_path)])
    elif old is not None:
        p = workdir / "old.txt"
        p.write_text(old, encoding="utf-8")
        argv.extend(["--old-file", str(p)])

    # New content: same pattern
    if new_file_path is not None:
        argv.extend(["--new-file", str(new_file_path)])
    elif new_text is not None:
        p = workdir / "new.txt"
        p.write_text(new_text, encoding="utf-8")
        argv.extend(["--new-file", str(p)])

    if pattern:
        argv.extend(["--pattern", pattern])
    if start_marker:
        argv.extend(["--start-marker", start_marker])
    if end_marker:
        argv.extend(["--end-marker", end_marker])
    if count:
        argv.extend(["--count", str(count)])
    if multiline:
        argv.append("--multiline")
    if dotall:
        argv.append("--dotall")
    if interpret_escapes:
        argv.append("--interpret-escapes")
    if backup_dir:
        argv.extend(["--backup-dir", backup_dir])
    if validator:
        argv.extend(["--validator", validator])
    if validator_preset:
        argv.extend(["--validator-preset", validator_preset])
    if diff:
        argv.append("--diff")
    if dry_run:
        argv.append("--dry-run")
    if allow_no_change:
        argv.append("--allow-no-change")
    if create:
        argv.append("--create")

    return argv


async def _run_argv(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    """Run the assembled argv directly (no shell). Returns legacy-shape dict."""
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "output": "⏱️ Timeout",
            "duration": round(time.time() - start, 2),
            "returncode": -1,
        }
    except FileNotFoundError as exc:
        raise HandlerError(
            "binary_missing",
            f"required binary not found: {exc.filename}",
        ) from exc

    duration = round(time.time() - start, 2)
    stdout = (stdout_b.decode(errors="replace") or "").strip()
    stderr = (stderr_b.decode(errors="replace") or "").strip()
    output = (stdout + "\n" + stderr).strip() or "⚠️ Sin salida"
    return {"output": output, "duration": duration, "returncode": proc.returncode}


def make_edit_handler(policy: Policy, upload_base: Path):
    """Single-call edit, content passed inline as 'old' and 'new_text'."""
    binary = _resolve_safe_edit_bin()

    async def handle_edit(payload: dict[str, Any]) -> dict[str, Any]:
        path = payload.get("path")
        mode = payload.get("mode")
        sudo = bool(payload.get("sudo", False))

        if not path or not str(path).strip():
            raise HandlerError("invalid_payload", "missing 'path'")
        if not mode:
            raise HandlerError("invalid_payload", "missing 'mode'")

        # Path-enforce under the unified r/rw model. `edit` is a mutating
        # op: the path must resolve under a file_ops entry with access
        # rw, and canonicalization (resolve symlinks, collapse `..`)
        # always happens first so the verdict cannot be dodged by
        # traversal.
        #
        # sudo does NOT exempt an edit from this. It used to: the
        # reasoning was that a sudo edit crossed a separate boundary,
        # the operator's sudoers fragment, assumed to be locked to the
        # pensa-safe-edit binary. The installer never wrote such a
        # fragment -- it granted NOPASSWD:ALL -- so the assumed boundary
        # did not exist, and the exemption let any request write any
        # file as root, including this very policy file. An agent that
        # can rewrite its own allowlist has no allowlist, which made the
        # rw model advisory rather than enforced. Reported by OpenAI
        # Security, 2026-09.
        #
        # Operators who genuinely want the agent to administer its own
        # policy can still have it: add the config file to file_ops as
        # rw. That is then a visible, deliberate entry in their config
        # instead of an invisible property of the sudo flag.
        resolved = policy.resolve_path(str(path), need_write=True)
        if resolved is not None:
            # Under an rw entry (sudo or not): use the canonical path.
            path = str(resolved)
        else:
            # Not under any rw entry: reject, sudo or not. This is the
            # load-bearing check for A2 (compromised LLM).
            rw_paths = [
                e.path for e in policy.file_ops_paths if e.access == "rw"
            ]
            raise HandlerError(
                "path_not_allowed",
                "edit requires a path under a file_ops entry with "
                "access: rw. The requested path is not within any "
                "writable allowlist entry. sudo does not lift this: to "
                "let the agent write here, add the path to file_ops "
                "with access: rw.",
                details={"writable_paths": rw_paths},
            )

        _validate_mode_payload(mode, payload)

        tmp_root = staging_root(upload_base)

        workdir = tmp_root / f"edit_job_{uuid.uuid4().hex}"
        workdir.mkdir(parents=True, exist_ok=True)

        try:
            argv = _build_argv(
                binary=binary,
                workdir=workdir,
                path=path,
                sudo=sudo,
                mode=mode,
                old=payload.get("old"),
                new_text=payload.get("new_text"),
                pattern=payload.get("pattern"),
                start_marker=payload.get("start_marker"),
                end_marker=payload.get("end_marker"),
                count=int(payload.get("count", 0) or 0),
                multiline=bool(payload.get("multiline", False)),
                dotall=bool(payload.get("dotall", False)),
                interpret_escapes=bool(payload.get("interpret_escapes", False)),
                backup_dir=payload.get("backup_dir"),
                validator=payload.get("validator"),
                validator_preset=payload.get("validator_preset"),
                diff=bool(payload.get("diff", False)),
                dry_run=bool(payload.get("dry_run", False)),
                allow_no_change=bool(payload.get("allow_no_change", False)),
                create=bool(payload.get("create", False)),
            )

            result = await _run_argv(argv)
            return {
                "ok": result["returncode"] == 0,
                "path": path,
                "mode": mode,
                "sudo": sudo,
                "command": argv,
                **result,
            }
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    return handle_edit


# --- Chunked edit upload --------------------------------------------------------

def _edit_upload_dir(upload_base: Path, upload_id: str) -> Path:
    tmp_root = staging_root(upload_base)
    upload_dir = tmp_root / f"edit_{upload_id}"
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def _safe_filename(filename: str) -> str:
    """Refuse path traversal: only basename allowed."""
    safe = Path(filename).name
    if not safe or safe.startswith("."):
        raise HandlerError("invalid_payload", f"invalid filename: {filename}")
    return safe


def make_edit_upload_init_handler(upload_base: Path):
    async def handle_edit_upload_init(payload: dict[str, Any]) -> dict[str, Any]:
        """Allocate a workdir, return the upload_id to use in subsequent calls."""
        upload_id = uuid.uuid4().hex
        upload_dir = _edit_upload_dir(upload_base, upload_id)
        return {
            "upload_id": upload_id,
            "upload_dir": str(upload_dir),
        }

    return handle_edit_upload_init


def make_edit_upload_file_handler(upload_base: Path):
    async def handle_edit_upload_file(payload: dict[str, Any]) -> dict[str, Any]:
        """Receive a role file ('old' or 'new') for an in-progress edit upload.

        Content can come either as 'content' (utf-8 string) or 'content_base64'.
        Filename is sanitized to its basename only.
        """
        upload_id = payload.get("upload_id")
        role = payload.get("role")
        # `filename` from the payload is accepted as a hint (kept in the
        # response for client-side bookkeeping) but is NOT used as the
        # on-disk name. The disk layout is fixed by role: 'old' -> old.txt,
        # 'new' -> new.txt. This guarantees that handle_edit_upload_complete,
        # which looks up the staged files by those exact names, can always
        # find them — independently of what the client called the file.
        filename_hint = payload.get("filename")
        content = payload.get("content")
        content_b64 = payload.get("content_base64")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if role not in ("old", "new"):
            raise HandlerError("invalid_payload", "role must be 'old' or 'new'")

        # Disk name is fixed by role, NOT by the client-supplied filename.
        # The hint is sanitized only for echo purposes (not used as a path).
        disk_name = f"{role}.txt"
        echoed_name = _safe_filename(filename_hint) if filename_hint else disk_name

        upload_dir = _edit_upload_dir(upload_base, upload_id)
        dest = upload_dir / disk_name

        if content is not None and content_b64 is not None:
            raise HandlerError(
                "invalid_payload",
                "provide exactly one of 'content' or 'content_base64'",
            )
        if content is not None:
            dest.write_text(str(content), encoding="utf-8")
        elif content_b64 is not None:
            import base64
            try:
                dest.write_bytes(base64.b64decode(content_b64))
            except Exception as exc:  # noqa: BLE001
                raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc
        else:
            raise HandlerError(
                "invalid_payload",
                "missing 'content' or 'content_base64'",
            )

        return {
            "upload_id": upload_id,
            "role": role,
            # `filename` echoes either the sanitized client hint or the
            # disk name. Note: `path` always points to <role>.txt — that
            # is the actual disk location regardless of the hint.
            "filename": echoed_name,
            "size_bytes": dest.stat().st_size,
            "path": str(dest),
        }

    return handle_edit_upload_file


def make_edit_upload_complete_handler(policy: Policy, upload_base: Path):
    """Run pensa-safe-edit using files staged via edit_upload_file."""
    binary = _resolve_safe_edit_bin()

    async def handle_edit_upload_complete(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        path = payload.get("path")
        mode = payload.get("mode")
        sudo = bool(payload.get("sudo", False))

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if not path or not str(path).strip():
            raise HandlerError("invalid_payload", "missing 'path'")
        if not mode:
            raise HandlerError("invalid_payload", "missing 'mode'")

        # Mode validation, but slightly looser than single-edit because the
        # 'old' / 'new' content lives in files, not in the payload.
        if mode not in VALID_MODES:
            raise HandlerError(
                "invalid_payload",
                f"mode must be one of: {', '.join(VALID_MODES)}",
            )
        if payload.get("validator") and payload.get("validator_preset"):
            raise HandlerError(
                "invalid_payload",
                "cannot use 'validator' and 'validator_preset' together",
            )
        if mode == "regex" and not payload.get("pattern"):
            raise HandlerError("invalid_payload", "mode=regex requires 'pattern'")
        if mode == "replace-block" and (
            not payload.get("start_marker") or not payload.get("end_marker")
        ):
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'start_marker' and 'end_marker'",
            )

        # Path-enforce under the unified r/rw model (same rule as
        # handle_edit: the chunked-upload path is just as much a write,
        # so it must not become the bypass that the single-call path no
        # longer is). sudo does not exempt it either.
        resolved = policy.resolve_path(str(path), need_write=True)
        if resolved is not None:
            path = str(resolved)
        else:
            rw_paths = [
                e.path for e in policy.file_ops_paths if e.access == "rw"
            ]
            raise HandlerError(
                "path_not_allowed",
                "edit requires a path under a file_ops entry with "
                "access: rw. The requested path is not within any "
                "writable allowlist entry. sudo does not lift this: to "
                "let the agent write here, add the path to file_ops "
                "with access: rw.",
                details={"writable_paths": rw_paths},
            )

        upload_dir = _edit_upload_dir(upload_base, upload_id)
        old_file = upload_dir / "old.txt"
        new_file = upload_dir / "new.txt"

        # Fail-loud: refuse to invoke the binary with missing role files
        # for modes that require them. The previous behaviour was to pass
        # `None` silently, which produced a corrupt edit (e.g. mode=write
        # without --new-file leaves the target file empty). The validator
        # would still pass on the empty result, so the bug was invisible
        # in the response. Better to refuse the operation here than to
        # write garbage and report success.
        modes_needing_new = {"replace", "regex", "replace-block", "append", "prepend", "write"}
        modes_needing_old = {"replace", "replace-block"}
        if mode in modes_needing_new and not new_file.exists():
            raise HandlerError(
                "missing_role_file",
                f"mode={mode} requires the 'new' role file to be uploaded "
                f"first via sentinel_edit_upload_file (role='new'). "
                f"No file was found at {new_file}.",
            )
        if mode in modes_needing_old and not old_file.exists():
            raise HandlerError(
                "missing_role_file",
                f"mode={mode} requires the 'old' role file to be uploaded "
                f"first via sentinel_edit_upload_file (role='old'). "
                f"No file was found at {old_file}.",
            )

        argv = _build_argv(
            binary=binary,
            workdir=upload_dir,
            path=path,
            sudo=sudo,
            mode=mode,
            pattern=payload.get("pattern"),
            start_marker=payload.get("start_marker"),
            end_marker=payload.get("end_marker"),
            count=int(payload.get("count", 0) or 0),
            multiline=bool(payload.get("multiline", False)),
            dotall=bool(payload.get("dotall", False)),
            interpret_escapes=bool(payload.get("interpret_escapes", False)),
            backup_dir=payload.get("backup_dir"),
            validator=payload.get("validator"),
            validator_preset=payload.get("validator_preset"),
            diff=bool(payload.get("diff", False)),
            dry_run=bool(payload.get("dry_run", False)),
            allow_no_change=bool(payload.get("allow_no_change", False)),
            create=bool(payload.get("create", False)),
            old_file_path=old_file if old_file.exists() else None,
            new_file_path=new_file if new_file.exists() else None,
        )

        try:
            result = await _run_argv(argv)
            return {
                "ok": result["returncode"] == 0,
                "path": path,
                "mode": mode,
                "sudo": sudo,
                "upload_id": upload_id,
                "command": argv,
                **result,
            }
        finally:
            shutil.rmtree(upload_dir, ignore_errors=True)

    return handle_edit_upload_complete
