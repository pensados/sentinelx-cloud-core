"""Vendored copy of pensa-safe-edit (refactored).

This is a snapshot of /usr/local/bin/pensa-safe-edit from pensa-orion,
shipped with sentinelx-cloud-core so the agent can perform structured
file edits without depending on a system-installed binary.

When invoked as a script (entry point sentinelx-pensa-safe-edit),
main() runs argparse on sys.argv. The CLI surface (flags + stdout
prefixes OK:/BACKUP:/CHANGES:/VALIDATOR:/DRY-RUN:/SOURCE_BACKUP:/
BACKUP_BEFORE_RESTORE:) is IDENTICAL to the legacy binary so
handlers/edit.py keeps working unchanged.

What changed in the refactor (and why)
======================================

1. NO SHELL. The validator used to run via subprocess.run(cmd,
   shell=True) with the preset being a shell string (e.g. the nginx
   preset was literally "sudo nginx -t -c /etc/nginx/nginx.conf").
   That put a shell-interpreted command on the edit path — a vector
   the core threat model does not account for here. Presets are now
   argv LISTS and execution is subprocess.run(argv, shell=False).
   The target file is passed as a list ELEMENT, never substituted into
   a string, so quoting/metacharacters are no longer a concern.

2. STRUCTURED ERRORS IN ENGLISH. The internal failures used to be
   ad-hoc Spanish strings ("Texto objetivo no encontrado", ...) that
   the LLM received verbatim. They are now SafeEditError(code, message)
   with stable English codes. The CLI prints them as
   "ERROR[<code>]: <message>".

3. API-FIRST. The editing logic lives in apply_edit(spec) ->
   EditResult (a pure-ish function returning a structured result).
   main() is a thin wrapper: parse argv -> build EditSpec -> call
   apply_edit -> print the legacy stdout format. Other Python callers
   can import apply_edit and skip the text round-trip entirely.

4. copy_metadata NO LONGER SWALLOWS chown failures silently. When the
   process can't chown the temp file to the original owner (typical
   when the agent runs as a non-root user editing another user's
   file), it records chown_skipped + reason on the result instead of
   silently passing. Surfaced as "METADATA: chown_skipped (<reason>)".

Only stdlib is used (argparse, re, shutil, subprocess, tempfile).
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SafeEditError(Exception):
    """A structured, English-coded failure.

    `code` is a stable machine-readable token (snake_case). `message`
    is a short human-readable English sentence. The CLI maps the code
    to its historical exit status so the contract with the agent's
    handler (which only inspects returncode + output text) is intact.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Map error codes to the legacy process exit codes. Keeping the exit
# codes stable matters because handlers/edit.py sets ok = (returncode
# == 0); any nonzero keeps meaning "failed".
_EXIT_FOR_CODE = {
    "bad_arguments": 2,
    "target_not_found": 2,
    "target_missing_value": 2,
    "missing_pattern": 2,
    "missing_markers": 2,
    "unsupported_mode": 2,
    "inline_and_file": 2,
    "target_text_not_found": 2,
    "insufficient_matches": 2,
    "regex_no_match": 2,
    "start_marker_not_found": 2,
    "end_marker_not_found": 2,
    "no_effective_change": 3,
    "validation_failed": 4,
    "write_failed": 5,
    "restore_backup_missing": 2,
    "restore_backup_not_file": 2,
    "restore_failed": 5,
    "unsupported_validator_preset": 2,
}


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def run_argv(
    argv: list[str], env=None
) -> subprocess.CompletedProcess:
    """Run a command WITHOUT a shell.

    argv is a real argument vector. shell=False means metacharacters in
    any element (including the target path) are inert — they are passed
    to the program as literal arguments, never interpreted by /bin/sh.
    This is the core hardening of the refactor.
    """
    return subprocess.run(
        argv, shell=False, text=True, capture_output=True, env=env
    )


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class MetadataResult:
    """Outcome of trying to preserve a file's metadata onto the temp."""

    chown_skipped: bool = False
    chown_skip_reason: str = ""


def copy_metadata(src: Path, dst: Path) -> MetadataResult:
    """Copy stat + ownership from src to dst.

    shutil.copystat (mode/atime/mtime/flags) is best-effort and rarely
    fails. os.chown CAN fail with PermissionError when the running
    process is not root and not the file's owner — which is exactly the
    common case for the agent (runs as its service user, edits files
    owned by someone else).

    The legacy code did `except PermissionError: pass` here, silently
    losing ownership. We instead RECORD the skip so the caller can put
    it in the result/stdout. We do not attempt to escalate (no sudo
    chown) — escalating inside the editor is out of scope and would
    widen the trust surface.
    """
    res = MetadataResult()
    shutil.copystat(src, dst, follow_symlinks=False)
    chown = getattr(os, "chown", None)
    if chown is None:
        # Windows: no POSIX ownership model (os.chown doesn't exist); ACLs
        # govern access, and copystat above copied the portable bits. Nothing
        # to chown -- record it as skipped rather than crashing the edit.
        res.chown_skipped = True
        res.chown_skip_reason = "not applicable on Windows (no os.chown)"
        return res
    try:
        st = src.stat()
        chown(dst, st.st_uid, st.st_gid)
    except PermissionError as exc:
        res.chown_skipped = True
        res.chown_skip_reason = f"EPERM ({exc.strerror or 'not permitted'})"
    except OSError as exc:
        res.chown_skipped = True
        res.chown_skip_reason = f"OSError ({exc.strerror or exc})"
    return res


def make_backup(src: Path, backup_dir: Path | None) -> Path:
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    base_dir = backup_dir if backup_dir else src.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    backup = base_dir / f"{src.name}.bak.{ts}"
    shutil.copy2(src, backup)
    return backup


# ---------------------------------------------------------------------------
# Editing primitives (pure string transforms)
# ---------------------------------------------------------------------------


def replace_text_once(
    content: str, old: str, new: str, count: int
) -> tuple[str, int]:
    if count == 0:
        occurrences = content.count(old)
        if occurrences == 0:
            raise SafeEditError(
                "target_text_not_found",
                "the target text to replace was not found in the file",
            )
        return content.replace(old, new), occurrences
    occurrences = content.count(old)
    if occurrences < count:
        raise SafeEditError(
            "insufficient_matches",
            f"not enough matches: found {occurrences}, "
            f"requested {count}",
        )
    return content.replace(old, new, count), min(occurrences, count)


def replace_regex(
    content: str, pattern: str, repl: str, count: int, flags: int
) -> tuple[str, int]:
    new_content, n = re.subn(
        pattern, repl, content, count=count, flags=flags
    )
    if n == 0:
        raise SafeEditError(
            "regex_no_match", "the regex pattern matched nothing"
        )
    return new_content, n


def replace_block(
    content: str, start: str, end: str, new_block: str
) -> tuple[str, int]:
    s = content.find(start)
    if s == -1:
        raise SafeEditError(
            "start_marker_not_found", "start marker not found"
        )
    e = content.find(end, s + len(start))
    if e == -1:
        raise SafeEditError(
            "end_marker_not_found", "end marker not found"
        )
    e += len(end)
    return content[:s] + new_block + content[e:], 1


def load_value(
    inline: str | None, file_path: str | None, empty_ok: bool = True
) -> str:
    if inline is not None and file_path is not None:
        raise SafeEditError(
            "inline_and_file",
            "cannot use an inline value and a file at the same time",
        )
    if file_path is not None:
        return Path(file_path).read_text(encoding="utf-8")
    if inline is None:
        if empty_ok:
            return ""
        raise SafeEditError(
            "target_missing_value", "a required value is missing"
        )
    return inline


def interpret_escapes(value: str) -> str:
    return bytes(value, "utf-8").decode("unicode_escape")


# ---------------------------------------------------------------------------
# Validators — argv lists, NO shell
# ---------------------------------------------------------------------------


def _yaml_validator_argv(target: Path) -> list[str]:
    # Inline Python: load the YAML, raise on error. The file path is a
    # separate argv element (sys.argv[1] inside the snippet), never
    # interpolated into the code string.
    snippet = (
        "import sys; from pathlib import Path; import yaml; "
        "yaml.safe_load(Path(sys.argv[1]).read_text(encoding='utf-8'))"
    )
    return [sys.executable, "-c", snippet, str(target)]


def _toml_validator_argv(target: Path) -> list[str]:
    # tomllib ships with Python 3.11+. Binary mode because tomllib.load
    # expects a binary stream. Covers pyproject.toml, Cargo.toml, etc.
    snippet = (
        "import sys, tomllib; tomllib.load(open(sys.argv[1], 'rb'))"
    )
    return [sys.executable, "-c", snippet, str(target)]


def _json_validator_argv(target: Path) -> list[str]:
    # json.tool would normally print the reformatted document to
    # stdout; the legacy preset redirected it to /dev/null via shell.
    # Without a shell we just discard stdout in run_argv's capture
    # (capture_output=True swallows it); a zero return code still means
    # "valid JSON".
    return [sys.executable, "-m", "json.tool", str(target)]


def build_validator_preset(preset: str, target: Path) -> list[str]:
    """Return the validator command as an argv LIST (never a string).

    The target path is always a discrete list element. This is the
    structural reason the validator path is no longer shell-injectable.
    """
    t = str(target)
    if preset == "nginx":
        return ["sudo", "nginx", "-t", "-c", "/etc/nginx/nginx.conf"]
    if preset == "json":
        return _json_validator_argv(target)
    if preset == "python":
        return [sys.executable, "-m", "py_compile", t]
    if preset == "sh":
        return ["bash", "-n", t]
    if preset == "systemd":
        return ["systemd-analyze", "verify", t]
    if preset == "yaml":
        return _yaml_validator_argv(target)
    if preset == "toml":
        return _toml_validator_argv(target)
    raise SafeEditError(
        "unsupported_validator_preset",
        f"unsupported validator preset: {preset!r}",
    )


def build_validator(
    cmd: str | None, preset: str | None, target: Path
) -> list[str] | None:
    """Resolve the effective validator to an argv list, or None.

    - preset: looked up in build_validator_preset (argv list).
    - cmd (custom --validator): the legacy contract allowed a shell
      string with a {file} placeholder. To keep that usable WITHOUT a
      shell we shlex.split() it and substitute {file} as a discrete
      element. A custom validator that genuinely needs a pipe or
      redirect must now wrap itself explicitly, e.g.
      `bash -c 'jq . {file} > /dev/null'` — an explicit, visible
      decision rather than an implicit shell on every edit.
    """
    if cmd and preset:
        raise SafeEditError(
            "bad_arguments",
            "cannot use --validator and --validator-preset together",
        )
    if preset:
        return build_validator_preset(preset, target)
    if not cmd:
        return None
    import shlex

    parts = shlex.split(cmd)
    return [
        (str(target) if tok == "{file}" else tok) for tok in parts
    ]


def show_diff(src: Path, dst: Path) -> str:
    """Return a unified diff string (also printed by the CLI).

    Uses stdlib difflib rather than shelling out to `diff -u`: the external
    binary isn't present on Windows (and this avoids a process spawn on every
    diff). Output is a standard unified diff on every platform.
    """
    import difflib

    def _lines(p: Path) -> list[str]:
        try:
            return p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            return []

    return "".join(
        difflib.unified_diff(_lines(src), _lines(dst), fromfile=str(src), tofile=str(dst))
    )


# ---------------------------------------------------------------------------
# API: EditSpec / EditResult / apply_edit
# ---------------------------------------------------------------------------


@dataclass
class EditSpec:
    """Everything apply_edit needs. Mirrors the CLI flags 1:1."""

    path: str
    mode: str | None = None
    restore: str | None = None
    old: str | None = None
    old_file: str | None = None
    new: str | None = None
    new_file: str | None = None
    pattern: str | None = None
    start_marker: str | None = None
    end_marker: str | None = None
    count: int = 0
    multiline: bool = False
    dotall: bool = False
    do_interpret_escapes: bool = False
    backup_dir: str | None = None
    validator: str | None = None
    validator_preset: str | None = None
    diff: bool = False
    dry_run: bool = False
    allow_no_change: bool = False
    create: bool = False


@dataclass
class EditResult:
    """Structured outcome. The CLI renders this into legacy stdout."""

    ok: bool
    action: str  # "edit" | "restore"
    target: str
    changed: int = 0
    backup: str | None = None
    source_backup: str | None = None
    backup_before_restore: str | None = None
    validator: list[str] | None = None
    diff_text: str = ""
    dry_run: bool = False
    chown_skipped: bool = False
    chown_skip_reason: str = ""
    messages: list[str] = field(default_factory=list)


def _apply_mode(spec: EditSpec, original: str) -> tuple[str, int]:
    new_value = load_value(spec.new, spec.new_file)

    if spec.mode == "replace":
        old_value = load_value(spec.old, spec.old_file, empty_ok=False)
        if spec.do_interpret_escapes:
            old_value = interpret_escapes(old_value)
            new_value = interpret_escapes(new_value)
        return replace_text_once(
            original, old_value, new_value, spec.count
        )

    if spec.mode == "regex":
        if not spec.pattern:
            raise SafeEditError(
                "missing_pattern", "--pattern is required for mode=regex"
            )
        if spec.do_interpret_escapes:
            new_value = interpret_escapes(new_value)
        flags = 0
        if spec.multiline:
            flags |= re.MULTILINE
        if spec.dotall:
            flags |= re.DOTALL
        return replace_regex(
            original, spec.pattern, new_value, spec.count, flags
        )

    if spec.mode == "replace-block":
        if not spec.start_marker or not spec.end_marker:
            raise SafeEditError(
                "missing_markers",
                "--start-marker and --end-marker are required for "
                "mode=replace-block",
            )
        if spec.do_interpret_escapes:
            new_value = interpret_escapes(new_value)
        return replace_block(
            original, spec.start_marker, spec.end_marker, new_value
        )

    if spec.mode == "append":
        if spec.do_interpret_escapes:
            new_value = interpret_escapes(new_value)
        return original + new_value, (1 if new_value else 0)

    if spec.mode == "prepend":
        if spec.do_interpret_escapes:
            new_value = interpret_escapes(new_value)
        return new_value + original, (1 if new_value else 0)

    if spec.mode == "write":
        if spec.do_interpret_escapes:
            new_value = interpret_escapes(new_value)
        return new_value, 1

    raise SafeEditError(
        "unsupported_mode", f"unsupported mode: {spec.mode!r}"
    )


def _do_restore(spec: EditSpec) -> EditResult:
    target = Path(spec.path)
    backup_path = Path(spec.restore or "")
    backup_dir = Path(spec.backup_dir) if spec.backup_dir else None

    if not backup_path.exists():
        raise SafeEditError(
            "restore_backup_missing",
            "the specified backup does not exist",
        )
    if not backup_path.is_file():
        raise SafeEditError(
            "restore_backup_not_file",
            "the specified backup is not a regular file",
        )

    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".", dir=str(target.parent)
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    result = EditResult(
        ok=True, action="restore", target=str(target),
        source_backup=str(backup_path),
    )
    try:
        shutil.copy2(backup_path, tmp_path)
        if target.exists():
            meta = copy_metadata(target, tmp_path)
            result.chown_skipped = meta.chown_skipped
            result.chown_skip_reason = meta.chown_skip_reason
        if spec.diff and target.exists():
            result.diff_text = show_diff(target, tmp_path)
        if spec.dry_run:
            result.dry_run = True
            return result
        if target.exists():
            result.backup_before_restore = str(
                make_backup(target, backup_dir)
            )
        os.replace(tmp_path, target)
        return result
    except SafeEditError:
        raise
    except Exception as exc:
        raise SafeEditError(
            "restore_failed", f"failed restoring backup: {exc}"
        ) from exc
    finally:
        tmp_path.unlink(missing_ok=True)


def apply_edit(spec: EditSpec) -> EditResult:
    """Apply an edit (or restore) atomically. Pure-ish: the only side
    effects are the temp file and the final os.replace.

    Raises SafeEditError on any handled failure; the CLI converts that
    to the historical exit code. Atomicity is unchanged from legacy:
    write to a temp file in the same directory, validate, then
    os.replace() (atomic rename). If anything fails before the replace,
    the original file is untouched.
    """
    target = Path(spec.path)
    ensure_parent(target)
    backup_dir = Path(spec.backup_dir) if spec.backup_dir else None

    if spec.restore and spec.mode:
        raise SafeEditError(
            "bad_arguments", "cannot use --restore and --mode together"
        )
    if not spec.restore and not spec.mode:
        raise SafeEditError(
            "bad_arguments", "either --mode or --restore is required"
        )

    if spec.restore:
        return _do_restore(spec)

    if not target.exists():
        if spec.create:
            target.touch()
        else:
            raise SafeEditError(
                "target_not_found",
                "file does not exist; pass --create to create it",
            )

    original = read_text(target)
    updated, changed = _apply_mode(spec, original)

    if updated == original and not spec.allow_no_change:
        raise SafeEditError(
            "no_effective_change", "the edit produced no changes"
        )

    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".", dir=str(target.parent)
    )
    os.close(fd)
    tmp_path = Path(tmp_name)

    result = EditResult(
        ok=True, action="edit", target=str(target), changed=changed
    )
    try:
        write_text(tmp_path, updated)
        meta = copy_metadata(target, tmp_path)
        result.chown_skipped = meta.chown_skipped
        result.chown_skip_reason = meta.chown_skip_reason

        validator_argv = build_validator(
            spec.validator, spec.validator_preset, tmp_path
        )
        if validator_argv:
            result.validator = validator_argv
            proc = run_argv(validator_argv)
            if proc.returncode != 0:
                detail = (proc.stdout or "").strip()
                err = (proc.stderr or "").strip()
                tail = " / ".join(x for x in (detail, err) if x)
                raise SafeEditError(
                    "validation_failed",
                    "validation failed"
                    + (f": {tail}" if tail else ""),
                )

        if spec.diff:
            result.diff_text = show_diff(target, tmp_path)

        if spec.dry_run:
            result.dry_run = True
            return result

        result.backup = str(make_backup(target, backup_dir))
        os.replace(tmp_path, target)
        return result
    except SafeEditError:
        raise
    except Exception as exc:
        raise SafeEditError(
            "write_failed", f"failed editing file: {exc}"
        ) from exc
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI wrapper — preserves the legacy stdout contract verbatim
# ---------------------------------------------------------------------------


def _render_result(result: EditResult) -> None:
    """Print the legacy stdout format so handlers/edit.py is unaffected.

    handlers/edit.py only reads returncode + the combined stdout/stderr
    text, so the exact prefixes are kept for the LLM's benefit and for
    any other consumer that greps them.
    """
    if result.diff_text:
        print(result.diff_text)

    if result.action == "restore":
        if result.dry_run:
            print(f"DRY-RUN: restore simulated on {result.target}")
            print(f"SOURCE_BACKUP: {result.source_backup}")
        else:
            print(f"OK: restored {result.target}")
            print(f"SOURCE_BACKUP: {result.source_backup}")
            if result.backup_before_restore:
                print(
                    "BACKUP_BEFORE_RESTORE: "
                    f"{result.backup_before_restore}"
                )
        if result.chown_skipped:
            print(f"METADATA: chown_skipped ({result.chown_skip_reason})")
        return

    # action == "edit"
    if result.dry_run:
        print(f"DRY-RUN: change simulated on {result.target}")
        print(f"CHANGES: {result.changed}")
        if result.validator:
            print(f"VALIDATOR: {' '.join(result.validator)}")
        if result.chown_skipped:
            print(f"METADATA: chown_skipped ({result.chown_skip_reason})")
        return

    print(f"OK: edited {result.target}")
    print(f"BACKUP: {result.backup}")
    print(f"CHANGES: {result.changed}")
    if result.validator:
        print(f"VALIDATOR: {' '.join(result.validator)}")
    if result.chown_skipped:
        print(f"METADATA: chown_skipped ({result.chown_skip_reason})")


def _spec_from_args(args: argparse.Namespace) -> EditSpec:
    return EditSpec(
        path=args.path,
        mode=args.mode,
        restore=args.restore,
        old=args.old,
        old_file=args.old_file,
        new=args.new,
        new_file=args.new_file,
        pattern=args.pattern,
        start_marker=args.start_marker,
        end_marker=args.end_marker,
        count=args.count,
        multiline=args.multiline,
        dotall=args.dotall,
        do_interpret_escapes=args.interpret_escapes,
        backup_dir=args.backup_dir,
        validator=args.validator,
        validator_preset=args.validator_preset,
        diff=args.diff,
        dry_run=args.dry_run,
        allow_no_change=args.allow_no_change,
        create=args.create,
    )


def main() -> int:
    # Issue #26: apply_edit() COMMITS before the result is rendered, and
    # the rendered diff can carry characters the console encoding cannot
    # represent (Windows cp1252). A raising print would therefore report
    # failure AFTER the state changed, and a retried non-idempotent
    # append would duplicate the mutation. Force a non-throwing UTF-8
    # text layer up front. Harmless on Linux/macOS.
    for _stream in (sys.stdout, sys.stderr):
        _reconfigure = getattr(_stream, "reconfigure", None)
        if _reconfigure is not None:
            try:
                _reconfigure(encoding="utf-8", errors="backslashreplace")
            except (ValueError, OSError):
                pass

    parser = argparse.ArgumentParser(
        description="Safe atomic file editing (API-first, no shell)"
    )
    parser.add_argument("path", help="File to edit or restore")
    parser.add_argument(
        "--mode",
        choices=[
            "replace", "regex", "replace-block",
            "append", "prepend", "write",
        ],
        help="Edit mode",
    )
    parser.add_argument(
        "--restore", help="Restore from an existing backup"
    )
    parser.add_argument("--old", help="Text to replace")
    parser.add_argument("--old-file", help="File with text to replace")
    parser.add_argument("--new", help="New text")
    parser.add_argument("--new-file", help="File with new text")
    parser.add_argument("--pattern", help="Regex to replace")
    parser.add_argument("--start-marker", help="Block start marker")
    parser.add_argument("--end-marker", help="Block end marker")
    parser.add_argument(
        "--count", type=int, default=0,
        help="Number of replacements (0 = all)",
    )
    parser.add_argument(
        "--multiline", action="store_true", help="Regex multiline"
    )
    parser.add_argument(
        "--dotall", action="store_true", help="Regex dotall"
    )
    parser.add_argument(
        "--interpret-escapes",
        action="store_true",
        help="Interpret \\n, \\t and unicode escapes in --old/--new",
    )
    parser.add_argument("--backup-dir", help="Backup directory")
    parser.add_argument(
        "--validator",
        help="Validation command. Use {file} as placeholder. "
        "Runs WITHOUT a shell (shlex-split); wrap in bash -c "
        "explicitly if you need pipes/redirects.",
    )
    parser.add_argument(
        "--validator-preset",
        choices=[
            "nginx", "json", "python", "sh", "yaml", "systemd", "toml",
        ],
        help="Predefined validator",
    )
    parser.add_argument(
        "--diff", action="store_true", help="Show a unified diff"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the change without writing the final file",
    )
    parser.add_argument(
        "--allow-no-change",
        action="store_true",
        help="Do not fail if the final content is identical",
    )
    parser.add_argument(
        "--create", action="store_true",
        help="Create the file if it does not exist",
    )
    args = parser.parse_args()

    spec = _spec_from_args(args)
    try:
        result = apply_edit(spec)
    except SafeEditError as exc:
        eprint(f"ERROR[{exc.code}]: {exc.message}")
        return _EXIT_FOR_CODE.get(exc.code, 1)

    # Issue #26 (belt and braces): the edit is already committed at this
    # point, so no rendering problem may be reported as a failed edit.
    try:
        _render_result(result)
    except Exception:  # noqa: BLE001 - never fail after the commit
        try:
            eprint(
                "WARNING: rendering the result failed; "
                "the edit WAS applied"
            )
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
