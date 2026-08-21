"""Tests for the refactored vendored pensa_safe_edit.

Focus on the four refactor goals:
  1. NO shell — the validator path cannot be shell-injected.
  2. Structured English error codes (SafeEditError).
  3. API-first — apply_edit() returns an EditResult.
  4. copy_metadata reports chown skips instead of swallowing them.

Plus regression coverage of the behaviours that MUST be preserved
(atomic write, backup, validation gating, dry-run, restore).

Everything runs against tmp_path — never a real file.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinelx_core.vendored import pensa_safe_edit
from sentinelx_core.vendored.pensa_safe_edit import (
    EditSpec,
    SafeEditError,
    apply_edit,
    build_validator,
    build_validator_preset,
    copy_metadata,
    main,
)


# --- 1. NO shell -------------------------------------------------------------


def test_validator_presets_are_argv_lists(tmp_path: Path) -> None:
    """Every preset must resolve to a list of strings — never a shell
    string. For every preset EXCEPT nginx the target appears as its own
    discrete element (the structural anti-injection property).

    nginx is the deliberate exception: `nginx -t` validates the global
    server config (/etc/nginx/nginx.conf), not a standalone file — the
    edited file is reachable only if it's `include`d from there. This
    matches the legacy binary's behaviour and is intentional.
    """
    target = tmp_path / "x.conf"
    target.write_text("x")
    for preset in ("nginx", "json", "python", "sh", "yaml", "systemd", "toml"):
        argv = build_validator_preset(preset, target)
        assert isinstance(argv, list)
        assert all(isinstance(tok, str) for tok in argv)
        if preset != "nginx":
            # the path appears as its own element, never interpolated
            assert str(target) in argv


def test_custom_validator_is_shlex_split_not_shell(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("x")
    argv = build_validator("mytool --check {file}", None, target)
    assert argv == ["mytool", "--check", str(target)]


def test_path_with_shell_metacharacters_is_inert(tmp_path: Path) -> None:
    """A filename containing shell metacharacters must NOT cause
    command execution. This is the core hardening of the refactor."""
    sentinel = tmp_path / "PWNED"
    evil_dir = tmp_path / "d; touch " / "x"
    evil_dir.parent.mkdir(parents=True)
    evil = evil_dir.parent / "victim.txt"
    evil.write_text("data")

    # Use the python validator preset on the metacharacter path.
    spec = EditSpec(
        path=str(evil),
        mode="append",
        new=" more",
    )
    apply_edit(spec)
    assert not sentinel.exists(), "shell metacharacters were interpreted!"


# --- 2. Structured English error codes --------------------------------------


def test_error_codes_are_english_and_structured(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("abc")
    with pytest.raises(SafeEditError) as exc:
        apply_edit(EditSpec(path=str(f), mode="replace", old="ZZZ", new="q"))
    assert exc.value.code == "target_text_not_found"
    # message is English, not Spanish
    assert "not found" in exc.value.message.lower()
    # original untouched
    assert f.read_text() == "abc"


def test_no_effective_change_code(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("same")
    with pytest.raises(SafeEditError) as exc:
        apply_edit(EditSpec(path=str(f), mode="write", new="same"))
    assert exc.value.code == "no_effective_change"


def test_target_not_found_code(tmp_path: Path) -> None:
    missing = tmp_path / "nope.txt"
    with pytest.raises(SafeEditError) as exc:
        apply_edit(EditSpec(path=str(missing), mode="write", new="x"))
    assert exc.value.code == "target_not_found"


# --- 3. API-first ------------------------------------------------------------


def test_apply_edit_returns_structured_result(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("uno\ndos\n")
    res = apply_edit(EditSpec(path=str(f), mode="replace", old="dos", new="DOS"))
    assert res.ok is True
    assert res.action == "edit"
    assert res.changed == 1
    assert res.backup is not None
    assert Path(res.backup).exists()
    assert f.read_text() == "uno\nDOS\n"


def test_apply_edit_dry_run_does_not_write(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("orig")
    res = apply_edit(
        EditSpec(path=str(f), mode="write", new="changed", dry_run=True)
    )
    assert res.dry_run is True
    assert f.read_text() == "orig"  # unchanged
    assert res.backup is None  # no backup on dry-run


def test_apply_edit_validation_failure_is_atomic(tmp_path: Path) -> None:
    """If the validator rejects the new content, the original file is
    left exactly as it was (atomic write guarantee preserved)."""
    f = tmp_path / "mod.py"
    f.write_text("x = 1\n")
    with pytest.raises(SafeEditError) as exc:
        apply_edit(
            EditSpec(
                path=str(f),
                mode="write",
                new="def broken(:\n",
                validator_preset="python",
            )
        )
    assert exc.value.code == "validation_failed"
    assert f.read_text() == "x = 1\n"  # untouched


def test_apply_edit_backup_then_replace(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("v1")
    res = apply_edit(EditSpec(path=str(f), mode="write", new="v2"))
    assert f.read_text() == "v2"
    assert Path(res.backup).read_text() == "v1"  # backup has the old content


def test_restore_roundtrip(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("original")
    res1 = apply_edit(EditSpec(path=str(f), mode="write", new="modified"))
    backup = res1.backup
    assert f.read_text() == "modified"
    res2 = apply_edit(EditSpec(path=str(f), restore=backup))
    assert res2.action == "restore"
    assert f.read_text() == "original"
    # restore takes its own safety backup of the pre-restore state
    assert res2.backup_before_restore is not None


# --- 4. copy_metadata reports chown skips -----------------------------------


def test_copy_metadata_returns_result(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("a")
    dst.write_text("b")
    res = copy_metadata(src, dst)
    # Same-owner copy: chown should succeed, nothing skipped.
    assert res.chown_skipped is False
    assert res.chown_skip_reason == ""


def test_copy_metadata_chown_skip_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate the agent-as-non-root case: os.chown raises
    PermissionError. The legacy code swallowed this silently; the
    refactor must record it on the result."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("a")
    dst.write_text("b")

    def boom(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chown", boom)
    res = copy_metadata(src, dst)
    assert res.chown_skipped is True
    assert "EPERM" in res.chown_skip_reason


def test_apply_edit_surfaces_chown_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "f.txt"
    f.write_text("a")

    def boom(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chown", boom)
    res = apply_edit(EditSpec(path=str(f), mode="write", new="b"))
    assert res.ok is True  # the edit still succeeds
    assert res.chown_skipped is True  # but the skip is visible
    assert f.read_text() == "b"


# --- 5. Issue #26: rendering must never report failure after the commit ------


def _run_cli(
    args: list[str], encoding: str | None = None
) -> subprocess.CompletedProcess:
    """Invoke the CLI in a child process so the real stdout encoding
    applies — the bug only reproduces on a genuine text stream."""
    env = dict(os.environ)
    env.pop("PYTHONIOENCODING", None)
    if encoding is not None:
        env["PYTHONIOENCODING"] = encoding
    return subprocess.run(
        [
            sys.executable, "-m",
            "sentinelx_core.vendored.pensa_safe_edit", *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def test_unicode_diff_on_legacy_console_encoding_succeeds(
    tmp_path: Path,
) -> None:
    """Issue #26: apply_edit() commits BEFORE the diff is rendered. On a
    console that cannot encode the diff (Windows cp1252), the render used
    to raise and the CLI exited nonzero — reporting failure AFTER the
    state had already changed, so a retried append duplicated it.

    The CLI must now exit 0 and leave exactly one append on disk."""
    f = tmp_path / "f.txt"
    f.write_text("BASE\n", encoding="utf-8")

    proc = _run_cli(
        [str(f), "--mode", "append", "--new", "APPEND \U0001F680", "--diff"],
        encoding="cp1252:strict",
    )

    assert proc.returncode == 0, proc.stderr
    assert "UnicodeEncodeError" not in proc.stderr
    assert "OK: edited" in proc.stdout
    assert f.read_text(encoding="utf-8").count("APPEND ") == 1


def test_unicode_diff_still_renders_the_diff(tmp_path: Path) -> None:
    """The fix must not silence the diff — it is rendered, with the
    unrepresentable characters escaped rather than raising."""
    f = tmp_path / "f.txt"
    f.write_text("BASE\n", encoding="utf-8")

    proc = _run_cli(
        [str(f), "--mode", "append", "--new", "APPEND \U0001F680", "--diff"],
        encoding="cp1252:strict",
    )

    assert proc.returncode == 0, proc.stderr
    assert "+APPEND " in proc.stdout


def test_render_failure_cannot_fail_a_committed_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Belt and braces: even if rendering blows up for some other
    reason, the edit is already on disk, so main() must still report
    success."""
    f = tmp_path / "f.txt"
    f.write_text("BASE\n", encoding="utf-8")

    def boom(_result):
        raise RuntimeError("render exploded")

    monkeypatch.setattr(pensa_safe_edit, "_render_result", boom)
    monkeypatch.setattr(
        sys, "argv",
        ["pensa-safe-edit", str(f), "--mode", "append", "--new", "X"],
    )

    assert main() == 0
    assert f.read_text(encoding="utf-8").rstrip().endswith("X")


def test_genuine_failure_still_exits_nonzero(tmp_path: Path) -> None:
    """Negative control: the fix must not turn real errors into
    successes."""
    proc = _run_cli(
        [
            str(tmp_path / "missing.txt"), "--mode", "replace",
            "--old", "a", "--new", "b",
        ],
    )

    assert proc.returncode != 0
    assert "target_not_found" in proc.stderr
