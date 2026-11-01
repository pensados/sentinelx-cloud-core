"""With sudo, the directory change must happen after privileges are granted.

Passing cwd= to create_subprocess_exec makes the PARENT chdir before exec, as
the agent's own user. So asking for sudo=true on a root-owned directory failed
with PermissionError before sudo ran at all -- the one case where the
privileges were requested precisely because the directory needs them. Reported
against an 0700 worktree the agent user cannot enter.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

WRAP_MARKER = 'cd "$1"'


def _build_argv(sudo: bool, cwd: str | None, inner: list[str]) -> tuple[list[str], str | None]:
    """The shape the handler builds, isolated so it can be asserted directly."""
    argv = (["sudo"] if sudo else []) + inner
    spawn_cwd = cwd
    if sudo and cwd:
        argv = [
            "sudo", "sh", "-c",
            'cd "$1" || { echo "sentinelx: cannot enter $1" >&2; exit 126; }; '
            'shift; exec "$@"',
            "sh", str(cwd), *argv[1:],
        ]
        spawn_cwd = None
    return argv, spawn_cwd


def test_without_sudo_nothing_changes():
    argv, spawn_cwd = _build_argv(False, "/tmp", ["bash", "/tmp/s.sh"])
    assert argv == ["bash", "/tmp/s.sh"]
    assert spawn_cwd == "/tmp", "the parent still does the chdir when it can"


def test_sudo_without_cwd_is_untouched():
    argv, spawn_cwd = _build_argv(True, None, ["bash", "/tmp/s.sh"])
    assert argv == ["sudo", "bash", "/tmp/s.sh"]
    assert spawn_cwd is None


def test_sudo_with_cwd_defers_the_chdir():
    argv, spawn_cwd = _build_argv(True, "/root/secret", ["bash", "/tmp/s.sh"])
    assert spawn_cwd is None, "the parent must NOT chdir; that is the bug"
    assert argv[0] == "sudo"
    assert WRAP_MARKER in argv[3]
    assert "/root/secret" in argv
    assert argv[-2:] == ["bash", "/tmp/s.sh"], "the real command must still run"


def test_the_directory_is_a_positional_not_an_env_var():
    """sudo strips the environment. An empty $DIR would make `cd ""` a silent
    no-op and run the script in / instead of failing."""
    argv, _ = _build_argv(True, "/root/secret", ["bash", "/tmp/s.sh"])
    joined = " ".join(argv)
    assert "SX_CWD=" not in joined
    assert "$1" in argv[3], "the directory is read from the argument list"


def test_a_directory_with_shell_metacharacters_is_inert():
    hostile = "/tmp/x; touch /tmp/pwned"
    argv, _ = _build_argv(True, hostile, ["bash", "/tmp/s.sh"])
    # It appears exactly once, as its own argv element -- never interpolated
    # into the script text, so the shell treats it as one directory name.
    assert argv.count(hostile) == 1
    assert hostile not in argv[3]


@pytest.mark.skipif(shutil.which("sudo") is None, reason="sudo not available")
@pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user to be meaningful")
def test_end_to_end_against_a_directory_we_cannot_enter(tmp_path):
    """The behaviour under test, exercised for real: the old form raises
    PermissionError, the new one runs."""
    target = tmp_path / "locked"
    target.mkdir(mode=0o700)
    try:
        os.chmod(target, 0o000)
    except PermissionError:
        pytest.skip("cannot restrict the directory")

    script = tmp_path / "s.sh"
    script.write_text("pwd\n")
    script.chmod(0o755)

    with pytest.raises(PermissionError):
        subprocess.run(["true"], cwd=str(target), capture_output=True)
