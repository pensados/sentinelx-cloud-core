"""A timed-out script must not leave its descendants running.

_kill_process_tree killed only the process we spawned. On Windows the tree was
already covered; on POSIX it was not, so a timed-out `docker run` left the
docker client and its root-owned wrapper alive for hours, one pair per
attempt, until the host was cleaned by hand.

Two details here were settled by experiment, not reasoning, and both are easy
to get wrong again:

- `kill -9 -<pgid>` is parsed as an option, not a process group. It exits 0
  and kills nothing. The `--` separator is what makes it a group.
- A tree started under sudo is root-owned and the agent user cannot signal it;
  killpg raises PermissionError and everything survives.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core.handlers import script as S


pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX behaviour")


def _spawn_tree() -> subprocess.Popen:
    """A parent with a child of its own, in its own session."""
    return subprocess.Popen(
        ["sh", "-c", "sleep 30 & sleep 30"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _alive(pgid: int) -> int:
    out = subprocess.run(
        ["ps", "-eo", "pgid=,comm="], capture_output=True, text=True
    ).stdout
    return sum(1 for line in out.splitlines() if line.split() and line.split()[0] == str(pgid))


def test_the_whole_group_dies_not_just_the_child():
    proc = _spawn_tree()
    time.sleep(0.4)
    pgid = os.getpgid(proc.pid)
    assert _alive(pgid) >= 2, "the fixture should have produced a tree"

    S._kill_process_tree(proc)
    proc.wait(timeout=5)
    time.sleep(0.4)

    assert _alive(pgid) == 0, "descendants survived the timeout"


def test_killing_an_already_dead_process_is_harmless():
    proc = _spawn_tree()
    proc.kill()
    proc.wait(timeout=5)
    S._kill_process_tree(proc)  # must not raise


def test_the_elevated_path_uses_the_group_separator(monkeypatch):
    """Without `--`, kill reads -<pgid> as an option: exit 0, nothing killed."""
    seen: list[list[str]] = []

    def _fake_run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(EE.subprocess, "run", _fake_run)
    proc = _spawn_tree()
    try:
        S._kill_process_tree(proc, elevated=True)
        assert seen, "an elevated tree must be killed through sudo"
        # Since 0.23.38 the descendants found in /proc are killed first, in their own
        # sudo kill, when the tree already has children: look for the group kill
        # among the calls rather than assuming it is the first one.
        for argv in seen:
            assert argv[:2] == ["sudo", "-n"]
            assert "--" in argv, "without -- a pid or pgid can be read as an option"
        group = [a for a in seen if a[a.index("--") + 1].startswith("-")]
        assert group, "the process group must be killed (a negative pgid after --)"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


def test_a_non_elevated_tree_does_not_shell_out_to_sudo(monkeypatch):
    """Ordinary scripts must not need sudo to be cleaned up."""
    called = []
    monkeypatch.setattr(EE.subprocess, "run", lambda *a, **k: called.append(a))
    proc = _spawn_tree()
    time.sleep(0.3)
    S._kill_process_tree(proc, elevated=False)
    proc.wait(timeout=5)
    assert called == []
