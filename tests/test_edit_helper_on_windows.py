"""On Windows, sentinel_edit runs pensa-safe-edit through the agent's interpreter.

GitHub issue #56: Windows App Control (WDAC) blocked pip's unsigned console-script
launcher sentinelx-pensa-safe-edit.exe (WinError 4551), so every sentinel_edit failed
while the same code ran fine as `python -m sentinelx_core.vendored.pensa_safe_edit`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinelx_core.handlers import edit


def _argv(tmp_path, sudo):
    return edit._build_argv(binary="/opt/x/bin/sentinelx-pensa-safe-edit", workdir=tmp_path,
                            path="/srv/app/a.md", sudo=sudo, mode="write", new_text="hi\n")


def test_windows_uses_the_agents_interpreter_not_the_exe(tmp_path, monkeypatch):
    monkeypatch.setattr(edit.sys, "platform", "win32")
    argv = _argv(tmp_path, sudo=False)
    assert argv[:3] == [sys.executable, "-m", "sentinelx_core.vendored.pensa_safe_edit"]
    assert argv[3:6] == ["/srv/app/a.md", "--mode", "write"]
    assert not any(a.endswith("sentinelx-pensa-safe-edit") or a.endswith(".exe") for a in argv[:3])


def test_posix_keeps_the_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(edit.sys, "platform", "linux")
    assert _argv(tmp_path, sudo=False)[0] == "/opt/x/bin/sentinelx-pensa-safe-edit"


def test_sudo_keeps_the_exact_binary_sudoers_authorises(tmp_path, monkeypatch):
    monkeypatch.setattr(edit.sys, "platform", "linux")
    argv = _argv(tmp_path, sudo=True)
    assert argv[:2] == ["sudo", "/opt/x/bin/sentinelx-pensa-safe-edit"]


def test_the_module_command_really_edits_a_file(tmp_path):
    """Run the very argv the Windows path builds (here with this interpreter)."""
    import subprocess
    target = tmp_path / "doc.md"
    target.write_text("old\n")
    argv = [sys.executable, "-m", edit.SAFE_EDIT_MODULE, str(target), "--mode", "write",
            "--new-file", str(Path(tmp_path, "new.txt"))]
    Path(tmp_path, "new.txt").write_text("new\n")
    r = subprocess.run(argv, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert target.read_text() == "new\n"
