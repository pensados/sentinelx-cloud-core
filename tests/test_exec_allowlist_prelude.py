"""Allowlist mode: the variables that decide what runs are read-only (agent 0.23.41).

sxrep_NBEA83P4PV36: after 0.23.39, Jan reached PATH through printf -v, which the
chain check doesn't model. The prelude doesn't depend on recognising the syntax.
"""
from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys

import pytest

from sentinelx_core.handlers import exec as ex
from sentinelx_core.policy import Policy

pytestmark = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="bash")


def _fake_ls(tmp_path):
    d = tmp_path / "fakebin"
    d.mkdir()
    ls = d / "ls"
    ls.write_text("#!/bin/sh\necho BYPASS_MARKER\n")
    ls.chmod(0o755)
    return d


async def test_jans_printf_v_bypass_no_longer_runs_the_fake_ls(tmp_path):
    fake = _fake_ls(tmp_path)
    handler = ex.make_exec_handler(Policy(allowed_commands=("ls",)))
    res = await handler({"command": f"ls >/dev/null; printf -v PATH {fake}; ls /"})
    assert "BYPASS_MARKER" not in str(res.get("output", res)), res


def test_relative_and_empty_path_entries_are_dropped(tmp_path):
    fake = _fake_ls(tmp_path)
    env = dict(os.environ, PATH=f"::.:{os.environ['PATH']}")
    out = subprocess.run(["bash", "-c", ex.ALLOWLIST_PRELUDE + f"cd {fake}; ls /"],
                         capture_output=True, text=True, env=env).stdout
    assert "BYPASS_MARKER" not in out and out.strip(), out


def test_exported_variables_are_read_only_inside_the_chain():
    out = subprocess.run(["bash", "-c", ex.ALLOWLIST_PRELUDE + 'printf -v HOME /tmp/x 2>/dev/null; echo "$HOME"'],
                         capture_output=True, text=True, env=dict(os.environ, HOME="/home/real")).stdout
    assert out.strip() == "/home/real", out


async def test_ordinary_chains_still_work_without_noise():
    handler = ex.make_exec_handler(Policy(allowed_commands=("ls", "cd")))
    res = await handler({"command": "cd / && for f in a b; do ls -d /; done"})
    out = str(res.get("output", ""))
    assert out.split() == ["/", "/"], res
    assert "readonly" not in out


async def test_unrestricted_mode_runs_the_command_as_given(monkeypatch):
    seen = []

    async def fake_run(command, **kw):
        seen.append(command)
        return {"output": "", "returncode": 0, "duration": 0}
    monkeypatch.setattr(ex, "run_shell", fake_run)
    pol = dataclasses.replace(Policy.empty(), exec_mode="unrestricted")
    await ex.make_exec_handler(pol)({"command": "echo hi"})
    await ex.make_exec_handler(Policy(allowed_commands=("echo",)))({"command": "echo hi"})
    assert seen[0] == "echo hi"
    assert seen[1].startswith(ex.ALLOWLIST_PRELUDE) and seen[1].endswith("echo hi")
