"""Jan's follow-ups on 0.23.38-0.23.40 (agent 0.23.42).

sxrep_YW9E73QKVSQC  the 0.23.40 recovery copy could outlive a crash in /tmp
sxrep_69N1GEHNAN1K  non-HandlerError failures after staging escaped without kept paths
sxrep_AZ931A9557MC  kill_pids ignored a failed sudo kill of escaped descendants
sxrep_YC39MPSTA6S2  the audit cap counted characters, the file is UTF-8 bytes
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core import local_audit
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import script as S
from sentinelx_core.policy import Policy
from sentinelx_core.vendored import pensa_safe_edit as pse

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX")


def _owner_lost(tmp_path, monkeypatch):
    tdir = tmp_path / "tmp"
    tdir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tdir))

    def refuse_chown(*a, **k):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(pse.os, "chown", refuse_chown)
    return tdir


@posix
def test_a_secret_edit_that_cant_keep_the_owner_is_refused_untouched(tmp_path, monkeypatch):
    tdir = _owner_lost(tmp_path, monkeypatch)
    target = tmp_path / "secret.env"
    target.write_text("SUPER_SECRET_ORIGINAL\n")

    def must_not_write(*a, **k):
        raise AssertionError("the target was written in place without a backup")
    monkeypatch.setattr(pse, "_write_over", must_not_write)
    with pytest.raises(pse.SafeEditError) as e:
        pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="NEW\n", no_backup=True))
    assert "sudo=true" in e.value.message
    assert target.read_text() == "SUPER_SECRET_ORIGINAL\n"
    assert not list(tdir.iterdir()), "a copy of the secret was left in the temp dir"


@posix
def test_an_ordinary_edit_that_cant_keep_the_owner_still_writes_in_place(tmp_path, monkeypatch):
    _owner_lost(tmp_path, monkeypatch)
    target = tmp_path / "app.conf"
    target.write_text("old\n")
    pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new="new\n", backup_dir=str(tmp_path / "bk")))
    assert target.read_text() == "new\n"


def test_the_audit_cap_is_in_bytes_as_written(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", log)
    emoji = {"endpoint": "e", "action": "a", "params": {"items": ["\U0001F600" * 200 for _ in range(300)]}}
    local_audit.record("local_api", emoji, ok=True)
    raw = log.read_bytes().splitlines()[0]
    assert len(raw) <= local_audit.MAX_ENTRY_BYTES, len(raw)
    assert json.loads(raw)["payload"]["_summarized"] is True


def test_a_failed_sudo_kill_of_escaped_descendants_falls_back_per_pid(monkeypatch):
    monkeypatch.setattr(EE.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(args=a[0] if a else [], returncode=1))
    killed = []

    def fake_kill(pid, sig):
        killed.append((pid, sig))
        raise ProcessLookupError
    monkeypatch.setattr(EE.os, "kill", fake_kill)
    assert EE.kill_pids([111, 222], elevated=True) is True
    assert killed == [(111, signal.SIGKILL), (222, signal.SIGKILL)]


def _handler(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    return S.make_script_run_handler(Policy.empty(), base), base


@posix
@pytest.mark.parametrize("env", [{"BAD=NAME": "x"}, {"X": "a\0b"}, {"": "x"}])
async def test_env_the_os_would_refuse_is_rejected_before_staging(tmp_path, env):
    h, base = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "cleanup": False, "timeout": 5, "env": env, "content": "true"})
    assert e.value.code == "invalid_payload"
    assert not list(base.rglob("script_job_*"))


@posix
async def test_a_raw_failure_after_staging_still_says_where_the_kept_workdir_is(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sudo").write_text('#!/bin/sh\nexec env -i PATH="$PATH" "$@"\n')
    (bindir / "sudo").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    real_open = os.open

    def full_disk(path, *a, **k):
        if str(path).endswith("sentinelx_env.sh"):
            raise OSError(28, "synthetic disk full during env-file creation")
        return real_open(path, *a, **k)
    monkeypatch.setattr(S.os, "open", full_disk)
    h, _ = _handler(tmp_path)
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "sudo": True, "cleanup": False, "timeout": 5,
                 "env": {"GOOD": "x"}, "content": "true"})
    assert e.value.code == "internal_error"
    assert os.path.isdir(e.value.details["workdir"])
