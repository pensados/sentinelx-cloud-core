"""Jan's reports of 2026-10-31 (agent 0.23.40).

sxrep_YW9E73QKVSQC  a failed in-place secret edit corrupted the file with no backup
sxrep_YC39MPSTA6S2  audit entries had no whole-entry cap (918 KB lines, ~4.3 GiB)
sxrep_AZ931A9557MC  script_run treated a failed taskkill/sudo kill as success
sxrep_058HW8X403G3, sxrep_C8GHQR7WEGKS  alternate hub URL doubled/garbled
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sentinelx_core import local_audit
from sentinelx_core.handlers import script as S
from sentinelx_core.huburl import hub_bases
from sentinelx_core.preflight import _ws_url
from sentinelx_core.vendored import pensa_safe_edit as pse

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX owner semantics")


def _secret_in_place(tmp_path, monkeypatch):
    tdir = tmp_path / "tmp"
    tdir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tdir))
    target = tmp_path / "secret.env"
    target.write_text("A" * 16 + "\n")

    def refuse_chown(*a, **k):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(pse.os, "chown", refuse_chown)
    return target, tdir


# The two 0.23.40 recovery-copy tests were replaced in 0.23.42: secret edits that
# can't keep the owner are now refused (see test_jan_followups_1031b.py).


def test_an_audit_entry_is_capped_whatever_its_shape(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", log)
    big = {"endpoint": "e", "action": "a", "params": {"items": ["x" * 200 for _ in range(4500)]}}
    local_audit.record("local_api", big, ok=True)
    local_audit.record("local_api", {"endpoint": "e", "action": "a"}, ok=True)
    lines = log.read_text().splitlines()
    assert len(lines[0]) <= local_audit.MAX_ENTRY_CHARS + 4096, len(lines[0])
    assert json.loads(lines[0])["payload"]["_summarized"] is True
    assert json.loads(lines[1])["payload"] == {"endpoint": "e", "action": "a"}


class _Proc:
    def __init__(self, pid):
        self.pid, self.killed = pid, False

    def kill(self):
        self.killed = True


def _failing_run(*a, **k):
    return subprocess.CompletedProcess(args=a[0] if a else [], returncode=1)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group")
def test_a_failed_sudo_kill_falls_back_to_kill(monkeypatch):
    sleeper = subprocess.Popen(["sleep", "30"], start_new_session=True)
    try:
        monkeypatch.setattr(S.subprocess, "run", _failing_run)
        proc = _Proc(sleeper.pid)
        S._kill_process_tree(proc, elevated=True)
        assert proc.killed, "a failed sudo kill returned as if it had worked"
    finally:
        sleeper.kill()
        sleeper.wait()


def test_a_failed_taskkill_falls_back_to_kill(monkeypatch):
    monkeypatch.setattr(S.subprocess, "run", _failing_run)
    monkeypatch.setattr(S.sys, "platform", "win32")
    proc = _Proc(999999)
    S._kill_process_tree(proc)
    assert proc.killed


@pytest.mark.parametrize("given,http,ws", [
    ("wss://localhost:8000/agent/connect", "https://localhost:8000", "wss://localhost:8000"),
    ("wss://localhost:8000/agent/connect/", "https://localhost:8000", "wss://localhost:8000"),
    ("https://localhost:8000", "https://localhost:8000", "wss://localhost:8000"),
    ("https://mcp.sentinelx.app/", "https://mcp.sentinelx.app", "wss://mcp.sentinelx.app"),
    ("ws://10.0.0.5:8000", "http://10.0.0.5:8000", "ws://10.0.0.5:8000"),
    ("http://10.0.0.5:8000/agent/connect", "http://10.0.0.5:8000", "ws://10.0.0.5:8000"),
])
def test_the_hub_url_gives_both_bases_whatever_form_it_has(given, http, ws):
    assert hub_bases(given) == (http, ws)
    assert _ws_url(given) == ws


def test_the_readme_sample_is_a_base_url():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    assert "SENTINELX_HUB_URL=https://localhost:8000 " in readme.read_text()
