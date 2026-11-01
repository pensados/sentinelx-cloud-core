"""Jan's follow-ups on 0.23.41/0.23.42 (agent 0.23.50).

sxrep_NBEA83P4PV36  allowlist exec ran `bash -lc`: login profiles, BASH_ENV and exported
                    functions ran before the prelude and could redefine the allowed `ls`
sxrep_AZ931A9557MC  kill_pids() said descendants survived; a successful group kill hid it
sxrep_YC39MPSTA6S2  only the payload was capped; an oversized `error` still wrote 280 KB
"""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from sentinelx_core import executor_engine as EE
from sentinelx_core import local_audit
from sentinelx_core.handlers import exec as ex
from sentinelx_core.policy import Policy

posix = pytest.mark.skipif(sys.platform == "win32", reason="bash")
HIJACK = "ls() { echo HIJACKED; }\n"


@posix
async def test_allowlisted_ls_is_not_redefined_by_startup_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in (".bash_profile", ".bash_login", ".profile", ".bashrc"):
        (home / name).write_text(HIJACK)
    (tmp_path / "bash_env.sh").write_text(HIJACK)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("BASH_ENV", str(tmp_path / "bash_env.sh"))
    monkeypatch.setenv("ENV", str(tmp_path / "bash_env.sh"))
    monkeypatch.setenv("BASH_FUNC_ls%%", "() {  echo HIJACKED; }")
    r = await ex.make_exec_handler(Policy(allowed_commands=("ls",)))({"command": "ls /"})
    assert "HIJACKED" not in r["output"], r["output"]
    assert "usr" in r["output"].split(), r["output"]


async def test_escaped_descendants_not_reached_are_reported_as_left_running(monkeypatch):
    monkeypatch.setattr(EE, "kill_pids", lambda pids, elevated=False: False)
    kw = {} if sys.platform == "win32" else {"start_new_session": True}
    proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(30)", **kw)
    assert EE._kill_process_tree(proc) is False
    proc2 = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(30)", **kw)
    assert await asyncio.wait_for(EE._stop_process_tree(proc2), 10) is False
    await proc.wait()


def test_the_cap_applies_to_the_whole_entry(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", log)
    local_audit.record("exec", {"command": "x"}, ok=False, error="E" * 300_000)
    raw = log.read_bytes().splitlines()[0]
    assert len(raw) <= local_audit.MAX_ENTRY_BYTES, len(raw)
    entry = json.loads(raw)
    assert entry["op"] == "exec" and entry["error"].startswith("EEE")
