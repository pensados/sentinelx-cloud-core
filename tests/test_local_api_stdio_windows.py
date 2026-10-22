"""local_api stdio on Windows: start, answer, and kill the tree on timeout.

Windows is where stdio matters most: there are no unix sockets, so before
stdio local_api had no transport there at all. The binary is python.exe with
the server script as a fixed argument, which is also how an operator declares
a script-based server on Windows. CI runs on Linux only, so this is skipped
there explicitly rather than silently.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from sentinelx_core import local_api
from sentinelx_core.local_api import LocalApiError, call_action
from sentinelx_core.policy import LocalApiAction, LocalApiEndpoint

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows process handling; runs on a Windows host"
)

SERVER = r'''
import json, os, subprocess, sys, time
mode = sys.argv[1]
if mode == "hang":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    open(os.environ["PIDFILE"], "w").write(f"{os.getpid()} {child.pid}")
    time.sleep(600)
req = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": req["params"]}) + "\n")
sys.stdout.flush()
'''


def _ep(script, mode, **kw):
    return LocalApiEndpoint(
        name="win", transport="stdio", path=sys.executable, protocol="jsonrpc",
        actions={"echo": LocalApiAction(method="echo")},
        args=(str(script), mode), timeout_s=kw.get("timeout_s", 15.0),
        env=kw.get("env", {}),
    )


def _alive(pid: int) -> bool:
    out = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True
    ).stdout
    return str(pid) in out


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(local_api, "STDIO_EXIT_GRACE_S", 0.5)


async def test_a_call_round_trips_on_windows(tmp_path) -> None:
    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    assert await call_action(_ep(script, "echo"), "echo", {"a": 1}) == {"a": 1}


async def test_a_timeout_kills_the_tree_on_windows(tmp_path) -> None:
    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    pidfile = tmp_path / "pids"
    ep = _ep(script, "hang", timeout_s=3.0, env={"PIDFILE": str(pidfile)})
    with pytest.raises(LocalApiError) as exc:
        await call_action(ep, "echo", {})
    assert exc.value.code == "timeout"
    pids = [int(p) for p in pidfile.read_text().split()]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(_alive(p) for p in pids):
        time.sleep(0.2)
    assert not any(_alive(p) for p in pids)
