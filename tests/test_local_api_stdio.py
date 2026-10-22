"""local_api with transport stdio: a declared binary spoken to over stdin/stdout.

Policy accepted `transport: stdio` since 0.12.0 but no version implemented it:
every call opened `path` as a unix socket and failed with endpoint_unreachable
(reported 2026-10-22). These tests run a REAL child process, a small JSON-RPC
server written to tmp_path, so spawning, framing, the handshake, the timeout
and the process-tree kill are exercised as they run on a host.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from sentinelx_core import local_api
from sentinelx_core.local_api import LocalApiError, call_action
from sentinelx_core.policy import LocalApiAction, LocalApiEndpoint, Policy

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the fake server is a shebang script; Windows has its own test file",
)

FAKE_SERVER = r'''
import json, os, subprocess, sys, time

mode = sys.argv[1] if len(sys.argv) > 1 else "echo"

def out(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)

def linger_with_a_child():
    # Ignores EOF and leaves a grandchild: only killing the TREE ends both.
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    with open(os.environ["PIDFILE"], "w") as f:
        f.write(f"{os.getpid()} {child.pid}")
    while True:
        time.sleep(1)

if mode == "exit_early":
    sys.stderr.write("boom: no config file\n")
    sys.exit(3)
if mode == "hang":
    linger_with_a_child()
if mode == "mcp":
    init = read()
    if init.get("method") != "initialize":
        sys.stderr.write("expected initialize first\n")
        sys.exit(4)
    out({"jsonrpc": "2.0", "id": init["id"], "result": {
        "protocolVersion": init["params"]["protocolVersion"],
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "fake", "version": "1"}}})
    note = read()
    if note.get("method") != "notifications/initialized" or "id" in note:
        sys.stderr.write("no notifications/initialized\n")
        sys.exit(4)

req = read()
rid = req["id"]
if mode == "echo":
    out({"jsonrpc": "2.0", "id": rid, "result": {
        "method": req["method"], "params": req["params"], "argv": sys.argv[1:],
        "secret": os.environ.get("SECRET"), "leak": os.environ.get("SX_AGENT_ONLY"),
        "cwd": os.getcwd()}})
elif mode == "error":
    out({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "bad target"}})
elif mode == "chatty":
    out({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    out({"jsonrpc": "2.0", "id": "someone-else", "result": 1})
    out({"jsonrpc": "2.0", "id": 99, "method": "ping"})
    reply = read()
    out({"jsonrpc": "2.0", "id": rid,
         "result": {"ping_answer": (reply.get("error") or {}).get("code")}})
elif mode == "notjson":
    sys.stdout.write("starting server...\n")
    sys.stdout.flush()
    time.sleep(30)
elif mode == "huge":
    out({"jsonrpc": "2.0", "id": rid, "result": "a" * 200000})
elif mode == "mcp":
    out({"jsonrpc": "2.0", "id": rid, "result": {
        "content": [{"type": "text", "text": json.dumps(req["params"])}],
        "isError": False}})
elif mode == "versioned":
    if req["method"] == "version":
        out({"jsonrpc": "2.0", "id": rid, "result": {"protocol": int(sys.argv[2])}})
    else:
        out({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}})
elif mode == "answer_then_linger":
    out({"jsonrpc": "2.0", "id": rid, "result": "done"})
    linger_with_a_child()
'''


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # Keep the slow paths fast; the values are about bounds, not their size.
    monkeypatch.setattr(local_api, "STDIO_EXIT_GRACE_S", 0.2)
    monkeypatch.setattr(local_api, "STDIO_KILL_GRACE_S", 2.0)
    local_api._compat_verdicts.clear()
    local_api._compat_epochs.clear()
    yield
    local_api._compat_verdicts.clear()
    local_api._compat_epochs.clear()


@pytest.fixture
def server(tmp_path) -> Path:
    tmp_path.chmod(0o700)
    path = tmp_path / "fake-server"
    path.write_text(f"#!{sys.executable}\n" + FAKE_SERVER, encoding="utf-8")
    path.chmod(0o755)
    return path


def _ep(server, *args, **kw) -> LocalApiEndpoint:
    return LocalApiEndpoint(
        name=kw.pop("name", "fake"),
        transport="stdio",
        path=str(server),
        protocol="jsonrpc",
        actions={
            "echo": LocalApiAction(method="do.thing"),
            "tools.call": LocalApiAction(method="tools/call"),
            "version": LocalApiAction(method="version"),
        },
        timeout_s=kw.pop("timeout_s", 10.0),
        run_as=kw.pop("run_as", None),
        compatibility=kw.pop("compatibility", {}),
        args=tuple(args),
        cwd=kw.pop("cwd", None),
        env=kw.pop("env", {}),
        handshake=kw.pop("handshake", "none"),
    )


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(") ", 1)[1].startswith("Z")
    except OSError:
        return True


def _all_gone(pids, within: float = 3.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if all(_gone(p) for p in pids):
            return True
        time.sleep(0.05)
    return False


def _pids(pidfile: Path) -> list[int]:
    return [int(x) for x in pidfile.read_text().split()]


# --- the round trip ---------------------------------------------------------


async def test_a_call_reaches_the_binary_and_returns_its_result(server) -> None:
    # The defect itself: this used to open `path` as a socket.
    out = await call_action(_ep(server, "echo", "--flag"), "echo", {"target": "a; rm -rf /"})
    assert out["method"] == "do.thing"
    assert out["params"] == {"target": "a; rm -rf /"}


async def test_parameters_never_reach_argv(server) -> None:
    # argv is the declared list, whatever the call sends.
    out = await call_action(_ep(server, "echo", "--flag"), "echo", {"x": "--evil"})
    assert out["argv"] == ["echo", "--flag"]


async def test_the_child_gets_a_minimal_environment_plus_the_declared_one(
    server, monkeypatch
) -> None:
    monkeypatch.setenv("SX_AGENT_ONLY", "agent-secret")
    out = await call_action(_ep(server, "echo", env={"SECRET": "s3"}), "echo", {})
    assert out["secret"] == "s3"
    assert out["leak"] is None, "the agent's own environment must not reach the child"


async def test_cwd_is_where_the_binary_runs(server, tmp_path) -> None:
    out = await call_action(_ep(server, "echo", cwd=str(tmp_path)), "echo", {})
    assert os.path.realpath(out["cwd"]) == os.path.realpath(tmp_path)


async def test_a_jsonrpc_error_is_endpoint_error(server) -> None:
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "error"), "echo", {})
    assert exc.value.code == "endpoint_error"
    assert "bad target" in exc.value.message


async def test_notifications_and_other_ids_are_skipped_and_server_requests_answered(
    server,
) -> None:
    # A server may log progress, answer someone else, or ask us something (an
    # MCP ping) before it answers. None of those is our answer, and a request
    # left unanswered would leave the server waiting on us.
    out = await call_action(_ep(server, "chatty"), "echo", {})
    assert out == {"ping_answer": -32601}


# --- failures ---------------------------------------------------------------


async def test_non_json_on_stdout_is_bad_response(server) -> None:
    start = time.monotonic()
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "notjson"), "echo", {})
    assert exc.value.code == "bad_response"
    assert "not JSON" in exc.value.message
    assert time.monotonic() - start < 5, "the child must be stopped, not waited out"


async def test_exiting_before_answering_reports_the_code_and_stderr(server) -> None:
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "exit_early"), "echo", {})
    assert exc.value.code == "bad_response"
    assert "code 3" in exc.value.message
    assert "boom: no config file" in exc.value.message


async def test_a_hung_binary_times_out_and_its_whole_tree_is_killed(
    server, tmp_path
) -> None:
    pidfile = tmp_path / "pids"
    ep = _ep(server, "hang", timeout_s=1.0, env={"PIDFILE": str(pidfile)})
    start = time.monotonic()
    with pytest.raises(LocalApiError) as exc:
        await call_action(ep, "echo", {})
    assert exc.value.code == "timeout"
    assert time.monotonic() - start < 4
    assert _all_gone(_pids(pidfile)), "the server and its child must not outlive the call"


async def test_a_binary_that_lingers_after_answering_is_stopped(server, tmp_path) -> None:
    pidfile = tmp_path / "pids"
    out = await call_action(
        _ep(server, "answer_then_linger", env={"PIDFILE": str(pidfile)}), "echo", {}
    )
    assert out == "done"
    assert _all_gone(_pids(pidfile))


async def test_output_beyond_the_cap_is_refused(server, monkeypatch) -> None:
    monkeypatch.setattr(local_api, "MAX_RESPONSE_BYTES", 64 * 1024)
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "huge"), "echo", {})
    assert exc.value.code == "too_large"


async def test_a_missing_binary_is_unreachable(tmp_path) -> None:
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(tmp_path / "nope"), "echo", {})
    assert exc.value.code == "endpoint_unreachable"


async def test_a_binary_that_became_writable_by_others_is_refused_at_call_time(
    server,
) -> None:
    # Checked before every call, not only at load: permissions can change.
    server.chmod(0o777)
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "echo"), "echo", {})
    assert exc.value.code == "unsafe_binary"


# --- MCP over stdio ---------------------------------------------------------


async def test_the_mcp_handshake_precedes_the_call(server) -> None:
    params = {"name": "echo", "arguments": {"x": 1}}
    out = await call_action(_ep(server, "mcp", handshake="mcp"), "tools.call", params)
    assert json.loads(out["content"][0]["text"]) == params


async def test_without_the_handshake_an_mcp_server_refuses(server) -> None:
    # Why the option exists: an MCP server answers nothing before initialize.
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "mcp"), "tools.call", {"name": "echo"})
    assert exc.value.code == "bad_response"
    assert "initialize" in exc.value.message


# --- run_as -----------------------------------------------------------------


def _fake_sudo(tmp_path, monkeypatch, body: str) -> Path:
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    sudo = fakebin / "sudo"
    sudo.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    sudo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}")
    return fakebin


async def test_run_as_goes_through_sudo_with_the_declared_command(
    server, tmp_path, monkeypatch
) -> None:
    log = tmp_path / "sudo-argv"
    _fake_sudo(tmp_path, monkeypatch, f"""
        import os, sys, json
        open({str(log)!r}, "w").write(json.dumps(sys.argv[1:]))
        cmd = sys.argv[sys.argv.index("--") + 1:]
        os.execv(cmd[0], cmd)
    """)
    out = await call_action(_ep(server, "echo", run_as="userx"), "echo", {"a": 1})
    assert out["params"] == {"a": 1}
    assert json.loads(log.read_text()) == ["-n", "-u", "userx", "--", str(server), "echo"]


async def test_a_refused_sudo_names_the_sudoers_line(server, tmp_path, monkeypatch) -> None:
    _fake_sudo(tmp_path, monkeypatch, """
        import sys
        sys.stderr.write("sudo: a password is required\\n")
        sys.exit(1)
    """)
    with pytest.raises(LocalApiError) as exc:
        await call_action(_ep(server, "echo", "--x", run_as="userx"), "echo", {})
    assert exc.value.code == "run_as_not_permitted"
    assert f"ALL=(userx) NOPASSWD: {server} echo --x" in exc.value.message


# --- compatibility ----------------------------------------------------------


_EXACT_20 = {
    "probe": {"method": "version"},
    "extract": "protocol",
    "accept": {"exact": 20},
}


async def test_the_compatibility_probe_goes_over_stdio(server) -> None:
    ok = _ep(server, "versioned", "20", compatibility=_EXACT_20)
    assert await call_action(ok, "echo", {}) == {"ok": True}
    bad = _ep(server, "versioned", "21", compatibility=_EXACT_20, name="other")
    with pytest.raises(LocalApiError) as exc:
        await call_action(bad, "echo", {})
    assert exc.value.code == "compatibility_mismatch"


async def test_replacing_the_binary_starts_a_new_epoch(server) -> None:
    # A stdio binary never "goes away" between calls, so without this an
    # upgrade would inherit the verdict reached for the old one forever.
    ep = _ep(server, "versioned", "20", compatibility=_EXACT_20)
    assert await call_action(ep, "echo", {}) == {"ok": True}
    upgraded = FAKE_SERVER.replace("int(sys.argv[2])", "21")   # same argv, new answer
    server.write_text(f"#!{sys.executable}\n" + upgraded, encoding="utf-8")
    with pytest.raises(LocalApiError) as exc:
        await call_action(ep, "echo", {})
    assert exc.value.code == "compatibility_mismatch"


# --- the handler --------------------------------------------------------------


def _policy(body: str, tmp_path: Path) -> Policy:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return Policy.from_file(p)


def _stdio_config(server: Path, extra: str = "") -> str:
    return f"""
        local_apis:
          fake:
            transport: stdio
            protocol: jsonrpc
            path: {server}
            args: ["echo", "--token", "s3cret"]
            handshake: none
            timeout_s: 10
{textwrap.indent(textwrap.dedent(extra), " " * 12)}
            actions:
              echo: {{ method: do.thing }}
        """


async def _handle(pol, payload):
    from sentinelx_core.handlers import build_registry

    return await build_registry(policy=pol)["local_api"](payload)


async def test_describe_shows_what_runs_but_not_the_argument_values(
    server, tmp_path
) -> None:
    pol = _policy(_stdio_config(server), tmp_path)
    d = await _handle(pol, {"operation": "describe", "endpoint": "fake"})
    assert d["transport"] == "stdio"
    assert d["path"] == str(server)
    assert d["handshake"] == "none"
    assert d["arg_count"] == 3
    assert "s3cret" not in json.dumps(d)


async def test_the_handler_calls_through_stdio(server, tmp_path) -> None:
    pol = _policy(_stdio_config(server), tmp_path)
    listed = await _handle(pol, {"operation": "list"})
    assert listed["endpoints"][0]["transport"] == "stdio"
    r = await _handle(
        pol, {"operation": "call", "endpoint": "fake", "action": "echo", "params": {"k": "v"}}
    )
    assert r["ok"] is True
    assert r["result"]["params"] == {"k": "v"}


# --- policy -------------------------------------------------------------------


def test_a_valid_stdio_endpoint_carries_its_fields(server, tmp_path) -> None:
    pol = _policy(
        _stdio_config(server, f"cwd: {tmp_path}\nenv: {{ A: '1', PORT: 8080 }}\n"),
        tmp_path,
    )
    ep = pol.local_apis["fake"]
    assert ep.transport == "stdio"
    assert ep.args == ("echo", "--token", "s3cret")
    assert ep.cwd == str(tmp_path)
    assert ep.env == {"A": "1", "PORT": "8080"}
    assert ep.handshake == "none"


def test_stdio_with_protocol_http_is_skipped(server, tmp_path) -> None:
    # The action carries a `request` too, so the only thing refusing this is
    # the stdio rule, not the http action check.
    body = _stdio_config(server).replace("protocol: jsonrpc", "protocol: http").replace(
        "echo: { method: do.thing }", 'echo: { method: do.thing, request: "GET /" }'
    )
    assert _policy(body, tmp_path).local_apis == {}


@pytest.mark.parametrize(
    "change",
    [
        ("handshake: none", "handshake: lsp"),          # unknown handshake
        ('args: ["echo", "--token", "s3cret"]', "args: --stdio"),  # not a list
        ('args: ["echo", "--token", "s3cret"]', "args: [{a: 1}]"),  # not strings
    ],
)
def test_a_malformed_stdio_endpoint_is_skipped(server, tmp_path, change) -> None:
    body = _stdio_config(server).replace(*change)
    assert _policy(body, tmp_path).local_apis == {}


def test_a_relative_path_is_skipped(server, tmp_path) -> None:
    body = _stdio_config(server).replace(f"path: {server}", "path: bin/fake-server")
    assert _policy(body, tmp_path).local_apis == {}


def test_a_relative_cwd_is_skipped(server, tmp_path) -> None:
    assert _policy(_stdio_config(server, "cwd: work\n"), tmp_path).local_apis == {}


def test_env_with_run_as_is_skipped_since_sudo_would_drop_it(server, tmp_path) -> None:
    body = _stdio_config(server, "run_as: userx\nenv: { A: '1' }\n")
    assert _policy(body, tmp_path).local_apis == {}


def test_a_binary_writable_by_others_is_skipped(server, tmp_path) -> None:
    server.chmod(0o757)
    assert _policy(_stdio_config(server), tmp_path).local_apis == {}


def test_a_binary_in_a_directory_writable_by_others_is_skipped(tmp_path) -> None:
    tmp_path.chmod(0o700)
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)        # not sticky: anyone can swap the file
    binary = shared / "srv"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    assert _policy(_stdio_config(binary), tmp_path).local_apis == {}


def test_a_missing_binary_still_registers(tmp_path) -> None:
    # Like a socket that is down at boot: it may be installed later, and each
    # call reports it rather than the endpoint silently not existing.
    pol = _policy(_stdio_config(tmp_path / "later"), tmp_path)
    assert "fake" in pol.local_apis


def test_stdio_options_on_a_unix_endpoint_are_ignored_with_a_warning(
    tmp_path, caplog
) -> None:
    import logging

    with caplog.at_level(logging.WARNING):
        pol = _policy(
            """
            local_apis:
              x:
                transport: unix
                path: /tmp/x.sock
                protocol: jsonrpc
                args: ["--nope"]
                actions:
                  a: { method: a }
            """,
            tmp_path,
        )
    assert pol.local_apis["x"].args == ()
    assert any("only apply to transport stdio" in r.getMessage() for r in caplog.records)
