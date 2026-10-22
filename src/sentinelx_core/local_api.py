"""Talk to a host-local endpoint that already speaks a structured protocol.

WHY THIS EXISTS. To read something a local tool already knows, the assistant
goes through `exec`: build a command line, spawn a process, and parse output
written for human eyes. Docker is the clearest case, at 568 distinct users in a
week, and its most-run subcommands are READS that /var/run/docker.sock already
answers in JSON.

WHAT IT KNOWS. Open a socket, speak HTTP or JSON-RPC, make the declared request,
keep the declared fields. Nothing about Docker or any other product lives here;
that knowledge is in the host's YAML. Same shape as `services:`, where the agent
holds a generic systemctl mechanism and no nginx profile in code.

PROJECTION IS NOT COSMETIC. Measured against nine real containers: `docker ps`
text 712 bytes, raw socket JSON for the same question 20,336, curated projection
1,457. Passing the raw body through would be 28x worse than the text it replaces,
so every action declares what to keep.

NO SHELL. With transport "unix" there is no process, no argv and no shell, so
the entire shell-injection class simply cannot occur on this path. In the audit,
"command_not_allowed: contains shell operator" is among the most frequent
failures on the exec path. With transport "stdio" there IS a process, the
binary the host's owner declared, but still no shell: argv is fixed in the
config and the call's parameters only ever travel inside the JSON-RPC message.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from uuid import uuid4
from typing import Any
from sentinelx_core.winspawn import spawn_kwargs

logger = logging.getLogger(__name__)

# A body larger than this is refused rather than buffered. The far side is
# opaque to us: it can answer with anything, and a container log endpoint can
# stream indefinitely.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class LocalApiError(Exception):
    """Something went wrong talking to a local endpoint."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def project(data: Any, select: tuple[str, ...]) -> Any:
    """Keep only `select` from a dict, or from every dict in a list.

    Supports dotted paths ("Config.Image") because the interesting field is
    often nested. An empty `select` returns the data untouched, which is the
    escape hatch for endpoints whose answers are already small.
    """
    if not select:
        return data
    if isinstance(data, list):
        return [project(item, select) for item in data]
    if not isinstance(data, dict):
        return data
    out: dict[str, Any] = {}
    for spec in select:
        cur: Any = data
        for part in spec.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur is not None:
            out[spec] = cur
    return out


def _render(template: str, params: dict[str, Any]) -> str:
    """Substitute {name} placeholders from `params`.

    Values are quoted for a URL path, not for a shell: there is no shell here.
    A missing placeholder is an error rather than an empty string, because
    silently requesting /containers//json is worse than refusing.
    """
    from urllib.parse import quote

    out = template
    for key, value in (params or {}).items():
        out = out.replace("{" + str(key) + "}", quote(str(value), safe=""))
    if "{" in out and "}" in out:
        missing = out[out.index("{") + 1 : out.index("}")]
        raise LocalApiError(
            "missing_param", f"the action needs a value for '{missing}'"
        )
    return out


async def _read_http_response(reader: asyncio.StreamReader) -> bytes:
    """Read one HTTP/1.1 response body. Handles both framings Docker uses."""
    header_blob = await reader.readuntil(b"\r\n\r\n")
    head = header_blob.decode("latin-1")
    status_line = head.split("\r\n", 1)[0]
    try:
        status = int(status_line.split(" ")[1])
    except (IndexError, ValueError) as exc:
        raise LocalApiError("bad_response", f"unparseable status: {status_line!r}") from exc

    headers = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        chunks = bytearray()
        while True:
            size_line = (await reader.readuntil(b"\r\n")).strip()
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                await reader.readuntil(b"\r\n")
                break
            chunks += await reader.readexactly(size)
            await reader.readexactly(2)
            if len(chunks) > MAX_RESPONSE_BYTES:
                raise LocalApiError("too_large", "endpoint response exceeded the cap")
        body = bytes(chunks)
    else:
        length = int(headers.get("content-length") or 0)
        if length > MAX_RESPONSE_BYTES:
            raise LocalApiError("too_large", "endpoint response exceeded the cap")
        body = await reader.readexactly(length) if length else b""

    if status >= 400:
        raise LocalApiError(
            "endpoint_error",
            f"endpoint answered HTTP {status}: {body[:200].decode('utf-8', 'replace')}",
        )
    return body


async def call_http(endpoint: Any, action: Any, params: dict[str, Any]) -> Any:
    """One HTTP request over a unix socket. Docker's shape."""
    raw = (action.request or "").strip()
    try:
        method, target = raw.split(" ", 1)
    except ValueError as exc:
        raise LocalApiError(
            "bad_action", f"request must look like 'GET /path', got {raw!r}"
        ) from exc
    target = _render(target.strip(), params)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(endpoint.path), timeout=endpoint.timeout_s
        )
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
        raise LocalApiError(
            "endpoint_unreachable",
            f"cannot open {endpoint.path}: {exc.__class__.__name__}",
        ) from exc
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise LocalApiError("timeout", f"timed out opening {endpoint.path}") from exc

    try:
        request = (
            f"{method.upper()} {target} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode("latin-1"))
        await writer.drain()
        body = await asyncio.wait_for(
            _read_http_response(reader), timeout=endpoint.timeout_s
        )
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise LocalApiError("timeout", f"{endpoint.name} did not answer in time") from exc
    except asyncio.IncompleteReadError as exc:
        raise LocalApiError("bad_response", "endpoint closed mid-response") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - closing must not mask the real error
            pass

    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError as exc:
        raise LocalApiError("bad_response", "endpoint did not return JSON") from exc


# ---------------------------------------------------------------------------
# run_as: reach a socket owned by a different Unix user
#
# An endpoint like Herdr creates its socket 0600 and checks the peer
# credentials, so reaching it means BEING that user. Opening it as the agent's
# own user fails with EACCES, and running the agent as root does not help
# either: root connects but identifies as uid 0, which is not the owner.
#
# So when `run_as` is declared, the connect happens in a tiny helper invoked
# through `sudo -n -u <user>`. Measured on a real 0600 socket: as the agent
# user EACCES, as root peer_uid=0, through the helper peer_uid=<target>.
#
# WHY NOT CAP_SETUID. Forking and setuid'ing before connect also works and
# needs no sudo, but it requires AmbientCapabilities=CAP_SETUID on the unit:
# a permanently privileged agent on every host in the fleet to serve a feature
# few will use. Sudo keeps the cost on the hosts that opt in.
#
# THE OPERATOR HAS TO ALLOW IT. Since the OpenAI security work, sudo is not
# granted by default, so `run_as` does not silently acquire authority: it fails
# with an explanation naming the exact sudoers line, and the host's owner
# decides. That is the same shape the requester asked for, which was not to
# weaken the socket's permissions nor put the agent in a shared group.
# ---------------------------------------------------------------------------


def _relay_command(endpoint: Any) -> list[str]:
    return [
        "sudo", "-n", "-u", endpoint.run_as,
        sys.executable, "-m", "sentinelx_core.local_api_relay",
        endpoint.path, str(endpoint.timeout_s),
    ]


async def _call_via_run_as(endpoint: Any, payload: bytes) -> bytes:
    """Send one request through the relay, under the declared Unix identity."""
    proc = await asyncio.create_subprocess_exec(
        *_relay_command(endpoint),
        **spawn_kwargs(
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        ),
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(payload), timeout=endpoint.timeout_s + 5
        )
    except (TimeoutError, asyncio.TimeoutError) as exc:
        proc.kill()
        raise LocalApiError(
            "timeout", f"{endpoint.name} did not answer in time"
        ) from exc

    if proc.returncode == 0 and out:
        return out

    detail = (err or b"").decode("utf-8", "replace").strip()
    # sudo's own refusal is the common case and deserves a real answer rather
    # than the raw message, because the fix is a specific sudoers line.
    if "a password is required" in detail or "not allowed to execute" in detail or (
        proc.returncode == 1 and "sudo" in detail
    ):
        raise LocalApiError(
            "run_as_not_permitted",
            f"'{endpoint.name}' declares run_as={endpoint.run_as!r}, but this "
            f"agent may not become that user. The host's owner can allow just "
            f"this, and nothing else, with a sudoers rule such as:\n"
            f"  sentinelx ALL=({endpoint.run_as}) NOPASSWD: "
            f"{sys.executable} -m sentinelx_core.local_api_relay\n"
            f"Until then this endpoint is unreachable. ({detail[:120]})",
        )
    if proc.returncode == 3:
        raise LocalApiError(
            "endpoint_unreachable",
            f"cannot open {endpoint.path} as {endpoint.run_as}: {detail[:160]}",
        )
    raise LocalApiError(
        "bad_response", f"relay failed (rc={proc.returncode}): {detail[:160]}"
    )


async def call_jsonrpc(endpoint: Any, action: Any, params: dict[str, Any]) -> Any:
    """One JSON-RPC 2.0 call over a unix socket, newline framed."""
    payload = {
        "jsonrpc": "2.0",
        # A STRING id. JSON-RPC 2.0 permits either, but a receiver may declare
        # it as a string in its own schema, and a string is the shape that
        # satisfies both. Named after the caller so it is recognisable in an
        # endpoint's logs.
        "id": f"sentinel-local-api-{uuid4().hex[:8]}",
        "method": action.method,
        "params": params or {},
    }
    if getattr(endpoint, "run_as", None):
        line = await _call_via_run_as(
            endpoint, (json.dumps(payload) + "\n").encode()
        )
        try:
            message = json.loads(line)
        except ValueError as exc:
            raise LocalApiError(
                "bad_response", "endpoint did not return JSON"
            ) from exc
        if isinstance(message, dict) and message.get("error"):
            err = message["error"]
            raise LocalApiError(
                "endpoint_error",
                f"{err.get('code')}: {err.get('message')}"
                if isinstance(err, dict) else str(err),
            )
        return message.get("result") if isinstance(message, dict) else message
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(endpoint.path), timeout=endpoint.timeout_s
        )
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
        raise LocalApiError(
            "endpoint_unreachable",
            f"cannot open {endpoint.path}: {exc.__class__.__name__}",
        ) from exc
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise LocalApiError("timeout", f"timed out opening {endpoint.path}") from exc

    try:
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=endpoint.timeout_s)
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise LocalApiError("timeout", f"{endpoint.name} did not answer in time") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    if not line:
        raise LocalApiError("bad_response", "endpoint closed without answering")
    try:
        message = json.loads(line)
    except ValueError as exc:
        raise LocalApiError("bad_response", "endpoint did not return JSON") from exc
    if isinstance(message, dict) and message.get("error"):
        err = message["error"]
        raise LocalApiError(
            "endpoint_error",
            f"{err.get('code')}: {err.get('message')}" if isinstance(err, dict) else str(err),
        )
    return message.get("result") if isinstance(message, dict) else message


# ---------------------------------------------------------------------------
# transport: stdio
#
# The binary at `path` is DECLARED by the host's owner in config.yaml. The
# agent starts it, writes JSON-RPC 2.0 to its stdin one message per line (the
# framing MCP servers use over stdio), reads its stdout until the answer with
# the same id arrives, and stops it. Policy accepted `transport: stdio` since
# 0.12.0 while every call opened `path` as a socket and failed with a
# misleading endpoint_unreachable.
#
# ONE PROCESS PER CALL. A resident process would need supervising: restarts,
# a crash between calls, state from one caller leaking into the next. Starting
# fresh costs a spawn and gives every call the same clean starting point. A
# server that is slow to start is what timeout_s is for.
#
# NO SHELL, FIXED ARGV. argv is [path, *args] with both from config.yaml. The
# call's parameters travel only inside the JSON message, so nothing a caller
# sends can become an argument, a flag or a file name.
#
# STOPPING. stdin is closed after the answer (a stdio server exits on EOF);
# whatever is still running after a short grace is killed as a TREE, because a
# server that spawned helpers would otherwise leave them behind. With run_as
# the child runs under sudo as another user and the agent's signal may not
# reach it; closing stdin is then what ends it, and the agent never waits on
# it beyond a bounded grace.
# ---------------------------------------------------------------------------

# Time a binary gets to exit on its own after its stdin closes.
STDIO_EXIT_GRACE_S = 2.0
# Time to wait for the tree to go away once killed. Bounded so that a child the
# agent cannot signal (run_as) does not hold the call open.
STDIO_KILL_GRACE_S = 5.0
# Kept from stderr for error messages: the tail is where the reason usually is.
STDERR_TAIL_BYTES = 8 * 1024
# Messages that are not our answer (notifications, other ids) tolerated before
# giving up. The size cap and timeout_s bound the rest.
MAX_SKIPPED_MESSAGES = 1000
# Sent in `initialize` with handshake: mcp. A server that prefers another
# version answers with its own; the agent does not depend on any feature that
# differs between them.
MCP_PROTOCOL_VERSION = "2025-06-18"

# The child's environment starts from these, not from the agent's: the agent's
# environment is not the endpoint's business. Windows programs need the system
# variables to start at all.
_INHERITED_ENV_POSIX = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "LOGNAME",
)
_INHERITED_ENV_WINDOWS = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP",
    "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMPUTERNAME", "USERNAME",
)


def _private_group(st: os.stat_result) -> bool:
    """True for a user-private group: named after the owner, nobody else in it.

    Distros with umask 002 make a user's files group-writable on purpose; with
    a group that only holds its owner that grants nobody anything.
    """
    try:
        import grp
        import pwd

        group = grp.getgrgid(st.st_gid)
        owner = pwd.getpwuid(st.st_uid)
    except (ImportError, KeyError):
        return False
    return (
        group.gr_name == owner.pw_name
        and owner.pw_gid == st.st_gid
        and all(m == owner.pw_name for m in group.gr_mem)
    )


def _replaceable_by_others(st: os.stat_result) -> bool:
    """Could a user other than the owner change this file, or swap a directory entry?"""
    import stat as _stat

    if _stat.S_ISDIR(st.st_mode) and st.st_mode & _stat.S_ISVTX:
        # Sticky directory (/tmp): only an entry's owner can rename or remove it.
        return False
    if st.st_mode & _stat.S_IWOTH:
        return True
    return bool(st.st_mode & _stat.S_IWGRP) and not _private_group(st)


def binary_problem(path: str, run_as: str | None = None) -> tuple[str, str] | None:
    """Why the binary at `path` cannot be run, as (code, message), or None.

    unsafe_binary: the binary, or a directory holding it, is writable by
    someone other than its owner. Whoever can replace the file chooses what
    the agent runs, the same reasoning systemd applies to its unit files. The
    check runs at load AND before every call, since permissions can change.
    """
    if not os.path.isabs(path):
        return ("endpoint_unreachable", f"{path} is not an absolute path")
    try:
        real = os.path.realpath(path)
        st = os.stat(real)
    except FileNotFoundError:
        return ("endpoint_unreachable", f"{path} does not exist")
    except OSError as exc:
        return ("endpoint_unreachable", f"cannot inspect {path}: {exc.__class__.__name__}")
    import stat as _stat

    if not _stat.S_ISREG(st.st_mode):
        return ("endpoint_unreachable", f"{path} is not a regular file")
    if sys.platform == "win32":
        # POSIX mode bits mean nothing there; ACLs are the operator's job.
        return None
    if _replaceable_by_others(st):
        return (
            "unsafe_binary",
            f"{real} is writable by users other than its owner "
            f"(mode {_stat.S_IMODE(st.st_mode):o}); whoever can replace it "
            "chooses what the agent runs. Fix with: chmod go-w " + real,
        )
    for directory in sorted({os.path.dirname(real), os.path.dirname(path)}):
        try:
            dst = os.stat(directory)
        except OSError:
            continue
        if _replaceable_by_others(dst):
            return (
                "unsafe_binary",
                f"{directory} (which holds the binary) is writable by users "
                f"other than its owner (mode {_stat.S_IMODE(dst.st_mode):o}), "
                "so the binary can be swapped. Move it, or: chmod go-w "
                + directory,
            )
    if not run_as and not os.access(real, os.X_OK):
        # With run_as it is the target user who executes it, not the agent.
        return ("endpoint_unreachable", f"{path} is not executable by the agent's user")
    return None


def _stdio_command(endpoint: Any) -> list[str]:
    cmd = [endpoint.path, *getattr(endpoint, "args", ())]
    if getattr(endpoint, "run_as", None):
        # `--` so that nothing in the declared command is read as a sudo flag.
        return ["sudo", "-n", "-u", endpoint.run_as, "--", *cmd]
    return cmd


def _child_env(endpoint: Any) -> dict[str, str]:
    keys = _INHERITED_ENV_WINDOWS if sys.platform == "win32" else _INHERITED_ENV_POSIX
    env = {k: os.environ[k] for k in keys if k in os.environ}
    env.setdefault("PATH", os.defpath)
    if sys.platform != "win32":
        env.setdefault("LANG", "C.UTF-8")
    env.update(getattr(endpoint, "env", None) or {})
    return env


def _agent_user() -> str:
    try:
        import pwd

        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        return "sentinelx"


def _unwrap(message: Any) -> Any:
    """The `result` of a JSON-RPC response, or endpoint_error for its `error`."""
    if isinstance(message, dict) and message.get("error"):
        err = message["error"]
        raise LocalApiError(
            "endpoint_error",
            f"{err.get('code')}: {err.get('message')}" if isinstance(err, dict) else str(err),
        )
    return message.get("result") if isinstance(message, dict) else message


class _ProcessGone(Exception):
    """stdout closed, or stdin refused a write: the child is exiting."""


class _StdioConversation:
    """One request/response exchange (plus the MCP handshake) with one child."""

    def __init__(self, proc: Any, endpoint: Any) -> None:
        self.proc = proc
        self.endpoint = endpoint
        self.read_bytes = 0

    async def send(self, message: dict[str, Any]) -> None:
        try:
            self.proc.stdin.write((json.dumps(message) + "\n").encode())
            await self.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise _ProcessGone() from exc

    async def receive(self, want_id: str) -> dict[str, Any]:
        """Read until the response to `want_id`, skipping everything else."""
        skipped = 0
        while True:
            try:
                line = await self.proc.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError) as exc:
                raise LocalApiError(
                    "too_large", f"{self.endpoint.name} wrote a line longer than the cap"
                ) from exc
            if not line:
                raise _ProcessGone()
            self.read_bytes += len(line)
            if self.read_bytes > MAX_RESPONSE_BYTES:
                raise LocalApiError(
                    "too_large", f"{self.endpoint.name} wrote more than the cap to stdout"
                )
            text = line.strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except ValueError as exc:
                # A stdio JSON-RPC server must keep stdout for protocol
                # messages only (MCP says so explicitly); logs go to stderr.
                raise LocalApiError(
                    "bad_response",
                    f"{self.endpoint.name} wrote something that is not JSON to "
                    f"stdout: {text[:120].decode('utf-8', 'replace')!r}",
                ) from exc
            if isinstance(message, dict):
                if message.get("id") == want_id and (
                    "result" in message or "error" in message
                ):
                    return message
                if message.get("method") and message.get("id") is not None:
                    # A request FROM the server (an MCP ping, sampling). Answer
                    # it rather than leave the server waiting on us.
                    await self.send({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {
                            "code": -32601,
                            "message": "not supported by the SentinelX agent",
                        },
                    })
            skipped += 1
            if skipped > MAX_SKIPPED_MESSAGES:
                raise LocalApiError(
                    "bad_response",
                    f"{self.endpoint.name} sent {skipped} messages without answering",
                )

    async def run(self, action: Any, params: dict[str, Any]) -> dict[str, Any]:
        if getattr(self.endpoint, "handshake", "none") == "mcp":
            from sentinelx_core import AGENT_VERSION

            init_id = f"sentinel-local-api-init-{uuid4().hex[:8]}"
            await self.send({
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "sentinelx-agent", "version": AGENT_VERSION},
                },
            })
            reply = await self.receive(init_id)
            if reply.get("error"):
                try:
                    _unwrap(reply)
                except LocalApiError as exc:
                    raise LocalApiError(
                        "endpoint_error", f"initialize was refused: {exc.message}"
                    ) from exc
            await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        request_id = f"sentinel-local-api-{uuid4().hex[:8]}"
        await self.send({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": action.method,
            "params": params or {},
        })
        return await self.receive(request_id)


def _kill_stdio_tree(proc: Any) -> None:
    """Kill the child and anything it started. Safe to call after it exited."""
    if sys.platform == "win32":
        if proc.returncode is None:
            from sentinelx_core.executor_engine import _kill_process_tree

            _kill_process_tree(proc)
        return
    import signal

    try:
        # Started with start_new_session, so its process group id is its pid.
        # Signalling the group after a clean exit sweeps helpers it left.
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if proc.returncode is None:
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError):
            pass


async def _stop_stdio(proc: Any, endpoint: Any) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        try:
            proc.stdin.close()
        except Exception:  # noqa: BLE001 - stopping must not mask the real result
            pass
    if proc.returncode is None:
        try:
            await asyncio.wait_for(proc.wait(), STDIO_EXIT_GRACE_S)
        except (TimeoutError, asyncio.TimeoutError):
            pass
    _kill_stdio_tree(proc)
    if proc.returncode is None:
        try:
            await asyncio.wait_for(proc.wait(), STDIO_KILL_GRACE_S)
        except (TimeoutError, asyncio.TimeoutError):
            logger.warning(
                "local_api: %s (pid %s) still running after kill; not waiting for it",
                endpoint.name, proc.pid,
            )


def _sudo_refused(detail: str, returncode: int | None) -> bool:
    return (
        "a password is required" in detail
        or "is not allowed to execute" in detail
        or (returncode == 1 and detail.startswith("sudo:"))
    )


async def call_stdio_jsonrpc(endpoint: Any, action: Any, params: dict[str, Any]) -> Any:
    """One JSON-RPC 2.0 call to a binary started for this call alone."""
    problem = binary_problem(endpoint.path, run_as=getattr(endpoint, "run_as", None))
    if problem is not None:
        raise LocalApiError(*problem)

    run_as = getattr(endpoint, "run_as", None)
    extra: dict[str, Any] = {} if sys.platform == "win32" else {"start_new_session": True}
    try:
        proc = await asyncio.create_subprocess_exec(
            *_stdio_command(endpoint),
            **spawn_kwargs(
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=getattr(endpoint, "cwd", None),
                env=_child_env(endpoint),
                limit=MAX_RESPONSE_BYTES,
                **extra,
            ),
        )
    except OSError as exc:
        how = " through sudo" if run_as else ""
        where = f" in {endpoint.cwd}" if getattr(endpoint, "cwd", None) else ""
        raise LocalApiError(
            "endpoint_unreachable",
            f"cannot start {endpoint.path}{how}{where}: "
            f"{exc.__class__.__name__}: {exc.strerror or exc}",
        ) from exc

    stderr_tail = bytearray()

    async def drain_stderr() -> None:
        # Drained concurrently: a child that fills the stderr pipe would block
        # and never answer.
        while True:
            chunk = await proc.stderr.read(4096)
            if not chunk:
                return
            stderr_tail.extend(chunk)
            if len(stderr_tail) > STDERR_TAIL_BYTES:
                del stderr_tail[:-STDERR_TAIL_BYTES]

    def tail() -> str:
        return bytes(stderr_tail).decode("utf-8", "replace").strip()

    stderr_task = asyncio.create_task(drain_stderr())
    conversation = _StdioConversation(proc, endpoint)
    try:
        try:
            message = await asyncio.wait_for(
                conversation.run(action, params), timeout=endpoint.timeout_s
            )
        except (TimeoutError, asyncio.TimeoutError) as exc:
            detail = tail()
            raise LocalApiError(
                "timeout",
                f"{endpoint.name} did not answer within {endpoint.timeout_s:g} s"
                + (f"; stderr: {detail[-300:]}" if detail else ""),
            ) from exc
        except _ProcessGone:
            try:
                await asyncio.wait_for(proc.wait(), 1.0)
            except (TimeoutError, asyncio.TimeoutError):
                pass
            await asyncio.wait({stderr_task}, timeout=0.5)
            detail, rc = tail(), proc.returncode
            if run_as and _sudo_refused(detail, rc):
                declared = " ".join([endpoint.path, *endpoint.args])
                raise LocalApiError(
                    "run_as_not_permitted",
                    f"'{endpoint.name}' declares run_as={run_as!r}, but this agent "
                    f"may not become that user. The host's owner can allow just "
                    f"this, and nothing else, with a sudoers rule such as:\n"
                    f"  {_agent_user()} ALL=({run_as}) NOPASSWD: {declared}\n"
                    f"Until then this endpoint is unreachable. ({detail[:120]})",
                ) from None
            raise LocalApiError(
                "bad_response",
                f"{endpoint.name} exited (code {'unknown' if rc is None else rc}) "
                "before answering" + (f"; stderr: {detail[-300:]}" if detail else ""),
            ) from None
    finally:
        await _stop_stdio(proc, endpoint)
        if not stderr_task.done():
            stderr_task.cancel()
        try:
            await stderr_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    return _unwrap(message)


async def _call_transport(endpoint: Any, action: Any, params: dict[str, Any]) -> Any:
    """Route by (transport, protocol). Policy only admits stdio with jsonrpc."""
    if getattr(endpoint, "transport", "unix") == "stdio":
        return await call_stdio_jsonrpc(endpoint, action, params)
    if endpoint.protocol == "http":
        return await call_http(endpoint, action, params)
    return await call_jsonrpc(endpoint, action, params)


# ---------------------------------------------------------------------------
# Compatibility, per connection epoch (core#45)
#
# THE CONTRACT, in the requester's own words: "the profile declares how to
# obtain compatibility metadata and which values it accepts; SentinelX
# evaluates that declared constraint."
#
# WHY NOT PER CALL. A probe before every call pays a round trip for a guarantee
# it does not deliver: the endpoint can restart between the check and the call
# regardless. Binding validation to a connection epoch gives a real boundary
# instead of an expensive approximation.
#
# WHY NOT AT REGISTRATION. Probing when the agent boots would mean an endpoint
# that happens to be down at that moment never registers at all, and stays dead
# until someone restarts the agent. Validation is therefore lazy: first use in
# an epoch checks, the verdict is cached, and the cache entry is dropped the
# moment the endpoint becomes unreachable, because that IS the epoch ending.
#
# WHY NEVER `>=`. A higher version number does not imply the protocol still
# matches. `exact` is the default and `allowed` is how a maintainer widens it
# on purpose, which puts the judgement with whoever actually knows the answer.
# ---------------------------------------------------------------------------

# endpoint name -> True (passed) | (code, message) (failed). Absent means "not
# checked in this epoch".
_compat_verdicts: dict[str, Any] = {}
# endpoint name -> what identified its epoch when the verdict was reached.
_compat_epochs: dict[str, Any] = {}


def forget_compatibility(endpoint_name: str) -> None:
    """Drop a cached verdict. Called when an endpoint goes unreachable."""
    _compat_verdicts.pop(endpoint_name, None)
    _compat_epochs.pop(endpoint_name, None)


def _epoch_key(endpoint: Any) -> Any:
    """What marks a new epoch beyond losing the endpoint.

    A socket endpoint that is upgraded goes away and comes back, which ends the
    epoch through endpoint_unreachable. A stdio binary is started fresh on
    every call and never "goes away", so an upgrade would inherit the old
    verdict forever. Its epoch is the file itself: a different inode, size or
    mtime is a different binary, and gets probed again.
    """
    if getattr(endpoint, "transport", "unix") != "stdio":
        return None
    try:
        st = os.stat(endpoint.path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _extract(data: Any, path: str) -> Any:
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


async def ensure_compatible(endpoint: Any) -> None:
    """Check the declared constraint once per epoch. Raises on mismatch.

    Fails CLOSED: an endpoint that cannot be probed, or whose version cannot be
    read, is refused rather than allowed through on the assumption it is fine.
    """
    constraint = getattr(endpoint, "compatibility", None) or {}
    if not constraint:
        return

    key = _epoch_key(endpoint)
    if _compat_epochs.get(endpoint.name) != key:
        _compat_verdicts.pop(endpoint.name, None)
        _compat_epochs[endpoint.name] = key

    cached = _compat_verdicts.get(endpoint.name)
    if cached is True:
        return
    if isinstance(cached, tuple):
        raise LocalApiError(cached[0], cached[1])

    probe = constraint["probe"]
    accept = constraint["accept"]
    field = constraint["extract"]

    # The probe is described exactly like an action, so it goes through the same
    # transport rather than a parallel code path that could drift from it.
    probe_action = type(
        "ProbeAction",
        (),
        {
            "request": probe.get("request"),
            "method": probe.get("method"),
            "select": (),
        },
    )()
    try:
        reply = await _call_transport(endpoint, probe_action, {})
    except LocalApiError as exc:
        if exc.code in (
            "endpoint_unreachable", "timeout", "run_as_not_permitted", "unsafe_binary",
        ):
            # Not a verdict: the epoch never started. Leave the cache empty so
            # the next attempt probes again instead of inheriting a failure
            # that was only ever about reachability.
            #
            # run_as_not_permitted belongs here too, and for a sharper reason:
            # wrapping it as compatibility_unknown tells the operator their
            # endpoint has a version problem when what they actually need is a
            # sudoers line. The probe runs first, so without this the real cause
            # is hidden behind the first thing that happened to fail.
            raise
        verdict = (
            "compatibility_unknown",
            f"could not read the compatibility metadata '{field}' from "
            f"'{endpoint.name}': {exc.message}",
        )
        _compat_verdicts[endpoint.name] = verdict
        raise LocalApiError(*verdict) from exc

    found = _extract(reply, field)
    if found is None:
        verdict = (
            "compatibility_unknown",
            f"'{endpoint.name}' did not report '{field}', so its compatibility "
            "cannot be established. Refusing rather than assuming.",
        )
        _compat_verdicts[endpoint.name] = verdict
        raise LocalApiError(*verdict)

    if "exact" in accept:
        ok = found == accept["exact"]
        wanted = f"exactly {accept['exact']!r}"
    else:
        ok = found in (accept.get("allowed") or [])
        wanted = f"one of {accept.get('allowed')!r}"

    if not ok:
        verdict = (
            "compatibility_mismatch",
            f"'{endpoint.name}' reports {field}={found!r}, but this profile "
            f"accepts {wanted}. Widen `compatibility.accept.allowed` if the "
            "profile's maintainer says the versions are compatible; SentinelX "
            "will not assume a newer version is.",
        )
        _compat_verdicts[endpoint.name] = verdict
        logger.warning(
            "local_api compatibility mismatch on %s: %s=%r", endpoint.name, field, found
        )
        raise LocalApiError(*verdict)

    _compat_verdicts[endpoint.name] = True
    logger.info(
        "local_api compatibility ok on %s: %s=%r", endpoint.name, field, found
    )


async def call_action(endpoint: Any, action_name: str, params: dict[str, Any]) -> Any:
    """Run one ALLOWLISTED action and return its projected result."""
    action = endpoint.actions.get(action_name)
    if action is None:
        # Naming the permitted actions is deliberate: they are already visible
        # through `describe`, and guessing is the failure this avoids.
        raise LocalApiError(
            "action_not_allowed",
            f"'{action_name}' is not an allowed action on '{endpoint.name}'. "
            f"Allowed: {sorted(endpoint.actions)}",
        )
    await ensure_compatible(endpoint)
    try:
        raw = await _call_transport(endpoint, action, params)
    except LocalApiError as exc:
        if exc.code in ("endpoint_unreachable", "timeout"):
            # The epoch ended. Whatever we concluded about this endpoint no
            # longer describes whatever comes back, so re-check next time.
            forget_compatibility(endpoint.name)
        raise
    return project(raw, action.select)
