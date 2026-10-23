"""Hub WebSocket client.

Owns the connection lifecycle: handshake, reconnection with exponential backoff,
ping/pong heartbeat, dispatching incoming requests to the executor.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import random
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import websockets
from sentinelx_protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_BINARY_FRAME_BYTES,
    PROTOCOL_VERSION,
    ConfigSummary,
    EventMessage,
    HelloMessage,
    HostInfo,
    PongMessage,
    bound_response,
    decode_binary_frame,
    encode_binary_frame,
    is_binary_transfer_frame,
    parse_message,
)
from websockets.exceptions import ConnectionClosed

from sentinelx_core import AGENT_VERSION
from sentinelx_core.executor import Executor
from sentinelx_core.identity import Identity
from sentinelx_core.jobs import build_completed_event_data

from sentinelx_core import pending_results

logger = logging.getLogger(__name__)


# Reconnect delays, in seconds. The early steps are deliberately gentle: the
# common failure is a momentary break on an otherwise healthy path, where the
# next attempt usually works and waiting buys nothing. The old curve jumped
# 5 -> 30, so a host whose connection dropped spent close to a minute away
# (1s, a failed handshake, 5s, another failed handshake, 30s) even though the
# hub was up the whole time. The tail stays long for the case the curve was
# written for: the hub genuinely being down, where hammering it on the way
# back up is how a fleet of ours takes it out again.
#
# The tail stops at 60 s (0.23.26). With 120 and 300 s steps, an agent that went
# through a network outage of a few minutes kept sleeping up to 5 minutes after
# the network came back: orion, 2026-10-15, last failed attempt 20:07:35, then a
# 265 s wait, connected at 20:12:01. Across the fleet that showed up as hosts
# returning 12-17 minutes after a drop. At 60 s with full jitter, a fleet of
# ~3100 comes back at ~50 connections/s, the same wave every deploy already
# absorbs; and a hub that is up can still ask for longer with Retry-After.
BACKOFF_SCHEDULE = [0, 1, 2, 5, 10, 20, 30, 60]

# Seconds before trying the hub's next address when the first one doesn't answer
# (RFC 8305 recommends 250 ms). See _run_once's websockets.connect.
HAPPY_EYEBALLS_DELAY = 0.25

# Cap on a hub-supplied retry hint. The hub knows things the agent cannot --
# how many agents are reconnecting at once, whether it is mid-deploy -- so its
# suggestion is worth following. It is a suggestion, though: a buggy or hostile
# hub must not be able to tell the fleet to go quiet for a day, so the agent
# decides the ceiling.
MAX_RETRY_AFTER_SECONDS = 300


def _read_text(path: str) -> str | None:
    """Read a small pseudo-file, returning None on any error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _run(args: list[str]) -> str | None:
    """Run a short command; return stripped stdout, or None on any failure."""
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _detect_machine_type() -> str | None:
    """Classify a Linux host as wsl / container / vm / physical (best-effort)."""
    osrelease = (_read_text("/proc/sys/kernel/osrelease") or "").lower()
    version = (_read_text("/proc/version") or "").lower()
    if "microsoft" in osrelease or "wsl" in osrelease or "microsoft" in version:
        return "wsl"
    if os.path.exists("/.dockerenv"):
        return "container"
    cgroup = (_read_text("/proc/1/cgroup") or "").lower()
    if any(x in cgroup for x in ("docker", "lxc", "kubepods", "containerd")):
        return "container"
    for p in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
        v = (_read_text(p) or "").lower()
        if any(x in v for x in ("kvm", "vmware", "virtualbox", "qemu", "xen",
                                "hyper-v", "amazon", "google", "digitalocean",
                                "vultr", "openstack", "bochs")):
            return "vm"
    if "hypervisor" in (_read_text("/proc/cpuinfo") or "").lower():
        return "vm"
    return "physical"


def _gather_linux(info: dict[str, Any]) -> None:
    """Fill cpu_model / mem / distro / machine_type from Linux /proc and /sys."""
    try:
        for line in (_read_text("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith("model name"):
                info["cpu_model"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    try:
        for line in (_read_text("/proc/meminfo") or "").splitlines():
            if line.startswith("MemTotal:"):
                info["mem_total_bytes"] = int(line.split()[1]) * 1024
                break
    except Exception:
        pass
    try:
        for line in (_read_text("/etc/os-release") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                info["distro"] = line.split("=", 1)[1].strip().strip('"')
                break
    except Exception:
        pass
    try:
        info["machine_type"] = _detect_machine_type()
    except Exception:
        pass


def _gather_darwin(info: dict[str, Any]) -> None:
    """Fill cpu_model / mem / distro / machine_type on macOS via sysctl/sw_vers."""
    try:
        info["cpu_model"] = _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or None
    except Exception:
        pass
    try:
        mem = _run(["sysctl", "-n", "hw.memsize"])
        if mem:
            info["mem_total_bytes"] = int(mem)
    except Exception:
        pass
    try:
        name = _run(["sw_vers", "-productName"]) or "macOS"
        ver = _run(["sw_vers", "-productVersion"]) or ""
        info["distro"] = (name + " " + ver).strip()
    except Exception:
        pass
    try:
        vmm = _run(["sysctl", "-n", "kern.hv_vmm_present"])
        model = (_run(["sysctl", "-n", "hw.model"]) or "").lower()
        if vmm == "1" or any(x in model for x in ("vmware", "parallels", "virtualbox", "qemu")):
            info["machine_type"] = "vm"
        else:
            info["machine_type"] = "physical"
    except Exception:
        pass


def _gather_windows(info: dict[str, Any]) -> None:
    """Fill cpu_model / mem / distro / machine_type on Windows using stdlib
    only (no PowerShell at handshake time — keeps the handshake fast and
    avoids depending on pwsh being present)."""
    try:
        info["cpu_model"] = (
            os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor() or None
        )
    except Exception:
        pass
    try:
        import ctypes

        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            info["mem_total_bytes"] = int(stat.ullTotalPhys)
    except Exception:
        pass
    try:
        info["distro"] = _detect_os()
    except Exception:
        pass
    # VM-vs-physical detection needs CIM (Win32_ComputerSystem); defer to a
    # later milestone. Default to "physical" so the field isn't None.
    info["machine_type"] = "physical"


def _gather_machine_info() -> dict[str, Any]:
    """Best-effort machine details for the dashboard. Each field is guarded so a
    failure yields None and never breaks the handshake. Cross-platform: Linux
    reads /proc and /sys; macOS uses sysctl and sw_vers."""
    info: dict[str, Any] = {
        "cpu_model": None, "cpu_cores": None, "mem_total_bytes": None,
        "disk_total_bytes": None, "machine_type": None, "distro": None,
    }
    # Cross-platform fields
    try:
        info["cpu_cores"] = os.cpu_count()
    except Exception:
        pass
    try:
        info["disk_total_bytes"] = shutil.disk_usage("/").total
    except Exception:
        pass
    # Platform-specific fields
    try:
        if sys.platform == "win32":
            _gather_windows(info)
        elif sys.platform == "darwin":
            _gather_darwin(info)
        else:
            _gather_linux(info)
    except Exception:
        pass
    return info


def _detect_os() -> str:
    """Best-effort human-readable OS name from /etc/os-release.

    Returns something like "Ubuntu 24.04.1 LTS" (the PRETTY_NAME) when the
    file is present, else falls back to "linux". Never raises — a missing
    or malformed file, a minimal container, or a non-standard distro all
    degrade gracefully to the generic label. The hub stores whatever we
    send, so an older agent (plain "linux") and a newer one (pretty name)
    coexist fine. On macOS, /etc/os-release is absent, so we use sw_vers.
    """
    if sys.platform == "win32":
        # e.g. "Windows 11 (build 26200)". platform.version() -> "10.0.26200",
        # so the last dotted component is the build number.
        rel = platform.release()
        build = platform.version().split(".")[-1] if platform.version() else ""
        return f"Windows {rel} (build {build})" if build else f"Windows {rel}"
    if sys.platform == "darwin":
        name = _run(["sw_vers", "-productName"]) or "macOS"
        ver = _run(["sw_vers", "-productVersion"]) or ""
        return (name + " " + ver).strip()
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "linux"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    return "linux"


class HubClient:
    def __init__(
        self,
        hub_url: str,
        identity: Identity,
        config_path: Path,
        identity_path: Path | None = None,
    ) -> None:
        # Normalize: hub URL might be https://, we need wss://
        if hub_url.startswith("http://"):
            self._ws_url = "ws://" + hub_url[7:]
        elif hub_url.startswith("https://"):
            self._ws_url = "wss://" + hub_url[8:]
        else:
            self._ws_url = hub_url

        # Kept as-is for the HTTP rotate endpoint (which is http(s), not ws).
        self._hub_url = hub_url
        # Where identity.json lives; the rotated credential is written in a
        # writable dir near it. None disables rotation (nowhere to persist).
        self._identity_path = identity_path

        self._identity = identity
        self._executor = Executor(config_path=config_path)
        self._stop = asyncio.Event()
        self._session_established = False
        self._background_tasks: set[asyncio.Task[Any]] = set()

    async def run(self) -> None:
        """Main loop: connect, handle messages, reconnect on failure."""
        attempt = 0
        retry_hint: float | None = None
        while not self._stop.is_set():
            if retry_hint is not None:
                wait = retry_hint
                logger.info("reconnecting in %.0fs (hub asked us to wait)", wait)
                retry_hint = None
            else:
                wait = apply_jitter(
                    BACKOFF_SCHEDULE[min(attempt, len(BACKOFF_SCHEDULE) - 1)]
                )
                if wait > 0:
                    logger.info(
                        "reconnecting in %.1fs (attempt %d)", wait, attempt
                    )
            if wait > 0:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait)
                    return  # stop signalled during wait
                except asyncio.TimeoutError:
                    pass

            self._session_established = False
            try:
                await self._connect_and_serve()
                attempt = 0  # reset on clean disconnect
            except FatalProtocolError as exc:
                logger.error("fatal protocol error, not reconnecting: %s", exc)
                return
            except EnrollmentRejected as exc:
                _log_enrollment_rejected(str(exc))
                attempt += 1
            except ConnectionClosed as exc:
                # 1012 = "service restart": the hub told us it is coming
                # right back (e.g. a deploy). That is not a network failure,
                # so don't grow the backoff — reset it and reconnect promptly.
                # Otherwise a hub restart could leave an agent that already
                # had a high attempt count waiting up to the top of the curve.
                if exc.code == 1012:
                    retry_hint = parse_retry_after(_close_reason(exc))
                    logger.info(
                        "hub restarting (1012); reconnecting %s",
                        f"in {retry_hint:.0f}s as asked"
                        if retry_hint is not None
                        else "promptly",
                    )
                    attempt = 0
                elif exc.code == 1008:
                    # Policy rejection. The hub closes right after sending the
                    # error frame, so whether we get to read that frame is a
                    # race; losing it used to surface here as a plain
                    # "connection closed" and retry in silence. Same cause,
                    # same message, either way.
                    _log_enrollment_rejected(
                        _close_reason(exc) or "policy violation"
                    )
                    attempt += 1
                else:
                    logger.warning("connection closed (%s): %s", exc.code, exc)
                    retry_hint = parse_retry_after(_close_reason(exc))
                    attempt = 1 if self._session_established else attempt + 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("connection failed: %s", exc)
                attempt = 1 if self._session_established else attempt + 1

    async def _connect_and_serve(self) -> None:
        url = f"{self._ws_url}/agent/connect"
        logger.info("connecting to %s", self._ws_url)

        # Carry the enrollment token in the Authorization header, not the query
        # string, so the request URL stays short. Long query strings are
        # rejected by some edges/proxies with HTTP 400 (issue #34). websockets
        # renamed extra_headers -> additional_headers in 14.0.
        hdr_kw = (
            "additional_headers"
            if int(websockets.__version__.split(".")[0]) >= 14
            else "extra_headers"
        )
        auth_headers = {"Authorization": f"Bearer {self._identity.token}"}

        async with websockets.connect(
            url,
            **{hdr_kw: auth_headers},
            ping_interval=30,
            ping_timeout=60,
            max_size=MAX_BINARY_FRAME_BYTES,
            # Passed through to loop.create_connection: when the hub name has
            # several addresses (mcp-direct has two relays since 2026-10-23) and
            # the first doesn't answer, e.g. filtered in this agent's network,
            # race the next one after a short delay instead of spending the
            # whole open_timeout on the first and never trying the second.
            happy_eyeballs_delay=HAPPY_EYEBALLS_DELAY,
            interleave=1,
        ) as ws:
            # 1. Send hello
            hello = HelloMessage(
                protocol_version=PROTOCOL_VERSION,
                agent_version=AGENT_VERSION,
                agent_name="sentinelx-core",
                host=HostInfo(
                    id=self._identity.host_id,
                    hostname=socket.gethostname(),
                    os=_detect_os(),
                    kernel=platform.release(),
                    arch=platform.machine(),
                    config_summary=ConfigSummary(**self._executor.config_summary()),
                    **_gather_machine_info(),
                ),
                capabilities=self._executor.capability_names(),
                preferred_profile=self._executor.preferred_profile(),
            )
            await ws.send(hello.model_dump_json())

            # 2. Wait for welcome (or fatal error)
            raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
            welcome = parse_message(json.loads(raw))
            if welcome.type == "error":  # type: ignore[union-attr]
                code = welcome.code  # type: ignore[union-attr]
                message = welcome.message  # type: ignore[union-attr]
                if code == "enrollment_rejected":
                    raise EnrollmentRejected(message)
                raise FatalProtocolError(f"hub rejected: {code}: {message}")
            if welcome.type != "welcome":  # type: ignore[union-attr]
                raise RuntimeError(f"expected welcome, got {welcome.type}")  # type: ignore[union-attr]

            # A valid welcome starts a new retry history. If this session later
            # fails, the exception handler advances from zero to the first retry.
            self._session_established = True
            logger.info("connected; session=%s", welcome.session_id)  # type: ignore[union-attr]

            # Rotate the credential if it is past its half-life. AFTER a
            # proven-good session, so a rotation only ever follows a credential
            # that just worked. Best-effort: any failure is logged and the
            # agent keeps its current, still-valid credential.
            await self._maybe_rotate_credential()

            # 3. Deliver results whose own connection did not survive them.
            # Before the read loop, so an operator waiting on an answer from
            # before the interruption gets it as soon as we are back.
            self._result_state()["current_ws"] = ws
            await self._replay_pending_results(ws)

            # 4. Concurrent loops: read messages, send heartbeat
            read_task = asyncio.create_task(self._read_loop(ws))
            heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
            try:
                done, pending = await asyncio.wait(
                    [read_task, heartbeat_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                # surface the first exception
                for task in done:
                    if exc := task.exception():
                        raise exc
            finally:
                for task in (read_task, heartbeat_task):
                    if not task.done():
                        task.cancel()
                # Always await both connection-loop tasks so a simultaneous
                # transport failure cannot leave an exception un-retrieved.
                await asyncio.gather(read_task, heartbeat_task, return_exceptions=True)
                state = self._result_state()
                if state["current_ws"] is ws:
                    state["current_ws"] = None

    async def _read_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        async for raw in ws:
            # Binary transfer frames (this host is the DESTINATION receiving
            # chunks from the Hub) are raw bytes carrying the mini-framing
            # header; everything else is JSON control. See sentinelx_protocol.binary.
            if is_binary_transfer_frame(raw):
                self._spawn_background_task(self._handle_binary_frame(ws, raw))
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
                msg = parse_message(data)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to parse incoming message: %s", exc)
                continue

            if msg.type == "request":  # type: ignore[union-attr]
                # Handle in background so a slow op doesn't block the read loop
                self._spawn_background_task(self._handle_request(ws, msg))
            elif msg.type == "ping":  # type: ignore[union-attr]
                await ws.send(
                    PongMessage(timestamp=datetime.now(timezone.utc)).model_dump_json()
                )
            elif msg.type == "error":  # type: ignore[union-attr]
                raise FatalProtocolError(
                    f"{msg.code}: {msg.message}"  # type: ignore[union-attr]
                )
            elif msg.type == "pong":  # type: ignore[union-attr]
                pass  # heartbeat ack
            else:
                logger.warning("unexpected message type: %s", msg.type)  # type: ignore[union-attr]

    async def _maybe_rotate_credential(self) -> None:
        """Rotate past the credential's half-life; never disturb the session."""
        import asyncio as _asyncio

        # getattr, not self._identity_path: some construction paths (tests using
        # object.__new__) skip __init__, and rotation must simply no-op then
        # rather than raise into the connect path.
        if getattr(self, "_identity_path", None) is None:
            return
        try:
            from sentinelx_core import rotation

            if not rotation.should_rotate(self._identity.token):
                return
            new_token = await _asyncio.to_thread(
                self._rotate_over_http, self._hub_url, self._identity.token
            )
            if not new_token:
                return
            ok = await _asyncio.to_thread(
                rotation.persist_rotated,
                self._identity_path,
                self._identity.host_id,
                new_token,
                self._identity.hub,
            )
            if ok:
                logger.info("credential rotated; effective next reconnect")
        except Exception as exc:  # noqa: BLE001
            logger.warning("credential rotation skipped: %s", exc)

    @staticmethod
    def _rotate_over_http(hub_url: str, token: str) -> "str | None":
        """POST /agent/rotate with urllib (the agent has no HTTP dependency).
        Returns the new credential, or None on any failure."""
        import json as _json
        import urllib.error
        import urllib.request

        url = f"{hub_url.rstrip('/')}/agent/rotate"
        req = urllib.request.Request(
            url, data=b"", method="POST",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = _json.loads(resp.read().decode("utf-8") or "{}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("rotate request failed: %s", exc)
            return None
        cred = body.get("credential") if isinstance(body, dict) else None
        if isinstance(cred, str) and cred.count(".") == 2:
            return cred
        return None

    async def _replay_pending_results(
        self, ws: websockets.WebSocketClientProtocol
    ) -> None:
        """Re-send job results recorded while no connection could carry them.

        Safe to repeat: the hub matches a completion by job id and owning user,
        not by session, and applying the same one twice leaves the same record.
        A result for a job the hub has already forgotten is discarded there,
        which is why these expire locally too.

        Never raises. A replay failure must not stop a session from starting --
        the results stay on disk for the next one.

        Runs after welcome, on every heartbeat, and right after a job fails to
        send on its own (dead) socket. One replay at a time, and it skips a
        result whose job is sending it right now, so nothing goes out twice.
        """
        state = self._result_state()
        async with state["replay_lock"]:
            try:
                waiting = [
                    (path, event)
                    for path, event in pending_results.drain(self._executor.upload_base)
                    if _held_job_id(event) not in state["sending"]
                ]
            except Exception:  # noqa: BLE001
                logger.exception("could not read pending results")
                return
            if not waiting:
                return
            logger.info("replaying %d held result(s)", len(waiting))
            for path, event in waiting:
                try:
                    await ws.send(json.dumps(event, default=str))
                except Exception:  # noqa: BLE001
                    logger.warning("replay failed for %s; keeping it", path.name)
                    return  # the socket is gone again; stop and keep the rest
                pending_results.clear(path)

    def _result_state(self) -> dict:
        """Per-client state for result delivery, created on first use.

        Lazily, not in __init__: tests and other callers build the client with
        HubClient.__new__. Holds the live connection (None between sessions),
        the replay lock, and the job ids whose own send is in flight.
        """
        state = self.__dict__.get("_results_state")
        if state is None:
            state = {"current_ws": None, "replay_lock": asyncio.Lock(), "sending": set()}
            self.__dict__["_results_state"] = state
        return state

    async def _start_background_job(
        self,
        ws: websockets.WebSocketClientProtocol,
        request: Any,  # RequestMessage
    ) -> None:
        """Ack a background op as "running" at once, then run it detached and
        emit a job_completed event when it finishes. The immediate ack is a
        normal response on the request id, so the hub's pending future for the
        call resolves right away instead of blocking on the real result."""
        job_id = request.payload.get("job_id") or f"job_{uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc)
        ack = {
            "type": "response",
            "id": request.id,
            "ok": True,
            "result": {
                "status": "running",
                "job_id": job_id,
                "tool": request.op,
                "host": self._identity.host_id,
            },
        }
        await ws.send(json.dumps(ack, default=str))
        self._spawn_background_task(
            self._run_job_and_report(ws, request, job_id, started_at)
        )

    async def _run_job_and_report(
        self,
        ws: websockets.WebSocketClientProtocol,
        request: Any,  # RequestMessage
        job_id: str,
        started_at: datetime,
    ) -> None:
        """Run the op to completion and emit its job_completed event. Never
        raises into the caller: a failed op is a completed job with
        status=failed, and even an emit failure is only logged (the hub's
        §3d reaper covers a job whose event never arrives)."""
        try:
            response = await self._executor.dispatch(request)
        except Exception as exc:  # noqa: BLE001
            logger.exception("background job crashed on %s", request.op)
            response = {
                "ok": False,
                "error": {"code": "internal_error", "message": str(exc)},
            }
        # A job_completed event rides the same WS frame limit as a
        # synchronous response, so bound its result too (issue #24, repro C).
        if isinstance(response, dict):
            response, _ = bound_response(response)
        data = build_completed_event_data(
            job_id=job_id,
            op=request.op,
            host=self._identity.host_id,
            dispatch_response=response,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
        )
        event = EventMessage(
            kind="job_completed",
            data=data,
            timestamp=datetime.now(timezone.utc),
        )

        # Write the answer down BEFORE trying to send it. This send goes over
        # the socket the request arrived on, and if that socket has gone the
        # result is lost -- the work done, the answer built, and nobody
        # listening. Recorded here, it is replayed on the next connection.
        pending_path = None
        try:
            pending_path = pending_results.record(
                self._executor.upload_base, job_id, json.loads(event.model_dump_json())
            )
        except Exception:  # noqa: BLE001
            logger.exception("could not record pending result for %s", job_id)

        state = self._result_state()
        state["sending"].add(job_id)
        try:
            await ws.send(event.model_dump_json())
        except Exception:  # noqa: BLE001
            logger.exception("failed to emit job_completed for %s", job_id)
            state["sending"].discard(job_id)
            # It's on disk. If a newer connection is already up, its opening
            # replay may have run before this job finished: deliver it there now
            # instead of waiting for a heartbeat (issue #38, FalconZip).
            current = state["current_ws"]
            if current is not None and current is not ws:
                await self._replay_pending_results(current)
            return
        state["sending"].discard(job_id)
        pending_results.clear(pending_path)

    async def _handle_request(
        self,
        ws: websockets.WebSocketClientProtocol,
        request: Any,  # RequestMessage
    ) -> None:
        # Background ops (spec §3): ack "running" now, run detached, and report
        # completion as a job_completed event. notify_* implies background; the
        # hub sets payload["background"] and payload["job_id"].
        if request.payload.get("background"):
            await self._start_background_job(ws, request)
            return

        # When this request reached us, before anything else happens to it. The
        # hub already knows when it dispatched and when the answer came back,
        # but end to end is all it can measure, so "this took 57 seconds" has
        # never been answerable: transit, queueing here, and the work itself
        # were one number. An operator reported exactly that -- seconds-long
        # calls whose host-side work was milliseconds -- and we could only
        # reason from distributions. These two stamps split the number.
        received_at = time.time()
        try:
            response = await self._executor.dispatch(request)
        except Exception as exc:  # noqa: BLE001
            logger.exception("executor crashed on %s", request.op)
            response = {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {"code": "internal_error", "message": str(exc)},
            }
        # Cross-host transfer: a successful file_export_chunk carries its bytes
        # under "__binary_payload__" — emit them as a raw binary frame instead of
        # a JSON response (the Hub coordinator awaits the binary frame, not a
        # response; a chunk-level failure still comes back as a JSON error).
        # Carried inside `result`, which is a free-form dict, rather than as a
        # new top-level field: ResponseMessage is extra="forbid", so a field the
        # hub's pinned protocol does not know would make it reject the whole
        # message. That exact shape of mismatch cost us an outage once already.
        # The hub records these and strips the key before the caller sees it.
        result = response.get("result") if isinstance(response, dict) else None
        if isinstance(result, dict) and "__binary_payload__" not in result:
            result["_sx_timing"] = {
                "received_at": received_at,
                "finished_at": time.time(),
            }

        if response.get("ok") and isinstance(result, dict) and "__binary_payload__" in result:
            payload = result.pop("__binary_payload__")  # bytes leave the JSON path
            try:
                frame = encode_binary_frame(
                    bytes.fromhex(result["transfer_id"]),
                    int(result["chunk_index"]),
                    payload,
                )
                await ws.send(frame)
            except Exception as exc:  # noqa: BLE001
                logger.exception("failed to emit binary transfer chunk")
                await ws.send(json.dumps({
                    "type": "response", "id": request.id, "ok": False,
                    "error": {"code": "binary_emit_error", "message": str(exc)},
                }))
                return
            # Binary chunk sent; fall through to ALSO send the JSON ack response
            # (result no longer holds the bytes) so the Hub correlates the chunk
            # via normal request/response and reads bytes/eof. The binary frame
            # is sent first, so by the time this ack arrives at the Hub the chunk
            # is already queued there.
        # Bound an oversized response before it hits the frame limit (issue
        # #24, repro C): truncate the largest field(s) + attach truncation
        # metadata so an executed op is never lost to a 1009 "message too big".
        if isinstance(response, dict):
            response, _ = bound_response(response)
        await ws.send(json.dumps(response, default=str))

    async def _handle_binary_frame(
        self, ws: websockets.WebSocketClientProtocol, raw: bytes
    ) -> None:
        """DESTINATION side: a raw binary chunk arrived from the Hub. Write it to
        the upload staging dir and ack it (JSON event) so the Hub's backpressure
        can release the next chunk."""
        try:
            frame = decode_binary_frame(bytes(raw))
        except Exception as exc:  # noqa: BLE001
            logger.warning("bad binary transfer frame: %s", exc)
            return
        upload_id = frame.transfer_id.hex()
        data = {"transfer_id": upload_id, "chunk_index": frame.chunk_index}
        try:
            written = await self._executor.ingest_transfer_chunk(
                upload_id, frame.chunk_index, frame.payload
            )
            data.update(ok=True, bytes=written)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", "ingest_error")
            data.update(ok=False, error=f"{code}: {exc}")
        try:
            await ws.send(EventMessage(
                kind="transfer_chunk_ack", data=data,
                timestamp=datetime.now(timezone.utc),
            ).model_dump_json())
        except Exception:  # noqa: BLE001
            pass

    def _spawn_background_task(self, awaitable: Any) -> asyncio.Task[Any]:
        """Retain fire-and-forget work and deterministically consume failures.

        Foreground request execution is deliberately not cancelled when a
        connection closes: the operation may already have crossed a mutation
        boundary and existing request replay/idempotency remains authoritative.
        The task is retained until completion so Python never reports an orphaned
        exception if response delivery later fails on the old WebSocket.
        """
        task = asyncio.create_task(awaitable)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_task_done)
        return task

    def _background_task_done(self, task: asyncio.Task[Any]) -> None:
        self._background_tasks.discard(task)
        if task.cancelled():
            return
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        if exc is None:
            return
        if isinstance(exc, ConnectionClosed):
            logger.debug("background task ended after WebSocket close: %s", exc)
        else:
            logger.error(
                "background client task failed",
                exc_info=(type(exc), exc, exc.__traceback__),
            )

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        from sentinelx_protocol import PingMessage

        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            ping = PingMessage(timestamp=datetime.now(timezone.utc))
            await ws.send(ping.model_dump_json())
            # A result can land on disk after this connection's opening replay
            # (its job finished on the socket it started on, which had died), and
            # nothing else would look until the next disconnect. Never raises.
            await self._replay_pending_results(ws)


def _held_job_id(event: dict) -> str | None:
    """The job id of a held job_completed event: it lives under ``data``."""
    data = event.get("data")
    return (data or {}).get("job_id") if isinstance(data, dict) else event.get("job_id")


def _close_reason(exc: ConnectionClosed) -> str:
    """Close reason across websockets versions.

    ``ConnectionClosed.reason`` is deprecated since 13.1 in favour of
    ``.rcvd.reason``, but ``.rcvd`` does not exist on older releases the agent
    still runs on, so prefer the new accessor and fall back.
    """
    rcvd = getattr(exc, "rcvd", None)
    if rcvd is not None and getattr(rcvd, "reason", None):
        return str(rcvd.reason)
    try:
        return str(exc.reason or "")
    except Exception:  # noqa: BLE001
        return ""


def parse_retry_after(reason: str | None) -> float | None:
    """Read a ``retry_after=<seconds>`` hint out of a close reason.

    The hub appends it to the reason string (``hub_shutdown;retry_after=37``)
    so that a fleet-wide reconnect can be spread deliberately instead of every
    agent picking the same delay. Returns None when absent or unusable: a
    malformed hint must fall back to the local schedule rather than break
    reconnection.
    """
    if not reason:
        return None
    for part in str(reason).replace(",", ";").split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip() != "retry_after":
            continue
        try:
            seconds = float(value.strip())
        except (TypeError, ValueError):
            return None
        if seconds != seconds or seconds in (float("inf"), float("-inf")):
            return None  # NaN / infinity
        return max(0.0, min(seconds, MAX_RETRY_AFTER_SECONDS))
    return None


def apply_jitter(wait: float) -> float:
    """Spread a delay over its own window so agents stop retrying in lockstep.

    Every agent sees the same hub restart at the same instant and, without
    this, waits exactly the same time and comes back in one spike -- roughly
    1700 of them, precisely while the hub is starting up. Full jitter over the
    interval turns that into a steady trickle. Zero stays zero: the first
    attempt after a clean disconnect should still be immediate.
    """
    if wait <= 0:
        return 0.0
    return random.uniform(0.0, wait)


def _log_enrollment_rejected(detail: str) -> None:
    """One place for the message, so the frame and close paths never diverge."""
    logger.error(
        "ENROLLMENT REJECTED by the hub (%s). This host will keep retrying but "
        "cannot connect until it is fixed. Either the enrollment token in "
        "identity.json is not the one the hub issued (it can be altered when "
        "copied -- re-run enrollment from the dashboard to get a fresh one), or "
        "the owner disabled this host in the dashboard (re-enable it and this "
        "agent reconnects on its own within a few minutes).",
        detail,
    )


class FatalProtocolError(Exception):
    """Hub sent a fatal error. Don't reconnect."""


class EnrollmentRejected(Exception):
    """The hub refused our enrollment token, or this host is disabled.

    Deliberately NOT a FatalProtocolError: retrying is the point. The two
    causes both clear from the other side without touching this machine -- an
    owner re-enables a disabled host, or a hub-side problem is fixed -- and an
    agent that gave up would then need a manual restart on every host. So we
    keep the normal retry cadence and instead make each attempt say plainly
    what is wrong and what fixes it, because the previous behaviour was to log
    it as an ordinary network failure and retry in silence.
    """
