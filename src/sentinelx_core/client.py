"""Hub WebSocket client.

Owns the connection lifecycle: handshake, reconnection with exponential backoff,
ping/pong heartbeat, dispatching incoming requests to the executor.
"""

from __future__ import annotations

import asyncio
import json
import logging
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
from websockets.exceptions import ConnectionClosed
from sentinelx_protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_BINARY_FRAME_BYTES,
    PROTOCOL_VERSION,
    ConfigSummary,
    EventMessage,
    HelloMessage,
    HostInfo,
    PongMessage,
    decode_binary_frame,
    encode_binary_frame,
    is_binary_transfer_frame,
    parse_message,
)

from sentinelx_core import AGENT_VERSION
from sentinelx_core.executor import Executor
from sentinelx_core.identity import Identity
from sentinelx_core.jobs import build_completed_event_data

logger = logging.getLogger(__name__)


# Reconnection backoff (seconds): inmediate, 1, 5, 30, 60, 120, 300...
BACKOFF_SCHEDULE = [0, 1, 5, 30, 60, 120, 300]


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
    ) -> None:
        # Normalize: hub URL might be https://, we need wss://
        if hub_url.startswith("http://"):
            self._ws_url = "ws://" + hub_url[7:]
        elif hub_url.startswith("https://"):
            self._ws_url = "wss://" + hub_url[8:]
        else:
            self._ws_url = hub_url

        self._identity = identity
        self._executor = Executor(config_path=config_path)
        self._stop = asyncio.Event()

    async def run(self) -> None:
        """Main loop: connect, handle messages, reconnect on failure."""
        attempt = 0
        while not self._stop.is_set():
            wait = BACKOFF_SCHEDULE[min(attempt, len(BACKOFF_SCHEDULE) - 1)]
            if wait > 0:
                logger.info("reconnecting in %ss (attempt %d)", wait, attempt)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait)
                    return  # stop signalled during wait
                except asyncio.TimeoutError:
                    pass

            try:
                await self._connect_and_serve()
                attempt = 0  # reset on clean disconnect
            except FatalProtocolError as exc:
                logger.error("fatal protocol error, not reconnecting: %s", exc)
                return
            except ConnectionClosed as exc:
                # 1012 = "service restart": the hub told us it is coming
                # right back (e.g. a deploy). That is not a network failure,
                # so don't grow the backoff — reset it and reconnect promptly.
                # Otherwise a hub restart could leave an agent that already
                # had a high attempt count waiting up to 300s to return.
                if exc.code == 1012:
                    logger.info("hub restarting (1012); reconnecting promptly")
                    attempt = 0
                else:
                    logger.warning("connection closed (%s): %s", exc.code, exc)
                    attempt += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("connection failed: %s", exc)
                attempt += 1

    async def _connect_and_serve(self) -> None:
        url = f"{self._ws_url}/agent/connect?token={self._identity.token}"
        logger.info("connecting to %s", self._ws_url)

        async with websockets.connect(
            url, ping_interval=None, max_size=MAX_BINARY_FRAME_BYTES
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
                raise FatalProtocolError(
                    f"hub rejected: {welcome.code}: {welcome.message}"  # type: ignore[union-attr]
                )
            if welcome.type != "welcome":  # type: ignore[union-attr]
                raise RuntimeError(f"expected welcome, got {welcome.type}")  # type: ignore[union-attr]

            logger.info("connected; session=%s", welcome.session_id)  # type: ignore[union-attr]

            # 3. Concurrent loops: read messages, send heartbeat
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

    async def _read_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        async for raw in ws:
            # Binary transfer frames (this host is the DESTINATION receiving
            # chunks from the Hub) are raw bytes carrying the mini-framing
            # header; everything else is JSON control. See sentinelx_protocol.binary.
            if is_binary_transfer_frame(raw):
                asyncio.create_task(self._handle_binary_frame(ws, raw))
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
                msg = parse_message(data)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to parse incoming message: %s", exc)
                continue

            if msg.type == "request":  # type: ignore[union-attr]
                # Handle in background so a slow op doesn't block the read loop
                asyncio.create_task(self._handle_request(ws, msg))
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
        asyncio.create_task(
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
        data = build_completed_event_data(
            job_id=job_id,
            op=request.op,
            host=self._identity.host_id,
            dispatch_response=response,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
        )
        try:
            await ws.send(
                EventMessage(
                    kind="job_completed",
                    data=data,
                    timestamp=datetime.now(timezone.utc),
                ).model_dump_json()
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to emit job_completed for %s", job_id)

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
        result = response.get("result") if isinstance(response, dict) else None
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

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        from sentinelx_protocol import PingMessage

        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            ping = PingMessage(timestamp=datetime.now(timezone.utc))
            await ws.send(ping.model_dump_json())


class FatalProtocolError(Exception):
    """Hub sent a fatal error. Don't reconnect."""
