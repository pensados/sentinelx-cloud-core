"""Generic execution primitives ported from the legacy SentinelX core.

These are the low-level building blocks used by handlers. They DO NOT know
about MCP, JSON-RPC, or the wire protocol — they take arguments and return
results, full stop. That makes them easy to test and reuse.

Source: /home/carlos/projects/sentinelx/agent.py (legacy SentinelX 0.3.5)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sentinelx_core.winspawn import spawn_kwargs

logger = logging.getLogger(__name__)


def _process_group_kwargs() -> dict[str, Any]:
    """Start the shell in a killable process group on POSIX."""
    if sys.platform == "win32":
        return {}
    return {"start_new_session": True}


def _kill_process_tree(proc: asyncio.subprocess.Process) -> None:
    """Best-effort kill of the shell and every descendant it started."""
    if sys.platform == "win32":
        try:
            # spawn_kwargs adds CREATE_NO_WINDOW, like every other child we
            # start: without it, a per-user install (pythonw) flashes a console.
            completed = subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                **spawn_kwargs(capture_output=True, timeout=10, check=False),
            )
            if completed.returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            logger.debug("taskkill process-tree cleanup failed", exc_info=True)
    else:
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            pgid = None
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except PermissionError:
                pass

    try:
        proc.kill()
    except ProcessLookupError:
        pass


# How long to wait for the process tree to go away after the kill. Something that
# outlives the kill and still holds our pipes - typically a process started through
# sudo, which runs as root, so an unprivileged agent can't signal it - would otherwise
# keep proc.wait() blocked until it exits on its own (asyncio's wait() also waits for
# the pipes to close): a command with a 300 s limit came back at 900 s, when the
# root process finished (sxrep_64T9VXZEVC61).
STOP_GRACE_SECONDS = 5.0


async def _stop_process_tree(proc: asyncio.subprocess.Process) -> bool:
    """Kill the tree and wait briefly for it to go. Returns False when something
    outlived the kill and still held our pipes: we close our end and return
    instead of waiting for it, and it keeps running on its own."""
    _kill_process_tree(proc)
    try:
        await asyncio.wait_for(proc.wait(), timeout=STOP_GRACE_SECONDS)
        return True
    except ProcessLookupError:
        return True
    except (asyncio.TimeoutError, TimeoutError):
        transport = getattr(proc, "_transport", None)
        if transport is not None:
            transport.close()
        logger.warning(
            "a process started by a timed-out command outlived the kill and was left running (shell pid %s)",
            proc.pid,
        )
        return False


async def communicate_partial(
    proc: asyncio.subprocess.Process, timeout: float | None
) -> tuple[bytes, bytes, bool]:
    """proc.communicate() under a timeout that keeps what was already read.

    communicate() inside wait_for() threw away everything a process had written
    when the timeout hit, so a script that printed its progress (even with
    flush) came back as a bare "Timeout" (sxrep_AY8JPBQKSAXR). Both streams are
    read as they arrive; returns (stdout, stderr, timed_out). The caller still
    owns stopping the process tree on a timeout.
    """
    out, err = bytearray(), bytearray()

    async def pump(stream, buf: bytearray) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            buf.extend(chunk)

    try:
        await asyncio.wait_for(
            asyncio.gather(pump(proc.stdout, out), pump(proc.stderr, err), proc.wait()),
            timeout=timeout,
        )
        return bytes(out), bytes(err), False
    except TimeoutError:
        return bytes(out), bytes(err), True


LEFT_RUNNING_NOTE = (
    "A process this command started didn't stop when asked (for example one running "
    "as root through sudo) and is still running on the host."
)


def timeout_text(partial: str, left_running: bool = False) -> str:
    """The timeout marker, plus whatever the process wrote before it, if anything.

    It still starts with the marker hub and assistants already recognise.
    """
    partial = (partial or "").strip()
    text = "⏱️ Timeout" if not partial else f"⏱️ Timeout. Output written before the timeout:\n{partial}"
    return f"{text}\n{LEFT_RUNNING_NOTE}" if left_running else text


def _shell_argv(cmd: str) -> list[str]:
    """Build the argv that runs `cmd` through the platform's default shell.

    POSIX: `bash -lc <cmd>`. Windows has no bash natively, so we use
    PowerShell — pwsh (PowerShell 7, UTF-8 native) when present, else the
    always-available Windows PowerShell. `-NoProfile -NonInteractive` keep it
    fast and non-blocking; `-Command` takes the full command string.
    """
    if sys.platform == "win32":
        return [_win_powershell(), "-NoProfile", "-NonInteractive", "-Command", cmd]
    return ["bash", "-lc", cmd]


# Cache the resolved interpreter: the probing below touches the filesystem and
# the answer does not change while the process runs.
_WIN_PS_CACHE: str | None = None


def _win_powershell() -> str:
    """Return a PowerShell executable the SERVICE ACCOUNT can actually launch.

    shutil.which('pwsh') was trusted directly, and under a LocalSystem service
    it resolves to the per-user WindowsApps execution alias
    (C:\\Users\\<someone>\\AppData\\Local\\Microsoft\\WindowsApps\\pwsh.EXE) --
    a zero-byte reparse stub in a user profile that LocalSystem cannot execute,
    failing with WinError 1920. script_run worked and exec did not, on the same
    host, for exactly this reason. Reported with the alias path and the working
    Program Files path side by side.

    Resolution order, each candidate checked for real:
      1. concrete PowerShell 7 install locations (Program Files),
      2. shutil.which('pwsh'), but ONLY if it is not a WindowsApps alias,
      3. Windows PowerShell 5.1 at its System32 absolute path,
      4. the bare name 'powershell' as a last resort.
    """
    global _WIN_PS_CACHE
    if _WIN_PS_CACHE is not None:
        return _WIN_PS_CACHE

    import os as _os
    import shutil as _shutil

    def _usable(path: str | None) -> bool:
        # A real, executable file -- not a WindowsApps alias stub. The alias
        # lives under ...\Local\Microsoft\WindowsApps and is a reparse point
        # the service token cannot traverse, so exclude that path outright and
        # require an ordinary readable file elsewhere.
        if not path:
            return False
        low = path.replace("/", "\\").lower()
        if "\\microsoft\\windowsapps\\" in low:
            return False
        return _os.path.isfile(path)

    candidates: list[str] = []
    pf = _os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = _os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    candidates.append(_os.path.join(pf, "PowerShell", "7", "pwsh.exe"))
    candidates.append(_os.path.join(pf86, "PowerShell", "7", "pwsh.exe"))

    which_pwsh = _shutil.which("pwsh")
    if which_pwsh:
        candidates.append(which_pwsh)

    sysroot = _os.environ.get("SystemRoot", r"C:\Windows")
    candidates.append(
        _os.path.join(sysroot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    )

    for cand in candidates:
        if _usable(cand):
            _WIN_PS_CACHE = cand
            return cand

    # Nothing concrete resolved; the bare name lets the OS search PATH and is
    # the historical behaviour. Not cached, so a later-installed shell is found.
    return "powershell"


async def run_shell(
    cmd: str,
    *,
    timeout: float = 60.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a shell command via `bash -lc`. Returns a dict identical to the legacy shape.

    Returns:
        {"output": str, "duration": float, "returncode": int}

    The legacy core merges stdout+stderr into one "output" string for backward
    compatibility. Newer callers can use run_shell_split() for separate streams.
    """
    start = time.time()

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *_shell_argv(cmd),
            **spawn_kwargs(
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=full_env,
                **_process_group_kwargs(),
            ),
        )
        try:
            stdout_b, stderr_b, timed_out = await communicate_partial(proc, timeout)
        except asyncio.CancelledError:
            await _stop_process_tree(proc)
            raise
        if timed_out:
            left_running = not await _stop_process_tree(proc)
            partial = "\n".join(
                t for t in (stdout_b.decode(errors="replace").strip(),
                            stderr_b.decode(errors="replace").strip()) if t
            )
            return {
                "output": timeout_text(partial, left_running),
                "duration": round(time.time() - start, 2),
                "returncode": -1,
                "timed_out": True,
                **({"left_running": True} if left_running else {}),
            }

        stdout = stdout_b.decode(errors="replace").strip()
        stderr = stderr_b.decode(errors="replace").strip()

        if not stdout and not stderr:
            output = "⚠️ Sin salida"
        else:
            output = f"{stdout}\n{stderr}".strip()

        return {
            "output": output,
            "duration": round(time.time() - start, 2),
            "returncode": proc.returncode,
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "output": f"❌ Error: {exc}",
            "duration": round(time.time() - start, 2),
            "returncode": -1,
        }


async def run_shell_split(
    cmd: str,
    *,
    timeout: float = 60.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Like run_shell but returns stdout and stderr separately.

    Returns:
        {"stdout": str, "stderr": str, "duration": float, "returncode": int}
    """
    start = time.time()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *_shell_argv(cmd),
            **spawn_kwargs(
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=full_env,
                **_process_group_kwargs(),
            ),
        )
        try:
            stdout_b, stderr_b, timed_out = await communicate_partial(proc, timeout)
        except asyncio.CancelledError:
            await _stop_process_tree(proc)
            raise
        if timed_out:
            left_running = not await _stop_process_tree(proc)
            return {
                **({"left_running": True} if left_running else {}),
                "stdout": stdout_b.decode(errors="replace").strip(),
                "stderr": timeout_text(stderr_b.decode(errors="replace"), left_running),
                "duration": round(time.time() - start, 2),
                "returncode": -1,
                "timed_out": True,
            }

        return {
            "stdout": stdout_b.decode(errors="replace"),
            "stderr": stderr_b.decode(errors="replace"),
            "duration": round(time.time() - start, 2),
            "returncode": proc.returncode,
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "stdout": "",
            "stderr": f"❌ Error: {exc}",
            "duration": round(time.time() - start, 2),
            "returncode": -1,
        }


async def get_command_help(cmd: str, timeout: float = 10.0) -> str:
    """Run `<cmd>` (typically `<bin> --help` or just `<bin>`) and capture output.

    Used to embed live help text in capabilities responses, matching the legacy
    behavior. Errors are returned as a string rather than raising.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *_shell_argv(cmd),
            **spawn_kwargs(
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **_process_group_kwargs(),
            ),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            await _stop_process_tree(proc)
            return "Error getting help: timeout"
        except asyncio.CancelledError:
            await _stop_process_tree(proc)
            raise

        text = stdout_b.decode(errors="replace") or stderr_b.decode(errors="replace") or "No help available"
        return text.strip()

    except Exception as exc:  # noqa: BLE001
        return f"Error getting help: {exc}"


def safe_path_under(base: Path, candidate_str: str) -> Path:
    """Return resolved path that must live under `base`. Raises ValueError otherwise.

    Used to harden upload/edit endpoints against path traversal.
    """
    if not candidate_str or not candidate_str.strip():
        raise ValueError("missing path")

    raw = candidate_str.strip().lstrip("/")
    candidate = (base / raw).resolve()
    base_resolved = base.resolve()

    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError("path escapes base directory")

    return candidate
