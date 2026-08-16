"""Generic execution primitives ported from the legacy SentinelX core.

These are the low-level building blocks used by handlers. They DO NOT know
about MCP, JSON-RPC, or the wire protocol — they take arguments and return
results, full stop. That makes them easy to test and reuse.

Source: /home/carlos/projects/sentinelx/agent.py (legacy SentinelX 0.3.5)
"""

from __future__ import annotations

import asyncio
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any


def _shell_argv(cmd: str) -> list[str]:
    """Build the argv that runs `cmd` through the platform's default shell.

    POSIX: `bash -lc <cmd>`. Windows has no bash natively, so we use
    PowerShell — pwsh (PowerShell 7, UTF-8 native) when present, else the
    always-available Windows PowerShell. `-NoProfile -NonInteractive` keep it
    fast and non-blocking; `-Command` takes the full command string.
    """
    if sys.platform == "win32":
        import shutil as _shutil

        exe = _shutil.which("pwsh") or _shutil.which("powershell") or "powershell"
        return [exe, "-NoProfile", "-NonInteractive", "-Command", cmd]
    return ["bash", "-lc", cmd]


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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=full_env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "output": "⏱️ Timeout",
                "duration": round(time.time() - start, 2),
                "returncode": -1,
                "timed_out": True,
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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=full_env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "stdout": "",
                "stderr": "⏱️ Timeout",
                "duration": round(time.time() - start, 2),
                "returncode": -1,
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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Error getting help: timeout"

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
