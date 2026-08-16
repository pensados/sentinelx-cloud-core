"""script_run handler: execute a temporary bash/python script with optional sudo.

Ported from legacy SentinelX 0.3.5 /script/run endpoint. Writes the script
content to a workdir under the upload base, executes it, returns stdout/stderr/
returncode. Cleans up unless cleanup=False is requested (in which case the
caller gets the path back, useful for debugging).

Security model:
- The script is written to a per-request workdir (no name collisions).
- Optional `sudo` requires that the agent user is in sudoers without password
  for the relevant binary. We don't try to validate that here.
- timeout is hard-capped at 600 seconds (10 min); longer work should run
  in the background and be polled rather than blocking the caller.
- The script's content itself is NOT validated against the policy allowlist
  — the allowlist applies to `exec` only. `script_run` is a separate
  capability with its own scope, intentionally more powerful.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.jobs import BACKGROUND_TIMEOUT_MAX
from sentinelx_core.policy import Policy

# Hard limits, mirror legacy behavior
TIMEOUT_MIN = 1
# 600s (10 min) covers legitimately long operations (large package upgrades,
# builds, backups) while still bounding how long a stuck operation ties up the
# hub. For anything longer, the right pattern is to launch it in the background
# (nohup/systemd/screen) and poll for the result rather than block the caller.
TIMEOUT_MAX = 600
ALLOWED_INTERPRETERS = ("bash", "python3", "powershell", "pwsh")


def make_script_run_handler(policy: Policy, upload_base: Path):
    """Return an async handler that creates a workdir under upload_base."""

    async def handle_script_run(payload: dict[str, Any]) -> dict[str, Any]:
        interpreter = payload.get("interpreter")
        content = payload.get("content")
        args = payload.get("args") or []
        cwd = payload.get("cwd")
        timeout = int(payload.get("timeout", 60))
        sudo = bool(payload.get("sudo", False))
        cleanup = bool(payload.get("cleanup", True))
        filename = payload.get("filename")
        env_extra = payload.get("env") or {}
        background = bool(payload.get("background", False))

        # Validation, mirrors legacy ScriptRunRequest
        if interpreter not in ALLOWED_INTERPRETERS:
            raise HandlerError(
                "invalid_payload",
                f"interpreter must be one of: {', '.join(ALLOWED_INTERPRETERS)}",
            )
        if not content or not str(content).strip():
            raise HandlerError("invalid_payload", "missing 'content'")
        max_timeout = BACKGROUND_TIMEOUT_MAX if background else TIMEOUT_MAX
        if timeout < TIMEOUT_MIN or timeout > max_timeout:
            hint = (
                ""
                if background
                else (
                    f" For work longer than {TIMEOUT_MAX // 60} minutes, run it "
                    "in the background (background=true) and poll the result "
                    "with notifications(check) instead of blocking."
                )
            )
            raise HandlerError(
                "invalid_payload",
                f"timeout must be between {TIMEOUT_MIN} and {max_timeout} "
                f"seconds.{hint}",
            )
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise HandlerError("invalid_payload", "'args' must be a list of strings")
        if env_extra and not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in env_extra.items()
        ):
            raise HandlerError("invalid_payload", "'env' must be dict[str, str]")

        # Workdir
        upload_base.mkdir(parents=True, exist_ok=True)
        tmp_root = upload_base / ".sentinelx_uploads"
        tmp_root.mkdir(parents=True, exist_ok=True)

        script_id = uuid.uuid4().hex
        workdir = tmp_root / f"script_job_{script_id}"
        workdir.mkdir(parents=True, exist_ok=True)

        ext = {"bash": "sh", "python3": "py", "powershell": "ps1", "pwsh": "ps1"}.get(
            interpreter, "txt"
        )
        # Sanitize filename: only basename, never escapes workdir
        if filename:
            safe_name = Path(filename).name
            if not safe_name or safe_name.startswith("."):
                safe_name = f"script.{ext}"
        else:
            safe_name = f"script.{ext}"
        script_path = workdir / safe_name

        try:
            script_path.write_text(content, encoding="utf-8")
            script_path.chmod(0o700)

            argv: list[str] = []
            # sudo has no meaning on Windows; ignore it there (M1 is read-only).
            if sudo and sys.platform != "win32":
                argv.append("sudo")
            if interpreter == "bash":
                argv.extend(["bash", str(script_path)])
            elif interpreter == "python3":
                # Windows has no `python3` on PATH; use the agent's own venv
                # python so scripts can import the agent's deps. But in the
                # no-admin user-mode install the agent is HOSTED by
                # pythonw.exe (windowless, no console stdio), and spawning a
                # script under pythonw hangs with no output until timeout --
                # so resolve the sibling console python.exe. Linux/macOS keep
                # the system python3.
                if sys.platform == "win32":
                    _py = Path(sys.executable)
                    if _py.name.lower() == "pythonw.exe":
                        _py = _py.with_name("python.exe")
                    py = str(_py)
                else:
                    py = "python3"
                argv.extend([py, str(script_path)])
            else:  # powershell / pwsh
                exe = shutil.which(interpreter) or (
                    "pwsh" if interpreter == "pwsh" else "powershell"
                )
                argv.extend(
                    [exe, "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
                )
            argv.extend(args)

            full_env = os.environ.copy()
            full_env.update(env_extra)

            start = time.time()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=full_env,
                )
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                returncode = proc.returncode
                stdout = stdout_b.decode(errors="replace").strip()
                stderr = stderr_b.decode(errors="replace").strip()
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "ok": False,
                    "interpreter": interpreter,
                    "sudo": sudo,
                    "cwd": cwd,
                    "cleanup": cleanup,
                    "command": argv,
                    "output": "⏱️ Timeout",
                    "duration": round(time.time() - start, 2),
                    "returncode": -1,
                    "timed_out": True,
                }
            except FileNotFoundError as exc:
                # interpreter binary missing
                raise HandlerError(
                    "interpreter_missing",
                    f"interpreter not found: {exc}",
                ) from exc

            duration = round(time.time() - start, 2)
            output = (stdout + "\n" + stderr).strip() or "⚠️ Sin salida"

            response: dict[str, Any] = {
                "ok": returncode == 0,
                "interpreter": interpreter,
                "sudo": sudo,
                "cwd": cwd,
                "cleanup": cleanup,
                "command": argv,
                "output": output,
                "duration": duration,
                "returncode": returncode,
            }
            if not cleanup:
                response["script_path"] = str(script_path)
                response["workdir"] = str(workdir)

            return response

        finally:
            if cleanup:
                shutil.rmtree(workdir, ignore_errors=True)

    return handle_script_run
