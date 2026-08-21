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

Text integrity on Windows (issue #28)
=====================================

Unicode must survive `script_run` without the caller adding boilerplate,
and Windows breaks that in three places, each handled at its own boundary:

  - Python inherits the console's legacy code page for stdio and raises
    UnicodeEncodeError on ordinary accented text -> PYTHONIOENCODING=utf-8
    is set for the child (setdefault: an explicit value still wins).
  - Windows PowerShell 5.1 reads a BOM-less .ps1 through the ANSI code
    page, mojibaking non-ASCII literals before the script runs -> .ps1
    files are written with a UTF-8 BOM on Windows.
  - the same shell encodes REDIRECTED output in the console code page,
    which we then decoded as UTF-8 -> captured bytes are decoded UTF-8
    first and fall back to the host code page only when that fails.

All three stay on the encoding boundary: invocation, argv, exit codes and
the shared console code page are untouched.
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

# Interpreters whose script file is a .ps1.
_POWERSHELL_INTERPRETERS = ("powershell", "pwsh")


def _windows_legacy_encoding() -> str | None:
    """The code page a Windows child most likely encoded its output in.

    Windows PowerShell 5.1 encodes redirected output using
    [Console]::OutputEncoding, which comes from the console output code page
    (or the ANSI one when no console is attached) — not UTF-8. Ask Windows
    directly; fall back to the locale's preferred encoding if that fails.
    Returns None when nothing usable can be determined, and never raises.
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        cp = kernel32.GetConsoleOutputCP() or kernel32.GetACP()
        if cp:
            return f"cp{cp}"
    except Exception:
        pass
    try:
        import locale

        return locale.getpreferredencoding(False) or None
    except Exception:
        return None


def _decode_output(raw: bytes) -> str:
    """Decode a child's captured bytes to text (issue #28).

    Everywhere except Windows this is what it always was: UTF-8 with
    replacement. On Windows a child may legitimately emit legacy-code-page
    bytes — Windows PowerShell 5.1 does exactly that for redirected output —
    and decoding those as UTF-8 produced mojibake.

    So on Windows: try UTF-8 strictly first, because a child that emits
    UTF-8 (most of them, and every child once PYTHONIOENCODING is set) must
    be decoded as UTF-8. Only when that fails do we fall back to the host's
    code page, and only then to replacement. Accented Latin-1/1252 bytes are
    not valid UTF-8, so the fallback fires exactly where it should. This
    touches no invocation, argument or exit-code semantics: it is a decision
    about bytes we already captured.
    """
    if sys.platform != "win32":
        return raw.decode(errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    legacy = _windows_legacy_encoding()
    if legacy:
        try:
            return raw.decode(legacy)
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("utf-8", errors="replace")


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
            # Windows PowerShell 5.1 reads a BOM-less .ps1 through the legacy
            # ANSI code page, so a script with non-ASCII literals is mojibaked
            # before it ever runs (issue #28). A UTF-8 BOM is the documented
            # way to tell it otherwise, and PowerShell Core reads it happily
            # too. Everywhere else the file stays plain UTF-8.
            script_encoding = (
                "utf-8-sig"
                if sys.platform == "win32" and interpreter in _POWERSHELL_INTERPRETERS
                else "utf-8"
            )
            script_path.write_text(content, encoding=script_encoding)
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
            if interpreter == "python3" and sys.platform == "win32":
                # Without this, Python inherits the console's legacy code page
                # for stdio and raises UnicodeEncodeError the moment a script
                # prints ordinary accented text or an emoji (issue #28).
                # setdefault, so an explicit caller value — or one the
                # operator set for the service — stays authoritative.
                full_env.setdefault("PYTHONIOENCODING", "utf-8")

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
                stdout = _decode_output(stdout_b).strip()
                stderr = _decode_output(stderr_b).strip()
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
