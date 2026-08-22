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
    destroying anything outside it before we ever see the bytes -> the
    user's script runs through a UTF-8 bootstrap (see
    _POWERSHELL_BOOTSTRAP), in a child console of its own.

As a safety net, captured bytes are decoded as UTF-8 first and fall back
to the host's code page only when that fails, which covers children that
still emit legacy bytes (a caller who pins a legacy PYTHONIOENCODING, a
bash port, pwsh on an exotic host).

Argv, exit-code semantics, the user's script text and the workstation's
console code page are all left exactly as they were — each verified on a
real Windows PowerShell 5.1 host.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.jobs import BACKGROUND_TIMEOUT_MAX
from sentinelx_core.policy import Policy

logger = logging.getLogger(__name__)

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

# Windows: give the child its own (windowless) console. Two reasons, both
# measured on a real 5.1 host: the encoding bootstrap below sets a console
# code page, and without this flag that lands on the console the agent
# itself inherits — leaking 65001 into every later child. With it, the
# change dies with the child and the agent's console keeps its own code
# page. It also guarantees the child HAS a console, which is what makes
# the bootstrap work at all when the agent runs as a service.
_CREATE_NO_WINDOW = 0x08000000

# Windows PowerShell 5.1 encodes redirected output in the console code page
# (cp437 on a default es/en install), so anything outside it is destroyed at
# the source: an em dash became "-" and a CJK character became "?" before
# the bytes ever reached us. No amount of decoding on our side brings those
# back, so the encoding has to be fixed IN the child (issue #28).
#
# The bootstrap sets the process's output encoding to UTF-8 and then runs
# the user's script as an INNER `powershell -File`. That indirection is the
# whole point: a wrapper that merely called `& $script` would collapse two
# different outcomes, because after it an explicit `exit 7` and a handled
# native failure both leave 7 in $LASTEXITCODE. Measured on 5.1:
#
#   invocation            explicit exit 7   handled native 7   throw
#   -File (reference)            7                 0             1
#   bootstrap + & $script        7                 7  <-- wrong  1
#   bootstrap + inner -File      7                 0             1
#
# The inner process is a native command, so its exit code is unambiguous and
# `-File` semantics survive intact — as do argv, `using namespace`, and the
# user's script text, which is never prefixed with anything.
_POWERSHELL_BOOTSTRAP = (
    "param([Parameter(Mandatory=$true)][string]$SentinelXScript,"
    "[Parameter(ValueFromRemainingArguments=$true)]$SentinelXArgs)\n"
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n"
    "$OutputEncoding = [Console]::OutputEncoding\n"
    "& powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    "-File $SentinelXScript @SentinelXArgs\n"
    "exit $LASTEXITCODE\n"
)


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


def _kill_process_tree(proc) -> None:
    """Kill a timed-out child, and on Windows its children too.

    The PowerShell bootstrap runs the user's script as an inner process, so
    killing only the process we spawned would leave that inner one running
    after a timeout. taskkill /T covers the tree; if it is unavailable we
    still kill what we spawned rather than nothing.
    """
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
            )
            return
        except Exception:
            logger.warning("taskkill failed; falling back to kill()", exc_info=True)
    try:
        proc.kill()
    except ProcessLookupError:
        pass


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
                target = str(script_path)
                if sys.platform == "win32" and interpreter == "powershell":
                    # Windows PowerShell 5.1 only: run the user's script
                    # through the UTF-8 bootstrap (see above). pwsh already
                    # speaks UTF-8 and is left on the direct path, which
                    # also spares it the extra process.
                    bootstrap = workdir / "sentinelx_bootstrap.ps1"
                    bootstrap.write_text(
                        _POWERSHELL_BOOTSTRAP, encoding="utf-8-sig"
                    )
                    target = str(bootstrap)
                    argv.extend(
                        [exe, "-NoProfile", "-NonInteractive",
                         "-ExecutionPolicy", "Bypass", "-File", target,
                         str(script_path)]
                    )
                else:
                    argv.extend(
                        [exe, "-NoProfile", "-NonInteractive",
                         "-ExecutionPolicy", "Bypass", "-File", target]
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

            spawn_kwargs: dict[str, Any] = {}
            if sys.platform == "win32":
                spawn_kwargs["creationflags"] = _CREATE_NO_WINDOW

            start = time.time()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=full_env,
                    **spawn_kwargs,
                )
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                returncode = proc.returncode
                stdout = _decode_output(stdout_b).strip()
                stderr = _decode_output(stderr_b).strip()
            except asyncio.TimeoutError:
                _kill_process_tree(proc)
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
