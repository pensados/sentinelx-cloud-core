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

from sentinelx_core.executor_engine import STOP_GRACE_SECONDS as _ENGINE_STOP_GRACE
from sentinelx_core.executor_engine import communicate_partial, timeout_text, wait_gone
import logging
import re
import shlex
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.jobs import BACKGROUND_TIMEOUT_MAX
from sentinelx_core.policy import Policy
from sentinelx_core.staging import staging_root


def _staging_oserror(exc: OSError, path: str) -> HandlerError:
    """Turn an OS error while preparing the work area into a named failure.

    These are host conditions, not agent defects, and the operator can act on
    each one -- but only if we say which it is instead of returning a bare
    internal_error with an errno in it.
    """
    import errno as _errno

    if exc.errno == _errno.ENOSPC:
        return HandlerError(
            "no_space",
            f"cannot prepare the work area at {path!r}: the filesystem is full "
            f"([Errno {exc.errno}]). This is a host condition, not a policy or "
            "allowlist issue. Free space on that filesystem (or point "
            "`upload_base` in the agent config at one with room) and retry. "
            "A full disk also makes the agent itself unstable, so unrelated "
            "errors on this host may clear up once space is available.",
        )
    if exc.errno in (_errno.EACCES, _errno.EPERM):
        return HandlerError(
            "permission_denied",
            f"cannot prepare the work area at {path!r}: the agent's OS user "
            f"lacks write permission ([Errno {exc.errno}]). Grant that user "
            "write access to the staging directory, or set `upload_base` in "
            "the agent config to a directory it can write.",
        )
    if exc.errno == _errno.EROFS:
        return HandlerError(
            "read_only_filesystem",
            f"cannot prepare the work area at {path!r}: the filesystem is "
            f"mounted read-only ([Errno {exc.errno}]). Set `upload_base` to a "
            "writable location.",
        )
    return HandlerError(
        "staging_failed",
        f"cannot prepare the work area at {path!r}: {exc}.",
    )
from sentinelx_core.winspawn import spawn_kwargs

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
#
# The flag itself now lives in sentinelx_core.winspawn, applied at every spawn
# site rather than only this one -- which is how seven others ended up without
# it and flashed windows on operators' desktops.

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
    # -WindowStyle Hidden on the INNER powershell too. The outer process gets
    # CREATE_NO_WINDOW below, but this one is launched by PowerShell itself and
    # that flag does not carry across, so it could still paint a window on the
    # operator's desktop. Placed before -File, which must stay last for its
    # argument semantics to survive.
    "& powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    "-WindowStyle Hidden "
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


def _kill_process_tree(proc, *, elevated: bool = False) -> None:
    """Kill a timed-out child and everything it started.

    Killing only the process we spawned leaves its descendants running. On
    Windows that was already handled; on POSIX it was not, and a timed-out
    `docker run` left the docker client and its root-owned wrapper alive for
    hours -- reported after repeated attempts each leaked another pair.

    On POSIX the child is started in its own session (start_new_session), so
    the whole tree shares one process group and a single signal reaches all of
    it. Two details decided by experiment rather than assumption:

    - A tree started with sudo is root-owned, and the agent user cannot signal
      it: killpg raises PermissionError and the processes survive. Those need
      `sudo kill`.
    - `kill -9 -<pgid>` is read as an option, not a group. It returns success
      and kills nothing, which is the worst way to fail. The `--` separator is
      what makes it a process group.
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
    # POSIX: signal the whole group.
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = None

    if pgid is not None:
        if elevated:
            # Root-owned tree: we have no permission of our own.
            try:
                subprocess.run(
                    ["sudo", "-n", "kill", "-9", "--", f"-{pgid}"],
                    capture_output=True,
                    timeout=10,
                )
                return
            except Exception:
                logger.warning("sudo kill of process group failed", exc_info=True)
        else:
            try:
                os.killpg(pgid, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except PermissionError:
                logger.warning("no permission to kill process group %s", pgid)

    # Last resort: at least the process we spawned.
    try:
        proc.kill()
    except ProcessLookupError:
        pass


# How long to wait for the tree to go after the kill: the same grace exec uses.
STOP_GRACE_SECONDS = _ENGINE_STOP_GRACE


async def _stop_tree(proc, *, elevated: bool) -> bool:
    """Kill the tree, then wait at most STOP_GRACE_SECONDS for it to go.

    Returns False when something outlived the kill and still holds our pipes (a
    descendant that left the group with setsid, or a root process the agent can't
    signal): we close our end and return instead of waiting for it. Before 0.23.36
    script_run waited without a limit, so a 1 s timeout came back whenever that
    descendant exited (sxrep_9GWKAWPTXZWM).
    """
    _kill_process_tree(proc, elevated=elevated)
    if await wait_gone(proc, STOP_GRACE_SECONDS):
        return True
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        transport.close()
    logger.warning(
        "a process started by script_run outlived the kill and was left running (pid %s)", proc.pid
    )
    return False


# sudo resets the environment, so payload.env never reached an elevated script
# (sxrep_5CE1B15G691J). The names and values go into a 0600 file in the workdir
# that the elevated sh loads before exec: never on the command line, where other
# users could read them. The cwd travels as a positional argument, as before.
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SUDO_WRAPPER = (
    'if [ -n "$1" ]; then set -a; . "$1" || exit 126; set +a; fi; '
    'if [ -n "$2" ]; then cd "$2" || { echo "sentinelx: cannot enter $2" >&2; exit 126; }; fi; '
    'shift 2; exec "$@"'
)


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

        # Workdir. A full disk surfaces here first, and used to escape as a bare
        # "internal_error: [Errno 28] No space left on device" -- which reads like
        # an agent defect when it is the host filling up. An operator chased a
        # duplicate_session symptom for hours before the real cause (ENOSPC
        # restarting the agent in a loop) became visible. Name it.
        tmp_root = staging_root(upload_base)

        script_id = uuid.uuid4().hex
        workdir = tmp_root / f"script_job_{script_id}"
        env_file: Path | None = None
        try:
            workdir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise _staging_oserror(exc, str(workdir)) from exc

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
            try:
                script_path.write_text(content, encoding=script_encoding)
            except OSError as exc:
                raise _staging_oserror(exc, str(script_path)) from exc
            script_path.chmod(0o700)

            argv: list[str] = []
            # sudo has no meaning on Windows; ignore it there (M1 is read-only).
            use_sudo = sudo and sys.platform != "win32"
            if use_sudo:
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

            # With sudo, let the ELEVATED process do the chdir.
            #
            # Passing cwd= to create_subprocess_exec makes the parent chdir
            # before exec, which happens as the agent's own user. Asking for
            # sudo=true on a root-owned directory therefore failed with
            # PermissionError before sudo ran at all -- the one case where the
            # privileges were requested precisely because the directory needs
            # them. Reported against an 0700 worktree the agent user cannot
            # enter.
            #
            # The directory travels as a positional argument, not in the
            # environment: sudo strips the environment, and an empty $DIR would
            # make `cd ""` a silent no-op that runs the script in / instead.
            # As a positional it is also inert -- a value containing shell
            # metacharacters is just a directory name that does not exist.
            spawn_cwd = cwd
            if use_sudo and env_extra:
                bad = sorted(k for k in env_extra if not _ENV_NAME.fullmatch(k))
                if bad:
                    raise HandlerError(
                        "invalid_payload",
                        "with sudo=true, env names must be letters, digits and _ "
                        f"(not starting with a digit): {bad}",
                    )
                env_file = workdir / "sentinelx_env.sh"
                fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("".join(f"{k}={shlex.quote(v)}\n" for k, v in env_extra.items()))
            if use_sudo and (cwd or env_file is not None):
                argv = [
                    "sudo", "sh", "-c", _SUDO_WRAPPER, "sh",
                    str(env_file) if env_file is not None else "",
                    str(cwd) if cwd else "",
                    *argv[1:],
                ]
                spawn_cwd = None
            # cleanup=false keeps the workdir: say where, on every outcome
            # (sxrep_69N1GEHNAN1K: a timeout or a launch failure kept it silently).
            kept = {} if cleanup else {"workdir": str(workdir), "script_path": str(script_path)}

            # Windows: no console window (see winspawn). POSIX: own session, so
            # the whole tree shares one process group and a timeout can reach
            # every descendant with a single signal.
            extra: dict[str, Any] = {}
            if sys.platform != "win32":
                extra["start_new_session"] = True

            start = time.time()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    **spawn_kwargs(
                        cwd=spawn_cwd,
                        env=full_env,
                        **extra,
                    ),
                )
                try:
                    stdout_b, stderr_b, timed_out = await communicate_partial(proc, timeout)
                except asyncio.CancelledError:
                    # The request was cancelled mid-run: stop the tree before letting
                    # the cancellation through, as exec does. Before 0.23.36 the
                    # finally removed the workdir while the script kept running and
                    # its side effects still happened (sxrep_E7RCC1FKQC7P).
                    await _stop_tree(proc, elevated=use_sudo)
                    raise
                if timed_out:
                    raise asyncio.TimeoutError
                returncode = proc.returncode
                stdout = _decode_output(stdout_b).strip()
                stderr = _decode_output(stderr_b).strip()
            except (PermissionError, NotADirectoryError, FileNotFoundError) as exc:
                # Without sudo the PARENT chdirs into cwd, as the agent's own
                # user, before the script exists as a process. A directory that
                # user cannot enter raised a bare PermissionError here, which
                # surfaced as "internal_error: [Errno 13]" and read like an
                # agent defect. Only the cwd case is renamed: a
                # FileNotFoundError for a missing interpreter is a different
                # failure and must keep its own meaning.
                if spawn_cwd and str(getattr(exc, "filename", "") or "") == str(spawn_cwd):
                    if isinstance(exc, PermissionError):
                        raise HandlerError(
                            "permission_denied",
                            f"cannot enter cwd {cwd!r}: the agent's OS user lacks "
                            f"permission to change into it ([Errno {exc.errno}]). "
                            "Being inside an rw file_ops path does not grant Unix "
                            "access. Either run with sudo=true -- the directory is "
                            "then entered after elevation -- or grant the agent's "
                            "user execute (+x) on it and its parents.",
                        ) from exc
                    if isinstance(exc, NotADirectoryError):
                        raise HandlerError(
                            "not_a_directory", f"cwd {cwd!r} is not a directory."
                        ) from exc
                    raise HandlerError(
                        "not_found", f"cwd {cwd!r} does not exist."
                    ) from exc
                if isinstance(exc, FileNotFoundError):
                    # The interpreter itself is missing. This clause used to re-raise
                    # it raw; the `except FileNotFoundError` that named it came later
                    # in the same try and was unreachable (sxrep_69N1GEHNAN1K).
                    raise HandlerError(
                        "interpreter_missing", f"interpreter not found: {exc}", kept
                    ) from exc
                raise
            except asyncio.TimeoutError:
                left_running = not await _stop_tree(proc, elevated=use_sudo)
                partial = "\n".join(
                    t for t in (_decode_output(stdout_b).strip(), _decode_output(stderr_b).strip()) if t
                )
                return {
                    "ok": False,
                    "interpreter": interpreter,
                    "sudo": sudo,
                    "cwd": cwd,
                    "cleanup": cleanup,
                    "command": argv,
                    "output": timeout_text(partial, left_running),
                    "duration": round(time.time() - start, 2),
                    "returncode": -1,
                    "timed_out": True,
                    **({"left_running": True} if left_running else {}),
                    **kept,
                }

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
            if env_file is not None:
                # It may hold secrets: gone even when cleanup=false keeps the rest.
                env_file.unlink(missing_ok=True)
            if cleanup:
                shutil.rmtree(workdir, ignore_errors=True)

    return handle_script_run
