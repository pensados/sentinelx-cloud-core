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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelx_core.winspawn import spawn_kwargs

logger = logging.getLogger(__name__)


def _process_group_kwargs() -> dict[str, Any]:
    """Start the shell in a killable process group on POSIX."""
    if sys.platform == "win32":
        return {}
    return {"start_new_session": True}


def descendants(pid: int) -> list[int]:
    """Every process below `pid`, read from /proc (Linux; empty elsewhere).

    A descendant that called setsid has left the process group, so killpg misses
    it, but it is still our descendant here until its parent dies. Read before
    killing anything: once the shell dies, the escaped child is reparented and
    out of reach (sxrep_E7RCC1FKQC7P).
    """
    if not sys.platform.startswith("linux"):
        return []
    out: list[int] = []
    todo = [pid]
    while todo:
        p = todo.pop()
        try:
            tasks = os.listdir(f"/proc/{p}/task")
        except OSError:
            continue
        for t in tasks:
            try:
                with open(f"/proc/{p}/task/{t}/children") as fh:
                    kids = [int(x) for x in fh.read().split()]
            except (OSError, ValueError):
                continue
            out.extend(kids)
            todo.extend(kids)
    return out


def kill_pids(pids: list[int], *, elevated: bool = False) -> bool:
    """SIGKILL each pid; through sudo when they may be root-owned. Best effort.

    Returns False when some pid could not be signalled. A failed sudo kill falls
    back to signalling each pid directly instead of being taken as success
    (sxrep_AZ931A9557MC, follow-up on 0.23.40).
    """
    if not pids:
        return True
    if elevated:
        try:
            done = subprocess.run(["sudo", "-n", "kill", "-9", "--", *map(str, pids)],
                                  capture_output=True, timeout=10)
            if done.returncode == 0:
                return True
            logger.warning("sudo kill of escaped descendants exited %s; trying them one by one",
                           done.returncode)
        except Exception:  # noqa: BLE001
            logger.warning("sudo kill of escaped descendants failed", exc_info=True)
    ok = True
    for p in pids:
        try:
            os.kill(p, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            ok = False
    return ok


async def finish_cleanup(coro) -> Any:
    """Run a cleanup coroutine to the end even if the caller is cancelled again.

    A second task.cancel() used to interrupt the cleanup of the first: the call
    returned while waiting for the tree was still in progress (sxrep_E7RCC1FKQC7P).
    The cleanup is bounded (STOP_GRACE_SECONDS), so finishing it is cheap.
    """
    task = asyncio.ensure_future(coro)
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


def _kill_process_tree(proc: asyncio.subprocess.Process, *, elevated: bool = False) -> bool:
    """Kill a child and everything it started (best effort; see STOP_GRACE_SECONDS).

    One implementation for every caller since 0.23.47 (script_run had its own).
    Decided by experiment rather than assumption:

    - descendants that left the group with setsid are killed from a /proc snapshot
      taken before the group dies (sxrep_E7RCC1FKQC7P);
    - a tree started with sudo is root-owned and the agent user can't signal it:
      killpg raises PermissionError and it survives, so `elevated` uses `sudo kill`;
    - `kill -9 -<pgid>` is read as an option, not a group: it succeeds and kills
      nothing. The `--` separator is what makes it a process group;
    - a failed taskkill or sudo kill falls back to proc.kill() (sxrep_AZ931A9557MC).
    """
    # Those that left the group. Whether they were all reached is part of the answer:
    # a group kill that succeeds says nothing about them (sxrep_AZ931A9557MC).
    reached = kill_pids(descendants(proc.pid), elevated=elevated)
    if sys.platform == "win32":
        try:
            # spawn_kwargs adds CREATE_NO_WINDOW, like every other child we
            # start: without it, a per-user install (pythonw) flashes a console.
            completed = subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                **spawn_kwargs(capture_output=True, timeout=10, check=False),
            )
            if completed.returncode == 0:
                return reached
            logger.warning("taskkill exited %s; falling back to kill()", completed.returncode)
        except (OSError, subprocess.SubprocessError):
            logger.debug("taskkill process-tree cleanup failed", exc_info=True)
    else:
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            pgid = None
        if pgid is not None:
            if elevated:
                try:
                    done = subprocess.run(["sudo", "-n", "kill", "-9", "--", f"-{pgid}"],
                                          capture_output=True, timeout=10)
                    if done.returncode == 0:
                        return reached
                    logger.warning("sudo kill of process group %s exited %s; falling back to kill()",
                                   pgid, done.returncode)
                except Exception:  # noqa: BLE001
                    logger.warning("sudo kill of process group failed", exc_info=True)
            else:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                    return reached
                except ProcessLookupError:
                    return reached
                except PermissionError:
                    logger.warning("no permission to kill process group %s", pgid)

    # Last resort: at least the process we spawned (a root-owned one may refuse).
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
    return reached


# How long to wait for the process tree to go away after the kill. Something that
# outlives the kill and still holds our pipes - typically a process started through
# sudo, which runs as root, so an unprivileged agent can't signal it - would otherwise
# keep proc.wait() blocked until it exits on its own (asyncio's wait() also waits for
# the pipes to close): a command with a 300 s limit came back at 900 s, when the
# root process finished (sxrep_64T9VXZEVC61).
STOP_GRACE_SECONDS = 5.0


async def _drain(stream) -> None:
    if stream is None:
        return
    while await stream.read(65536):
        pass


async def wait_gone(proc: asyncio.subprocess.Process, grace: float) -> bool:
    """Wait at most `grace` for the process to exit AND its pipes to reach EOF.

    On Python 3.12, Process.wait() also waits for the pipes to close; on 3.14 it
    returns as soon as the process itself exits. A descendant that escaped the
    group (setsid) or a root process we can't signal, still holding stdout, then
    went unnoticed and left_running was never reported (sxrep_9GWKAWPTXZWM, seen
    in CI on 3.14.9). Draining both pipes to EOF gives the same answer on both.
    """
    try:
        await asyncio.wait_for(
            asyncio.gather(proc.wait(), _drain(proc.stdout), _drain(proc.stderr)), timeout=grace
        )
        return True
    except ProcessLookupError:
        return True
    except (asyncio.TimeoutError, TimeoutError):
        return False


async def _stop_process_tree(proc: asyncio.subprocess.Process, *, elevated: bool = False) -> bool:
    """Kill the tree and wait briefly for it to go. Returns False when something
    outlived the kill and still held our pipes: we close our end and return
    instead of waiting for it, and it keeps running on its own."""
    reached = _kill_process_tree(proc, elevated=elevated)
    if await wait_gone(proc, STOP_GRACE_SECONDS):
        # The shell's group is gone; an escaped descendant the kill couldn't reach
        # may still be running, without holding our pipes.
        return reached
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        transport.close()
    logger.warning(
        "a process started by a timed-out command outlived the kill and was left running (shell pid %s)",
        proc.pid,
    )
    return False


async def communicate_partial(
    proc: asyncio.subprocess.Process, timeout: float | None, input: bytes | None = None
) -> tuple[bytes, bytes, bool]:
    """proc.communicate() under a timeout that keeps what was already read.

    communicate() inside wait_for() threw away everything a process had written
    when the timeout hit, so a script that printed its progress (even with
    flush) came back as a bare "Timeout" (sxrep_AY8JPBQKSAXR). Both streams are
    read as they arrive; returns (stdout, stderr, timed_out). The caller still
    owns stopping the process tree on a timeout.
    """
    out, err = bytearray(), bytearray()

    async def feed() -> None:
        # `input`, like communicate(input=...): written, then stdin closed so the
        # child sees EOF. A child that exits without reading it is not an error.
        if input is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(input)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass

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
            asyncio.gather(feed(), pump(proc.stdout, out), pump(proc.stderr, err), proc.wait()),
            timeout=timeout,
        )
        return bytes(out), bytes(err), False
    except TimeoutError:
        return bytes(out), bytes(err), True


@dataclass(frozen=True)
class ProcResult:
    """What run_process saw. returncode is -1 when the timeout stopped the process."""

    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    left_running: bool = False


def left_running_from(exc: BaseException | None) -> bool:
    """True when a cancellation behind exc passed through run_process and something it
    started outlived the kill. asyncio.wait_for raises TimeoutError from the cancel, so
    the chain is followed through __cause__ and __context__."""
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if getattr(exc, "sx_left_running", False):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


async def run_process(
    argv: list[str],
    *,
    timeout: float | None,
    input: bytes | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    elevated: bool = False,
) -> ProcResult:
    """Run argv to completion in its own process group: THE way the agent starts a
    child process (Jan's audit, 2026-10-31: every place that rolled its own lifecycle
    got some part of it wrong). It guarantees what each of those places needs:

    - its own process group (a new session on POSIX), so the whole tree can be stopped;
    - output read as it arrives, so a timeout keeps what the process already wrote;
    - on timeout, the tree is killed, including descendants that left the group with
      setsid, and waited for at most STOP_GRACE_SECONDS; left_running says whether
      something outlived it;
    - on cancellation, the same kill, run to the end even if the task is cancelled
      again; then the cancellation propagates.

    `env` is the child's whole environment (None inherits the agent's); `input` is
    written to stdin, which is then closed. `elevated` is for a tree started through
    sudo: the agent can't signal root's processes, so they are killed with sudo kill. tests/test_process_contract.py holds every
    caller to these guarantees.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        **spawn_kwargs(
            stdin=asyncio.subprocess.PIPE if input is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            **_process_group_kwargs(),
        ),
    )
    try:
        out, err, timed_out = await communicate_partial(proc, timeout, input=input)
    except asyncio.CancelledError as exc:
        if await finish_cleanup(_stop_process_tree(proc, elevated=elevated)) is False:
            # Whoever turns this cancel into an answer (asyncio.wait_for raises TimeoutError
            # from it) learns that something outlived the kill: see left_running_from
            # (sx-review, 2026-11-01: total budgets answered without left_running).
            exc.sx_left_running = True
        raise
    if timed_out:
        left_running = not await _stop_process_tree(proc, elevated=elevated)
        return ProcResult(-1, out, err, timed_out=True, left_running=left_running)
    return ProcResult(proc.returncode if proc.returncode is not None else -1, out, err)


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


def _shell_argv(cmd: str, *, clean_startup: bool = False) -> list[str]:
    """Build the argv that runs `cmd` through the platform's default shell.

    POSIX: `bash -lc <cmd>`. Windows has no bash natively, so we use
    PowerShell — pwsh (PowerShell 7, UTF-8 native) when present, else the
    always-available Windows PowerShell. `-NoProfile -NonInteractive` keep it
    fast and non-blocking; `-Command` takes the full command string.
    """
    if sys.platform == "win32":
        return [_win_powershell(), "-NoProfile", "-NonInteractive", "-Command", cmd]
    if clean_startup:
        # No login shell and no rc files: what they define (a function named like
        # the allowed command, a PATH entry) would run before anything the caller
        # checked (Jan's audit, sxrep_NBEA83P4PV36 on 0.23.41).
        return ["bash", "--noprofile", "--norc", "-c", cmd]
    return ["bash", "-lc", cmd]


# Variables bash reads at startup that change how it behaves before the command runs.
# SHELLOPTS=xtrace with a PS4 holding $(...) ran code on the prelude's first command
# (sxrep_NBEA83P4PV36, after 0.23.50 had removed BASH_ENV/ENV/BASH_FUNC_* only).
_BASH_STARTUP_VARS = frozenset({
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS0", "PS1", "PS2", "PS3", "PS4",
    "PROMPT_COMMAND", "GLOBIGNORE", "EXECIGNORE", "IFS", "CDPATH", "BASH_XTRACEFD",
    "BASH_COMPAT", "POSIXLY_CORRECT", "BASH_LOADABLES_PATH", "INPUTRC", "HISTFILE",
})


def _without_startup_hooks(env: dict[str, str]) -> dict[str, str]:
    """The environment minus everything bash acts on at startup: the files it sources
    (BASH_ENV, ENV), the options and prompts it imports (SHELLOPTS, BASHOPTS, PS4...),
    what changes word splitting or command lookup, and exported functions."""
    return {k: v for k, v in env.items()
            if k not in _BASH_STARTUP_VARS and not k.startswith("BASH_FUNC_")}


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
    clean_startup: bool = False,
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
        if clean_startup:
            full_env = _without_startup_hooks(full_env)
        r = await run_process(_shell_argv(cmd, clean_startup=clean_startup), timeout=timeout,
                              cwd=cwd, env=full_env)
        stdout_b, stderr_b, left_running = r.stdout, r.stderr, r.left_running
        if r.timed_out:
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
            "returncode": r.returncode,
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
    clean_startup: bool = True,
) -> dict[str, Any]:
    """Like run_shell but returns stdout and stderr separately.

    Returns:
        {"stdout": str, "stderr": str, "duration": float, "returncode": int}
    

    Service commands (its only caller) get the same clean startup as exec in
    allowlist mode: no profile files, no bash startup variables, no exported
    functions, which could otherwise redefine systemctl (sx-review, 2026-11-01).
    """
    start = time.time()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        if clean_startup:
            full_env = _without_startup_hooks(full_env)
        r = await run_process(_shell_argv(cmd, clean_startup=clean_startup), timeout=timeout,
                              cwd=cwd, env=full_env)
        stdout_b, stderr_b, left_running = r.stdout, r.stderr, r.left_running
        if r.timed_out:
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
            "returncode": r.returncode,
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
            await finish_cleanup(_stop_process_tree(proc))
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
