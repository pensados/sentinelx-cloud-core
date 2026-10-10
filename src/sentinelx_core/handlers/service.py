"""service / restart handlers: systemctl wrappers, gated by policy.

Each `service` request specifies the service name (e.g. "nginx") and an action
("start", "restart", "status", etc.). The agent looks up the service in the
policy, checks the action is allowed, then runs systemctl.

Note: the policy stores the SYSTEMD UNIT name (e.g. "nginx.service" or
"sentinelx-core") which may differ from the friendly service name the user
provides. This decoupling lets you alias `core` -> `sentinelx-core.service`.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core import platform_guidance as _pg
from sentinelx_core.executor_engine import run_shell_split
from sentinelx_core.policy import Policy


# systemctl actions that only read state. Verified on a real host as the agent's
# own unprivileged user: status, is-active and is-enabled all return 0, while
# restart and stop fail with "Interactive authentication required".
_SYSTEMCTL_READ_ONLY = frozenset({"status", "is-active", "is-enabled"})


def _user_uid(user: str) -> int | None:
    """UID of a local user, or None if there is no such user (or no pwd)."""
    try:
        import pwd

        return pwd.getpwnam(user).pw_uid
    except (ImportError, KeyError):
        return None


def _runs_as(user: str) -> bool:
    uid = _user_uid(user)
    return uid is not None and uid == os.geteuid()


def _build_systemctl(
    action: str, unit: str, requires_sudo: bool, user: str = "", as_that_user: bool = False
) -> str:
    """Build the systemctl command, elevating only when the action needs it.

    requires_sudo is a property of the SERVICE, and an operator sets it because
    restarting needs root -- which then dragged sudo onto plain status reads as
    well. On a host installed with NoNewPrivileges (our hardened default) sudo
    cannot run at all, so asking whether a service was up failed on exactly the
    hosts that had followed our own security advice.

    Reading state needs no privileges, so it no longer asks for any.

    A USER unit (`user` set) goes to that user's own manager. When the agent
    runs as that user, plain `systemctl --user` needs no privileges at all.
    Otherwise reaching another user's manager needs root even to read it
    ("Failed to connect to bus: Permission denied"), so it always goes through
    sudo, with --machine=<user>@.host (systemd 248+).
    """
    if user:
        if as_that_user:
            return f"systemctl --user {action} {unit}"
        return f"sudo systemctl --user --machine={user}@.host {action} {unit}"
    elevate = requires_sudo and action not in _SYSTEMCTL_READ_ONLY
    prefix = "sudo " if elevate else ""
    return f"{prefix}systemctl {action} {unit}"


# launchd action -> launchctl subcommand. status/is-* read the current state
# (launchctl print dumps it); restart/reload use kickstart -k; start/stop use
# kickstart / bootout. Target is "<domain>/<label>", e.g. system/app.sentinelx.core.
_LAUNCHCTL_ACTIONS = {
    "status": "print",
    "is-active": "print",
    "is-enabled": "print",
    "restart": "kickstart -k",
    "reload": "kickstart -k",
    "start": "kickstart",
    "stop": "bootout",
}


def _build_launchctl(action: str, label: str, domain: str, requires_sudo: bool) -> str:
    sub = _LAUNCHCTL_ACTIONS.get(action)
    if sub is None:
        raise HandlerError(
            "service_action_not_allowed",
            f"action '{action}' has no launchctl equivalent on macOS "
            f"(supported: {', '.join(sorted(_LAUNCHCTL_ACTIONS))}).",
        )
    prefix = "sudo " if requires_sudo else ""
    return f"{prefix}launchctl {sub} {domain}/{label}"


# Windows Service Control: map actions to the *-Service cmdlets (run through
# the PowerShell shell). No per-command sudo — elevation on Windows comes from
# the agent's own process token (LocalSystem when installed as a service), so
# spec.requires_sudo isn't applied here.
def _ps_single(value: str) -> str:
    """Quote a value for a PowerShell single-quoted string.

    Task and service names are operator-chosen and go straight into a command
    line. Unquoted, a name with a space splits into two arguments and the call
    silently addresses the wrong thing -- on a restart that means the stop
    half runs and the start half does not, leaving the agent down with nothing
    to bring it back. A literal single quote is escaped by doubling it, which
    is PowerShell's own rule.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _cmd_double(value: str) -> str:
    """Quote a value for a cmd.exe argument nested inside a PowerShell string.

    The outer PowerShell literal already uses single quotes, so the inner
    quoting has to be double. A name containing a double quote cannot be
    expressed here and Windows does not allow one in a task name, so it is
    rejected rather than mangled.
    """
    text = str(value)
    if '"' in text:
        raise HandlerError(
            "invalid_service_name",
            "service or task names containing a double quote are not supported",
        )
    return '"' + text + '"'


_WIN_SERVICE_ACTIONS = {
    "status":     "Get-Service -Name {name}",
    "is-active":  "Get-Service -Name {name}",
    "is-enabled": "Get-Service -Name {name}",
    "start":      "Start-Service -Name {name}",
    "stop":       "Stop-Service -Name {name} -Force",
}
# Every {name} above is filled with _ps_single(), never the raw value.

# restart/reload: a plain Restart-Service is Stop+Start IN THE CALLER, so when the
# agent restarts its OWN service the Stop kills the caller before Start runs and
# the service stays down. Instead we spawn a DETACHED restarter via WMI
# (Win32_Process.Create) -- owned by the WMI service, outside the agent's process
# tree -- which waits briefly, then stops and starts the service. It survives the
# agent being stopped (so self-restart works) and works for any other service too.
# All-single-quoted CommandLine, no inner double quotes -> safe through the outer
# `powershell -Command <cmd>` wrapper.
_WIN_RESTART_DETACHED = (
    "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
    "@{{ CommandLine = 'cmd /c timeout /t 2 /nobreak >nul & net stop {name} & net start {name}' }} "
    "| Select-Object -ExpandProperty ProcessId"
)

# Hardened self-restart (issue #19). net stop can leave the old Python child tree
# orphaned on some installs (LocalService / during an update), producing a
# duplicate_session split-brain. taskkill /F /T on the LIVE WinSW wrapper PID kills
# the whole service-owned tree atomically before it can orphan, then a fresh
# generation starts. The wrapper PID is resolved in Python and injected as a literal
# so the CommandLine stays single-quoted with no inner double quotes.
_WIN_RESTART_DETACHED_TREEKILL = (
    "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
    "@{{ CommandLine = 'cmd /c timeout /t 2 /nobreak >nul & taskkill /F /T /PID {pid} "
    "& timeout /t 2 /nobreak >nul & net start {name}' }} "
    "| Select-Object -ExpandProperty ProcessId"
)

# Windows Scheduled-Task backend (the no-admin user-mode install): the agent
# runs as a per-user Scheduled Task instead of an SCM service, so map actions to
# schtasks (no admin needed to control your own task).
_WIN_TASK_ACTIONS = {
    "status":     "schtasks /Query /TN {name} /FO LIST /V",
    "is-active":  "schtasks /Query /TN {name} /FO LIST",
    "is-enabled": "schtasks /Query /TN {name} /FO LIST",
    "start":      "schtasks /Run /TN {name}",
    "stop":       "schtasks /End /TN {name}",
}

# task restart/reload: /End kills the running instance (the agent) before /Run --
# same self-kill problem as Restart-Service. Spawn the restarter DETACHED via WMI
# so it survives the /End (a user can End/Run their own task + create their own
# process, no admin).
_WIN_TASK_RESTART_DETACHED = (
    "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
    "@{{ CommandLine = 'cmd /c timeout /t 2 /nobreak >nul & schtasks /End /TN {name} & schtasks /Run /TN {name}' }} "
    "| Select-Object -ExpandProperty ProcessId"
)


def _build_windows_service(action: str, name: str, backend: str = "service") -> str:
    if backend == "task":
        if action in ("restart", "reload"):
            return _WIN_TASK_RESTART_DETACHED.format(name=_ps_single(name))
        cmd = _WIN_TASK_ACTIONS.get(action)
        if cmd is None:
            supported = sorted([*_WIN_TASK_ACTIONS, "restart", "reload"])
            raise HandlerError(
                "service_action_not_allowed",
                f"action '{action}' has no Windows Scheduled-Task equivalent "
                f"(supported: {', '.join(supported)}).",
            )
        return cmd.format(name=_ps_single(name))

    if action in ("restart", "reload"):
        return _WIN_RESTART_DETACHED.format(name=_ps_single(name))
    cmd = _WIN_SERVICE_ACTIONS.get(action)
    if cmd is None:
        supported = sorted([*_WIN_SERVICE_ACTIONS, "restart", "reload"])
        raise HandlerError(
            "service_action_not_allowed",
            f"action '{action}' has no Windows Service equivalent "
            f"(supported: {', '.join(supported)}).",
        )
    return cmd.format(name=_ps_single(name))


def _build_service_cmd(action: str, spec) -> str:
    """Platform-native service command: systemctl on Linux, launchctl on macOS
    (spec.unit is the launchd label, spec.domain the launchd domain), and on
    Windows either the *-Service cmdlets (backend="service") or schtasks
    (backend="task", the no-admin user-mode install); spec.unit is the service
    or task name."""
    if sys.platform == "win32":
        return _build_windows_service(action, spec.unit, getattr(spec, "backend", "service"))
    if sys.platform == "darwin":
        return _build_launchctl(action, spec.unit, getattr(spec, "domain", "system"), spec.requires_sudo)
    user = getattr(spec, "user", "")
    return _build_systemctl(
        action, spec.unit, spec.requires_sudo, user, bool(user) and _runs_as(user)
    )


def _service_env(spec) -> dict[str, str] | None:
    """Environment for `systemctl --user` run as the unit's own user.

    A service process doesn't get XDG_RUNTIME_DIR, and without it
    `systemctl --user` can't find the user's manager ("Failed to connect to
    bus: No medium found"). Only for the own-user mode; everything else runs
    with the agent's environment as before.
    """
    if sys.platform in ("win32", "darwin"):
        return None
    user = getattr(spec, "user", "")
    if not user or not _runs_as(user):
        return None
    runtime = f"/run/user/{os.geteuid()}"
    return {"XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus"}


# SCM-recovery self-kill (issue #19, underprivileged / LocalService case). On a
# LocalService (or other non-SYSTEM) install, a detached WMI helper inherits the
# same underprivileged token, so its `net start` is DENIED (System error 5) and
# 0.11.9 would kill the tree with no way to bring it back. Instead the helper does
# ONLY a forced tree-kill of the WinSW wrapper; the service's SCM RESTART failure
# action then restarts it under the SCM's own privilege. We REQUIRE an SCM RESTART
# recovery action to exist (verified before launch) and otherwise fail closed.
_WIN_RESTART_DETACHED_TREEKILL_ONLY = (
    "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
    "@{{ CommandLine = 'cmd /c timeout /t 2 /nobreak >nul & taskkill /F /T /PID {pid}' }} "
    "| Select-Object -ExpandProperty ProcessId"
)


def _win_is_system_account(account: str | None) -> bool:
    """True if a service's SERVICE_START_NAME denotes LocalSystem (SYSTEM) -- the
    one privileged case where a detached helper can `net start` the service itself.
    Everything else (LocalService, NetworkService, a normal user) is underprivileged."""
    if not account:
        return False
    a = account.strip().lower()
    if a in ("localsystem", ".\\localsystem", "s-1-5-18"):
        return True
    # "NT AUTHORITY\\System" and any domain-qualified \System.
    return a.endswith("\\system")


async def _win_cim_service_field(name: str, field: str) -> str | None:
    """Read one Win32_Service property via CIM as plain text.

    PowerShell hands CIM back as objects and we ask for a single property, so
    there is no console codepage in the path and no localized label to match --
    the two things that made the sc.exe text parse fail on a non-English host.
    Returns the trimmed value, or None if empty/unavailable.
    """
    # -EncodedCommand would be sturdier still, but a single ExpandProperty of a
    # known-ASCII field (StartName, ProcessId) is safe as plain -Command.
    ps = (
        f"(Get-CimInstance Win32_Service -Filter \"Name='{name}'\" "
        f"-ErrorAction Stop).{field}"
    )
    try:
        res = await run_shell_split(ps, timeout=10.0)
        if (res.get("returncode") or res.get("exit_code") or 0) not in (0, None):
            return None
        value = (res.get("stdout") or "").strip()
        return value or None
    except Exception:
        return None


async def _win_service_account(name: str) -> str | None:
    """Resolve the service's start account. None if it can't be resolved.

    Primary source is CIM (Win32_Service.StartName): a structured value returned
    as an object property, so it is immune to the two failures that dogged the
    sc.exe path. sc.exe qc emits console-codepage OEM text -- decoded as UTF-8
    it becomes mojibake -- and its labels are LOCALIZED, so on a non-English
    Windows the line does not even start with SERVICE_START_NAME. A LocalSystem
    host was refused a self-restart on both counts. Reported with CIM proving
    LocalSystem while sc.exe came back garbled.

    sc.exe qc remains a fallback for the rare box where CIM is unavailable, with
    the optional-colon parsing from 0.18.1 -- but it is no longer the primary,
    and its locale/encoding fragility no longer decides the safe path.
    """
    cim = await _win_cim_service_field(name, "StartName")
    if cim:
        return cim
    try:
        qc = await run_shell_split(f"sc.exe qc {_cmd_double(name)}", timeout=10.0)
        for line in (qc.get("stdout") or "").splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("SERVICE_START_NAME"):
                continue
            # sc.exe qc aligns columns with whitespace, and whether a colon
            # appears depends on Windows version and locale:
            #     SERVICE_START_NAME : LocalSystem
            #     SERVICE_START_NAME   LocalSystem      <- no colon
            # The old code required the colon, so on hosts whose sc.exe omits it
            # this returned None, _win_is_system_account(None) was False, and a
            # LocalSystem service fell into the underprivileged branch and was
            # refused with a message flatly contradicted by `sc.exe qc`.
            # Reported with the sc.exe readback proving LocalSystem. Strip the
            # label (with or without a trailing colon), take the remainder.
            rest = stripped[len("SERVICE_START_NAME"):].lstrip()
            if rest.startswith(":"):
                rest = rest[1:]
            value = rest.strip()
            if value:
                return value
    except Exception:
        pass
    return None


async def _win_has_scm_restart_recovery(name: str) -> bool:
    """True if the service has at least one SCM RESTART failure action.

    Read from the registry FailureActions blob rather than parsed from
    `sc.exe qfailure` text: qfailure is both localized and OEM-encoded, so the
    word RESTART may be translated or turned to mojibake, and the old regex for
    it returned False on a host that plainly had RESTART/10000 configured. The
    registry value is a fixed binary layout, language-independent.

    The FailureActions binary encodes an array of (Type, Delay) pairs; the Type
    for "restart the service" is SC_ACTION_RESTART = 1. We ask PowerShell for
    the raw bytes and look for a type-1 action. Falls back to the qfailure text
    only if the registry read fails outright.
    """
    ps = (
        "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\" + name + "';"
        "$v=(Get-ItemProperty -Path $p -Name FailureActions -ErrorAction Stop)"
        ".FailureActions;"
        # bytes 0..11 are header (reset period, reboot msg ptr, command ptr);
        # from offset 20 come (type:int32, delay:int32) pairs. Type 1 = RESTART.
        "$n=[BitConverter]::ToInt32($v,16);$off=20;$found=$false;"
        "for($i=0;$i -lt $n;$i++){if([BitConverter]::ToInt32($v,$off) -eq 1){$found=$true};$off+=8};"
        "if($found){'RESTART'}else{'NONE'}"
    )
    try:
        res = await run_shell_split(ps, timeout=10.0)
        out = (res.get("stdout") or "").strip().upper()
        if out in ("RESTART", "NONE"):
            return out == "RESTART"
    except Exception:
        pass
    # Fallback: the old text parse, better than nothing where the registry read
    # failed. Still locale-fragile, hence only a fallback.
    try:
        qf = await run_shell_split(f"sc.exe qfailure {name}", timeout=10.0)
        return re.search(r"\bRESTART\b", qf.get("stdout") or "", re.IGNORECASE) is not None
    except Exception:
        return False


async def _windows_service_restart(name: str) -> dict[str, Any]:
    """Hardened Windows SCM self-restart (issue #19).

    Two paths, chosen by the service account:

    * SYSTEM (LocalSystem): force-kill the whole service-owned process tree
      (taskkill /F /T) and `net start` a fresh generation from the detached helper
      -- the helper inherits SYSTEM so the start succeeds (method=taskkill_tree).

    * Underprivileged (LocalService / NetworkService / user): a detached helper
      inherits the same token and its `net start` is DENIED (System error 5), so we
      do NOT start from the helper. We force-kill the tree ONLY and let the
      service's SCM RESTART failure action restart it under the SCM's privilege
      (method=scm_recovery_self_kill). This REQUIRES an SCM RESTART recovery action
      -- if none exists we FAIL CLOSED and kill nothing, because a self-restart
      would otherwise leave the service down with no way back.

    Returns a structured restart_started ack (never "completed"); the caller must
    verify the new PID/version/single-tree after reconnect.
    """
    wrapper_pid: int | None = None
    try:
        # `sc` is a PowerShell alias for Set-Content -> use sc.exe explicitly.
        q = await run_shell_split(f"sc.exe queryex {name}", timeout=10.0)
        for line in (q.get("stdout") or "").splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("PID") and ":" in stripped:
                wrapper_pid = int(stripped.split(":", 1)[1].strip())
                break
    except Exception:
        wrapper_pid = None

    account = await _win_service_account(name)
    privileged = _win_is_system_account(account)

    # --- SYSTEM path: unchanged 0.11.9 behaviour (the helper can net start) ---
    if privileged:
        if wrapper_pid:
            cmd = _WIN_RESTART_DETACHED_TREEKILL.format(pid=wrapper_pid, name=name)
            method = "taskkill_tree"
        else:
            # Fallback: graceful stop/start if we could not resolve the wrapper PID.
            cmd = _WIN_RESTART_DETACHED.format(name=name)
            method = "net_stop_start"
        launch = await run_shell_split(cmd, timeout=30.0)
        return {
            "ok": True,
            "status": "restart_started",
            "expected_disconnect": True,
            "verification_required": True,
            "method": method,
            "wrapper_pid": wrapper_pid,
            "service_account": account,
            "detail": (
                "Windows service restart launched (detached, SYSTEM). The whole "
                "service-owned process tree is force-terminated, then a fresh "
                "generation starts. The agent connection will drop and reconnect on "
                "the new generation -- this is expected, not a failure. Confirm with "
                "the capabilities op and verify the new PID/version once it responds."
            ),
            "helper": launch,
        }

    # --- Underprivileged path: rely on SCM recovery, fail closed without it ---
    has_recovery = await _win_has_scm_restart_recovery(name)
    if not has_recovery:
        raise HandlerError(
            "service_restart_unsafe",
            f"service '{name}' runs as {account or 'a non-SYSTEM account'} and has no "
            "SCM RESTART recovery action, so a self-restart would force-kill the agent "
            "with no way to bring it back (a detached helper inherits the same "
            "underprivileged token and its 'net start' is denied with System error 5). "
            "Add an SCM restart recovery action (e.g. `sc.exe failure <svc> reset= 86400 "
            "actions= restart/10000`) or reinstall the service as LocalSystem, then retry.",
            details={"service_account": account, "scm_restart_recovery": False},
        )
    if not wrapper_pid:
        raise HandlerError(
            "service_restart_unsafe",
            f"could not resolve the WinSW wrapper PID for '{name}', so the SCM-recovery "
            "self-restart (force-kill the tree, let SCM recovery restart it) cannot run "
            "safely under an underprivileged token. Verify the service is running and retry.",
            details={"service_account": account, "wrapper_pid": None},
        )

    cmd = _WIN_RESTART_DETACHED_TREEKILL_ONLY.format(pid=wrapper_pid)
    launch = await run_shell_split(cmd, timeout=30.0)
    return {
        "ok": True,
        "status": "restart_started",
        "expected_disconnect": True,
        "verification_required": True,
        "method": "scm_recovery_self_kill",
        "wrapper_pid": wrapper_pid,
        "service_account": account,
        "detail": (
            "Windows service restart launched (detached, non-SYSTEM). The service runs "
            f"as {account}; a detached helper cannot 'net start' it (System error 5), so "
            "the whole service-owned process tree is force-terminated ONLY and the "
            "service's SCM RESTART recovery action brings it back. The agent connection "
            "will drop and reconnect on the new generation -- this is expected, not a "
            "failure. Confirm with the capabilities op and verify the new PID/version "
            "once it responds."
        ),
        "helper": launch,
    }


# task restart/reload (issue #4): a plain `schtasks /End` kills the agent (and can
# orphan its child tree) before `/Run` -- the same self-kill / duplicate-session
# family as #19. Spawn a DETACHED helper (WMI Win32_Process.Create, inherits the
# interactive user token so it can control the user's own task) that force-kills the
# agent's whole process tree, ends the task instance, then /Run starts a fresh
# generation. The agent PID is resolved in Python and injected as a literal so the
# CommandLine stays single-quoted with no inner double quotes.
_WIN_TASK_RESTART_DETACHED_TREEKILL = (
    "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
    "@{{ CommandLine = 'cmd /c timeout /t 2 /nobreak >nul & taskkill /F /T /PID {pid} "
    "& schtasks /End /TN {qname} & timeout /t 2 /nobreak >nul & schtasks /Run /TN {qname}' }} "
    "| Select-Object -ExpandProperty ProcessId"
)


async def _windows_task_restart(name: str) -> dict[str, Any]:
    """Hardened Windows Scheduled-Task self-restart (issue #4).

    The per-user task backend (-User install) runs the agent directly as a
    Scheduled Task -- no WinSW wrapper, no admin -- so the agent IS the task's
    process and os.getpid() is the tree to kill. A plain `schtasks /End` kills the
    agent (and can orphan its children) before `/Run`, the same self-kill /
    duplicate-session family as #19. We launch a DETACHED helper (WMI, inheriting
    the interactive user token so it can control the user's own task) that
    force-kills the agent's whole process tree, ends the task instance, then /Run
    starts a fresh generation. Returns a structured restart_started ack (never
    "completed"); the caller must verify the new PID/version after reconnect.
    """
    agent_pid = os.getpid()
    cmd = _WIN_TASK_RESTART_DETACHED_TREEKILL.format(pid=agent_pid, qname=_cmd_double(name))
    launch = await run_shell_split(cmd, timeout=30.0)
    return {
        "ok": True,
        "status": "restart_started",
        "expected_disconnect": True,
        "verification_required": True,
        "method": "task_treekill_run",
        "backend": "task",
        "agent_pid": agent_pid,
        "task_name": name,
        "detail": (
            "Windows Scheduled-Task restart launched (detached, per-user). The "
            "agent's whole process tree is force-terminated, the task instance is "
            "ended, then a fresh instance starts via schtasks /Run. The agent "
            "connection will drop and reconnect on the new generation -- this is "
            "expected, not a failure. Confirm with the capabilities op and verify "
            "the new PID/version once it responds."
        ),
        "helper": launch,
    }


def make_service_handler(policy: Policy):
    """Return an async handler bound to the given policy."""

    async def handle_service(payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        action = payload.get("action")

        if not service or not isinstance(service, str):
            raise HandlerError("invalid_payload", "missing 'service'")
        if not action or not isinstance(action, str):
            raise HandlerError("invalid_payload", "missing 'action'")

        spec = policy.get_service(service)
        if spec is None:
            # The next step an assistant takes is to declare the service as this
            # message says. A user unit declared without `user:` would point at
            # the system manager, the wrong supervisor (sxrep_01JGTNPRKSS8).
            user_hint = (
                "; if it is a systemd USER unit (listed by `systemctl --user`, "
                "defined under ~/.config/systemd/user), also add 'user: <its "
                "owner>', or the agent will look for a system unit instead"
                if sys.platform not in ("win32", "darwin") else ""
            )
            raise HandlerError(
                "service_not_allowed",
                f"service '{service}' isn't registered in this agent's "
                "policy. If it's safe to manage here, add it with the "
                f"operator's approval, in three steps: (1) call {_pg.edit_config_via()}, "
                f"adding an entry under the 'services:' map for '{service}' "
                "with an 'actions:' list (e.g. actions: [status, restart, "
                "reload]; list only what you want to allow, and avoid 'stop' "
                f"unless the operator wants the service stoppable{user_hint}); (2) "
                f"{_pg.reload_agent()}; (3) confirm with the capabilities op "
                f"that '{service}' now appears under services.",
                details={"service": service, "available": sorted(policy.services.keys())},
            )

        if action not in spec.actions:
            raise HandlerError(
                "service_action_not_allowed",
                f"action '{action}' isn't in the allowed actions for "
                f"service '{service}' (allowed: "
                f"{', '.join(spec.actions)}). To permit '{action}', add "
                f"it to that service's 'actions:' list via {_pg.edit_config_via()} "
                f"(with the operator's approval), then {_pg.reload_agent()}. "
                "Or use one of the already-allowed actions listed above.",
                details={"allowed_actions": list(spec.actions)},
            )

        backend = getattr(spec, "backend", "service")
        if action in ("restart", "reload") and sys.platform == "win32":
            if backend == "service":
                return await _windows_service_restart(spec.unit)
            if backend == "task":
                return await _windows_task_restart(spec.unit)

        user = getattr(spec, "user", "")
        if user and sys.platform not in ("win32", "darwin") and _user_uid(user) is None:
            raise HandlerError(
                "service_user_not_found",
                f"service '{service}' is declared as a systemd user unit of "
                f"'{user}', but there is no user '{user}' on this host. Fix the "
                f"'user:' of that service via {_pg.edit_config_via()} (with the "
                f"operator's approval), then {_pg.reload_agent()}.",
                details={"service": service, "user": user},
            )
        cmd = _build_service_cmd(action, spec)
        return await run_shell_split(cmd, timeout=30.0, env=_service_env(spec))

    return handle_service


def make_restart_handler(policy: Policy):
    """Return an async handler that maps `restart {service}` to a service action."""

    service_handler = make_service_handler(policy)

    async def handle_restart(payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        if not service or not isinstance(service, str):
            raise HandlerError("invalid_payload", "missing 'service'")
        return await service_handler({"service": service, "action": "restart"})

    return handle_restart
