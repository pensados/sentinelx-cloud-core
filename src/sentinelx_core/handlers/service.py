"""service / restart handlers: systemctl wrappers, gated by policy.

Each `service` request specifies the service name (e.g. "nginx") and an action
("start", "restart", "status", etc.). The agent looks up the service in the
policy, checks the action is allowed, then runs systemctl.

Note: the policy stores the SYSTEMD UNIT name (e.g. "nginx.service" or
"sentinelx-core") which may differ from the friendly service name the user
provides. This decoupling lets you alias `core` -> `sentinelx-core.service`.
"""

from __future__ import annotations

import sys
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core import platform_guidance as _pg
from sentinelx_core.executor_engine import run_shell_split
from sentinelx_core.policy import Policy


def _build_systemctl(action: str, unit: str, requires_sudo: bool) -> str:
    prefix = "sudo " if requires_sudo else ""
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
_WIN_SERVICE_ACTIONS = {
    "status":     "Get-Service -Name {name}",
    "is-active":  "Get-Service -Name {name}",
    "is-enabled": "Get-Service -Name {name}",
    "start":      "Start-Service -Name {name}",
    "stop":       "Stop-Service -Name {name} -Force",
}

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
            return _WIN_TASK_RESTART_DETACHED.format(name=name)
        cmd = _WIN_TASK_ACTIONS.get(action)
        if cmd is None:
            supported = sorted([*_WIN_TASK_ACTIONS, "restart", "reload"])
            raise HandlerError(
                "service_action_not_allowed",
                f"action '{action}' has no Windows Scheduled-Task equivalent "
                f"(supported: {', '.join(supported)}).",
            )
        return cmd.format(name=name)

    if action in ("restart", "reload"):
        return _WIN_RESTART_DETACHED.format(name=name)
    cmd = _WIN_SERVICE_ACTIONS.get(action)
    if cmd is None:
        supported = sorted([*_WIN_SERVICE_ACTIONS, "restart", "reload"])
        raise HandlerError(
            "service_action_not_allowed",
            f"action '{action}' has no Windows Service equivalent "
            f"(supported: {', '.join(supported)}).",
        )
    return cmd.format(name=name)


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
    return _build_systemctl(action, spec.unit, spec.requires_sudo)


async def _windows_service_restart(name: str) -> dict[str, Any]:
    """Hardened Windows SCM self-restart (issue #19).

    Resolves the WinSW wrapper PID and force-kills the whole service-owned process
    tree (taskkill /F /T) before starting a fresh generation, so the old Python
    agent tree cannot survive and cause a duplicate_session split-brain. Returns a
    structured restart_started ack (never "completed"); the caller must verify the
    new PID/version after reconnect.
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

    if wrapper_pid:
        cmd = _WIN_RESTART_DETACHED_TREEKILL.format(pid=wrapper_pid, name=name)
    else:
        # Fallback: graceful stop/start if we could not resolve the wrapper PID.
        cmd = _WIN_RESTART_DETACHED.format(name=name)

    launch = await run_shell_split(cmd, timeout=30.0)
    return {
        "ok": True,
        "status": "restart_started",
        "expected_disconnect": True,
        "verification_required": True,
        "method": "taskkill_tree" if wrapper_pid else "net_stop_start",
        "wrapper_pid": wrapper_pid,
        "detail": (
            "Windows service restart launched (detached). The whole service-owned "
            "process tree is force-terminated, then a fresh generation starts. The "
            "agent connection will drop and reconnect on the new generation -- this "
            "is expected, not a failure. Confirm with the capabilities op and verify "
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
            raise HandlerError(
                "service_not_allowed",
                f"service '{service}' isn't registered in this agent's "
                "policy. If it's safe to manage here, add it with the "
                f"operator's approval, in three steps: (1) call {_pg.edit_config_via()}, "
                f"adding an entry under the 'services:' map for '{service}' "
                "with an 'actions:' list (e.g. actions: [status, restart, "
                "reload]; list only what you want to allow, and avoid 'stop' "
                "unless the operator wants the service stoppable); (2) "
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
        if action in ("restart", "reload") and sys.platform == "win32" and backend == "service":
            return await _windows_service_restart(spec.unit)

        cmd = _build_service_cmd(action, spec)
        return await run_shell_split(cmd, timeout=30.0)

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
