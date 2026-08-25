"""Platform-aware guidance for user-facing error messages and help text.

The agent runs on Linux (systemd, root-owned /etc/sentinelx), macOS (launchd,
user-owned ~/sentinelx) and Windows -- a WinSW service (LocalSystem) or a
no-admin per-user Scheduled Task; the service variant keeps its config under
C:\\ProgramData\\SentinelX). Messages that tell the operator how to edit the
policy or reload the agent must adapt to the platform, or a user gets pointed at
/etc/sentinelx and `systemctl` (neither of which exists off Linux). Centralized
here so each message stays a one-liner and there's a single place to update.
"""
from __future__ import annotations

import sys

_WINDOWS = sys.platform == "win32"
_DARWIN = sys.platform == "darwin"


def _pick(windows: str, macos: str, linux: str) -> str:
    """Choose the platform-appropriate string (Windows / macOS / Linux)."""
    if _WINDOWS:
        return windows
    if _DARWIN:
        return macos
    return linux


# Policy file the operator edits.
CONFIG_PATH = _pick(
    r"C:\ProgramData\SentinelX\config.yaml",
    "~/sentinelx/config.yaml",
    "/etc/sentinelx/config.yaml",
)

# Service key to pass to the service op for a self-restart.
SERVICE_KEY = _pick("sentinelx", "sentinelx", "sentinelx-cloud-core")

# Windows guidance splits by install backend: the default WinSW *service*
# (LocalSystem, C:\ProgramData\SentinelX) vs the no-admin per-user *Scheduled
# Task* (-User install, %LOCALAPPDATA%\SentinelX, run via pythonw). The agent
# records its own backend at startup via set_backend(); until then we assume the
# service backend (the historical default). Off Windows the split doesn't apply
# (Linux=systemd, macOS=launchd), so set_backend() is a no-op there.
_WIN_SVC_MANUAL_RESTART = "Restart-Service SentinelX  (in an elevated PowerShell)"
_WIN_TASK_MANUAL_RESTART = (
    "schtasks /End /TN SentinelX & schtasks /Run /TN SentinelX  (no admin needed)"
)
_WIN_SVC_LOGS_HINT = (
    r"Get-Content C:\ProgramData\SentinelX\logs\sentinelx-service.err.log -Tail 30"
)
_WIN_TASK_LOGS_HINT = r"Get-Content $env:LOCALAPPDATA\SentinelX\logs\agent.log -Tail 30"
_WIN_SVC_HOST_KIND = "Windows host"
_WIN_TASK_HOST_KIND = "Windows host (per-user Scheduled Task)"


# Manual restart command for a real terminal (when the service op isn't usable).
MANUAL_RESTART = _pick(
    _WIN_SVC_MANUAL_RESTART,
    "sudo launchctl kickstart -k system/app.sentinelx.core",
    "sudo systemctl restart sentinelx-cloud-core",
)

# sentinel_edit sudo hint: Linux config is root-owned (needs sudo=true); macOS
# and Windows configs are exposed file-scoped rw, so no sudo.
_EDIT_SUDO = _pick("", "", "sudo=true and ")

# Where to look for agent logs.
LOGS_HINT = _pick(
    _WIN_SVC_LOGS_HINT,
    "~/sentinelx/agent.err (or: log show --predicate 'process == "
    '"sentinelx-cloud-core"' "' --last 5m)",
    "sudo journalctl -u sentinelx-cloud-core -n 30",
)

HOST_KIND = _pick(_WIN_SVC_HOST_KIND, "macOS host", "Linux host")


def edit_config_via() -> str:
    """e.g. "sentinel_edit on <config> with validator_preset='yaml'"."""
    return f"sentinel_edit on {CONFIG_PATH} with {_EDIT_SUDO}validator_preset='yaml'"


def reload_agent() -> str:
    """How to reload the policy after editing it."""
    return (
        f"reload the agent (sentinel_service action='restart' service='{SERVICE_KEY}', "
        f"or run '{MANUAL_RESTART}' on a terminal)"
    )


# Diagnostic playbooks that ship by default (differ per platform).
DIAGNOSTIC_PLAYBOOKS = _pick(
    "network_debug, system_debug",
    "launchd_debug, network_debug, system_debug",
    "systemd_debug, nginx_debug, docker_debug, network_debug, ports_debug",
)

# Install command. The get.sentinelx.app dispatcher auto-detects the OS for the
# curl|bash path; Windows uses the PowerShell one-liner.
INSTALL_CMD = _pick(
    'iwr -useb https://get.sentinelx.app/install.ps1 -OutFile "$env:TEMP\\sx.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\\sx.ps1"',
    "curl -fsSL https://get.sentinelx.app | bash",
    "curl -fsSL https://get.sentinelx.app | bash",
)


# This agent's own install backend on Windows: "service" (WinSW/SCM) or "task"
# (per-user Scheduled Task). Set once at startup by build_registry() from the
# agent's own self-service entry; defaults to the historical "service".
BACKEND = "service"


def set_backend(backend: str) -> None:
    """Record this agent's own install backend and refresh the Windows guidance
    strings that depend on it (restart command, log location, host wording).

    Called once at startup from build_registry(), reading the agent's own
    self-service policy entry (keyed by SERVICE_KEY). A no-op off Windows --
    Linux (systemd) and macOS (launchd) have no service/task split -- and for an
    unknown value it leaves the service defaults in place.
    """
    global BACKEND, MANUAL_RESTART, LOGS_HINT, HOST_KIND
    BACKEND = backend if backend in ("service", "task") else "service"
    if not _WINDOWS:
        return
    if BACKEND == "task":
        MANUAL_RESTART, LOGS_HINT, HOST_KIND = (
            _WIN_TASK_MANUAL_RESTART,
            _WIN_TASK_LOGS_HINT,
            _WIN_TASK_HOST_KIND,
        )
    else:
        MANUAL_RESTART, LOGS_HINT, HOST_KIND = (
            _WIN_SVC_MANUAL_RESTART,
            _WIN_SVC_LOGS_HINT,
            _WIN_SVC_HOST_KIND,
        )



def set_config_path(path) -> None:
    """Record the agent's ACTUAL config path (its --config arg) so guidance that
    points the operator at the policy file uses the real path, not the platform
    default -- a per-user (-User / task) Windows install keeps its config under
    %LOCALAPPDATA%\\SentinelX, not C:\\ProgramData. Called once at startup from
    build_registry(). No-op if path is falsy (keep the platform default), so a
    policy built without a config_path (e.g. tests) is unaffected."""
    global CONFIG_PATH
    if path:
        CONFIG_PATH = str(path)