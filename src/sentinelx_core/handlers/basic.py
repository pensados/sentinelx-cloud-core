"""Read-only / introspection handlers: ping, capabilities, help, state."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

from sentinelx_core import AGENT_VERSION
from sentinelx_core import platform_guidance as _pg
from sentinelx_core.handlers.progressive_help import (
    capabilities_detail,
    select_help_response,
    summarize_capabilities,
)
from sentinelx_core.policy import Policy


async def handle_ping(payload: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "agent_version": AGENT_VERSION}


def make_read_audit_handler():
    """Return a handler that reads recent entries from the local audit log.

    Read-only. Returns entries from /var/lib/sentinelx/audit.jsonl (op +
    payload + status), newest first. This is the only path by which the
    on-host payload log leaves the host, and only in response to an explicit
    request routed through the hub to this host's owner.
    """
    from sentinelx_core import local_audit

    async def handle_read_audit(payload: dict[str, Any]) -> dict[str, Any]:
        limit = payload.get("limit", 200)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 200
        entries = local_audit.read_recent(limit=limit)
        return {
            "entries": entries,
            "count": len(entries),
            "source": str(local_audit.AUDIT_PATH),
            "max_retained": local_audit.MAX_LINES,
        }

    return handle_read_audit


def make_capabilities_handler(
    policy: Policy,
    config_path=None,
    *,
    ops_supported: list[str],
):
    async def handle_capabilities(payload: dict[str, Any]) -> dict[str, Any]:
        """Return the policy as introspection data + ops supported.

        This is the dynamic equivalent of legacy SentinelX's GET /capabilities.
        Output is shaped to be friendly for an LLM tool: lists, dicts, no fluff.
        """
        detail = capabilities_detail(payload)
        locations = {
            label: {"path": spec.path, "description": spec.description}
            for label, spec in policy.locations.items()
        }
        # Advertise the agent's own config path so hub-side tools (e.g. the
        # dashboard config editor) can locate it cross-platform instead of
        # assuming Linux's /etc/sentinelx/config.yaml. An explicit
        # `locations.config` in the config wins.
        if config_path is not None and "config" not in locations:
            locations["config"] = {
                "path": str(config_path),
                "description": "The agent's active config.yaml.",
            }
        result = {
            "agent": "sentinelx-cloud-core",
            "version": AGENT_VERSION,
            "host": {
                "hostname": socket.gethostname(),
                "label": policy.hostname_label,
                "kernel": platform.release(),
                "arch": platform.machine(),
            },
            # Registry membership is the single source of truth for operation
            # discoverability. Keep the registry's insertion order so the
            # capabilities payload remains deterministic/readable without a
            # second hand-maintained operation list that can drift.
            "ops_supported": list(ops_supported),
            "allowed_commands": list(policy.allowed_commands),
            "services": {
                name: {
                    "unit": spec.unit,
                    "actions": list(spec.actions),
                    "requires_sudo": spec.requires_sudo,
                    "description": spec.description,
                }
                for name, spec in policy.services.items()
            },
            "locations": locations,
            "playbooks": policy.playbooks,
            "limits": {
                "exec_timeout_default": policy.exec_timeout_default,
                "exec_timeout_max": policy.exec_timeout_max,
            },
            "fetch_policy": {
                # Hosts the agent will fetch from when sentinel_upload_file
                # is called with file_url. Empty list means file_url is
                # disabled — the LLM should use content_base64 (inline) or
                # the chunked upload path instead.
                "trusted_fetch_hosts": list(policy.trusted_fetch_hosts),
                "file_url_timeout_seconds": policy.file_url_timeout_seconds,
                # Hard requirements applied to every file_url, regardless
                # of allowlist:
                #   - https only (http blocked)
                #   - hostname in allowlist (above)
                #   - resolved IP must be public-routable
                #     (loopback / RFC1918 / link-local / etc. blocked)
                #   - redirects disabled
                # See SECURITY.md and THREAT_MODEL.md in the source repo
                # for the full threat model.
                "scheme_allowed": ["https"],
                "follow_redirects": False,
            },
            "file_ops": {
                # Unified r/rw path model. Each entry tells the LLM both
                # WHERE it can operate and WHAT it can do there:
                #   access "r"  -> read / list / search only
                #   access "rw" -> also edit / move / copy / delete /
                #                  chmod / chown
                # Empty list means all file_ops are effectively disabled
                # (path_not_allowed for any input).
                "paths": [
                    {"path": e.path, "access": e.access}
                    for e in policy.file_ops_paths
                ],
                # Back-compat / convenience: the flat list of every path
                # the agent will read under (both r and rw entries).
                # Existing clients that only knew about
                # `allowed_read_paths` keep getting a sensible value.
                "allowed_read_paths": [
                    e.path for e in policy.file_ops_paths
                ],
                # Just the writable subtree, so the LLM can tell at a
                # glance where mutations (edit + destructive ops) are
                # permitted without re-deriving it from `paths`.
                "writable_paths": [
                    e.path
                    for e in policy.file_ops_paths
                    if e.access == "rw"
                ],
                "max_read_bytes": policy.file_ops_max_read_bytes,
                "max_list_entries": policy.file_ops_max_list_entries,
                "max_search_results": policy.file_ops_max_search_results,
            },
        }
        if detail == "summary":
            return summarize_capabilities(result)
        return result

    return handle_capabilities


def make_help_handler(policy: Policy):
    async def handle_help(payload: dict[str, Any]) -> dict[str, Any]:
        """Rich orientation for the LLM: what SentinelX is, how its security
        model works, how to navigate and extend access, manage hosts, plus
        example tasks and reference links."""
        paths = policy.file_ops_paths
        writable = [p for p in paths if getattr(p, "access", "r") == "rw"]
        full = {
            "agent": "sentinelx-cloud-core",
            "version": AGENT_VERSION,
            "host_label": policy.hostname_label,
            "summary": (
                "SentinelX gives an LLM safe, structured, auditable control of "
                f"this {_pg.HOST_KIND}. The agent is open-source and dials OUTWARD to "
                "the hub over an authenticated WebSocket (no inbound ports), runs "
                "as a dedicated OS user, and gates every action behind an "
                "allowlist policy. Nothing here is hidden from the host's owner."
            ),
            "security_model": {
                "two_layers": (
                    "Every file/command/service action passes TWO independent "
                    "gates: (1) the SentinelX allowlist (this host's policy) and "
                    "(2) the agent OS user's Unix permissions. BOTH must pass."
                ),
                "allowlist_errors": (
                    "path_not_allowed = path not under file_ops.paths; "
                    "command_not_allowed = command not in allowed_commands; "
                    "service_not_allowed = service/action not in services. Fix by "
                    "adding it to the policy (see 'extending_access')."
                ),
                "permission_errors": (
                    "permission_denied [Errno 13] = the path IS allowed, but the "
                    "agent OS user lacks Unix permission. A filesystem issue, not "
                    "an allowlist one."
                ),
                "sudo": (
                    "read/list/search never escalate; sentinel_edit supports "
                    "sudo=true (the operator's sudoers is the boundary); "
                    "move/copy/delete/chmod/chown never sudo. For a privileged "
                    "read, use exec with 'sudo cat <path>' if it's allowlisted."
                ),
                "audit_transparency": (
                    "Every operation is logged (op, outcome, duration) to an "
                    "append-only audit the owner can review, never file contents "
                    "or command arguments."
                ),
            },
            "operating_notes": [
                "Diagnose before you mutate: prefer read/list/search and 'state' first.",
                "On sentinel_edit, use dry_run=true + diff=true before applying, and back up configs first.",
                "When an action is blocked, the error message contains the fix. Read it and act, don't guess.",
                "For destructive ops (delete, overwrite), confirm intent and keep a rollback.",
                "Use 'capabilities' for full policy detail; this 'help' is the orientation map.",
            ],
            "navigation": {
                "capabilities": "full policy: allowed paths (r/rw), commands, services, playbooks, limits",
                "state": "live host status (hostname, kernel, uptime, load)",
                "read / list / search": "inspect files under allowed paths",
                "edit": "structured file edits; sudo=true for rw-gated or privileged writes",
                "move / copy / delete / chmod / chown": "mutate files under rw paths (never sudo)",
                "exec": "run ONE allowlisted command (no pipes or redirects)",
                "script_run": "run a multi-step bash/python script for complex tasks",
                "service / restart": "manage allowlisted services",
                "upload_file / upload_init+chunk+complete": "get files onto the host",
                "read_audit": "review this host's own recent operation log",
                "playbooks": "guided multi-step recipes (see 'playbooks' in capabilities)",
            },
            "extending_access": {
                "read_or_write_directory": (
                    f"Add an entry under file_ops.paths (via {_pg.edit_config_via()}) "
                    "with access 'r' (read-only) or 'rw' (also editable), covering a "
                    f"parent directory; then {_pg.reload_agent()}. Or run the "
                    "add_allowed_read_path playbook."
                ),
                "command": (
                    "Add the command under allowed_commands, then reload. Or run "
                    "the add_allowed_command playbook."
                ),
                "service": (
                    "Add the service (with its allowed actions) under services, "
                    "then reload. Or run the add_service playbook."
                ),
                "how_to_edit_config": (
                    f"Config edits need the operator's approval: use {_pg.edit_config_via()}, "
                    f"back up first, then {_pg.reload_agent()} (or use the "
                    "sync_sentinelx_config playbook)."
                ),
            },
            "managing_hosts": {
                "add_a_host": (
                    f"On the new server (Linux or macOS) run: {_pg.INSTALL_CMD}, "
                    "and authenticate. It joins the same account."
                ),
                "update_this_agent": (
                    "Optional; the current agent keeps working. Follow the "
                    f"update_sentinelx_code playbook, or re-run the installer "
                    f"({_pg.INSTALL_CMD}), then {_pg.MANUAL_RESTART}."
                ),
                "targeting": (
                    "With multiple hosts, pass host_id on each op, or set a default "
                    "with sentinel_set_default_host."
                ),
            },
            "playbooks": {
                "what": (
                    "Named, guided multi-step recipes with steps/requires/notes. "
                    "Follow the step list in the playbook's definition (full text "
                    "in 'capabilities')."
                ),
                "diagnostics": f"{_pg.DIAGNOSTIC_PLAYBOOKS} ship by default.",
                "names": sorted(policy.playbooks.keys()),
                "count": len(policy.playbooks),
            },
            "policy": {
                "allowed_commands": len(policy.allowed_commands),
                "file_ops_paths": len(paths),
                "writable_paths": len(writable),
                "services": len(policy.services),
                "playbooks": len(policy.playbooks),
                "trusted_fetch_hosts": len(policy.trusted_fetch_hosts),
            },
            "examples": [
                "Diagnose why nginx is returning 502s and show me the fix.",
                "Check disk usage and tell me what's eating space.",
                "Review the last 50 lines of the auth log for anything suspicious.",
                "Restart the docker service safely and confirm it came back.",
                "Add /srv/myapp as a writable path so you can edit its config.",
            ],
            "getting_started": (
                "First time here: call 'capabilities' for the full policy and "
                "'state' for current status, then proceed. If something is "
                "blocked, the error tells you how to allow it."
            ),
            "resources": {
                "dashboard": "https://mcp.sentinelx.app/dashboard - per-host stats, host configuration, connected integrations, and an audit of every operation received.",
                "website": "https://sentinelx.app",
                "connect_your_llm": "SentinelX is an MCP server at https://mcp.sentinelx.app/mcp/mcp - add it as a custom connector in Claude, ChatGPT, Cursor, Cline, or Zed (OAuth sign-in). It routes to every host on your account.",
                "integrations": "Per-account integrations (Cloudflare DNS, email/Resend, Telegram) can be connected from the dashboard.",
                "source_and_issues": "Open-source agent (Apache-2.0): https://github.com/pensados/sentinelx-cloud-core - report bugs at https://github.com/pensados/sentinelx-cloud-core/issues",
                "contact": "sentinelx@pensa.ar",
            },
            "about": {
                "project": "SentinelX is an indie project: a self-hosted MCP hub that gives LLMs auditable, allowlist-gated access to your servers.",
                "creator": "Carlos Torres (@CarolusX74) - https://pensa.com.ar",
                "origin_story": "How I Accidentally Built an MCP Server for My Linux Servers: https://carolusx.medium.com/how-i-accidentally-built-an-mcp-server-for-my-linux-servers-11a288feb899",
            },
        }
        return select_help_response(payload, full, policy.playbooks)
    return handle_help


async def handle_state(payload: dict[str, Any]) -> dict[str, Any]:
    """Real-time host status."""
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": _read_uptime(),
        "loadavg": _read_loadavg(),
    }


def _read_uptime() -> float | None:
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return None


def _read_loadavg() -> tuple[float, float, float] | None:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, ValueError, IndexError):
        return None
