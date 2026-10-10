"""Read-only / introspection handlers: ping, capabilities, help, state."""

from __future__ import annotations

from pathlib import Path

import asyncio
import platform
import socket
from collections.abc import Callable, Iterable
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
        # Disk read off the event loop: read_recent now reads only the tail,
        # but it is still blocking I/O and the control plane should not wait
        # on a slow disk for it (issue #31).
        entries = await asyncio.to_thread(local_audit.read_recent, limit=limit)
        return {
            "entries": entries,
            "count": len(entries),
            "source": str(local_audit.AUDIT_PATH),
            "max_retained": local_audit.MAX_LINES,
        }

    return handle_read_audit


def _unusable_commands(policy: Policy) -> dict[str, Any]:
    """Allowlisted commands the host cannot actually execute, and why.

    Empty (and cheap) on the common case: the check is one small read, and
    nothing is reported unless the host really is in that state AND the
    operator really did allowlist something that needs privileges.
    """
    if not _no_new_privileges():
        return {}
    # Guard on the SPLIT, not on the string. The empty prefix is a first-class
    # entry in this format -- matching is `cmd.startswith(allowed)`, so "" is how
    # an operator grants any command within the host account -- and "".split() is
    # [], so the index access raised IndexError and took the whole capabilities
    # report with it. Reported by danshapiro (issue #47) with the traceback.
    #
    # `if c` would fix the reported case and leave a whitespace-only entry
    # crashing the same way: " " is truthy but " ".split() is also []. Our own
    # test for that failed on the first attempt, which is why this checks the
    # list the index is taken from rather than the string it came from.
    blocked = []
    for c in policy.allowed_commands:
        parts = c.split()
        if not parts:
            continue
        if c == "sudo" or c.startswith("sudo ") or "/sudo" in parts[0]:
            blocked.append(c)
    if not blocked:
        return {}
    return {
        "commands": blocked,
        "reason": "no_new_privileges",
        "detail": (
            "This agent runs with NoNewPrivileges set, so sudo can never "
            "elevate regardless of sudoers. These entries are in the allowlist "
            "but will always fail. Either run the privileged step through a "
            "service action, or have the operator install the agent without "
            "that hardening -- not recommended -- or wrap the work in a "
            "setuid-free helper the agent can call directly."
        ),
    }


def _no_new_privileges() -> bool:
    """Whether this process can never gain privileges, so sudo cannot work.

    Set by the hardened install (NoNewPrivileges=yes in the unit) and
    inherited by everything we spawn: once the bit is on, sudo fails with
    'the "no new privileges" flag is set' no matter what sudoers says.

    Reported by an operator whose allowlist contained an exact sudo command:
    we advertised it as executable, it could not possibly run, and the only
    way to find out was to run it and read the error. Linux-only; anywhere
    else there is no such bit and the answer is no.
    """
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("NoNewPrivs:"):
                    return line.split()[1].strip() == "1"
    except OSError:
        pass
    return False


def make_capabilities_handler(
    policy: Policy,
    config_path=None,
    ops_supported: Callable[[], Iterable[str]] | None = None,
    upload_base: Path | None = None,
):
    """Build the `capabilities` handler.

    `ops_supported` is a callable returning the canonical op names. It is
    injected by build_registry() so the advertised list is DERIVED from the
    registry instead of hand-maintained (it drifted twice: once for
    move/copy/delete/chmod/chown, once for file_export_*/project_snapshot --
    see issue #32). It is called lazily, at request time, because the
    registry is not yet fully populated when this handler is constructed.
    Built standalone (outside build_registry) the handler advertises an
    empty list: capabilities is only meaningful wired to a registry.
    """

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
            # DERIVED from build_registry() in handlers/__init__.py --
            # never hand-maintained. The registry's keys are the single
            # source of truth for what this agent can dispatch, so an op
            # that is registered is automatically advertised (and one
            # that is removed automatically disappears). Sorted for a
            # stable, readable, diff-friendly response.
            "ops_supported": sorted(ops_supported()) if ops_supported else [],
            "allowed_commands": list(policy.allowed_commands),
            # What the operator switched off, echoed back. ops_supported is the
            # permitted set -- a disabled op is simply not in it -- but that
            # alone cannot tell an auditor WHY something is absent: an old agent
            # that never had the op and a current one where it was deliberately
            # turned off look identical. Requested by an operator running a
            # governance audit, who needed to evidence the difference rather
            # than infer it.
            #
            # Echoed from the config, not derived from the registry: a name that
            # matched nothing still belongs here, because a typo in a deny list
            # otherwise reads as protection that was never applied.
            "disabled_ops": sorted(policy.disabled_ops),
            # Whether chained exec commands are checked segment by segment.
            # Part of the same question -- what is this host actually willing to
            # run -- and an auditor should not have to read config.yaml to know.
            "exec_strict": policy.exec_strict,
            # Commands that are allowlisted but cannot run on this host. Today
            # only one cause: sudo under NoNewPrivileges. Advertising a command
            # as executable when the kernel guarantees it will fail sends the
            # caller to run it and read the error, which is a poor way to learn
            # the shape of a host.
            "unusable_commands": _unusable_commands(policy),
            "services": {
                name: {
                    "unit": spec.unit,
                    "backend": getattr(spec, "backend", "service"),
                    "actions": list(spec.actions),
                    "requires_sudo": spec.requires_sudo,
                    "description": spec.description,
                    **({"user": spec.user} if getattr(spec, "user", "") else {}),
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
            # Where upload_file, edit and script_run stage their files.
            #
            # Resolved at start-up from the config, or from the first writable
            # candidate, or from the system temp space -- so it differs between
            # hosts and cannot be assumed. Without it, anything that hands a
            # bare filename to a host-side tool has to hard-code our path and
            # breaks silently when it is wrong. Two operators asked for this on
            # the same day, one of them after testing three different
            # directories to find the right one.
            #
            # Read-only: it reports where staging happens, it does not move it.
            # Separate from file_ops on purpose -- being able to stage a file
            # here grants nothing under file_ops, and this path is usually not
            # in that list at all.
            "upload_base": str(upload_base) if upload_base else None,
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

        # What this host can actually do. help used to list every operation in
        # navigation and recommend edit/service/playbooks unconditionally, so on
        # a deny-all host -- disabled_ops covering read/list/edit/exec/service,
        # no file_ops paths, no playbooks -- it guided the operator straight into
        # walls: "use op:edit" when edit is disabled, "run add_allowed_read_path"
        # when no playbook exists. Reported on a Windows host where only
        # ping/help/capabilities were live. Now navigation shows only live ops,
        # and extending_access is phrased for what is reachable.
        disabled = set(policy.disabled_ops)
        has_read_paths = bool(paths)
        has_commands = bool(policy.allowed_commands)
        has_services = bool(getattr(policy, "services", None))
        has_playbooks = bool(getattr(policy, "playbooks", None))

        def _op_live(*ops: str) -> bool:
            # An op is live if it is not switched off. ping/help/capabilities/
            # state are never disableable, so they are always live.
            return not any(o in disabled for o in ops)
        def _build_navigation() -> dict[str, str]:
            # Always-live orientation ops.
            nav = {
                "capabilities": "full policy: allowed paths (r/rw), commands, services, playbooks, limits",
                "state": "live host status (hostname, kernel, uptime, load)",
            }
            if _op_live("read", "list", "search") and has_read_paths:
                nav["read / list / search"] = "inspect files under allowed paths"
            if _op_live("edit"):
                nav["edit"] = "structured file edits; sudo=true for rw-gated or privileged writes"
            if _op_live("move", "copy", "delete", "chmod", "chown") and writable:
                nav["move / copy / delete / chmod / chown"] = "mutate files under rw paths (never sudo)"
            if _op_live("exec") and has_commands:
                nav["exec"] = "run ONE allowlisted command (no pipes or redirects)"
            if _op_live("script_run"):
                nav["script_run"] = "run a multi-step bash/python script for complex tasks"
            if _op_live("service", "restart") and has_services:
                nav["service / restart"] = "manage allowlisted services"
            if _op_live("upload_file", "upload_init"):
                nav["upload_file / upload_init+chunk+complete"] = "get files onto the host"
            if _op_live("read_audit"):
                nav["read_audit"] = "review this host's own recent operation log"
            if has_playbooks:
                nav["playbooks"] = "guided multi-step recipes (see 'playbooks' in capabilities)"
            return nav

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
            "navigation": _build_navigation(),
            "extending_access": {
                # On a deny-all host with edit disabled and no writable path,
                # the operator cannot apply these changes THROUGH the agent --
                # the playbooks and config edits below all need a capability this
                # host does not have. Say so first, rather than recommending a
                # door that is locked. Reported alongside the navigation issue.
                "note": (
                    "This host cannot edit its own config remotely: edit is "
                    "disabled and no writable path is configured. The steps below "
                    "must be applied by the operator ON the host (edit "
                    "config.yaml directly and reload the agent), not through "
                    "SentinelX."
                ) if (("edit" in disabled) or not writable) else (
                    "These changes need the operator's approval; apply them via "
                    "SentinelX where a config path is available, or on the host."
                ),
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
