"""Policy: allowlist + service registry + paths, loaded from /etc/sentinelx/config.yaml.

This is the ONLY place that knows about per-host configuration. Handlers consult
the policy to decide whether a command/service is allowed; they do not hardcode
anything site-specific.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelx_core import platform_guidance as _pg

logger = logging.getLogger(__name__)

# Candidates for upload_base when the config does not name one, best first.
# /var/lib is where the service actually keeps its state on current installs;
# /home/sentinelx/uploads is kept for legacy hosts that still use it.
_UPLOAD_BASE_CANDIDATES = (
    Path("/var/lib/sentinelx/uploads"),
    Path("/home/sentinelx/uploads"),
)


def _is_usable_dir(path: Path) -> bool:
    """True if `path` is a writable directory, or can be created in one."""
    try:
        if path.is_dir():
            return os.access(path, os.W_OK)
        parent = path.parent
        return parent.is_dir() and os.access(parent, os.W_OK)
    except OSError:
        return False


def default_upload_base() -> Path:
    """First writable candidate, else a directory in the system temp space.

    Never raises and creates nothing: callers (see staging.py) create the
    directory when they need it, and fall back again at that point if the
    filesystem has changed underneath.
    """
    for candidate in _UPLOAD_BASE_CANDIDATES:
        if _is_usable_dir(candidate):
            return candidate
    return Path(tempfile.gettempdir()) / "sentinelx-uploads"



# A POSIX-ish user name for a systemd user unit. It is interpolated into a shell
# command, so nothing outside this set is accepted.
_SERVICE_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}")



def read_config_text(path: Path) -> str:
    """config.yaml as text: UTF-8 first, the system's encoding only as a fallback.

    sentinel_edit and the installers write UTF-8, but this used path.read_text(),
    i.e. the platform default: cp949 on a Korean Windows, cp1252 on an English
    one. One non-ASCII character written by sentinel_edit (a Korean folder name)
    then raised UnicodeDecodeError, which escaped from_file and crashed the agent
    at every start, so it could never reconnect to be fixed remotely
    (sxrep_XGNWXC3Q6ZVR). utf-8-sig also accepts the BOM Notepad may add; the
    locale encoding covers a file saved by an editor that writes the ANSI page.
    """
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        import locale

        return raw.decode(locale.getpreferredencoding(False) or "utf-8")

@dataclass(frozen=True)
class ServiceSpec:
    """Allowed actions for a systemd service."""
    unit: str
    actions: tuple[str, ...]
    requires_sudo: bool = True
    description: str = ""
    # macOS launchd domain for this service ("system" for a LaunchDaemon, or
    # "gui/<uid>" for a per-user LaunchAgent). Ignored on Linux (systemd).
    domain: str = "system"
    # Windows backend: "service" (default; SCM/WinSW via Get-Service / net) or
    # "task" (a per-user Scheduled Task via schtasks -- the no-admin user-mode
    # install). Ignored on Linux/macOS.
    backend: str = "service"
    # Linux only: the owner of a systemd USER unit (~/.config/systemd/user),
    # managed with `systemctl --user` against that user's manager instead of
    # the system's. Empty (the default) = a system unit. Ignored on macOS and
    # Windows, like domain/backend are elsewhere. (sxrep_01JGTNPRKSS8)
    user: str = ""


@dataclass(frozen=True)
class LocationSpec:
    """A known path on this host."""
    path: str
    description: str = ""


# Access levels for a file_ops path entry.
#
#   "r"  -> read-only primitives (read / list / search). This is the
#           legacy behaviour and the safe default: an entry whose access
#           level is missing or unrecognized is treated as "r".
#   "rw" -> everything "r" allows PLUS the mutating ops (edit, move,
#           copy, delete, chmod, chown). A path must be EXPLICITLY
#           declared "rw" for any mutation to be permitted there.
FILE_OPS_ACCESS_LEVELS = ("r", "rw")


@dataclass(frozen=True)
class FileOpsPath:
    """One entry in the unified file_ops path allowlist.

    `path` is the directory the operator chose to expose. `access` is
    "r" (read/list/search only) or "rw" (also edit + destructive ops).

    The security boundary is enforced by Policy.resolve_path(): a path
    is canonicalized (symlinks resolved) BEFORE the prefix check, so a
    symlink escaping to /etc cannot bypass an /home-only allowlist, and
    `../` traversal is defeated by the same resolve(). need_write=True
    additionally requires access == "rw".
    """
    path: str
    access: str = "r"

    def __post_init__(self) -> None:
        # Normalize unknown / missing access to the most restrictive
        # level. We never silently grant write: an operator typo like
        # `access: readwrite` degrades to "r", not "rw".
        if self.access not in FILE_OPS_ACCESS_LEVELS:
            object.__setattr__(self, "access", "r")


@dataclass(frozen=True)
class LocalApiAction:
    """One permitted action on a local endpoint.

    `request` is for protocol=http ("GET /v1.44/containers/json"); `method` is
    for protocol=jsonrpc ("agent.list"). Exactly one applies.

    `select` is NOT cosmetic. Measured against nine real containers on jupiter:
    `docker ps` text is 712 bytes, the raw socket JSON for the same question is
    20,336, and a curated projection is 1,457. A passthrough would be 28x worse
    than the text it replaces, so an action declares what to keep.
    """

    request: str | None = None
    method: str | None = None
    select: tuple[str, ...] = ()
    description: str | None = None
    # Declared shape of this action's parameters, carried VERBATIM and never
    # interpreted here. `describe` hands it to the caller as-is.
    #
    # WHY DECLARED RATHER THAN PROBED. For an HTTP action the parameters are
    # readable from the request template ("/containers/{id}/json" yields `id`),
    # so nothing needs declaring. A JSON-RPC action has a method and no
    # template, so there is nothing to read: describe returned an empty list
    # for every such action, which is no use to a caller that has to build a
    # nested object. Asking the endpoint instead would be better, but it
    # assumes introspection: Herdr's schema is only reachable through its CLI
    # (verified against 0.9.0 / protocol 22, core#45) and Docker has none, so
    # a probe cannot be the baseline.
    #
    # The cost is a second source of truth that can drift. The compatibility
    # constraint is what bounds that: an endpoint that changes protocol fails
    # closed, which forces these declarations to be revisited rather than
    # silently used against a changed API.
    params_schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class LocalApiEndpoint:
    """A host-local endpoint the agent may talk to.

    With transport "unix", `path` is NOT a binary and actions are NOT
    subcommands: the agent OPENS a socket, so there is no process, no shell,
    no argv and no exit code.

    With transport "stdio", `path` IS a binary, declared here by the host's
    owner. The agent starts it once per call (no shell, argv = path + the
    FIXED `args`), writes JSON-RPC to its stdin and reads the answer from its
    stdout. Action parameters travel only inside the JSON, never in argv.
    """

    name: str
    transport: str            # "unix" | "stdio"
    path: str
    protocol: str             # "http" | "jsonrpc"
    actions: dict[str, LocalApiAction]
    timeout_s: float = 30.0
    run_as: str | None = None
    # Declared compatibility constraint, evaluated once per connection epoch.
    #
    # BOTH HALVES ARE DECLARED, per the contract agreed in core#45: "the profile
    # declares how to obtain compatibility metadata and which values it accepts;
    # SentinelX evaluates that declared constraint."
    #
    #   compatibility:
    #     probe:   { method: session.describe }   # or request: GET /version
    #     extract: protocol                        # dotted path into the reply
    #     accept:  { exact: 20 }                   # or { allowed: [20, 21] }
    #
    # `exact` is the default strictness and `allowed` is how a maintainer widens
    # it deliberately. SentinelX NEVER infers compatibility from
    # `new_version >= configured`: a higher number does not imply the protocol
    # still matches, and assuming it would put that judgement with the wrong
    # party.
    #
    # A block missing either half is dropped with a warning rather than
    # half-enforced, because a constraint that silently does nothing is worse
    # than no constraint: it reads as protection that is not there.
    compatibility: dict[str, Any] = field(default_factory=dict)
    # transport "stdio" only (validated in _parse_stdio_options).
    #
    # `args` is a FIXED list from this file. It is never built from a call's
    # parameters: those travel inside the JSON-RPC message and nowhere else, so
    # nothing a caller sends can become an argument, a flag or a file name.
    args: tuple[str, ...] = ()
    cwd: str | None = None
    # Added on top of a minimal environment (PATH, HOME, locale), never on top
    # of the agent's own: the agent's environment is not the endpoint's
    # business, and with run_as sudo would reset it anyway.
    env: dict[str, str] = field(default_factory=dict)
    # "none": the first line written is the action's request.
    # "mcp":  initialize + notifications/initialized first, as an MCP server
    #         over stdio requires before it answers anything else.
    handshake: str = "none"


EXEC_MODES = frozenset({"allowlist", "strict", "unrestricted"})


_STDIO_KEYS = ("args", "cwd", "env", "handshake")
_STDIO_HANDSHAKES = ("none", "mcp")


def _is_scalar_text(value: Any) -> bool:
    """A YAML scalar that reads as text: `--port` or 8080, not true or a list."""
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _parse_stdio_options(
    name: str, meta: dict, protocol: str, path_value: str
) -> dict[str, Any] | None:
    """Validate the transport-stdio fields of one local_apis endpoint.

    Returns the extra LocalApiEndpoint fields, or None after a warning when the
    endpoint must not be registered. Same rule as the rest of the block: a
    malformed endpoint is skipped loudly, never registered half-configured.
    """

    def skip(why: str) -> None:
        logger.warning("local_apis: %s (transport stdio) %s; skipped", name, why)

    if protocol != "jsonrpc":
        # JSON-RPC over stdio is how MCP servers and language servers run.
        # HTTP over a pipe is not something tools speak.
        return skip(f"needs protocol jsonrpc, got {protocol!r}")
    if not os.path.isabs(path_value):
        # A relative path would resolve against whatever directory the agent
        # happens to run in, or a PATH lookup: neither is a declaration.
        return skip(f"needs an absolute path to the binary, got {path_value!r}")

    raw_args = meta.get("args")
    if raw_args is None:
        args: tuple[str, ...] = ()
    elif isinstance(raw_args, list) and all(_is_scalar_text(a) for a in raw_args):
        args = tuple(str(a) for a in raw_args)
    else:
        return skip("has `args` that is not a list of strings")

    cwd = meta.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not os.path.isabs(cwd)):
        return skip(f"needs an absolute `cwd`, got {cwd!r}")

    raw_env = meta.get("env")
    env: dict[str, str] = {}
    if raw_env is not None:
        if not isinstance(raw_env, dict) or not all(
            isinstance(k, str) and k and "=" not in k and _is_scalar_text(v)
            for k, v in raw_env.items()
        ):
            return skip("has `env` that is not a mapping of names to strings")
        env = {k: str(v) for k, v in raw_env.items()}
    if env and meta.get("run_as"):
        # sudo resets the environment, and letting variables through needs
        # SETENV in sudoers: a far wider grant than the one rule run_as asks
        # for. Refusing beats variables that silently never arrive.
        return skip(
            "sets both `env` and `run_as`; sudo would drop the variables "
            "(set them in the binary's own configuration instead)"
        )

    handshake = str(meta.get("handshake") or "none").strip().lower()
    if handshake not in _STDIO_HANDSHAKES:
        return skip(f"has handshake={handshake!r}; expected none or mcp")

    from sentinelx_core.local_api import binary_problem

    problem = binary_problem(path_value, run_as=meta.get("run_as"))
    if problem is not None:
        code, message = problem
        if code == "unsafe_binary":
            return skip(message)
        # Missing or not executable does not drop it: it may be installed
        # after the agent starts, like a socket that is down at boot. Each
        # call re-checks and reports it.
        logger.warning(
            "local_apis: %s (transport stdio): %s; registered anyway, calls "
            "fail until it is fixed", name, message,
        )
    return {"args": args, "cwd": cwd, "env": env, "handshake": handshake}


def _resolve_exec_mode(data: dict) -> str:
    """exec_mode from config.yaml. An explicit exec_mode wins over the older
    exec_strict; an unknown value falls back to the default instead of keeping
    the agent from starting."""
    raw = data.get("exec_mode")
    if raw is None:
        return "strict" if bool(data.get("exec_strict", False)) else "allowlist"
    mode = str(raw).strip().lower()
    if mode not in EXEC_MODES:
        logger.warning(
            "policy_invalid_exec_mode",
            extra={"value": str(raw)[:40], "using": "allowlist",
                   "valid": sorted(EXEC_MODES)},
        )
        return "allowlist"
    if data.get("exec_strict") and mode != "strict":
        logger.warning("policy_exec_mode_overrides_exec_strict", extra={"exec_mode": mode})
    return mode


def _entry_matches(cmd: str, entry: str) -> bool:
    entry = (entry or "").strip()
    if not entry:
        # An empty entry has always matched everything (a known gotcha, pinned
        # by test_allowlist_empty_string_matches_everything). Keep it: an
        # operator relying on it must not be locked out by this change.
        return True
    if not cmd.startswith(entry):
        return False
    if len(cmd) == len(entry) or entry.endswith("/"):
        return True
    return cmd[len(entry)].isspace()


@dataclass
class Policy:
    """Loaded policy. Immutable after construction."""

    # Check EVERY segment of a chained command against allowed_commands, not
    # just what the whole string starts with. Off by default: measured against
    # 48h of fleet traffic, turning it on unconditionally would reject roughly a
    # third of chained calls even with the cd and read-only-filter concessions,
    # and every single one of them without. A security default that gets
    # reverted within the hour protects nobody. See segment_check.py.
    exec_strict: bool = False

    # How exec decides what may run: "allowlist" (default; every command in a
    # chain checked against allowed_commands), "strict" (also refuses newlines,
    # substitutions and redirections; what exec_strict=True has always meant) or
    # "unrestricted" (any command line under the agent's identity, like
    # script_run). The last is for trusted development hosts, where a customer
    # asked to "allow shell execution under this identity and let Linux enforce
    # the rest" instead of maintaining an ever-growing list (issue #57).
    exec_mode: str = "allowlist"

    @property
    def effective_exec_mode(self) -> str:
        if self.exec_strict:
            return "strict"
        return self.exec_mode if self.exec_mode in EXEC_MODES else "allowlist"

    # Ops the operator has switched off on this host. An op named here is not
    # built into the registry at all, so it vanishes from capabilities and
    # dispatch answers unsupported_op -- the same as if this agent had never
    # shipped it. One lever, one place, no second enforcement path to drift.
    #
    # WHY THIS EXISTS. allowed_commands gates `exec` and only `exec`; that is
    # what its own heading says and always has. script_run runs a script body
    # through an interpreter and was never bound by it. Reasonable operators
    # read an empty allowlist as "this host executes nothing" and were
    # surprised -- reported independently by two of them, one after a
    # governance audit on a Windows host where the service runs as LocalSystem.
    # Being documented did not make the surprise unreasonable, and there was no
    # supported way to say no. Now there is.
    disabled_ops: frozenset[str] = field(default_factory=frozenset)

    # Command prefixes the agent will execute via the `exec` op.
    # An exec request matches if cmd.startswith(allowed) for some entry.
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)

    # service name -> ServiceSpec
    services: dict[str, ServiceSpec] = field(default_factory=dict)

    # name -> LocalApiEndpoint. Empty unless the host declares `local_apis`,
    # and an endpoint with no `actions` is NOT registered: the allowlist is the
    # entire security boundary here. exec is bounded by command prefixes, but a
    # socket bridge is bounded only by whatever the far side exposes, which the
    # agent cannot enumerate.
    local_apis: dict[str, LocalApiEndpoint] = field(default_factory=dict)

    # short label -> LocationSpec
    locations: dict[str, LocationSpec] = field(default_factory=dict)

    # diagnostic playbook name -> ordered list of commands
    playbooks: dict[str, dict[str, Any]] = field(default_factory=dict)

    # optional human-readable label for this host
    hostname_label: str | None = None

    # Advisory MCP toolset profile this host prefers ('compact' | 'full'),
    # advertised in the hello. None (the default) = no preference; stock
    # SentinelX leaves it None and gets the full catalog. The hub treats this
    # as a default only, and only under unanimity across the user's agents —
    # an explicit dashboard choice always wins. Sanitized in from_file: any
    # value other than 'compact'/'full' degrades to None (never advertises a
    # bogus value that the hub's Literal would reject).
    preferred_profile: str | None = None

    # exec timeout default
    exec_timeout_default: int = 60
    exec_timeout_max: int = 600

    # Where uploads + edit workdirs live. Resolved rather than hardcoded: the
    # old default was /home/sentinelx/uploads, which on most installs either
    # does not exist or belongs to root, so an agent whose config lost its
    # `upload_base` (e.g. an emptied config.yaml) could not stage anything --
    # including the edit that would have restored the config.
    upload_base: Path = field(default_factory=lambda: default_upload_base())

    # ── file_url SSRF defense ──────────────────────────────────────────────
    # When the hub asks the agent to fetch a URL (upload_file with file_url),
    # the URL's hostname must be in this allowlist AND its resolved IP must
    # not be private/loopback/link-local.
    #
    # Default empty = file_url is effectively disabled. Operators must
    # opt-in by listing trusted hosts. This is the principle of least
    # privilege: the agent runs with elevated rights, so a fetch primitive
    # to arbitrary hosts is a SSRF gun pointed at the host's network.
    #
    # Typical configuration for SentinelX:
    #   trusted_fetch_hosts:
    #     - drop.pensa.ar
    #     - get.sentinelx.app
    trusted_fetch_hosts: tuple[str, ...] = ()

    # Tighter timeout than the legacy 60s — fetches that take that long
    # against an attacker-controlled host are tying up agent resources
    # while leaking timing info.
    file_url_timeout_seconds: int = 15

    # ── file_ops: read/list/search primitives ──────────────────────────────
    # Read-only filesystem primitives the agent exposes for inspecting files
    # and directories. Unlike `exec` (which has an explicit command allowlist)
    # these primitives are constrained by a PATH allowlist: the only paths
    # the agent will read/list/search are those that fall under one of
    # the configured `file_ops_paths` entries.
    #
    # Empty list = deny-all. The handlers return a clear "path_not_allowed"
    # error pointing the operator to add the directory in config.yaml.
    #
    # Why a separate allowlist rather than reusing `locations`? `locations`
    # is a list of "known places" the operator wants the agent to be aware
    # of (typically used by humans navigating capabilities output). The
    # file_ops allowlist is a security boundary: a directory could be in
    # `locations` for discoverability but NOT in this allowlist, and the
    # read/list/search primitives would still refuse to touch it.
    #
    # Path resolution is canonical (resolve symlinks before checking), and
    # the check rejects anything outside the allowed prefixes. This blocks
    # path-traversal attacks like ../../../etc/shadow even if the operator
    # accidentally allows /home/user.
    #
    # Unified r/rw model: each entry carries an access level. "r" entries
    # behave exactly like the legacy allowlist (read/list/search only).
    # "rw" entries additionally permit the mutating ops (edit, move,
    # copy, delete, chmod, chown). A path must be EXPLICITLY "rw" for any
    # mutation — the default and the fallback for anything unrecognized
    # is "r", so the model can never silently grant write.
    #
    # Backward compatibility: a legacy config with
    #   file_ops:
    #     allowed_read_paths: [/etc, /var/log]
    # is mapped automatically to read-only entries (access: r). Existing
    # agents keep working with zero changes and zero new permissions.
    file_ops_paths: tuple[FileOpsPath, ...] = ()

    # Maximum number of bytes to read per `read` op. Files larger than
    # this are returned truncated with truncated=True so the caller knows
    # to use view_range or accept the partial result.
    file_ops_max_read_bytes: int = 65536  # 64 KB

    # Maximum entries returned by `list` per call. Beyond this, the
    # response is truncated.
    file_ops_max_list_entries: int = 1000

    # Maximum matches returned by `search`. Search is recursive, so this
    # protects the agent from runaway grep over a massive tree.
    file_ops_max_search_results: int = 200

    @classmethod
    def empty(cls) -> "Policy":
        """Used in tests and as the default if no config file exists."""
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        if not path.exists():
            logger.warning("policy_config_missing", extra={"path": str(path)})
            return cls.empty()

        try:
            data = yaml.safe_load(read_config_text(path)) or {}
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
            logger.error("policy_config_invalid", extra={"path": str(path), "error": str(exc)})
            return cls.empty()

        # Schema errors (unknown keys, typos like `allow:` instead of
        # `allowed_commands:`) are reported as ValueError by from_dict. We
        # log them prominently and refuse to fall back to empty — silently
        # loading nothing was the exact bug we're trying to prevent.
        try:
            return cls.from_dict(data)
        except ValueError as exc:
            logger.error(
                "policy_config_schema_error",
                extra={"path": str(path), "error": str(exc)},
            )
            # Re-raise so the agent fails loudly at startup rather than
            # accepting WS connections with an empty allowlist. The systemd
            # unit will restart but journalctl will show this clearly.
            raise

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        # --- Schema validation: detect typos with high-confidence -----------
        # We deliberately use a TWO-TIER approach:
        #
        #   Tier 1: HARD FAIL on keys we know are common typos for required
        #           keys. These produce a ValueError so the agent crashes
        #           loudly at startup (better than silently loading nothing).
        #
        #   Tier 2: SOFT WARN on unknown keys that don't match any known
        #           typo. We just log a warning and continue. This avoids
        #           breaking forward-compatible configs that include keys
        #           we haven't seen yet (e.g. a future version adds a new
        #           top-level key, but the user is still running an older
        #           agent — their config keeps working).
        #
        # The bug we're preventing is the one from May 2 2026: someone
        # writes `allow:` instead of `allowed_commands:` and the agent
        # silently loads zero commands. We hard-fail on that exact typo
        # but stay tolerant of unknowns we don't recognize.
        TYPO_HINTS = {
            "allow": "allowed_commands",
            "allowedCommands": "allowed_commands",
            "commands": "allowed_commands",
            "service": "services",
            "location": "locations",
            "playbook": "playbooks",
            "hub": "hub_url",
        }
        # Hard fail: any key in TYPO_HINTS is a known mistake.
        typos_found = [k for k in data.keys() if k in TYPO_HINTS]
        if typos_found:
            hints = [
                f"  '{k}' is not recognized — did you mean '{TYPO_HINTS[k]}'?"
                for k in sorted(typos_found)
            ]
            raise ValueError(
                "config.yaml contains keys that look like common typos:\n"
                + "\n".join(hints)
                + "\nFix the key name(s) and restart the agent."
            )

        # Soft warn: anything else not in KNOWN_KEYS is just informational.
        # It does NOT block the agent from starting.
        KNOWN_KEYS = {
            "agent", "exec", "allowed_commands", "services", "locations",
            "playbooks", "hub_url", "upload_base", "log", "security",
            "file_ops",
            # Adding a top-level block means adding it here too, or a valid
            # config warns about itself: local_apis shipped parsed and working
            # while policy_unknown_keys told the operator it was unrecognised.
            "local_apis",
            "disabled_ops",
            "exec_strict",
            "exec_mode",
        }
        unknown = set(data.keys()) - KNOWN_KEYS - set(TYPO_HINTS.keys())
        if unknown:
            logger.warning(
                "policy_unknown_keys",
                extra={
                    "unknown_keys": sorted(unknown),
                    "known_keys": sorted(KNOWN_KEYS),
                },
            )

        agent_block = data.get("agent", {}) or {}
        exec_block = data.get("exec", {}) or {}
        security_block = data.get("security", {}) or {}
        file_ops_block = data.get("file_ops", {}) or {}

        services: dict[str, ServiceSpec] = {}
        for name, meta in (data.get("services") or {}).items():
            actions = tuple(meta.get("actions") or [])
            user = str(meta.get("user") or "").strip()
            if user and not _SERVICE_USER_RE.fullmatch(user):
                # Skipped, not downgraded to a system unit: managing a system
                # unit of the same name is worse than managing nothing, and the
                # user name ends up in a shell command.
                logger.warning(
                    "services: %s has an invalid user %r; skipped", name, user
                )
                continue
            services[name] = ServiceSpec(
                unit=meta.get("unit", name),
                actions=actions,
                requires_sudo=bool(meta.get("requires_sudo", True)),
                description=meta.get("description", ""),
                domain=meta.get("domain", "system"),
                backend=meta.get("backend", "service"),
                user=user,
            )

        # ── local_apis ────────────────────────────────────────────────────
        # Host-local endpoints that already speak a structured protocol. An
        # endpoint is skipped, loudly, unless it is fully formed: `actions` is
        # the whole security boundary, so a malformed block must not degrade
        # into "allow everything" or into a half-configured endpoint.
        local_apis: dict[str, LocalApiEndpoint] = {}
        for name, meta in (data.get("local_apis") or {}).items():
            if not isinstance(meta, dict):
                logger.warning("local_apis: %s is not a mapping; skipped", name)
                continue
            transport = str(meta.get("transport") or "").strip()
            protocol = str(meta.get("protocol") or "").strip()
            path_value = str(meta.get("path") or "").strip()
            raw_actions = meta.get("actions")
            if transport not in ("unix", "stdio"):
                logger.warning(
                    "local_apis: %s has transport=%r; expected unix or stdio; skipped",
                    name, transport,
                )
                continue
            if protocol not in ("http", "jsonrpc"):
                logger.warning(
                    "local_apis: %s has protocol=%r; expected http or jsonrpc; skipped",
                    name, protocol,
                )
                continue
            if not path_value:
                logger.warning("local_apis: %s has no path; skipped", name)
                continue
            stdio_opts: dict[str, Any] = {}
            if transport == "stdio":
                parsed = _parse_stdio_options(str(name), meta, protocol, path_value)
                if parsed is None:
                    continue
                stdio_opts = parsed
            else:
                stray = [k for k in _STDIO_KEYS if k in meta]
                if stray:
                    logger.warning(
                        "local_apis: %s sets %s, which only apply to transport "
                        "stdio; ignored", name, ", ".join(stray),
                    )
            if not isinstance(raw_actions, dict) or not raw_actions:
                # Deliberate: no list, no endpoint. Registering one without an
                # action allowlist would expose whatever the far side happens
                # to offer, which the agent cannot see or bound.
                logger.warning(
                    "local_apis: %s declares no actions; skipped (an action "
                    "allowlist is required)", name,
                )
                continue

            actions: dict[str, LocalApiAction] = {}
            for act_name, act in raw_actions.items():
                act = act or {}
                if not isinstance(act, dict):
                    logger.warning(
                        "local_apis: %s.%s is not a mapping; skipped", name, act_name
                    )
                    continue
                request = act.get("request")
                method = act.get("method")
                if protocol == "http" and not request:
                    logger.warning(
                        "local_apis: %s.%s needs `request` for protocol http; skipped",
                        name, act_name,
                    )
                    continue
                if protocol == "jsonrpc" and not method:
                    logger.warning(
                        "local_apis: %s.%s needs `method` for protocol jsonrpc; skipped",
                        name, act_name,
                    )
                    continue
                sel = act.get("select") or ()
                # `params:` on an action is its SCHEMA, not values. Only shape
                # is checked; the content is the endpoint's business and the
                # agent never reads it.
                pschema = act.get("params")
                if pschema is not None and not isinstance(pschema, dict):
                    logger.warning(
                        "local_apis: %s.%s has a non-mapping `params` schema; "
                        "ignoring it", name, act_name,
                    )
                    pschema = None
                actions[str(act_name)] = LocalApiAction(
                    request=str(request) if request else None,
                    method=str(method) if method else None,
                    select=tuple(str(x) for x in sel),
                    description=(
                        str(act["description"]) if act.get("description") else None
                    ),
                    params_schema=pschema,
                )
            if not actions:
                logger.warning(
                    "local_apis: %s had actions but none were usable; skipped", name
                )
                continue

            # Validate the compatibility block here so a malformed one is
            # caught at load, where the operator sees the warning, rather than
            # at first use where it would look like an endpoint fault.
            compat = meta.get("compatibility") or {}
            if compat:
                probe = compat.get("probe") if isinstance(compat, dict) else None
                accept = compat.get("accept") if isinstance(compat, dict) else None
                extract = compat.get("extract") if isinstance(compat, dict) else None
                problem = None
                if not isinstance(compat, dict):
                    problem = "compatibility must be a mapping"
                elif not isinstance(probe, dict) or not (
                    probe.get("method") or probe.get("request")
                ):
                    problem = "compatibility.probe needs a `method` or a `request`"
                elif not extract:
                    problem = "compatibility.extract must name the field to read"
                elif not isinstance(accept, dict) or not (
                    "exact" in accept or "allowed" in accept
                ):
                    problem = "compatibility.accept needs `exact` or `allowed`"
                elif "allowed" in accept and not isinstance(accept["allowed"], list):
                    problem = "compatibility.accept.allowed must be a list"
                if problem:
                    logger.warning(
                        "local_apis: %s has an unusable compatibility block (%s); "
                        "dropping the constraint rather than half-enforcing it",
                        name, problem,
                    )
                    compat = {}
            local_apis[str(name)] = LocalApiEndpoint(
                name=str(name),
                transport=transport,
                path=path_value,
                protocol=protocol,
                actions=actions,
                timeout_s=float(meta.get("timeout_s") or 30),
                run_as=str(meta["run_as"]) if meta.get("run_as") else None,
                compatibility=compat if isinstance(compat, dict) else {},
                **stdio_opts,
            )

        locations: dict[str, LocationSpec] = {}
        for label, meta in (data.get("locations") or {}).items():
            if isinstance(meta, str):
                locations[label] = LocationSpec(path=meta)
            else:
                locations[label] = LocationSpec(
                    path=meta["path"],
                    description=meta.get("description", ""),
                )

        # --- file_ops paths: unified r/rw model + legacy back-compat ------
        #
        # Three shapes are accepted, in priority order:
        #
        #   1. New model:
        #        file_ops:
        #          paths:
        #            - path: /home/carlos
        #              access: rw
        #            - path: /etc
        #              access: r
        #            - /var/log            # bare string == access: r
        #
        #   2. Legacy model (back-compat, zero breakage):
        #        file_ops:
        #          allowed_read_paths: [/etc, /var/log]
        #      Each entry becomes a read-only FileOpsPath (access: r).
        #      Existing agents keep the EXACT behaviour they had — no new
        #      permissions are ever granted by the migration.
        #
        #   3. Both keys present: `paths` wins, `allowed_read_paths` is
        #      ignored with a loud warning. We do NOT merge them: merging
        #      would make the effective access level of a directory
        #      ambiguous, and "explicit beats implicit" is the safer rule
        #      for a security boundary.
        #
        # An unknown `access` value (typo like "readwrite") degrades to
        # "r" inside FileOpsPath.__post_init__ — never to "rw".
        raw_paths = file_ops_block.get("paths")
        legacy_read_paths = file_ops_block.get("allowed_read_paths")

        file_ops_paths_list: list[FileOpsPath] = []
        if raw_paths:
            if legacy_read_paths:
                logger.warning(
                    "file_ops_both_keys_present",
                    extra={
                        "detail": (
                            "file_ops has BOTH 'paths' and the legacy "
                            "'allowed_read_paths'. Using 'paths'; "
                            "'allowed_read_paths' is ignored. Remove the "
                            "legacy key to silence this warning."
                        )
                    },
                )
            for entry in raw_paths:
                if isinstance(entry, str):
                    file_ops_paths_list.append(FileOpsPath(path=entry))
                elif isinstance(entry, dict) and entry.get("path"):
                    file_ops_paths_list.append(
                        FileOpsPath(
                            path=str(entry["path"]),
                            access=str(entry.get("access", "r")),
                        )
                    )
                else:
                    # Skip malformed entries loudly rather than crash the
                    # whole agent — a single bad list item shouldn't take
                    # the host offline, but the operator must see it.
                    logger.warning(
                        "file_ops_path_entry_invalid",
                        extra={"entry": repr(entry)},
                    )
        elif legacy_read_paths:
            logger.warning(
                "file_ops_allowed_read_paths_deprecated",
                extra={
                    "detail": (
                        "file_ops.allowed_read_paths is deprecated. It "
                        "still works (mapped to access: r) but please "
                        "migrate to the unified file_ops.paths model with "
                        "explicit r/rw access levels. See "
                        "config.example.yaml."
                    )
                },
            )
            for entry in legacy_read_paths:
                file_ops_paths_list.append(
                    FileOpsPath(path=str(entry), access="r")
                )

        # Advisory toolset-profile hint (optional). Only 'compact'/'full' are
        # meaningful; anything else degrades to None with a loud warning so a
        # typo can't advertise a value the hub's Literal would reject (which
        # would fail the hello and take the host offline).
        _raw_profile = agent_block.get("preferred_profile")
        if _raw_profile in (None, "compact", "full"):
            _preferred_profile = _raw_profile
        else:
            logger.warning(
                "policy_preferred_profile_invalid",
                extra={
                    "value": repr(_raw_profile),
                    "detail": (
                        "agent.preferred_profile must be 'compact' or 'full'; "
                        "ignoring and advertising no preference."
                    ),
                },
            )
            _preferred_profile = None

        policy = cls(
            allowed_commands=tuple(data.get("allowed_commands") or []),
            exec_strict=_resolve_exec_mode(data) == "strict",
            exec_mode=_resolve_exec_mode(data),
            disabled_ops=frozenset(
                str(o).strip() for o in (data.get("disabled_ops") or []) if str(o).strip()
            ),
            services=services,
            local_apis=local_apis,
            locations=locations,
            playbooks=dict(data.get("playbooks") or {}),
            hostname_label=agent_block.get("hostname_label"),
            preferred_profile=_preferred_profile,
            exec_timeout_default=int(exec_block.get("timeout_default", 60)),
            exec_timeout_max=int(exec_block.get("timeout_max", 600)),
            upload_base=Path(
                data.get("upload_base") or default_upload_base()
            ).resolve(),
            trusted_fetch_hosts=tuple(
                security_block.get("trusted_fetch_hosts") or ()
            ),
            file_url_timeout_seconds=int(
                security_block.get("file_url_timeout_seconds", 15)
            ),
            file_ops_paths=tuple(file_ops_paths_list),
            file_ops_max_read_bytes=int(
                file_ops_block.get("max_read_bytes", 65536)
            ),
            file_ops_max_list_entries=int(
                file_ops_block.get("max_list_entries", 1000)
            ),
            file_ops_max_search_results=int(
                file_ops_block.get("max_search_results", 200)
            ),
        )

        # --- Fix #7-prevention (part 2): warn on empty allowlist -----------
        # An empty allowed_commands list is technically valid (deny-all) but
        # it almost always means the operator forgot to populate it or used
        # the wrong key name. Loud warning at startup so it surfaces in
        # journalctl rather than only when the first exec attempt fails.
        if not policy.allowed_commands:
            # Note: don't pass `message` in extra — that's a reserved field
            # in stdlib logging.LogRecord and using it raises KeyError.
            logger.warning(
                "Policy loaded with NO allowed_commands. "
                "All `exec` calls will be rejected. "
                "If this is unintentional, check that "
                f"{_pg.CONFIG_PATH} contains an "
                "`allowed_commands:` block (with underscore — "
                "`allow:` won't work)."
            )
        else:
            logger.info(
                "policy_loaded",
                extra={
                    "allowed_commands_count": len(policy.allowed_commands),
                    "services_count": len(policy.services),
                    "playbooks_count": len(policy.playbooks),
                },
            )

        return policy

    # --- Query methods --------------------------------------------------------

    def is_command_allowed(self, cmd: str) -> bool:
        """Whole-word match against allowed_commands.

        An entry matches when the command IS the entry or continues after it with
        whitespace: `ls` allows `ls -la` but no longer `lsof` (GHSA-r2h3-76g7-m95x).
        An entry ending in '/' keeps its directory-prefix meaning, so `/opt/tools/`
        still allows `/opt/tools/run.sh`. Empty allowlist means deny-all.
        """
        cmd = (cmd or "").strip()
        if not cmd:
            return False
        return any(_entry_matches(cmd, allowed) for allowed in self.allowed_commands)

    def get_service(self, name: str) -> ServiceSpec | None:
        return self.services.get(name)

    def is_service_action_allowed(self, name: str, action: str) -> bool:
        spec = self.services.get(name)
        if spec is None:
            return False
        return action in spec.actions

    def resolve_path(
        self, path: str, *, need_write: bool = False
    ) -> Path | None:
        """Resolve `path` against the unified file_ops allowlist.

        Returns the canonical Path if `path` falls under one of the
        configured `file_ops_paths` entries with sufficient access, or
        None otherwise (no match, empty allowlist, or write needed on a
        read-only entry).

        `need_write`:
          - False (default): the path only needs to fall under ANY
            entry (access "r" or "rw"). Used by read/list/search.
          - True: the path must fall under an entry whose access is
            "rw". Used by edit and the destructive ops (move, copy,
            delete, chmod, chown).

        Security properties (UNCHANGED from the legacy
        resolve_read_path — this is the load-bearing check):

          - Canonicalization via Path.resolve(strict=False) follows
            symlinks BEFORE the prefix check. A symlink at
            /home/carlos/escape -> /etc/shadow does NOT bypass the
            allowlist: the resolved /etc/shadow is only allowed if /etc
            itself is a configured entry (with rw, if need_write).
          - Path traversal (`../`) is defeated by the same resolve().
          - Path.is_relative_to() is used so /etc/passwd does not match
            an allowlist entry of /etc-not-this-one.

        It does NOT check existence or readability — handlers do that
        AFTER the allowlist check passes, so they can return a clean
        not_found / permission_denied instead of masking those as
        path_not_allowed.

        When multiple entries match (e.g. /home is "r" and
        /home/carlos is "rw"), the MOST PERMISSIVE matching entry wins
        for the requested access: if any matching entry satisfies the
        need, the path is allowed. This is intentional and matches the
        operator's mental model — declaring a subtree "rw" is an
        explicit grant that a broader "r" parent must not silently
        veto. The narrower, more specific decision is the one the
        operator most recently/intentionally expressed.
        """
        if not self.file_ops_paths:
            return None
        if not path:
            return None

        try:
            candidate = Path(path).resolve(strict=False)
        except (OSError, RuntimeError):
            # OSError for paths with NUL chars / nonexistent parts on
            # some platforms; RuntimeError for circular symlinks.
            return None

        for entry in self.file_ops_paths:
            if need_write and entry.access != "rw":
                continue
            try:
                allowed = Path(entry.path).resolve(strict=False)
            except (OSError, RuntimeError):
                continue
            # Use Path.is_relative_to so /etc/passwd doesn't match
            # an allowlist of /etc-not-this-one. Python 3.9+.
            if candidate == allowed or candidate.is_relative_to(allowed):
                return candidate

        return None

    def resolve_read_path(self, path: str) -> Path | None:
        """Backward-compatible shim → resolve_path(need_write=False).

        Kept so existing callers (handlers/fileops.py and any
        out-of-tree consumers / tests) keep working unchanged after the
        unified r/rw refactor. New code should call resolve_path()
        directly and pass need_write=True for mutating operations.

        Behaviour is identical to the pre-refactor resolve_read_path:
        a path under ANY file_ops entry (r or rw) resolves; the access
        level is not consulted for read.
        """
        return self.resolve_path(path, need_write=False)
