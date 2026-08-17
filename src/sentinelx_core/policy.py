"""Policy: allowlist + service registry + paths, loaded from /etc/sentinelx/config.yaml.

This is the ONLY place that knows about per-host configuration. Handlers consult
the policy to decide whether a command/service is allowed; they do not hardcode
anything site-specific.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelx_core import platform_guidance as _pg

logger = logging.getLogger(__name__)


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


@dataclass
class Policy:
    """Loaded policy. Immutable after construction."""

    # Command prefixes the agent will execute via the `exec` op.
    # An exec request matches if cmd.startswith(allowed) for some entry.
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)

    # service name -> ServiceSpec
    services: dict[str, ServiceSpec] = field(default_factory=dict)

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

    # Where uploads + edit workdirs live. Default mirrors legacy SentinelX.
    upload_base: Path = field(default_factory=lambda: Path("/home/sentinelx/uploads"))

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
            data = yaml.safe_load(path.read_text()) or {}
        except (yaml.YAMLError, OSError) as exc:
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
            services[name] = ServiceSpec(
                unit=meta.get("unit", name),
                actions=actions,
                requires_sudo=bool(meta.get("requires_sudo", True)),
                description=meta.get("description", ""),
                domain=meta.get("domain", "system"),
                backend=meta.get("backend", "service"),
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
            services=services,
            locations=locations,
            playbooks=dict(data.get("playbooks") or {}),
            hostname_label=agent_block.get("hostname_label"),
            preferred_profile=_preferred_profile,
            exec_timeout_default=int(exec_block.get("timeout_default", 60)),
            exec_timeout_max=int(exec_block.get("timeout_max", 600)),
            upload_base=Path(
                data.get("upload_base") or "/home/sentinelx/uploads"
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
        """Match by prefix, like the legacy core does.

        Empty allowlist means deny-all.
        """
        cmd = (cmd or "").strip()
        if not cmd:
            return False
        return any(cmd.startswith(allowed) for allowed in self.allowed_commands)

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
