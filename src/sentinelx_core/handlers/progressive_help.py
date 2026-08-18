"""Small, progressive projections for SentinelX help and capabilities.

Legacy empty-payload responses stay unchanged. Optional selectors let a Hub
request only the guidance/policy summary an LLM needs and keep returned
instructions neutral across full and compact MCP presentations.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from sentinelx_core.executor import HandlerError

_PAGE_DEFAULT = 50
_PAGE_MAX = 100
_TOOL_RE = re.compile(r"\bsentinel_([a-z][a-z0-9_]*)\b")

_TOPICS: dict[str, tuple[str, str]] = {
    "getting_started": ("getting_started", "minimal first-use guidance"),
    "security": ("security_model", "security and permission model"),
    "operations": ("navigation", "operation/navigation map"),
    "operating_notes": ("operating_notes", "general operating notes"),
    "access": ("extending_access", "how to extend configured access"),
    "hosts": ("managing_hosts", "host enrollment, update, and targeting"),
    "playbooks": ("playbooks", "paged playbook-name index"),
    "policy": ("policy", "policy summary counts"),
    "examples": ("examples", "example task prompts"),
    "resources": ("resources", "project/dashboard/contact resources"),
    "about": ("about", "project/creator information"),
}


def _query(op: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"backend_operation": op, "payload": dict(payload)}


def _string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise HandlerError("invalid_payload", f"'{key}' must be a non-empty string")
    return value.strip()


def _integer(
    payload: Mapping[str, Any], key: str, *, default: int, minimum: int, maximum: int | None = None
) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise HandlerError("invalid_payload", f"'{key}' must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else "+"
        raise HandlerError("invalid_payload", f"'{key}' must be in range {minimum}{suffix}")
    return value


def _page(values: list[Any], payload: Mapping[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    offset = _integer(payload, "offset", default=0, minimum=0)
    limit = _integer(payload, "limit", default=_PAGE_DEFAULT, minimum=1, maximum=_PAGE_MAX)
    items = values[offset : offset + limit]
    next_offset = offset + len(items)
    if next_offset >= len(values):
        next_offset = None
    return items, {
        "total": len(values),
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
        "truncated": next_offset is not None,
    }


def _lookup(root: Any, path: str) -> Any:
    parts = path.split(".")
    if any(not part for part in parts):
        raise HandlerError("invalid_payload", "'path' must be dot-separated object keys")
    node = root
    walked: list[str] = []
    for part in parts:
        if not isinstance(node, Mapping):
            raise HandlerError(
                "invalid_payload",
                f"help path cannot descend through non-object at {'.'.join(walked) or '<root>'}",
            )
        if part not in node:
            names = sorted(str(key) for key in node)[:50]
            raise HandlerError(
                "invalid_payload",
                f"unknown help path component: {part}",
                details={
                    "path_prefix": ".".join(walked),
                    "available_keys": names,
                    "available_key_count": len(node),
                    "available_keys_truncated": len(node) > len(names),
                },
            )
        node = node[part]
        walked.append(part)
    return node


def _neutralize(value: Any) -> tuple[Any, dict[str, str]]:
    """Copy JSON-like guidance and replace full-profile sentinel_* references."""
    references: dict[str, str] = {}

    def visit(node: Any) -> Any:
        if isinstance(node, str):

            def replace(match: re.Match[str]) -> str:
                source = match.group(0)
                operation = match.group(1)
                references[source] = operation
                return f"op:{operation}"

            return _TOOL_RE.sub(replace, node)
        if isinstance(node, Mapping):
            return {key: visit(item) for key, item in node.items()}
        if isinstance(node, list):
            return [visit(item) for item in node]
        if isinstance(node, tuple):
            return tuple(visit(item) for item in node)
        return node

    return visit(value), dict(sorted(references.items()))


def _project_selected(value: Any, payload: Mapping[str, Any]) -> tuple[Any, dict[str, Any] | None]:
    has_page = "offset" in payload or "limit" in payload
    if isinstance(value, (list, tuple)):
        return _page(list(value), payload)
    if has_page:
        raise HandlerError("invalid_payload", "offset/limit require a list-valued path")
    return value, None


def _presentation(refs: Mapping[str, str]) -> dict[str, Any] | None:
    if not refs:
        return None
    # Design note: op:<name> is deliberately a small agent-side convention,
    # not a claim that every Hub/profile must render guidance this way. It keeps
    # newly-scoped responses usable when the same backend operation is exposed
    # as a full sentinel_* tool or as a compact multiplexed branch. A Hub that
    # prefers to translate presentation names itself can do so; this normalization
    # is confined to the new progressive responses and does not rewrite policy.
    return {
        "tool_reference_map": dict(refs),
        "note": (
            "Progressive guidance rewrites full-profile sentinel_* names as op:<name>. "
            "Route op:<name> through the active Hub profile."
        ),
    }


def select_help_response(
    payload: Mapping[str, Any], full: Mapping[str, Any], playbooks: Mapping[str, Any]
) -> dict[str, Any]:
    """Return legacy full help or a narrow topic/path/playbook projection."""
    unknown = sorted(set(payload) - {"topic", "path", "playbook", "offset", "limit"})
    if unknown:
        raise HandlerError("invalid_payload", f"unknown help field(s): {', '.join(unknown)}")

    topic = _string(payload, "topic")
    path = _string(payload, "path")
    playbook = _string(payload, "playbook")
    has_page = "offset" in payload or "limit" in payload
    if topic and (path or playbook):
        raise HandlerError("invalid_payload", "topic is mutually exclusive with path/playbook")

    if topic is None and path is None and playbook is None:
        if has_page:
            raise HandlerError(
                "invalid_payload", "offset/limit require an index or list-valued path"
            )
        return dict(full)

    base = {
        "agent": full.get("agent"),
        "version": full.get("version"),
        "host_label": full.get("host_label"),
    }

    if playbook is not None:
        definition = playbooks.get(playbook)
        if definition is None:
            names, page = _page(sorted(playbooks), {})
            raise HandlerError(
                "invalid_payload",
                f"unknown playbook: {playbook}",
                details={"available_playbooks": {"names": names, **page}},
            )
        if path is None:
            if has_page:
                raise HandlerError("invalid_payload", "offset/limit require a playbook subpath")
            value, refs = _neutralize(definition)
            result = {**base, "playbook": playbook, "definition": value}
        else:
            selected = _lookup(definition, path)
            selected, page = _project_selected(selected, payload)
            value, refs = _neutralize(selected)
            result = {**base, "playbook": playbook, "path": path, "value": value}
            if page is not None:
                result["pagination"] = page
                if page["next_offset"] is not None:
                    result["next"] = _query(
                        "help",
                        {
                            "playbook": playbook,
                            "path": path,
                            "offset": page["next_offset"],
                            "limit": page["limit"],
                        },
                    )
        presentation = _presentation(refs)
        if presentation:
            result["presentation"] = presentation
        return result

    if path is not None:
        selected = _lookup(full, path)
        selected, page = _project_selected(selected, payload)
        value, refs = _neutralize(selected)
        result = {**base, "path": path, "value": value}
        if page is not None:
            result["pagination"] = page
            if page["next_offset"] is not None:
                result["next"] = _query(
                    "help",
                    {"path": path, "offset": page["next_offset"], "limit": page["limit"]},
                )
        presentation = _presentation(refs)
        if presentation:
            result["presentation"] = presentation
        return result

    if topic is None:
        raise HandlerError("invalid_payload", "topic is required")
    topic = topic.lower()
    if topic == "all":
        if has_page:
            raise HandlerError("invalid_payload", "topic=all does not accept offset/limit")
        return dict(full)
    if topic == "index":
        names, page = _page(sorted(playbooks), payload)
        return {
            **base,
            "summary": full.get("summary"),
            "topics": {name: description for name, (_key, description) in _TOPICS.items()},
            "path_examples": [
                "security_model.permission_errors",
                "security_model.allowlist_errors",
                "navigation.exec",
                "managing_hosts.targeting",
            ],
            "playbooks": {"names": names, **page},
            "next": {
                "topic": _query("help", {"topic": "security"}),
                "path": _query("help", {"path": "security_model.permission_errors"}),
                "playbook": _query("help", {"playbook": "<name>"}),
                "next_page": (
                    _query(
                        "help",
                        {"topic": "index", "offset": page["next_offset"], "limit": page["limit"]},
                    )
                    if page["next_offset"] is not None
                    else None
                ),
                "full": _query("help", {"topic": "all"}),
            },
        }

    entry = _TOPICS.get(topic)
    if entry is None:
        raise HandlerError(
            "invalid_payload",
            f"unknown help topic: {topic}",
            details={"available_topics": ["index", *_TOPICS, "all"]},
        )
    key, _description = entry
    if topic == "playbooks":
        names, page = _page(sorted(playbooks), payload)
        return {
            **base,
            "topic": topic,
            "playbooks": {"names": names, **page},
            "next": {
                "playbook": _query("help", {"playbook": "<name>"}),
                "next_page": (
                    _query(
                        "help",
                        {
                            "topic": "playbooks",
                            "offset": page["next_offset"],
                            "limit": page["limit"],
                        },
                    )
                    if page["next_offset"] is not None
                    else None
                ),
            },
        }
    if has_page:
        raise HandlerError("invalid_payload", "offset/limit are valid only for paged lists")
    value, refs = _neutralize(full.get(key))
    result = {**base, "topic": topic, key: value}
    presentation = _presentation(refs)
    if presentation:
        result["presentation"] = presentation
    return result


def capabilities_detail(payload: Mapping[str, Any]) -> str:
    unknown = sorted(set(payload) - {"detail"})
    if unknown:
        raise HandlerError(
            "invalid_payload", f"unknown capabilities field(s): {', '.join(unknown)}"
        )
    raw = payload.get("detail", "full")
    if not isinstance(raw, str) or raw.strip().lower() not in {"full", "summary"}:
        raise HandlerError("invalid_payload", "detail must be 'full' or 'summary'")
    return raw.strip().lower()


def summarize_capabilities(full: Mapping[str, Any]) -> dict[str, Any]:
    """Return discovery metadata without policy values or playbook bodies."""
    commands = full.get("allowed_commands") or []
    services = full.get("services") or {}
    locations = full.get("locations") or {}
    playbooks = full.get("playbooks") or {}
    fetch = full.get("fetch_policy") or {}
    file_ops = full.get("file_ops") or {}
    paths = file_ops.get("paths") or []
    writable = file_ops.get("writable_paths") or []
    return {
        "agent": full.get("agent"),
        "version": full.get("version"),
        "host": full.get("host"),
        "ops_supported": full.get("ops_supported"),
        "limits": full.get("limits"),
        "file_ops_limits": {
            "max_read_bytes": file_ops.get("max_read_bytes"),
            "max_list_entries": file_ops.get("max_list_entries"),
            "max_search_results": file_ops.get("max_search_results"),
        },
        "policy_summary": {
            "allowed_commands": len(commands),
            "services": len(services),
            "locations": len(locations),
            "playbooks": len(playbooks),
            "file_ops_paths": len(paths),
            "writable_paths": len(writable),
            "trusted_fetch_hosts": len(fetch.get("trusted_fetch_hosts") or []),
        },
        "query_contract": {
            "help": ["topic", "path", "playbook", "offset", "limit"],
            "capabilities_detail": ["summary", "full"],
            "max_page_limit": _PAGE_MAX,
            "legacy_empty_payload": "full",
        },
        "next": {
            "help_index": _query("help", {"topic": "index"}),
            "playbook": _query("help", {"playbook": "<name>"}),
            "full_capabilities": _query("capabilities", {"detail": "full"}),
        },
    }
