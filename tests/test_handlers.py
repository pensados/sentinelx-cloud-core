"""Tests for the op handlers — pure unit tests, no real subprocess calls."""

from __future__ import annotations

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


@pytest.mark.asyncio
async def test_ping() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["ping"]({})
    assert result["pong"] is True
    assert "agent_version" in result


@pytest.mark.asyncio
async def test_capabilities_reflects_policy() -> None:
    p = Policy.from_dict(
        {
            "agent": {"hostname_label": "orion"},
            "allowed_commands": ["ls", "cat"],
            "services": {"nginx": {"actions": ["status", "restart"]}},
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    assert result["host"]["label"] == "orion"
    assert "ls" in result["allowed_commands"]
    assert result["services"]["nginx"]["actions"] == ["status", "restart"]


@pytest.mark.asyncio
async def test_capabilities_exposes_fetch_policy_defaults() -> None:
    """Default policy: empty allowlist, https only, no redirects."""
    p = Policy.from_dict({"allowed_commands": ["ls"]})
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    fp = result["fetch_policy"]
    assert fp["trusted_fetch_hosts"] == []
    assert fp["scheme_allowed"] == ["https"]
    assert fp["follow_redirects"] is False
    assert fp["file_url_timeout_seconds"] == 15  # default


@pytest.mark.asyncio
async def test_capabilities_exposes_configured_trusted_hosts() -> None:
    """When the operator configures trusted_fetch_hosts, capabilities
    surfaces them so the LLM knows where it can fetch from."""
    p = Policy.from_dict(
        {
            "allowed_commands": ["ls"],
            "security": {
                "trusted_fetch_hosts": ["drop.pensa.ar", "get.sentinelx.app"],
                "file_url_timeout_seconds": 20,
            },
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    fp = result["fetch_policy"]
    assert "drop.pensa.ar" in fp["trusted_fetch_hosts"]
    assert "get.sentinelx.app" in fp["trusted_fetch_hosts"]
    assert fp["file_url_timeout_seconds"] == 20


@pytest.mark.asyncio
async def test_exec_rejects_non_allowed_command() -> None:
    p = Policy(allowed_commands=("ls",))
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["exec"]({"command": "rm -rf /"})
    assert exc.value.code == "command_not_allowed"


@pytest.mark.asyncio
async def test_exec_runs_allowed_command() -> None:
    p = Policy(allowed_commands=("echo",))
    handlers = build_registry(policy=p)
    result = await handlers["exec"]({"command": "echo hello"})
    assert result["returncode"] == 0
    assert "hello" in result["output"]


@pytest.mark.asyncio
async def test_exec_missing_command() -> None:
    p = Policy(allowed_commands=("ls",))
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["exec"]({})
    assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_service_unknown_service() -> None:
    p = Policy.empty()
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["service"]({"service": "nginx", "action": "status"})
    assert exc.value.code == "service_not_allowed"


@pytest.mark.asyncio
async def test_service_action_not_allowed() -> None:
    p = Policy.from_dict({"services": {"nginx": {"actions": ["status"]}}})
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["service"]({"service": "nginx", "action": "kill"})
    assert exc.value.code == "service_action_not_allowed"


@pytest.mark.asyncio
async def test_state_returns_host_info() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["state"]({})
    assert "hostname" in result
    assert "kernel" in result
    assert "now_utc" in result


@pytest.mark.asyncio
async def test_ops_supported_matches_registry() -> None:
    """`ops_supported` in capabilities MUST equal the actual op registry.

    It used to be a hand-maintained literal and drifted twice: first when
    move/copy/delete/chmod/chown were registered but not advertised, then
    when file_export_init/chunk/complete + project_snapshot were (issue
    #32) -- in both cases a client introspecting ops_supported could not
    discover dispatchable ops. Since #32 the list is DERIVED from the
    registry inside build_registry(), so this test now guards the
    derivation itself: if someone reverts to a hand-maintained list, or
    the injection is dropped (ops_supported falls back to []), this fails.
    """
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["capabilities"]({})
    advertised = set(result["ops_supported"])
    registered = set(handlers)
    missing_from_caps = registered - advertised
    phantom_in_caps = advertised - registered
    assert not missing_from_caps, (
        f"ops registered but not advertised in capabilities: {sorted(missing_from_caps)}"
    )
    assert not phantom_in_caps, (
        f"ops advertised in capabilities but not registered: {sorted(phantom_in_caps)}"
    )
    # Cherry-picked from FalconZip's PR #33 (converged on the same #32 fix).
    # Their PR asserted registry INSERTION order; our derivation sorts the ops
    # alphabetically (also deterministic, more diff-friendly), so we guard our
    # deterministic order here, and check the summary path exposes the same set.
    assert result["ops_supported"] == sorted(handlers), (
        "ops_supported must be the full registry in a deterministic (sorted) order"
    )
    summary = await handlers["capabilities"]({"detail": "summary"})
    assert set(summary["ops_supported"]) == set(handlers), (
        "summary capabilities must expose the same operation contract"
    )


@pytest.mark.asyncio
async def test_capabilities_advertises_mutating_ops() -> None:
    """Explicit check that the five r/rw mutating ops are discoverable
    via capabilities (not just executable)."""
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["capabilities"]({})
    for op in ("move", "copy", "delete", "chmod", "chown"):
        assert op in result["ops_supported"], f"{op!r} missing from ops_supported"


@pytest.mark.asyncio
async def test_help_progressive_index_is_bounded() -> None:
    p = Policy.from_dict(
        {
            "allowed_commands": ["ls", "cat"],
            "playbooks": {
                "demo": {
                    "description": "Demo workflow",
                    "steps": ["do one thing", "do another thing"],
                }
            },
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["help"]({"topic": "index"})
    assert "topics" in result
    assert "security" in result["topics"]
    assert result["playbooks"]["names"] == ["demo"]
    assert result["playbooks"]["total"] == 1
    assert result["playbooks"]["truncated"] is False
    assert result["next"]["topic"] == {
        "backend_operation": "help",
        "payload": {"topic": "security"},
    }
    assert "security_model" not in result
    assert "navigation" not in result
    assert "resources" not in result


@pytest.mark.asyncio
async def test_help_progressive_index_paginates_large_playbook_sets() -> None:
    p = Policy.from_dict(
        {"playbooks": {f"playbook_{i:04d}": {"description": f"workflow {i}"} for i in range(250)}}
    )
    handlers = build_registry(policy=p)
    first = await handlers["help"]({"topic": "index"})
    assert len(first["playbooks"]["names"]) == 50
    assert first["playbooks"]["total"] == 250
    assert first["playbooks"]["next_offset"] == 50
    assert first["playbooks"]["truncated"] is True
    assert first["next"]["next_page"] == {
        "backend_operation": "help",
        "payload": {"topic": "index", "offset": 50, "limit": 50},
    }

    second = await handlers["help"]({"topic": "playbooks", "offset": 50, "limit": 25})
    assert second["playbooks"]["names"][0] == "playbook_0050"
    assert len(second["playbooks"]["names"]) == 25
    assert second["playbooks"]["next_offset"] == 75
    assert second["next"]["next_page"] == {
        "backend_operation": "help",
        "payload": {"topic": "playbooks", "offset": 75, "limit": 25},
    }


@pytest.mark.asyncio
async def test_help_progressive_topic_returns_only_requested_section() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["help"]({"topic": "security"})
    assert result["topic"] == "security"
    assert "security_model" in result
    assert "navigation" not in result
    assert "resources" not in result


@pytest.mark.asyncio
async def test_help_progressive_single_playbook_lookup_extracts_surface_hints() -> None:
    p = Policy.from_dict(
        {
            "playbooks": {
                "demo": {
                    "description": "Demo workflow",
                    "steps": [
                        "Inspect with sentinel_read, then run sentinel_exec if needed.",
                        "Verify with sentinel_capabilities.",
                    ],
                }
            }
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["help"]({"playbook": "demo"})
    assert result["playbook"] == "demo"
    assert result["definition"]["steps"][0].startswith("Inspect with op:read")
    assert result["presentation"]["tool_reference_map"] == {
        "sentinel_capabilities": "capabilities",
        "sentinel_exec": "exec",
        "sentinel_read": "read",
    }


@pytest.mark.asyncio
async def test_progressive_playbook_is_neutral_but_legacy_capabilities_keep_source_text() -> None:
    p = Policy.from_dict(
        {"playbooks": {"demo": {"steps": ["Run sentinel_exec then sentinel_service."]}}}
    )
    handlers = build_registry(policy=p)
    narrow = await handlers["help"]({"playbook": "demo"})
    full = await handlers["capabilities"]({})
    assert narrow["definition"]["steps"] == ["Run op:exec then op:service."]
    assert full["playbooks"]["demo"]["steps"] == ["Run sentinel_exec then sentinel_service."]


@pytest.mark.asyncio
async def test_help_empty_payload_preserves_legacy_full_response() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["help"]({})
    assert "security_model" in result
    assert "navigation" in result
    assert "resources" in result
    assert "introspection" not in result


@pytest.mark.asyncio
async def test_help_dotted_path_returns_exact_leaf() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["help"]({"path": "security_model.permission_errors"})
    assert result["path"] == "security_model.permission_errors"
    assert isinstance(result["value"], str)
    assert "permission_denied" in result["value"]
    assert "navigation" not in result


@pytest.mark.asyncio
async def test_help_playbook_subpath_can_page_steps() -> None:
    p = Policy.from_dict(
        {
            "playbooks": {
                "demo": {
                    "description": "Demo",
                    "steps": [f"step {i} uses sentinel_exec" for i in range(12)],
                    "notes": ["note"],
                }
            }
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["help"]({"playbook": "demo", "path": "steps", "offset": 3, "limit": 4})
    assert result["value"] == [
        "step 3 uses op:exec",
        "step 4 uses op:exec",
        "step 5 uses op:exec",
        "step 6 uses op:exec",
    ]
    assert result["pagination"]["next_offset"] == 7
    assert result["presentation"]["tool_reference_map"] == {"sentinel_exec": "exec"}
    assert result["next"] == {
        "backend_operation": "help",
        "payload": {"playbook": "demo", "path": "steps", "offset": 7, "limit": 4},
    }


@pytest.mark.asyncio
async def test_help_dotted_path_rejects_unknown_and_non_mapping_descent() -> None:
    handlers = build_registry(policy=Policy.empty())
    for path in ("security_model.nope", "getting_started.child", ".security_model"):
        with pytest.raises(HandlerError) as exc:
            await handlers["help"]({"path": path})
        assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_help_progressive_rejects_bad_queries() -> None:
    handlers = build_registry(policy=Policy.empty())
    bad_payloads = [
        {"topic": "security", "playbook": "x"},
        {"topic": "security", "path": "security_model.sudo"},
        {"topic": "does-not-exist"},
        {"path": "security_model.sudo", "limit": 2},
        {"surprise": True},
        {"limit": 10},
        {"topic": "security", "limit": 10},
        {"playbook": "x", "offset": 0},
        {"topic": "index", "limit": 0},
        {"topic": "index", "limit": 101},
        {"topic": "index", "offset": -1},
        {"topic": "index", "limit": True},
    ]
    for payload in bad_payloads:
        with pytest.raises(HandlerError) as exc:
            await handlers["help"](payload)
        assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_help_unknown_playbook_error_is_bounded() -> None:
    p = Policy.from_dict(
        {"playbooks": {f"playbook_{i:04d}": {"description": "x"} for i in range(500)}}
    )
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["help"]({"playbook": "missing"})
    details = exc.value.details
    assert details["available_playbooks"]["total"] == 500
    assert len(details["available_playbooks"]["names"]) == 50
    assert details["available_playbooks"]["truncated"] is True


@pytest.mark.asyncio
async def test_capabilities_summary_omits_policy_and_playbook_bodies() -> None:
    p = Policy.from_dict(
        {
            "allowed_commands": ["ls", "cat"],
            "services": {"nginx": {"actions": ["status"]}},
            "playbooks": {"demo": {"description": "Demo", "steps": ["large body"]}},
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({"detail": "summary"})
    assert result["policy_summary"]["allowed_commands"] == 2
    assert result["policy_summary"]["services"] == 1
    assert result["policy_summary"]["playbooks"] == 1
    assert "playbooks" not in result
    assert "allowed_commands" not in result
    assert "services" not in result
    assert "locations" not in result
    assert result["next"]["playbook"] == {
        "backend_operation": "help",
        "payload": {"playbook": "<name>"},
    }
    assert "playbook" in result["query_contract"]["help"]
    assert result["query_contract"]["capabilities_detail"] == ["summary", "full"]


@pytest.mark.asyncio
async def test_capabilities_summary_size_does_not_scale_with_playbook_bodies() -> None:
    p = Policy.from_dict(
        {
            "playbooks": {
                f"playbook_{i:04d}": {"description": "x" * 1000, "steps": ["y" * 4000]}
                for i in range(500)
            }
        }
    )
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({"detail": "summary"})
    assert result["policy_summary"]["playbooks"] == 500
    assert "playbooks" not in result


@pytest.mark.asyncio
async def test_capabilities_rejects_bad_projection_queries() -> None:
    handlers = build_registry(policy=Policy.empty())
    for payload in ({"detail": ""}, {"detail": "tiny"}, {"detail": 1}, {"detail": True}, {"x": 1}):
        with pytest.raises(HandlerError) as exc:
            await handlers["capabilities"](payload)
        assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_capabilities_default_stays_full_for_compatibility() -> None:
    p = Policy.from_dict({"allowed_commands": ["ls"]})
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    assert result["allowed_commands"] == ["ls"]
    assert "file_ops" in result
    assert "introspection" not in result


@pytest.mark.asyncio
async def test_capabilities_advertises_transfer_and_snapshot_ops() -> None:
    """Regression for #32 (cherry-picked from PR #33): the file_export_* and
    project_snapshot ops registered later stay discoverable via capabilities."""
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["capabilities"]({})
    for op in (
        "file_export_init",
        "file_export_chunk",
        "file_export_complete",
        "project_snapshot",
    ):
        assert op in result["ops_supported"], f"{op!r} missing from ops_supported"
