"""local_api: the parts that hold without a socket.

The security boundary here is the action allowlist, because a socket bridge is
bounded only by whatever the far side exposes and the agent cannot enumerate
that. These tests pin the allowlist, the projection and the config validation;
the transport itself is exercised against a real Docker socket.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinelx_core.local_api import LocalApiError, _render, project
from sentinelx_core.policy import Policy


def _policy(body: str, tmp_path: Path) -> Policy:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return Policy.from_file(p)


# --- projection -----------------------------------------------------------


def test_projection_keeps_only_what_the_action_declared() -> None:
    # The measurement behind this: raw Docker JSON for "what is running" is
    # 20,340 bytes against 712 for the text it replaces. Passing it through
    # would be a regression, not a feature.
    raw = {"Names": ["/web"], "Image": "nginx", "HostConfig": {"x": 1} }
    assert project(raw, ("Names", "Image")) == {"Names": ["/web"], "Image": "nginx"}


def test_projection_reaches_into_nested_fields() -> None:
    assert project({"Config": {"Image": "nginx"}}, ("Config.Image",)) == {
        "Config.Image": "nginx"
    }


def test_projection_maps_over_a_list() -> None:
    raw = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    assert project(raw, ("a",)) == [{"a": 1}, {"a": 3}]


def test_an_empty_selection_passes_the_body_through() -> None:
    # The escape hatch for endpoints whose answers are already small.
    raw = {"anything": [1, 2, 3]}
    assert project(raw, ()) == raw


def test_a_missing_field_is_omitted_rather_than_null() -> None:
    assert project({"a": 1}, ("a", "nope")) == {"a": 1}


# --- request rendering ----------------------------------------------------


def test_placeholders_are_filled() -> None:
    assert _render("/v1.44/containers/{id}/json", {"id": "abc"}) == (
        "/v1.44/containers/abc/json"
    )


def test_values_are_url_quoted() -> None:
    # There is no shell on this path, so quoting is for the URL. A slash in a
    # value must not become another path segment.
    assert _render("/c/{id}", {"id": "a/b"}) == "/c/a%2Fb"


def test_a_missing_placeholder_is_an_error_not_an_empty_string() -> None:
    # Silently requesting /containers//json is worse than refusing.
    with pytest.raises(LocalApiError) as exc:
        _render("/v1.44/containers/{id}/json", {})
    assert exc.value.code == "missing_param"
    assert "id" in exc.value.message


# --- config validation ----------------------------------------------------


def test_an_endpoint_without_actions_is_not_registered(tmp_path: Path) -> None:
    # The allowlist IS the boundary. No list, no endpoint.
    pol = _policy(
        """
        local_apis:
          docker:
            transport: unix
            path: /var/run/docker.sock
            protocol: http
        """,
        tmp_path,
    )
    assert pol.local_apis == {}


def test_an_unknown_transport_is_refused(tmp_path: Path) -> None:
    pol = _policy(
        """
        local_apis:
          x:
            transport: telepathy
            path: /tmp/x.sock
            protocol: http
            actions: { a: { request: "GET /" } }
        """,
        tmp_path,
    )
    assert pol.local_apis == {}


def test_one_bad_action_does_not_take_the_endpoint_down(tmp_path: Path) -> None:
    pol = _policy(
        """
        local_apis:
          herdr:
            transport: unix
            path: /run/herdr.sock
            protocol: jsonrpc
            actions:
              agent.list: { method: agent.list }
              broken: { request: "GET /" }
        """,
        tmp_path,
    )
    assert sorted(pol.local_apis["herdr"].actions) == ["agent.list"]


def test_a_host_without_the_block_has_no_endpoints(tmp_path: Path) -> None:
    # This is what makes the feature additive for a fleet that did not opt in.
    assert _policy("allowed_commands: []\n", tmp_path).local_apis == {}


def test_the_compatibility_constraint_is_carried_verbatim(tmp_path: Path) -> None:
    # BOTH halves are declared: how to obtain the metadata, and which values are
    # accepted. An earlier draft of this test only declared the second half,
    # which is exactly the shape that now gets dropped, because a constraint
    # with nothing to compare against cannot be evaluated.
    pol = _policy(
        """
        local_apis:
          herdr:
            transport: unix
            path: /run/herdr.sock
            protocol: jsonrpc
            compatibility:
              probe:   { method: session.describe }
              extract: protocol
              accept:  { exact: 20 }
            actions:
              agent.list: { method: agent.list }
        """,
        tmp_path,
    )
    assert pol.local_apis["herdr"].compatibility == {
        "probe": {"method": "session.describe"},
        "extract": "protocol",
        "accept": {"exact": 20},
    }


# --- compatibility, per connection epoch (core#45) -------------------------
#
# The contract, in the requester's words: "the profile declares how to obtain
# compatibility metadata and which values it accepts; SentinelX evaluates that
# declared constraint." Both halves are declared, and SentinelX never infers
# compatibility from `new_version >= configured`.


class _FakeEndpoint:
    """Endpoint whose probe answers whatever the test wants."""

    def __init__(self, compatibility, reply, name="ep"):
        self.name = name
        self.protocol = "jsonrpc"
        self.path = "/tmp/unused.sock"
        self.timeout_s = 5
        self.compatibility = compatibility
        self.actions = {}
        self._reply = reply


@pytest.fixture(autouse=True)
def _clear_verdicts():
    from sentinelx_core import local_api

    local_api._compat_verdicts.clear()
    yield
    local_api._compat_verdicts.clear()


@pytest.fixture
def probe(monkeypatch):
    """Answer the probe without a socket, counting how often it is asked."""
    from sentinelx_core import local_api

    calls = {"n": 0}

    async def fake(endpoint, action, params):
        calls["n"] += 1
        return endpoint._reply

    monkeypatch.setattr(local_api, "call_jsonrpc", fake)
    return calls


_EXACT_20 = {
    "probe": {"method": "session.describe"},
    "extract": "protocol",
    "accept": {"exact": 20},
}


async def test_a_matching_version_passes(probe) -> None:
    from sentinelx_core.local_api import ensure_compatible

    await ensure_compatible(_FakeEndpoint(_EXACT_20, {"protocol": 20}))


async def test_a_newer_version_is_refused_not_assumed_compatible(probe) -> None:
    # The whole point. A higher number does not imply the protocol matches, and
    # assuming it would put that judgement with the wrong party.
    from sentinelx_core.local_api import LocalApiError, ensure_compatible

    with pytest.raises(LocalApiError) as exc:
        await ensure_compatible(_FakeEndpoint(_EXACT_20, {"protocol": 21}))
    assert exc.value.code == "compatibility_mismatch"


async def test_allowed_is_how_a_maintainer_widens_it(probe) -> None:
    from sentinelx_core.local_api import ensure_compatible

    constraint = dict(_EXACT_20, accept={"allowed": [20, 21]})
    await ensure_compatible(_FakeEndpoint(constraint, {"protocol": 21}))


async def test_an_unreported_version_fails_closed(probe) -> None:
    # Refusing beats assuming: an endpoint that will not say what it speaks has
    # not demonstrated anything.
    from sentinelx_core.local_api import LocalApiError, ensure_compatible

    with pytest.raises(LocalApiError) as exc:
        await ensure_compatible(_FakeEndpoint(_EXACT_20, {"name": "x"}))
    assert exc.value.code == "compatibility_unknown"


async def test_no_constraint_means_no_probe(probe) -> None:
    from sentinelx_core.local_api import ensure_compatible

    await ensure_compatible(_FakeEndpoint({}, {"protocol": 99}))
    assert probe["n"] == 0


async def test_the_probe_runs_once_per_epoch_not_once_per_call(probe) -> None:
    # The reason for caching at all: a probe before every call pays a round trip
    # for a guarantee it cannot give, since the endpoint can restart between the
    # check and the call regardless.
    from sentinelx_core.local_api import ensure_compatible

    ep = _FakeEndpoint(_EXACT_20, {"protocol": 20})
    for _ in range(4):
        await ensure_compatible(ep)
    assert probe["n"] == 1


async def test_a_failure_is_remembered_too(probe) -> None:
    # Otherwise a mismatched endpoint gets re-probed on every single call.
    from sentinelx_core.local_api import LocalApiError, ensure_compatible

    ep = _FakeEndpoint(_EXACT_20, {"protocol": 21})
    for _ in range(3):
        with pytest.raises(LocalApiError):
            await ensure_compatible(ep)
    assert probe["n"] == 1


async def test_losing_the_endpoint_ends_the_epoch(probe) -> None:
    # The case a naive cache gets wrong: the endpoint comes back as a different
    # version and inherits the old verdict.
    from sentinelx_core.local_api import (
        ensure_compatible,
        forget_compatibility,
        LocalApiError,
    )

    ep = _FakeEndpoint(_EXACT_20, {"protocol": 20})
    await ensure_compatible(ep)

    forget_compatibility(ep.name)          # what an unreachable endpoint triggers
    ep._reply = {"protocol": 99}           # it restarts speaking something else

    with pytest.raises(LocalApiError) as exc:
        await ensure_compatible(ep)
    assert exc.value.code == "compatibility_mismatch"


def test_a_half_written_constraint_is_dropped_not_half_enforced(tmp_path) -> None:
    # A constraint that silently does nothing is worse than no constraint: it
    # reads as protection that is not there.
    pol = _policy(
        """
        local_apis:
          x:
            transport: unix
            path: /tmp/x.sock
            protocol: jsonrpc
            compatibility:
              accept: { exact: 20 }
            actions:
              a: { method: a }
        """,
        tmp_path,
    )
    assert pol.local_apis["x"].compatibility == {}


# --- run_as: reaching a socket owned by another Unix user ------------------
#
# Raised by @codxt in core#45: the field parsed and was never applied, so a
# 0600 socket owned by another user stayed unreachable while the config said
# otherwise. Measured against a real socket that checks peer credentials: as
# the agent user EACCES, as ROOT it connects but reports peer_uid=0, and only a
# connect performed as the target user reports the owner's uid. Running the
# agent as root is therefore not a fix.


def _endpoint_with_run_as(user="userx"):
    from sentinelx_core.policy import LocalApiAction, LocalApiEndpoint

    return LocalApiEndpoint(
        name="ep", transport="unix", path="/run/user/1002/x.sock",
        protocol="jsonrpc", run_as=user, timeout_s=5,
        actions={"a": LocalApiAction(method="a")},
    )


def test_the_relay_command_becomes_that_user_and_nothing_else() -> None:
    # The relay is the piece that runs under sudo, so what it is invoked with
    # is the security surface. It takes a path and a timeout: no shell, no
    # config, no arbitrary argv.
    from sentinelx_core.local_api import _relay_command

    cmd = _relay_command(_endpoint_with_run_as())
    assert cmd[:4] == ["sudo", "-n", "-u", "userx"]
    assert "-m" in cmd and "sentinelx_core.local_api_relay" in cmd
    assert cmd[-2] == "/run/user/1002/x.sock"
    assert float(cmd[-1]) == 5.0
    assert not any(";" in part or "&&" in part for part in cmd)


@pytest.mark.asyncio
async def test_a_refused_sudo_names_the_sudoers_line(monkeypatch) -> None:
    # The operator's next action is a specific sudoers rule, so the error says
    # which one rather than reporting a generic permission failure.
    from sentinelx_core import local_api as _la
    from sentinelx_core.executor_engine import ProcResult
    from sentinelx_core.local_api import LocalApiError, _call_via_run_as

    async def fake(argv, **kw):
        return ProcResult(1, b"", b"sudo: a password is required")

    monkeypatch.setattr(_la, "run_process", fake)
    with pytest.raises(LocalApiError) as exc:
        await _call_via_run_as(_endpoint_with_run_as(), b"{}\n")
    assert exc.value.code == "run_as_not_permitted"
    assert "NOPASSWD" in exc.value.message
    assert "userx" in exc.value.message


@pytest.mark.asyncio
async def test_a_refused_sudo_is_not_reported_as_a_version_problem(
    monkeypatch, probe
) -> None:
    # The compatibility probe runs first, so without an explicit pass-through
    # the operator is told their endpoint has a version problem when what they
    # need is a sudoers line.
    from sentinelx_core import local_api
    from sentinelx_core.local_api import LocalApiError, ensure_compatible

    async def refuse(endpoint, action, params):
        raise LocalApiError("run_as_not_permitted", "nope")

    monkeypatch.setattr(local_api, "call_jsonrpc", refuse)
    ep = _FakeEndpoint(_EXACT_20, {"protocol": 20})
    with pytest.raises(LocalApiError) as exc:
        await ensure_compatible(ep)
    assert exc.value.code == "run_as_not_permitted"


def test_the_jsonrpc_id_is_a_string() -> None:
    # 2.0 permits either, but a receiver may declare it as a string in its own
    # schema, and a string satisfies both.
    import inspect

    from sentinelx_core import local_api

    src = inspect.getsource(local_api.call_jsonrpc)
    assert '"id": f"sentinel-local-api-' in src


def test_local_apis_is_a_recognised_top_level_key(tmp_path, caplog) -> None:
    # It shipped parsed and working while policy_unknown_keys told the operator
    # the block was unrecognised, so a correct config warned about itself.
    # Reported twice from a real deployment before it was noticed here.
    import logging

    with caplog.at_level(logging.WARNING):
        _policy(
            """
            allowed_commands: ["echo"]
            local_apis:
              x:
                transport: unix
                path: /tmp/x.sock
                protocol: jsonrpc
                actions:
                  a: { method: a }
            """,
            tmp_path,
        )
    unknown = [r for r in caplog.records if "policy_unknown_keys" in r.getMessage()]
    assert not unknown, "a valid local_apis block must not warn about itself"


# --- declared parameter schemas (core#45) ----------------------------------
#
# describe returned an empty parameter list for EVERY JSON-RPC action: the
# derivation reads {placeholders} out of an HTTP request template, and a
# JSON-RPC action has a method and no template. A deployment with sixty such
# actions therefore learned nothing from describe beyond their names.
#
# Declared rather than probed because a probe cannot be the baseline: Herdr's
# schema is only reachable through its CLI (verified against 0.9.0 / protocol
# 22) and Docker has no introspection at all.


async def _describe(pol, endpoint):
    from sentinelx_core.handlers import build_registry

    return await build_registry(policy=pol)["local_api"](
        {"operation": "describe", "endpoint": endpoint}
    )


_HERDR = """
local_apis:
  herdr:
    transport: unix
    path: /tmp/h.sock
    protocol: jsonrpc
    actions:
      agent.wait:
        method: agent.wait
        params:
          type: object
          required: [target]
          properties:
            target: { type: string }
            until:
              type: array
              items:
                enum: [idle, done, blocked]
            timeout_ms:
              type: [integer, "null"]
      agent.list:
        method: agent.list
"""


async def test_a_declared_schema_gives_jsonrpc_actions_parameter_names(
    tmp_path,
) -> None:
    # The original complaint: this list was empty for every JSON-RPC action.
    d = await _describe(_policy(_HERDR, tmp_path), "herdr")
    assert d["actions"]["agent.wait"]["params"] == ["target", "timeout_ms", "until"]


async def test_required_parameters_come_first(tmp_path) -> None:
    d = await _describe(_policy(_HERDR, tmp_path), "herdr")
    assert d["actions"]["agent.wait"]["params"][0] == "target"


async def test_the_schema_is_carried_verbatim(tmp_path) -> None:
    # The agent does not interpret it: nesting, arrays and enums are the
    # endpoint's business, and rewriting them here would be a second place for
    # the truth to live.
    d = await _describe(_policy(_HERDR, tmp_path), "herdr")
    schema = d["actions"]["agent.wait"]["params_schema"]
    assert schema["required"] == ["target"]
    assert schema["properties"]["until"]["items"]["enum"] == [
        "idle", "done", "blocked",
    ]
    assert schema["properties"]["timeout_ms"]["type"] == ["integer", "null"]


async def test_an_undeclared_action_omits_the_schema_rather_than_nulling_it(
    tmp_path,
) -> None:
    # Absence means something; a null would not.
    d = await _describe(_policy(_HERDR, tmp_path), "herdr")
    assert "params_schema" not in d["actions"]["agent.list"]


async def test_http_actions_still_derive_from_the_template(tmp_path) -> None:
    # Nothing to declare there, and the template cannot drift from what runs.
    pol = _policy(
        """
        local_apis:
          docker:
            transport: unix
            path: /var/run/docker.sock
            protocol: http
            actions:
              inspect: { request: "GET /v1.44/containers/{id}/json" }
        """,
        tmp_path,
    )
    d = await _describe(pol, "docker")
    assert d["actions"]["inspect"]["params"] == ["id"]


def test_a_non_mapping_schema_is_ignored_not_carried(tmp_path) -> None:
    pol = _policy(
        """
        local_apis:
          x:
            transport: unix
            path: /tmp/x.sock
            protocol: jsonrpc
            actions:
              a:
                method: a
                params: "not a schema"
        """,
        tmp_path,
    )
    assert pol.local_apis["x"].actions["a"].params_schema is None
