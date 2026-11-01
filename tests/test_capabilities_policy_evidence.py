"""capabilities must evidence the operator's decisions, not only their effect.

ops_supported is the permitted set: a disabled op is simply not in it. But that
alone cannot tell an auditor WHY something is absent -- an old agent that never
had the op and a current one where it was deliberately turned off look
identical from outside. Requested by an operator running a governance audit who
needed to evidence the difference rather than infer it.
"""

from __future__ import annotations

import dataclasses

from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


def _policy(**kw) -> Policy:
    return dataclasses.replace(Policy.empty(), **kw)


async def _caps(policy: Policy) -> dict:
    return await build_registry(policy=policy)["capabilities"]({})


async def test_a_default_host_reports_nothing_disabled():
    caps = await _caps(_policy())
    assert caps["disabled_ops"] == []
    assert caps["exec_strict"] is False


async def test_a_disabled_op_is_named_in_capabilities():
    caps = await _caps(_policy(disabled_ops=frozenset({"script_run"})))
    assert caps["disabled_ops"] == ["script_run"]


async def test_and_is_absent_from_the_permitted_set():
    """Both halves: named as disabled, and genuinely not offered."""
    caps = await _caps(_policy(disabled_ops=frozenset({"script_run"})))
    assert "script_run" not in caps["ops_supported"]


async def test_the_two_fields_disagree_for_a_reason():
    """An auditor can tell a deliberate removal from an agent that never had it."""
    off = await _caps(_policy(disabled_ops=frozenset({"script_run"})))
    on = await _caps(_policy())
    assert "script_run" in on["ops_supported"]
    assert "script_run" not in off["ops_supported"]
    assert off["disabled_ops"] and not on["disabled_ops"]


async def test_a_name_that_matches_nothing_is_still_reported():
    """A typo in a deny list otherwise reads as protection never applied."""
    caps = await _caps(_policy(disabled_ops=frozenset({"scriptrun"})))
    assert caps["disabled_ops"] == ["scriptrun"]


async def test_strict_mode_is_visible_without_reading_config_yaml():
    caps = await _caps(_policy(exec_strict=True))
    assert caps["exec_strict"] is True


async def test_the_list_is_sorted_for_a_stable_diff():
    caps = await _caps(_policy(disabled_ops=frozenset({"git", "exec", "edit"})))
    assert caps["disabled_ops"] == ["edit", "exec", "git"]
