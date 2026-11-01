"""help must not point an operator at operations this host has switched off.

On a deny-all host -- disabled_ops covering read/list/edit/exec/service, no
file_ops paths, no playbooks -- help(topic='operations') listed every op anyway,
and help(topic='access') recommended op:edit, op:service and playbooks that do
not exist here. It guided the operator straight into locked doors. Reported on a
Windows host where only ping/help/capabilities were live.

navigation now shows only live ops, and extending_access says plainly when the
host cannot edit its own config remotely.
"""

from __future__ import annotations

import dataclasses

from sentinelx_core.handlers.basic import make_help_handler
from sentinelx_core.policy import Policy

DENY = frozenset({"read", "list", "search", "edit", "exec", "script_run", "service", "restart"})


def _policy(**kw) -> Policy:
    return dataclasses.replace(Policy.empty(), **kw)


async def _nav(policy: Policy) -> dict:
    r = await make_help_handler(policy)({"topic": "operations"})
    return r.get("navigation", {})


async def _access(policy: Policy) -> dict:
    r = await make_help_handler(policy)({"topic": "access"})
    return r.get("extending_access", {})


async def test_deny_all_hides_disabled_ops():
    nav = await _nav(_policy(disabled_ops=DENY))
    for gone in ("edit", "exec", "script_run", "service / restart"):
        assert gone not in nav


async def test_deny_all_keeps_the_always_live_ops():
    nav = await _nav(_policy(disabled_ops=DENY))
    assert "capabilities" in nav and "state" in nav


async def test_a_normal_host_still_shows_its_ops():
    nav = await _nav(_policy(allowed_commands=("ls", "cat")))
    assert "exec" in nav
    assert "script_run" in nav


async def test_exec_hidden_without_allowed_commands():
    """exec live but no commands allowlisted -> nothing to run, so do not offer it."""
    nav = await _nav(_policy(allowed_commands=()))
    assert "exec" not in nav


async def test_read_hidden_without_paths():
    nav = await _nav(_policy(allowed_commands=("ls",)))
    assert "read / list / search" not in nav


async def test_access_note_is_honest_on_deny_all():
    ea = await _access(_policy(disabled_ops=DENY))
    note = ea.get("note", "")
    assert "cannot edit its own config remotely" in note


async def test_access_does_not_push_disabled_edit_on_deny_all():
    """The exact complaint: do not recommend op:edit where edit is off."""
    ea = await _access(_policy(disabled_ops=DENY))
    note = ea.get("note", "")
    # the note must lead with the limitation, not with "use edit"
    assert note.startswith("This host cannot edit")


async def test_a_writable_host_gets_the_normal_note():
    from sentinelx_core.policy import FileOpsPath
    pol = _policy(file_ops_paths=(FileOpsPath(path="/srv", access="rw"),),
                  allowed_commands=("ls",))
    ea = await _access(pol)
    assert "cannot edit its own config remotely" not in ea.get("note", "")
