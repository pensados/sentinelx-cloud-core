"""An operator can switch an op off, and it disappears rather than refusing.

allowed_commands gates `exec` and only `exec` -- that is what its own heading
says. script_run runs a script body through an interpreter and was never bound
by it. Reasonable operators read an empty allowlist as "this host executes
nothing" and were surprised; two reported it independently, one after a
governance audit on a Windows host where the service runs as LocalSystem. Being
documented did not make the surprise unreasonable, and there was no supported
way to say no.

Removal from the registry rather than a guard inside each handler is the whole
design: capabilities derives ops_supported from those keys and dispatch answers
unsupported_op for anything absent, so one deletion makes an op both invisible
and unreachable. These tests hold that property.
"""

from __future__ import annotations

import dataclasses


from sentinelx_core.handlers import UNDISABLEABLE_OPS, build_registry
from sentinelx_core.policy import Policy


def _policy(**kw) -> Policy:
    return dataclasses.replace(Policy.empty(), **kw)


def test_nothing_disabled_changes_nothing():
    assert set(build_registry(policy=_policy())) == set(
        build_registry(policy=_policy(disabled_ops=frozenset()))
    )


def test_a_disabled_op_is_gone_from_the_registry():
    reg = build_registry(policy=_policy(disabled_ops=frozenset({"script_run"})))
    assert "script_run" not in reg


def test_only_the_named_op_is_removed():
    base = set(build_registry(policy=_policy()))
    reg = set(build_registry(policy=_policy(disabled_ops=frozenset({"script_run"}))))
    assert base - reg == {"script_run"}


def test_several_ops_can_be_disabled_at_once():
    off = frozenset({"script_run", "exec", "edit"})
    reg = build_registry(policy=_policy(disabled_ops=off))
    assert not (off & set(reg))


def test_the_core_ops_cannot_be_switched_off():
    """An agent that cannot say what it is still holds a slot and looks alive."""
    reg = build_registry(policy=_policy(disabled_ops=UNDISABLEABLE_OPS))
    for op in UNDISABLEABLE_OPS:
        assert op in reg, f"{op} must not be removable"


def test_core_protection_does_not_block_the_rest_of_the_list():
    """A list mixing a protected op with a real one still disables the real one."""
    reg = build_registry(policy=_policy(disabled_ops=frozenset({"ping", "script_run"})))
    assert "ping" in reg
    assert "script_run" not in reg


def test_an_unknown_op_name_is_harmless():
    """A typo must not take a real op with it, nor raise."""
    base = set(build_registry(policy=_policy()))
    reg = set(build_registry(policy=_policy(disabled_ops=frozenset({"scriptrun"}))))
    assert reg == base


def test_capabilities_stops_advertising_a_disabled_op():
    """The property that makes removal sufficient: advertisement is derived."""
    reg = build_registry(policy=_policy(disabled_ops=frozenset({"script_run"})))
    assert "script_run" not in sorted(reg.keys())


async def test_dispatch_answers_unsupported_op_for_a_disabled_op(tmp_path):
    """And the other half: unreachable, not merely unadvertised."""
    from sentinelx_core.executor import Executor
    from sentinelx_protocol import RequestMessage

    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: [echo]\ndisabled_ops: [script_run]\n")
    ex = Executor(config_path=cfg)

    res = await ex.dispatch(
        RequestMessage(id="r1", op="script_run", payload={"content": "echo hi"})
    )
    assert res["ok"] is False
    assert res["error"]["code"] == "unsupported_op"


def test_it_is_read_from_the_config_file(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: []\ndisabled_ops: [script_run, exec]\n")
    p = Policy.from_file(cfg)
    assert p.disabled_ops == frozenset({"script_run", "exec"})


def test_blank_entries_are_ignored(tmp_path):
    """An empty list item must not become an op named the empty string."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: []\ndisabled_ops: ['', '  ', script_run]\n")
    assert Policy.from_file(cfg).disabled_ops == frozenset({"script_run"})


def test_a_missing_key_means_nothing_disabled(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: [echo]\n")
    assert Policy.from_file(cfg).disabled_ops == frozenset()


def test_the_key_is_not_reported_as_unknown(tmp_path, caplog):
    """A valid config must not warn about itself -- local_apis did once."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: []\ndisabled_ops: [script_run]\n")
    with caplog.at_level("WARNING"):
        Policy.from_file(cfg)
    assert "disabled_ops" not in caplog.text
