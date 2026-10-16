"""exec_mode: allowlist (default), strict, unrestricted.

A customer with a development fleet asked to "allow shell execution under this
identity and let Linux enforce the rest" on trusted hosts instead of maintaining
an ever-growing allowed_commands (issue #57). unrestricted is that profile;
allowlist stays the default and strict is what exec_strict=True always meant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy


def _load(tmp_path: Path, body: str) -> Policy:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    return Policy.from_file(cfg)


@pytest.mark.parametrize("body, mode", [
    ("allowed_commands: [ls]\n", "allowlist"),
    ("allowed_commands: [ls]\nexec_strict: true\n", "strict"),
    ("allowed_commands: [ls]\nexec_mode: strict\n", "strict"),
    ("allowed_commands: [ls]\nexec_mode: unrestricted\n", "unrestricted"),
    ("allowed_commands: [ls]\nexec_mode: Unrestricted\n", "unrestricted"),
    ("allowed_commands: [ls]\nexec_strict: true\nexec_mode: unrestricted\n", "unrestricted"),
    ("allowed_commands: [ls]\nexec_mode: everything\n", "allowlist"),
])
def test_the_mode_is_resolved_from_config(tmp_path, body, mode):
    assert _load(tmp_path, body).effective_exec_mode == mode


async def _run(policy, command, monkeypatch):
    from sentinelx_core.handlers import exec as ex
    seen = {}

    async def fake_run(cmd, timeout):
        seen["cmd"] = cmd
        return {"output": "", "returncode": 0}

    monkeypatch.setattr(ex, "run_shell", fake_run)
    monkeypatch.setattr(ex.sys, "platform", "linux")
    await ex.make_exec_handler(policy)({"command": command})
    return seen.get("cmd")


async def test_unrestricted_runs_any_chain(tmp_path, monkeypatch):
    p = _load(tmp_path, "allowed_commands: []\nexec_mode: unrestricted\n")
    cmd = "journalctl -n 50 | grep x | awk '{print $1}' | sort | head | wc -l; id"
    assert await _run(p, cmd, monkeypatch) == cmd


async def test_allowlist_still_refuses_the_same_chain(tmp_path, monkeypatch):
    p = _load(tmp_path, "allowed_commands: [journalctl]\n")
    with pytest.raises(HandlerError):
        await _run(p, "journalctl -n 50 | awk '{print $1}'; id", monkeypatch)


def test_capabilities_say_which_mode(tmp_path):
    from sentinelx_core.handlers import basic
    p = _load(tmp_path, "allowed_commands: []\nexec_mode: unrestricted\n")
    import inspect
    src = inspect.getsource(basic)
    assert '"exec_mode": policy.effective_exec_mode' in src
    assert p.effective_exec_mode == "unrestricted"


def test_disabled_ops_still_wins(tmp_path):
    from sentinelx_core.handlers import build_registry
    p = _load(tmp_path, "allowed_commands: []\nexec_mode: unrestricted\ndisabled_ops: [exec]\n")
    assert "exec" not in build_registry(policy=p)


def test_exec_mode_is_a_known_key(tmp_path, caplog):
    _load(tmp_path, "allowed_commands: []\nexec_mode: allowlist\n")
    assert "policy_unknown_keys" not in caplog.text
