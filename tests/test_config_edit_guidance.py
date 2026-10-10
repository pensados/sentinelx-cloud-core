"""How to change the agent's own config: guidance that works on THIS host.

sxrep_092628RDH38B: service_not_allowed (and exec's 'not in allowlist') told the
assistant to "call sentinel_edit on /etc/sentinelx/config.yaml with sudo=true",
but since 0.11.18 edit refuses a path that isn't under an rw file_ops path, even
with sudo, which is the default Linux install: the assistant followed the steps
and got path_not_allowed. And the reload step named 'sentinel_service
action=restart', a retired tool.
"""

from __future__ import annotations

import pytest

from sentinelx_core import platform_guidance as _pg
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry


@pytest.fixture(autouse=True)
def restore_guidance():
    saved = (_pg.CONFIG_PATH, _pg.CONFIG_WRITABLE, _pg.BACKEND)
    yield
    _pg.CONFIG_PATH, _pg.CONFIG_WRITABLE, _pg.BACKEND = saved


def _agent(tmp_path, *, config_rw: bool):
    etc = tmp_path / "etc"; etc.mkdir()
    work = tmp_path / "work"; work.mkdir()
    cfg = etc / "config.yaml"
    paths = f"    - path: {work}\n      access: rw\n"
    if config_rw:
        paths += f"    - path: {etc}\n      access: rw\n"
    cfg.write_text("allowed_commands: [ls]\nservices:\n  nginx:\n    actions: [status]\n"
                   f"file_ops:\n  paths:\n{paths}")
    return build_registry(cfg), cfg


async def _message(registry, op, payload) -> str:
    with pytest.raises(HandlerError) as exc:
        await registry[op](payload)
    return str(exc.value)


async def test_default_install_does_not_send_the_assistant_to_an_edit_that_fails(tmp_path):
    reg, cfg = _agent(tmp_path, config_rw=False)
    assert _pg.CONFIG_WRITABLE is False
    msg = await _message(reg, "service", {"service": "ps-factory", "action": "status"})
    assert "ask the operator to edit" in msg and str(cfg) in msg
    assert "call sentinel_edit" not in msg and "isn't under an rw file_ops path" in msg


async def test_exec_not_allowed_says_the_same(tmp_path):
    reg, cfg = _agent(tmp_path, config_rw=False)
    msg = await _message(reg, "exec", {"command": "uptime"})
    assert "ask the operator to edit" in msg and "call sentinel_edit" not in msg


async def test_when_the_config_is_rw_sentinel_edit_is_still_the_way(tmp_path):
    reg, cfg = _agent(tmp_path, config_rw=True)
    assert _pg.CONFIG_WRITABLE is True
    msg = await _message(reg, "service", {"service": "ps-factory", "action": "status"})
    assert f"call sentinel_edit on {cfg}" in msg


async def test_the_reload_step_names_a_tool_that_exists(tmp_path):
    reg, cfg = _agent(tmp_path, config_rw=False)
    msg = await _message(reg, "service", {"service": "ps-factory", "action": "status"})
    assert "sentinel_restart with service=" in msg
    assert "sentinel_service action=" not in msg


def test_unknown_keeps_the_previous_guidance():
    _pg.set_config_writable(None)
    assert _pg.config_edit_step().startswith("call sentinel_edit on ")
