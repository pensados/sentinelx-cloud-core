"""On Windows, restarting another service or task must not kill the agent.

The hardened restarts kill the agent's own process tree (or its service
wrapper's): they are for restarting the agent itself, named "SentinelX" by
install.ps1. Until 0.23.25 every Scheduled-Task restart used them, so restarting
Desktop Commander disconnected SentinelX (sxrep_7AJZFT1VGEG5).
"""

from __future__ import annotations

import pytest

from sentinelx_core.handlers import service as S
from sentinelx_core.policy import Policy, ServiceSpec


def _policy(unit, backend):
    return Policy(services={"svc": ServiceSpec(unit=unit, actions=("restart",),
                                               requires_sudo=False, backend=backend)})


@pytest.fixture
def win(monkeypatch):
    calls = {"hard_task": [], "hard_service": [], "shell": []}

    async def hard_task(name):
        calls["hard_task"].append(name); return {"ok": True}

    async def hard_service(name):
        calls["hard_service"].append(name); return {"ok": True}

    async def shell(cmd, timeout=30.0, env=None):
        calls["shell"].append(cmd); return {"ok": True, "returncode": 0}

    monkeypatch.setattr(S, "_windows_task_restart", hard_task)
    monkeypatch.setattr(S, "_windows_service_restart", hard_service)
    monkeypatch.setattr(S, "run_shell_split", shell)
    monkeypatch.setattr(S.sys, "platform", "win32")
    return calls


async def _restart(policy):
    return await S.make_service_handler(policy)({"service": "svc", "action": "restart"})


async def test_another_task_restarts_without_touching_the_agent(win):
    await _restart(_policy("Desktop Commander", "task"))
    assert win["hard_task"] == []
    assert len(win["shell"]) == 1
    assert "schtasks /End" in win["shell"][0] and "taskkill" not in win["shell"][0]


async def test_the_agents_own_task_uses_the_hardened_restart(win):
    await _restart(_policy("SentinelX", "task"))
    assert win["hard_task"] == ["SentinelX"] and win["shell"] == []


async def test_another_service_restarts_without_the_tree_kill(win):
    await _restart(_policy("nginx", "service"))
    assert win["hard_service"] == [] and len(win["shell"]) == 1


@pytest.mark.parametrize("unit", ["SentinelX", "sentinelx", '"SentinelX"'])
async def test_the_agents_own_service_uses_the_hardened_restart(win, unit):
    await _restart(_policy(unit, "service"))
    assert len(win["hard_service"]) == 1 and win["shell"] == []
