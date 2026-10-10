"""systemd USER units in `services` (sxrep_01JGTNPRKSS8).

An app that runs as its own user (~/.config/systemd/user) is managed with
`systemctl --user` against that user's manager. Checked on systemd 255: as the
same user it needs XDG_RUNTIME_DIR (else "Failed to connect to bus: No medium
found"); reaching another user's manager needs root even to read
("Permission denied"), via --machine=<user>@.host.
"""

from __future__ import annotations

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import service as svc
from sentinelx_core.handlers.basic import make_capabilities_handler
from sentinelx_core.handlers.service import _build_systemctl, make_service_handler
from sentinelx_core.policy import Policy

UIDS = {"alice": 1000, "bob": 1001}


def _policy(tmp_path, services: str) -> Policy:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("allowed_commands: []\nservices:\n" + services)
    return Policy.from_file(cfg)


@pytest.fixture
def run(monkeypatch):
    calls = []

    async def fake(cmd, timeout=30.0, env=None):
        calls.append((cmd, env))
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(svc, "run_shell_split", fake)
    monkeypatch.setattr(svc, "_user_uid", lambda u: UIDS.get(u))
    monkeypatch.setattr(svc.os, "geteuid", lambda: 1000)   # the agent runs as alice
    return calls


# --- the command -----------------------------------------------------------------

def test_own_user_needs_no_privileges():
    for action in ("status", "restart", "stop"):
        assert _build_systemctl(action, "hermes.service", True, "alice", True) == \
            f"systemctl --user {action} hermes.service"


@pytest.mark.parametrize("action", ["status", "is-active", "restart", "stop"])
def test_another_user_always_goes_through_sudo_even_to_read(action):
    assert _build_systemctl(action, "hermes.service", False, "bob", False) == \
        f"sudo systemctl --user --machine=bob@.host {action} hermes.service"


def test_system_units_are_unchanged():
    assert _build_systemctl("restart", "nginx", True) == "sudo systemctl restart nginx"
    assert _build_systemctl("status", "nginx", True) == "systemctl status nginx"


# --- through the handler -------------------------------------------------------------

async def test_own_user_unit_runs_with_the_users_runtime_dir(tmp_path, run):
    pol = _policy(tmp_path, "  hermes.service:\n    user: alice\n    actions: [status, restart]\n")
    await make_service_handler(pol)({"service": "hermes.service", "action": "restart"})
    cmd, env = run[0]
    assert cmd == "systemctl --user restart hermes.service"
    assert env == {"XDG_RUNTIME_DIR": "/run/user/1000",
                   "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}


async def test_another_users_unit_uses_sudo_and_no_extra_env(tmp_path, run):
    pol = _policy(tmp_path, "  hermes.service:\n    user: bob\n    actions: [status]\n")
    await make_service_handler(pol)({"service": "hermes.service", "action": "status"})
    assert run[0] == ("sudo systemctl --user --machine=bob@.host status hermes.service", None)


async def test_an_unknown_user_is_a_clear_error(tmp_path, run):
    pol = _policy(tmp_path, "  hermes.service:\n    user: carol\n    actions: [status]\n")
    with pytest.raises(HandlerError) as exc:
        await make_service_handler(pol)({"service": "hermes.service", "action": "status"})
    assert exc.value.code == "service_user_not_found"
    assert run == []


async def test_a_system_unit_still_runs_as_before(tmp_path, run):
    pol = _policy(tmp_path, "  nginx:\n    actions: [restart]\n")
    await make_service_handler(pol)({"service": "nginx", "action": "restart"})
    assert run[0] == ("sudo systemctl restart nginx", None)


# --- config validation ---------------------------------------------------------------

@pytest.mark.parametrize("bad", ["alice; rm -rf /", "a b", "$(id)", "-alice", "x" * 40])
def test_an_unsafe_user_drops_that_service_instead_of_running_it(tmp_path, bad):
    pol = _policy(tmp_path, f"  hermes.service:\n    user: {bad!r}\n    actions: [status]\n"
                            "  nginx:\n    actions: [status]\n")
    assert "hermes.service" not in pol.services       # skipped, not downgraded to a system unit
    assert "nginx" in pol.services                     # the rest of the policy still loads


def test_a_valid_user_is_kept(tmp_path):
    pol = _policy(tmp_path, "  hermes.service:\n    user: marcelo\n    actions: [status]\n")
    assert pol.services["hermes.service"].user == "marcelo"


# --- capabilities -----------------------------------------------------------------------

async def test_capabilities_show_the_user_only_for_user_units(tmp_path):
    pol = _policy(tmp_path, "  hermes.service:\n    user: alice\n    actions: [status]\n"
                            "  nginx:\n    actions: [status]\n")
    caps = await make_capabilities_handler(pol, None)({"detail": "full"})
    assert caps["services"]["hermes.service"]["user"] == "alice"
    assert "user" not in caps["services"]["nginx"]


# --- discoverability --------------------------------------------------------------------
# An assistant learns how to declare a service from service_not_allowed, and then
# follows it. On Linux it has to mention user units, or a user unit gets declared
# as a system one.

async def test_service_not_allowed_mentions_user_units_on_linux(tmp_path, run, monkeypatch):
    monkeypatch.setattr(svc.sys, "platform", "linux")
    pol = _policy(tmp_path, "  nginx:\n    actions: [status]\n")
    with pytest.raises(HandlerError) as exc:
        await make_service_handler(pol)({"service": "hermes-gateway.service", "action": "status"})
    assert exc.value.code == "service_not_allowed"
    assert "systemctl --user" in str(exc.value) and "user: <its owner>" in str(exc.value)


@pytest.mark.parametrize("platform", ["darwin", "win32"])
async def test_but_not_where_user_is_ignored(tmp_path, run, monkeypatch, platform):
    monkeypatch.setattr(svc.sys, "platform", platform)
    pol = _policy(tmp_path, "  nginx:\n    actions: [status]\n")
    with pytest.raises(HandlerError) as exc:
        await make_service_handler(pol)({"service": "x", "action": "status"})
    assert "systemctl --user" not in str(exc.value)
