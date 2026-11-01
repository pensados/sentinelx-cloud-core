"""Reading a service's state must not ask for privileges it does not need.

requires_sudo is a property of the SERVICE, and operators set it because
restarting needs root. That then dragged sudo onto plain status reads too. On a
host installed with NoNewPrivileges -- our own hardened default -- sudo cannot
run at all, so asking whether a service was up failed on exactly the hosts that
had followed our security advice.

Measured on a real host as the agent's unprivileged user: status, is-active and
is-enabled return 0; restart and stop fail with "Interactive authentication
required". The split below follows that measurement, not an assumption.
"""

from __future__ import annotations

import pytest

from sentinelx_core.handlers.service import _build_systemctl

READ_ONLY = ("status", "is-active", "is-enabled")
MUTATING = ("start", "stop", "restart", "reload")


@pytest.mark.parametrize("action", READ_ONLY)
def test_read_only_never_elevates_even_when_the_service_requires_sudo(action):
    cmd = _build_systemctl(action, "eve-quota-free-worker.service", requires_sudo=True)
    assert not cmd.startswith("sudo"), f"{action} does not need root and must not ask"
    assert cmd == f"systemctl {action} eve-quota-free-worker.service"


@pytest.mark.parametrize("action", MUTATING)
def test_mutating_actions_still_elevate(action):
    cmd = _build_systemctl(action, "unit.service", requires_sudo=True)
    assert cmd.startswith("sudo "), f"{action} genuinely needs root"


@pytest.mark.parametrize("action", READ_ONLY + MUTATING)
def test_a_service_that_never_needed_sudo_still_does_not(action):
    cmd = _build_systemctl(action, "unit.service", requires_sudo=False)
    assert not cmd.startswith("sudo")


def test_the_unit_name_is_preserved_exactly():
    """Whatever the operator registered is what we address."""
    cmd = _build_systemctl("status", "eve-quota-free-worker.service", requires_sudo=True)
    assert "eve-quota-free-worker.service" in cmd
