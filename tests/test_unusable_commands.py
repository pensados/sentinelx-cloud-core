"""A command that cannot run must not be advertised as if it can.

An operator allowlisted an exact sudo command on a host installed with
NoNewPrivileges. The kernel guarantees sudo fails there regardless of sudoers,
but capabilities listed the command like any other, so the only way to find out
was to run it and read the error. Their own words: it should execute, or it
should not be advertised as executable.

We cannot make it execute -- the bit is the operator's security decision and
the right one. So we say so instead.
"""

from __future__ import annotations

from sentinelx_core.handlers import basic
from sentinelx_core.policy import Policy


def _policy(*commands):
    return Policy.from_dict({"allowed_commands": list(commands)})


def test_nothing_is_reported_on_an_ordinary_host(monkeypatch):
    """The common case stays silent and cheap."""
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: False)
    assert basic._unusable_commands(_policy("sudo systemctl", "echo")) == {}


def test_sudo_commands_are_flagged_under_no_new_privileges(monkeypatch):
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: True)
    out = basic._unusable_commands(_policy("sudo -n /usr/local/sbin/audit", "echo"))
    assert out["reason"] == "no_new_privileges"
    assert out["commands"] == ["sudo -n /usr/local/sbin/audit"]


def test_an_absolute_sudo_path_is_flagged_too(monkeypatch):
    """The report that prompted this used /usr/bin/sudo, not bare sudo."""
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: True)
    out = basic._unusable_commands(_policy("/usr/bin/sudo -n /usr/local/sbin/audit"))
    assert out["commands"] == ["/usr/bin/sudo -n /usr/local/sbin/audit"]


def test_non_sudo_commands_are_left_alone(monkeypatch):
    """NoNewPrivileges blocks elevation, not ordinary commands."""
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: True)
    assert basic._unusable_commands(_policy("echo", "systemctl status")) == {}


def test_a_hardened_host_with_no_sudo_entries_reports_nothing(monkeypatch):
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: True)
    assert basic._unusable_commands(_policy("echo", "ls")) == {}


def test_the_detail_says_what_to_do_instead(monkeypatch):
    """Naming the problem without a way forward just relocates the dead end."""
    monkeypatch.setattr(basic, "_no_new_privileges", lambda: True)
    out = basic._unusable_commands(_policy("sudo audit"))
    assert "service action" in out["detail"]


def test_the_probe_never_raises_on_a_system_without_the_bit(monkeypatch):
    """Windows and macOS have no /proc/self/status; the answer is just no."""
    def _boom(*a, **kw):
        raise OSError("no such file")

    monkeypatch.setattr("builtins.open", _boom)
    assert basic._no_new_privileges() is False
