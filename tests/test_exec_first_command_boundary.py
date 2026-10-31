"""`uptime; ls` must not be refused because the ';' touches `uptime` (0.23.28).

Since 0.23.22 the first command matches allowed_commands as a whole word, which
needs whitespace or the end of the string after it. On POSIX the whole string was
checked that way before the chain check, so a first command without arguments
followed directly by ; | & was refused even when every command was allowed
(found testing an Android/PRoot host). On POSIX each segment is checked on its
own; on Windows (no chain check) the whole string still is.
"""

from __future__ import annotations

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy

@pytest.fixture(autouse=True)
def _without_allowlist_prelude(monkeypatch):
    # These tests pin what the chain gate lets through and what reaches run_shell.
    # The allowlist prelude (0.23.41) is tested on its own in
    # test_exec_allowlist_prelude.py; here it would only prefix every command.
    import sentinelx_core.handlers.exec as _ex
    monkeypatch.setattr(_ex, "ALLOWLIST_PRELUDE", "")


async def _run(monkeypatch, allow, command, platform="linux", strict=False):
    from sentinelx_core.handlers import exec as ex
    seen = {}

    async def fake_run(cmd, timeout):
        seen["cmd"] = cmd
        return {"output": "", "returncode": 0}

    monkeypatch.setattr(ex, "run_shell", fake_run)
    monkeypatch.setattr(ex.sys, "platform", platform)
    await ex.make_exec_handler(Policy(allowed_commands=tuple(allow), exec_strict=strict))({"command": command})
    return seen.get("cmd")


@pytest.mark.parametrize("command", ["uptime; ls -la /tmp", "pwd&& ls", "uptime|cat", "uptime ;ls", "uptime"])
async def test_a_first_command_touching_a_separator_is_allowed(monkeypatch, command):
    assert await _run(monkeypatch, ["uptime", "ls", "pwd"], command) == command


@pytest.mark.parametrize("command", ["uptime;id", "uptime; id", "lsof -i", "ls;rm -rf /tmp/x"])
async def test_what_isnt_allowed_is_still_refused(monkeypatch, command):
    with pytest.raises(HandlerError) as e:
        await _run(monkeypatch, ["uptime", "ls"], command)
    assert e.value.code == "command_not_allowed"


async def test_the_refusal_names_the_command(monkeypatch):
    with pytest.raises(HandlerError) as e:
        await _run(monkeypatch, ["uptime"], "uptime;id")
    assert "`id`" in str(e.value)


async def test_strict_mode_also_takes_it(monkeypatch):
    assert await _run(monkeypatch, ["uptime", "ls"], "uptime; ls", strict=True) == "uptime; ls"


async def test_windows_still_checks_the_whole_string(monkeypatch):
    # No chain check on Windows: ls;rm must not pass because 'ls' is allowed.
    with pytest.raises(HandlerError):
        await _run(monkeypatch, ["ls"], "ls;rm x", platform="win32")
    assert await _run(monkeypatch, ["ls"], "ls -la", platform="win32") == "ls -la"
