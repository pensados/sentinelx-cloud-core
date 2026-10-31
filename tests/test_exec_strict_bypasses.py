"""exec_strict: an allowed command can't carry another one, or a file, past the check.

sxrep_4XCNXWP2A3VY (a careful code-reading report): a newline after an allowed
command passed the per-segment check, and bash ran the next line. Checking the
rest of the shell grammar the same way found more: a lone '&', process
substitution <( ) / >( ), and redirections that overwrite a file or read one
through the `cat` filter that is only allowed after a pipe so it can't open
files. These tests drive the real exec handler; nothing rejected may run.
"""

from __future__ import annotations

import dataclasses

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import exec as exec_mod
from sentinelx_core.handlers.exec import make_exec_handler
from sentinelx_core.policy import Policy

@pytest.fixture(autouse=True)
def _without_allowlist_prelude(monkeypatch):
    # These tests pin what the chain gate lets through and what reaches run_shell.
    # The allowlist prelude (0.23.41) is tested on its own in
    # test_exec_allowlist_prelude.py; here it would only prefix every command.
    import sentinelx_core.handlers.exec as _ex
    monkeypatch.setattr(_ex, "ALLOWLIST_PRELUDE", "")


def _policy(strict=True):
    return dataclasses.replace(Policy.empty(), allowed_commands=("uptime", "cd"), exec_strict=strict)


@pytest.fixture
def ran(monkeypatch):
    calls = []

    async def fake_run_shell(command, *args, **kwargs):
        calls.append(command)
        return {"output": "", "returncode": 0, "duration": 0.0}
    monkeypatch.setattr(exec_mod, "run_shell", fake_run_shell)
    return calls


@pytest.mark.parametrize("cmd", [
    "uptime\nid",                    # the report: newline is a separator to bash
    "uptime\rid",
    "uptime & id",                   # lone '&'
    "uptime &id",
    "uptime <(id)",                  # process substitution
    "uptime >(id)",
    "uptime > /tmp/x",               # overwrite a file
    "uptime >> /tmp/x",
    "uptime >| /tmp/x",
    "uptime &> /tmp/x",
    "uptime >&/tmp/x",
    "uptime 2> /tmp/x",
    "uptime | cat < /etc/shadow",    # read a file through the after-a-pipe filter
    "uptime < /etc/shadow",
])
async def test_strict_mode_refuses_and_runs_nothing(cmd, ran):
    with pytest.raises(HandlerError) as exc:
        await make_exec_handler(_policy())({"command": cmd})
    assert exc.value.code == "command_not_allowed"
    assert ran == []


@pytest.mark.parametrize("cmd, executed", [
    ("uptime", "uptime"),
    ("uptime -p", "uptime -p"),
    ("uptime\n", "uptime"),                     # a trailing newline is trimmed, then run as checked
    ("uptime 2>&1", "uptime 2>&1"),
    ("uptime 2>/dev/null", "uptime 2>/dev/null"),
    ("uptime > /dev/null", "uptime > /dev/null"),
    ("uptime &>/dev/null", "uptime &>/dev/null"),
    ("uptime >&2", "uptime >&2"),
    ("cd /srv && uptime", "cd /srv && uptime"),
    ("uptime | cat", "uptime | cat"),
    ("uptime | cat <<< hello", "uptime | cat <<< hello"),
    ("uptime 'a > b & c'", "uptime 'a > b & c'"),   # quoted operators are data
])
async def test_legitimate_commands_still_run_exactly_as_checked(cmd, executed, ran):
    await make_exec_handler(_policy())({"command": cmd})
    assert ran == [executed]


async def test_without_strict_mode_nothing_changes(ran):
    await make_exec_handler(_policy(strict=False))({"command": "uptime > /tmp/x"})
    assert ran == ["uptime > /tmp/x"]       # prefix allowlist, as documented
