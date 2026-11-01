"""Service and task names are quoted before they reach a command line.

They are operator-chosen and interpolated straight into PowerShell and cmd.
Unquoted, a name with a space splits into two arguments: `schtasks /End /TN My
Task` addresses "My" and passes "Task" as a stray argument. On the Windows
self-restart that matters more than usual, because the sequence is kill, end,
start -- the kill half always works and the start half is the one that
silently addresses nothing, leaving the agent down with nothing left to bring
it back. The operator loses remote access to the host precisely because the
tool they manage it with is what died.

The default install uses "SentinelX", which has no space, so this never showed
up in our own testing.
"""

from __future__ import annotations

import pytest

from sentinelx_core.handlers.service import (
    _WIN_SERVICE_ACTIONS,
    HandlerError,
    _cmd_double,
    _ps_single,
)

# --- PowerShell quoting ----------------------------------------------------

def test_a_plain_name_is_quoted():
    assert _ps_single("SentinelX") == "'SentinelX'"


def test_a_name_with_a_space_stays_one_argument():
    assert _ps_single("SentinelX Agent") == "'SentinelX Agent'"


def test_a_single_quote_is_doubled_not_dropped():
    """PowerShell's own escape. Without it the literal ends early and the rest
    of the command line is parsed as code."""
    assert _ps_single("Bob's Task") == "'Bob''s Task'"


# --- cmd.exe quoting, nested inside a PowerShell literal -------------------

def test_cmd_quoting_uses_double_quotes():
    """The outer PowerShell string is single-quoted, so the inner quoting has
    to be double or it would terminate it."""
    assert _cmd_double("SentinelX Agent") == '"SentinelX Agent"'
    assert "'" not in _cmd_double("SentinelX Agent")


def test_a_double_quote_in_the_name_is_refused_not_mangled():
    """Windows does not allow one in a task name, and guessing would produce a
    command that runs against something other than what was asked for."""
    with pytest.raises(HandlerError) as exc:
        _cmd_double('Weird"Name')
    assert exc.value.code == "invalid_service_name"


# --- the templates ---------------------------------------------------------

@pytest.mark.parametrize("action", sorted(_WIN_SERVICE_ACTIONS))
def test_every_service_action_survives_a_spaced_name(action):
    rendered = _WIN_SERVICE_ACTIONS[action].format(name=_ps_single("My Service"))
    assert "'My Service'" in rendered
    # the name must not appear bare anywhere in the rendered command
    assert " My Service" not in rendered.replace("'My Service'", "")
