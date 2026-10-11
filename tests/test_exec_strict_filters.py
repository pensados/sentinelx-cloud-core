"""exec_strict's after-a-pipe filters can't execute, write, or open a file.

Second half of sxrep_4XCNXWP2A3VY: READ_ONLY_FILTERS held sed/awk/jq/tee/sort,
which execute (awk system, sed s///e) or write (sed -i, tee, sort -o) for some
arguments, and any filter could be handed a file to read (| cat /etc/shadow).
"""

from __future__ import annotations

import dataclasses

import pytest

from sentinelx_core.handlers import exec as exec_mod
from sentinelx_core.handlers.exec import make_exec_handler
from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy
from sentinelx_core.segment_check import READ_ONLY_FILTERS, unauthorised_segment

PROBE = "uptime"


def _policy(*allowed):
    return dataclasses.replace(Policy.empty(), allowed_commands=tuple(allowed) or (PROBE,), exec_strict=True)


# --- the filter set no longer holds a writer or an executor ----------------------------

@pytest.mark.parametrize("cmd", [
    f"{PROBE} | sed -i 's/a/b/' /etc/hosts",       # sed -i writes
    f"{PROBE} | sed 's/x/id/e'",                    # sed e executes
    f"{PROBE} | awk 'BEGIN{{system(\"id\")}}'",     # awk executes
    f"{PROBE} | tee /tmp/x",                        # tee writes
    f"{PROBE} | sort -o /tmp/x",                    # sort writes
    f"{PROBE} | jq -R . /etc/shadow",              # jq reads a file
])
def test_a_side_effect_capable_filter_is_refused(cmd):
    assert unauthorised_segment(_policy(), cmd) is not None


# --- a genuine filter must not be handed a file to open --------------------------------

@pytest.mark.parametrize("cmd", [
    f"{PROBE} | cat /etc/shadow",
    f"{PROBE} | grep root /etc/passwd",
    f"{PROBE} | head -5 /etc/shadow",
    f"{PROBE} | base64 /etc/shadow",
])
def test_a_filter_with_a_file_argument_is_refused(cmd):
    assert unauthorised_segment(_policy(), cmd) is not None


# --- what still works ------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    f"{PROBE} | grep load",
    f"{PROBE} | grep -i Load",
    f"{PROBE} | grep -e up",
    f"{PROBE} | head -20",
    f"{PROBE} | wc -l",
    f"{PROBE} | sort | uniq -c",
    f"{PROBE} | cut -d' ' -f1 | tr a-z A-Z",
    f"{PROBE} | tail -n 5 | cat",
])
def test_ordinary_read_only_pipelines_still_pass(cmd):
    assert unauthorised_segment(_policy(), cmd) is None


def test_the_filter_set_holds_no_writer_or_executor():
    for bad in ("sed", "awk", "jq", "tee", "xargs", "env", "sh", "bash", "python3", "dd", "xxd"):
        assert bad not in READ_ONLY_FILTERS


@pytest.mark.parametrize("cmd", ["uptime | sort -o /tmp/x", "uptime | sort --compress-program=id"])
def test_sort_stays_a_filter_but_its_writing_options_are_refused(cmd):
    assert unauthorised_segment(_policy(), cmd) is not None


def test_plain_sort_is_still_a_filter():
    assert unauthorised_segment(_policy(), "uptime | sort | uniq") is None


def test_a_removed_filter_works_once_the_operator_allowlists_it():
    # sed is no longer a free filter, but an operator can still add it by name.
    assert unauthorised_segment(_policy(PROBE, "sed"), f"{PROBE} | sed 's/a/b/'") is None


async def test_the_handler_refuses_and_runs_nothing(monkeypatch):
    ran = []

    async def fake(cmd, *a, **k):
        ran.append(cmd); return {"output": "", "returncode": 0}
    monkeypatch.setattr(exec_mod, "run_shell", fake)
    with pytest.raises(HandlerError) as exc:
        await make_exec_handler(_policy())({"command": f"{PROBE} | tee /tmp/x"})
    assert exc.value.code == "command_not_allowed" and ran == []
