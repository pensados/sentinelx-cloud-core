"""Deny-all and narrow allowlists must not be bypassed by concession segments.

sxrep_CY0WMZK7W01F: since 0.23.28 the POSIX chain check lets a command through
when every segment is one it exempts -- cd (any position), a SAFE_BUILTINS
no-op, or a READ_ONLY_FILTERS filter after a separator. Three gaps made that
reachable with an EMPTY allowed_commands (deny-all):

  1. a filter's file-operand detection only flagged path-shaped names
     (/etc/x, ~/x), so a RELATIVE name (`cat passwd`, `base64 secret.key`) and
     a file-reading OPTION (`grep -f FILE`, `wc --files0-from=FILE`, `rg --pre`)
     slipped past;
  2. a redirection on an exempt segment (`true > f`, `echo k >> authorized_keys`)
     was never checked in the default mode, so an unauthorised-but-exempt
     command gained a write;
  3. an empty allowlist still ran a chain built only of those exemptions.

The same relative-name gap reached strict mode and, with a non-empty allowlist,
dates back to 0.23.22 (`uptime && cd /etc && cat passwd`).
"""

from __future__ import annotations

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import exec as ex
from sentinelx_core.policy import Policy
from sentinelx_core.segment_check import unauthorised_chain, unauthorised_segment


def _deny_all(strict=False):
    return Policy(allowed_commands=(), exec_strict=strict)


# --- unit: the chain check, deny-all -------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cd /etc && cat passwd",             # relative file to a filter
    "cd /etc; cat shadow",
    "true; cat .env",
    "true && grep -r password .",        # grep reads the tree (operand '.')
    "true | grep -f /etc/shadow x",      # -f reads a file of patterns
    "true | grep --file=/etc/shadow x",
    "true; wc --files0-from=/etc/x",     # option reads a file list
    "true; base64 secret.key",           # relative file to base64
    "true | rg --pre=sh x",              # rg --pre executes a program
    "true > /tmp/x",                     # redirection on a builtin
    "true; echo hi > /tmp/x",
    "cd ~/.ssh; true; echo KEY >> authorized_keys",  # write via redirection
])
def test_deny_all_refuses_the_reported_chains(cmd):
    assert unauthorised_chain(_deny_all(), cmd) is not None


@pytest.mark.parametrize("cmd", [
    "cd /etc && cat passwd",
    "true; cat .env",
    "true | grep -f /etc/shadow x",
    "true; base64 secret.key",
])
def test_strict_segment_check_refuses_relative_reads(cmd):
    # unauthorised_segment judges operands/options; strict mode's redirection
    # defence lives in the handler (file_redirection), exercised below.
    assert unauthorised_segment(_deny_all(strict=True), cmd) is not None


async def test_strict_handler_refuses_redirection_write(monkeypatch):
    # With a non-empty allowlist, strict must still refuse a write smuggled onto
    # an exempt segment via redirection.
    p = Policy(allowed_commands=("true", "echo"), exec_strict=True)
    with pytest.raises(HandlerError) as e:
        await _handle(monkeypatch, p, "echo KEY >> /home/u/.ssh/authorized_keys")
    assert e.value.code == "command_not_allowed"


def test_non_empty_allowlist_still_refuses_the_relative_file(monkeypatch):
    # The 0.23.22 variant: an allowed leading command does not license a
    # relative-named file read in a later concession segment.
    p = Policy(allowed_commands=("uptime",))
    assert unauthorised_chain(p, "uptime && cd /etc && cat passwd") is not None


def test_non_empty_allowlist_refuses_a_file_reading_option():
    # A file-reading option (grep -f FILE) in a concession filter is a file read
    # even when the leading command is allowlisted.
    p = Policy(allowed_commands=("uptime",))
    assert unauthorised_chain(p, "uptime | grep -f /etc/shadow x") is not None
    assert unauthorised_chain(p, "uptime | wc --files0-from=/etc/x") is not None


def test_non_empty_allowlist_refuses_redirection_on_a_concession_segment():
    # A write smuggled onto a cd/builtin/filter segment via redirection.
    p = Policy(allowed_commands=("uptime",))
    assert unauthorised_chain(p, "uptime; true > /tmp/x") is not None
    assert unauthorised_chain(p, "uptime; echo k >> /home/u/.bashrc") is not None


# --- unit: legitimate read-only pipelines still pass ---------------------------------

@pytest.mark.parametrize("allow, cmd", [
    (["uptime"], "uptime | grep load"),
    (["uptime"], "uptime | grep -i Load"),
    (["uptime"], "uptime | head -n 3"),
    (["uptime"], "uptime | wc -l"),
    (["uptime"], "uptime | sort | uniq -c"),
    (["uptime"], "uptime | cut -d' ' -f1 | tr a-z A-Z"),
    (["uptime"], "uptime | tail -n 5 | cat"),
    (["cat"], "cd /srv/app && cat config.yaml"),   # cat is allowlisted -> its file is fine
    (["make"], "cd /srv/app && make > build.log"),  # authorised cmd may redirect
])
def test_legitimate_pipelines_still_pass(allow, cmd):
    p = Policy(allowed_commands=tuple(allow))
    assert unauthorised_chain(p, cmd) is None


# --- handler level, real shape -------------------------------------------------------

async def _handle(monkeypatch, policy, command, platform="linux"):
    ran = []

    async def fake_run(cmd, timeout):
        ran.append(cmd)
        return {"output": "", "returncode": 0}

    monkeypatch.setattr(ex, "run_shell", fake_run)
    monkeypatch.setattr(ex.sys, "platform", platform)
    handler = ex.make_exec_handler(policy)
    await handler({"command": command})
    return ran


async def test_empty_allowlist_denies_every_command(monkeypatch):
    for cmd in ("cd /etc && cat passwd", "true", "cd /tmp", "echo hi"):
        with pytest.raises(HandlerError) as e:
            await _handle(monkeypatch, _deny_all(), cmd)
        assert e.value.code == "command_not_allowed"


async def test_empty_allowlist_runs_nothing(monkeypatch):
    with pytest.raises(HandlerError):
        await _handle(monkeypatch, _deny_all(), "cd ~/.ssh; echo KEY >> authorized_keys")


async def test_empty_allowlist_strict_also_denies(monkeypatch):
    with pytest.raises(HandlerError) as e:
        await _handle(monkeypatch, _deny_all(strict=True), "cd /etc; cat shadow")
    assert e.value.code == "command_not_allowed"
