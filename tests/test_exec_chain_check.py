"""Every command in an exec chain must be allowed, by default (GHSA-r2h3-76g7-m95x).

Before: allowed_commands matched the whole string by prefix and exec_strict was off,
so with `ls` allowed, `ls; id`, `ls $(id)`, `lsof`, `ls<newline>id` and `ls && id`
all ran. Now the allowlist matches whole words, and each segment of a chain (and the
inside of every substitution) is checked, while chains built from allowed commands,
read-only filters after a pipe, here-doc data and arithmetic keep working.
"""

from __future__ import annotations

import sys

import pytest

from sentinelx_core.policy import Policy
from sentinelx_core.segment_check import UnparseableCommand, unauthorised_chain


def ok(allow, cmd):
    p = Policy(allowed_commands=tuple(allow))
    return p.is_command_allowed(cmd) and unauthorised_chain(p, cmd) is None


@pytest.mark.parametrize("cmd", ["ls; id", "ls $(id)", "lsof -i", "ls\nid", "ls && id",
                                 "ls & id", "ls `id`", "ls || id", "ls | sh"])
def test_the_reported_vectors_are_refused(cmd):
    assert not ok(["ls"], cmd)


@pytest.mark.parametrize("allow, cmd", [
    (["ls"], "ls -la"),
    (["ls"], "ls | head -n 3"),
    (["git"], "git status && git log -1"),
    (["echo"], "echo $((1 + 2))"),
    (["echo"], "echo $(date)"),
    (["echo"], "echo 'a; id $(id)'"),
    (["cat"], "cat <<'EOF'\n$(id)\nEOF"),
    (["python3"], "python3 - <<'EOF'\nimport os; print(os.getcwd())\nEOF"),
    (["diff", "ls"], "diff <(ls) <(ls -a)"),
    (["/opt/tools/"], "/opt/tools/run.sh --flag"),
])
def test_legitimate_chains_still_work(allow, cmd):
    assert ok(allow, cmd)


@pytest.mark.parametrize("allow, cmd", [
    (["echo"], 'echo "$(id)"'),             # double quotes still substitute
    (["echo"], "echo $(( $(id) ))"),         # a command hidden in arithmetic
    (["cat"], "cat <<EOF\n$(id)\nEOF"),      # unquoted here-doc substitutes
    (["diff", "ls"], "diff <(ls) <(id)"),    # process substitution
    (["ls"], "ls | cat /etc/shadow"),        # a filter may not open a file
])
def test_hidden_commands_are_found(allow, cmd):
    assert not ok(allow, cmd)


def test_whole_word_not_prefix():
    p = Policy(allowed_commands=("ls",))
    assert p.is_command_allowed("ls") and p.is_command_allowed("ls -la")
    assert not p.is_command_allowed("lsof") and not p.is_command_allowed("lsblk")


def test_what_cannot_be_analysed_raises():
    p = Policy(allowed_commands=("cat",))
    with pytest.raises(UnparseableCommand):
        unauthorised_chain(p, "cat <<EOF\nno terminator\n")
    with pytest.raises(UnparseableCommand):
        unauthorised_chain(p, "cat $(echo x")


async def test_the_exec_handler_refuses_a_chain_and_names_the_command(monkeypatch):
    from sentinelx_core.executor import HandlerError
    from sentinelx_core.handlers import exec as ex
    monkeypatch.setattr(ex.sys, "platform", "linux")
    handler = ex.make_exec_handler(Policy(allowed_commands=("ls",)))
    with pytest.raises(HandlerError) as e:
        await handler({"command": "ls -la; id"})
    assert e.value.code == "command_not_allowed" and "`id`" in str(e.value)
    assert e.value.details["missing_command"] == "id"


async def test_windows_keeps_only_the_whole_word_check(monkeypatch):
    from sentinelx_core.handlers import exec as ex
    monkeypatch.setattr(ex.sys, "platform", "win32")
    seen = {}

    async def fake_run(cmd, timeout):
        seen["cmd"] = cmd
        return {"output": "", "returncode": 0}

    monkeypatch.setattr(ex, "run_shell", fake_run)
    handler = ex.make_exec_handler(Policy(allowed_commands=("Get-Process",)))
    await handler({"command": "Get-Process | Select-Object -First 3"})
    assert seen["cmd"].startswith("Get-Process")
