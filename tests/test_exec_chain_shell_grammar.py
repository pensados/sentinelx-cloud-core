"""Shell grammar words aren't commands (0.23.23).

0.23.22 checked `for`, `do`, `done`, `if`, `then`, `fi`, `{`, `}` as programs, so
loops and conditionals in an exec were refused. Found by running a customer's 30
days of exec history through the new rules before they upgraded.
"""

from __future__ import annotations

import pytest

from sentinelx_core.policy import Policy
from sentinelx_core.segment_check import UnparseableCommand, unauthorised_chain


def ok(allow, cmd):
    p = Policy(allowed_commands=tuple(allow))
    return p.is_command_allowed(cmd) and unauthorised_chain(p, cmd) is None


@pytest.mark.parametrize("allow, cmd", [
    (["cd", "bash"], 'cd /srv && set -e; for t in a.sh b.sh; do echo "=== $t ==="; bash "$t"; done'),
    (["ls"], "ls -la; if test -f x; then ls -la; else ls /tmp; fi"),
    (["ls"], "ls -la; while read x; do ls $x; done"),
    (["ls"], "ls -la; (cd /tmp && ls)"),
    (["ls"], "ls -la; { ls -a; }"),
    (["ls"], "ls -la; ! ls /x"),
    (["ls"], "ls -la || true"),
])
def test_loops_conditionals_and_groups_of_allowed_commands_pass(allow, cmd):
    assert ok(allow, cmd)


@pytest.mark.parametrize("cmd", [
    "ls -la; if true; then id; fi",
    "ls -la; for f in a b; do id; done",
    "ls -la && for f in $(id); do ls; done",
    "ls -la; (cd /tmp && id)",
    "ls -la; { ls; id; }",
    "ls -la; time id",
    "ls -la; export LD_PRELOAD=/tmp/x.so; ls",
])
def test_a_command_inside_the_grammar_is_still_checked(cmd):
    assert not ok(["ls"], cmd)


def test_case_is_refused_rather_than_guessed():
    with pytest.raises(UnparseableCommand):
        unauthorised_chain(Policy(allowed_commands=("ls",)), "ls -la; case x in a) id;; esac")
