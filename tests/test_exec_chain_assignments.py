"""Allowlist mode: what a chain assigns can't change which program runs (0.23.39).

sxrep_NBEA83P4PV36 (Jan): with only `ls` allowed, `PATH=<dir>:$PATH; ls` and
`for PATH in <dir>; do ls; done` ran an attacker's `ls`. The same class reaches
through HOME (git reads ~/.gitconfig), PS4 with set -x, and read targets.
"""
from __future__ import annotations

import dataclasses
import os
import subprocess
import sys

import pytest

from sentinelx_core.policy import Policy
from sentinelx_core.segment_check import UnparseableCommand, unauthorised_chain

def _refused(command: str) -> bool:
    """Refused either way the exec handler refuses: an offending segment, or unparseable."""
    try:
        return unauthorised_chain(POL, command) is not None
    except UnparseableCommand:
        return True


POL = dataclasses.replace(Policy.empty(), allowed_commands=("ls", "git status"), exec_mode="allowlist")

REFUSED = [
    "PATH=/tmp/x:$PATH; ls",
    "for PATH in /tmp/x; do ls; done",
    "select PATH in /tmp/x; do ls; done",
    "HOME=/tmp/x; git status",
    "for HOME in /tmp/x; do git status; done",
    "PS4='$(id)'; set -x; ls",
    "{ read PATH; ls; } <<< /tmp/x",   # already refused before 0.23.39: <<< is unparseable here
    "while read -r PATH; do ls; done",
    "read -a PATH; ls",
    "http_proxy=http://evil; git status",
    "x=1 PATH=/tmp/x; ls",
]
ALLOWED = [
    "ls",
    "for f in a b; do ls; done",
    "x=1; ls",
    "while read -r line; do ls; done",
    "read -r -p 'name? ' name; ls",
    "for i in 1 2 3; do git status; done",
]


@pytest.mark.parametrize("command", REFUSED)
def test_assigning_a_variable_that_steers_programs_is_refused(command):
    assert _refused(command), command


@pytest.mark.parametrize("command", ALLOWED)
def test_ordinary_chains_with_their_own_variables_still_pass(command):
    assert unauthorised_chain(POL, command) is None, command


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
@pytest.mark.parametrize("template", ["PATH={d}:$PATH; ls", "for PATH in {d}; do ls; done"])
def test_jans_repro_the_fake_ls_is_refused_before_it_can_run(tmp_path, template):
    fake = tmp_path / "ls"
    fake.write_text("#!/bin/sh\necho EVIL_LS\n")
    fake.chmod(0o755)
    command = template.format(d=tmp_path)
    # Without the gate, bash really runs the fake ls: that is what is being prevented.
    assert "EVIL_LS" in subprocess.run(["bash", "-c", command], capture_output=True, text=True).stdout
    assert _refused(command)
