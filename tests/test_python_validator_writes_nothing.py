"""The python validator checks a file without writing next to it.

sxrep_N318DCSMDYWE: validator_preset='python' ran py_compile on the candidate, which
sits next to the target, so Python tried to save bytecode into that directory's
__pycache__ and failed with Errno 13 where the agent can't write, rejecting a valid
edit (or left stray .pyc files where it can).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from sentinelx_core.vendored.pensa_safe_edit import build_validator_preset

pytestmark = pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0,
                                reason="needs POSIX permissions and a non-root user")


def _check(tmp_path, source: str) -> subprocess.CompletedProcess:
    d = tmp_path / "state"
    d.mkdir()
    f = d / "module.py.candidate"
    f.write_text(source)
    d.chmod(0o555)                      # like /opt/dunia-native/state: not writable
    try:
        return subprocess.run(build_validator_preset("python", f), capture_output=True, text=True)
    finally:
        d.chmod(0o755)


def test_valid_python_passes_in_a_directory_the_agent_cannot_write(tmp_path):
    r = _check(tmp_path, "def f(x):\n    return x + 1\n")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "state" / "__pycache__").exists()


@pytest.mark.parametrize("bad", ["def f(:\n    pass\n", "return 1\n", "x = (1,\n"])
def test_invalid_python_is_still_rejected(tmp_path, bad):
    r = _check(tmp_path, bad)
    assert r.returncode != 0 and "SyntaxError" in r.stderr


def test_nothing_is_written_where_writing_is_possible(tmp_path):
    f = tmp_path / "ok.py.candidate"
    f.write_text("a = 1\n")
    assert subprocess.run(build_validator_preset("python", f)).returncode == 0
    assert not (tmp_path / "__pycache__").exists()
