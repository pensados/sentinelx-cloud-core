"""script_run with python3 and a cwd imports modules from that cwd (agent 0.23.49).

Jan's audit #5: bash with a cwd could source ./helper.sh, but a Python script was run
by path, so sys.path[0] was the private staging directory and `import helper` failed.
"""
from __future__ import annotations

import dataclasses
import sys

import pytest

from sentinelx_core.handlers import script as S
from sentinelx_core.policy import FileOpsPath, Policy

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="python3 on PATH")


def _handler(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    pol = dataclasses.replace(Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),))
    return S.make_script_run_handler(pol, base)


async def test_a_python_script_imports_a_module_from_its_cwd(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "sx_helper_mod.py").write_text("VALUE = 42\n")
    r = await _handler(tmp_path)({
        "interpreter": "python3", "cwd": str(work), "timeout": 30,
        "content": "import sys, os, sx_helper_mod\n"
                   "print(sx_helper_mod.VALUE, __name__, sys.argv[0].endswith('.py'), os.getcwd())",
    })
    assert r["returncode"] == 0, r
    assert r["output"].strip() == f"42 __main__ True {work}", r["output"]


async def test_without_a_cwd_a_python_script_runs_as_before(tmp_path):
    r = await _handler(tmp_path)({
        "interpreter": "python3", "timeout": 30,
        "content": "import sys\nprint(__name__, sys.argv[0].endswith('.py'), __file__ == sys.argv[0])",
    })
    assert r["returncode"] == 0 and r["output"].strip() == "__main__ True True", r["output"]
