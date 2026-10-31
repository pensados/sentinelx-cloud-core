"""An unusable cwd is named, not surfaced as internal_error.

Without sudo, the parent process chdirs into `cwd` as the agent's own user
before the script exists. A directory that user cannot enter raised a bare
PermissionError, reported as "internal_error: [Errno 13]" -- which reads like an
agent defect. Reported by an operator who had declared the path rw in policy and
could not see why it failed; rw in file_ops does not grant Unix access, and the
error now says so.

The sudo=true variant of the same report was already fixed in 0.12.2 (the
chdir happens after elevation). These tests pin the no-sudo side.
"""

from __future__ import annotations

import dataclasses
import os

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import script as script_mod
from sentinelx_core.handlers.script import make_script_run_handler
from sentinelx_core.policy import FileOpsPath, Policy


@pytest.fixture
def handler(tmp_path):
    pol = dataclasses.replace(
        Policy.empty(), file_ops_paths=(FileOpsPath(path=str(tmp_path), access="rw"),)
    )
    return make_script_run_handler(pol, tmp_path / "uploads"), tmp_path


@pytest.mark.skipif(os.geteuid() == 0, reason="root enters any directory")
async def test_inaccessible_cwd_is_permission_denied(handler):
    h, root = handler
    locked = root / "locked"
    locked.mkdir()
    os.chmod(locked, 0o000)
    try:
        with pytest.raises(HandlerError) as e:
            await h({"interpreter": "bash", "content": "echo hi", "cwd": str(locked)})
        assert e.value.code == "permission_denied"
        assert "sudo=true" in str(e.value)
    finally:
        os.chmod(locked, 0o755)


async def test_missing_cwd_is_not_found(handler):
    h, root = handler
    with pytest.raises(HandlerError) as e:
        await h({"interpreter": "bash", "content": "echo hi", "cwd": str(root / "nope")})
    assert e.value.code == "not_found"


async def test_accessible_cwd_still_runs(handler):
    h, root = handler
    r = await h({"interpreter": "bash", "content": "pwd", "cwd": str(root)})
    assert r["ok"] is True
    assert str(root) in r["output"]


async def test_a_missing_interpreter_is_not_mistaken_for_the_cwd(handler, monkeypatch):
    """FileNotFoundError can also mean the interpreter binary is absent. That
    must keep its own meaning rather than be reported as 'cwd does not exist'."""
    h, root = handler

    async def _boom(*argv, **kw):
        raise FileNotFoundError(2, "No such file or directory", "/usr/bin/nonexistent")

    monkeypatch.setattr(script_mod.asyncio, "create_subprocess_exec", _boom)
    with pytest.raises(Exception) as e:
        await h({"interpreter": "bash", "content": "echo hi", "cwd": str(root)})
    assert not (isinstance(e.value, HandlerError) and e.value.code == "not_found")
