"""sentinel_edit's custom validator and backup_dir answer to the host's policy.

Found 2026-11-04 (sxrep_VZX9K6YFMT3K): `validator` is a command the safe edit
runs before installing the change, and nothing checked it. On a host with exec
in disabled_ops, or exec_mode strict and an empty allowed_commands, an edit with
validator="bash -c '...'" still ran it. backup_dir was not checked either, so
the copy of the previous version could land in any directory the agent's user
could write.

These tests run the real handler with the real vendored safe edit, and prove the
command ran (or did not) by the file it writes.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinelx_core
from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.handlers.edit import _check_validator
from sentinelx_core.policy import FileOpsPath, Policy

SRC = str(Path(sentinelx_core.__file__).resolve().parents[1])


@pytest.fixture
def real_safe_edit(tmp_path: Path) -> Path:
    b = tmp_path / "safe-edit"
    b.write_text(f'#!/bin/bash\nPYTHONPATH="{SRC}" exec "{sys.executable}" -m '
                 f'sentinelx_core.vendored.pensa_safe_edit "$@"\n')
    b.chmod(0o755)
    return b


def _setup(tmp_path: Path, **policy_kw) -> tuple[Policy, Path, Path]:
    rw = tmp_path / "rw"
    rw.mkdir()
    target = rw / "app.txt"
    target.write_text("old\n")
    p = Policy(file_ops_paths=(FileOpsPath(path=str(rw), access="rw"),), **policy_kw)
    up = tmp_path / "uploads"
    up.mkdir()
    object.__setattr__(p, "upload_base", up)
    return p, target, tmp_path / "marker"


def _marker_cmd(marker: Path) -> str:
    return f"bash -c 'echo ran > {marker}'"


async def _edit(policy: Policy, binary: Path, payload: dict):
    with patch("sentinelx_core.handlers.edit._resolve_safe_edit_bin", return_value=str(binary)):
        return await build_registry(policy=policy)["edit"](payload)


async def _edit_upload(policy: Policy, binary: Path, extra: dict):
    with patch("sentinelx_core.handlers.edit._resolve_safe_edit_bin", return_value=str(binary)):
        reg = build_registry(policy=policy)
        up = await reg["edit_upload_init"]({})
        await reg["edit_upload_file"]({"upload_id": up["upload_id"], "role": "new", "content": "new\n"})
        return await reg["edit_upload_complete"]({"upload_id": up["upload_id"], "mode": "write", **extra})


DENYING = [
    pytest.param(dict(disabled_ops=frozenset({"exec"}), exec_mode="unrestricted"), id="exec-disabled"),
    pytest.param(dict(exec_mode="strict", exec_strict=True), id="strict-empty-allowlist"),
    pytest.param(dict(exec_mode="allowlist", allowed_commands=("test",)), id="allowlist-without-bash"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_kw", DENYING)
async def test_custom_validator_refused_and_never_run(tmp_path, real_safe_edit, policy_kw) -> None:
    policy, target, marker = _setup(tmp_path, **policy_kw)
    with pytest.raises(HandlerError) as exc:
        await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                             "validator": _marker_cmd(marker)})
    assert exc.value.code == "validator_not_allowed"
    assert not marker.exists()
    assert target.read_text() == "old\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_kw", DENYING)
async def test_custom_validator_refused_on_the_chunked_path_too(tmp_path, real_safe_edit, policy_kw) -> None:
    policy, target, marker = _setup(tmp_path, **policy_kw)
    with pytest.raises(HandlerError) as exc:
        await _edit_upload(policy, real_safe_edit, {"path": str(target), "validator": _marker_cmd(marker)})
    assert exc.value.code == "validator_not_allowed"
    assert not marker.exists()
    assert target.read_text() == "old\n"


@pytest.mark.asyncio
async def test_validator_covered_by_allowed_commands_still_runs(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path, exec_mode="allowlist", allowed_commands=("test",))
    res = await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                               "validator": "test -s {file}"})
    assert res["ok"] is True, res
    assert target.read_text() == "new\n"


@pytest.mark.asyncio
async def test_unrestricted_host_keeps_custom_validators(tmp_path, real_safe_edit) -> None:
    policy, target, marker = _setup(tmp_path, exec_mode="unrestricted")
    res = await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                               "validator": _marker_cmd(marker)})
    assert res["ok"] is True, res
    assert marker.exists()


@pytest.mark.asyncio
async def test_presets_still_work_with_exec_disabled(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path, disabled_ops=frozenset({"exec"}), exec_mode="strict", exec_strict=True)
    res = await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": '{"a": 1}\n',
                                               "validator_preset": "json"})
    assert res["ok"] is True, res
    assert target.read_text() == '{"a": 1}\n'


@pytest.mark.asyncio
async def test_backup_dir_outside_rw_is_refused(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path)
    outside = tmp_path / "outside" / "baks"
    with pytest.raises(HandlerError) as exc:
        await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                             "backup_dir": str(outside)})
    assert exc.value.code == "path_not_allowed"
    assert not (tmp_path / "outside").exists()
    assert target.read_text() == "old\n"


@pytest.mark.asyncio
async def test_backup_dir_outside_rw_is_refused_on_the_chunked_path(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path)
    outside = tmp_path / "outside" / "baks"
    with pytest.raises(HandlerError) as exc:
        await _edit_upload(policy, real_safe_edit, {"path": str(target), "backup_dir": str(outside)})
    assert exc.value.code == "path_not_allowed"
    assert not (tmp_path / "outside").exists()
    assert target.read_text() == "old\n"


@pytest.mark.asyncio
async def test_backup_dir_inside_rw_receives_the_copy(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path)
    baks = target.parent / "baks"
    res = await _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                               "backup_dir": str(baks)})
    assert res["ok"] is True, res
    copies = list(baks.glob("app.txt.bak.*"))
    assert len(copies) == 1 and copies[0].read_text() == "old\n"


# --- sudo edits run the validator as root (sx-review on 2bf6aa9) --------------

def test_sudo_edit_checks_the_validator_as_sudo_command() -> None:
    p = Policy(exec_mode="allowlist", allowed_commands=("cat",))
    with pytest.raises(HandlerError) as exc:
        _check_validator(p, {"validator": "cat /etc/shadow /nonexistent", "sudo": True})
    assert exc.value.code == "validator_not_allowed"
    assert exc.value.details["checked_as"] == "sudo cat /etc/shadow /nonexistent"
    _check_validator(p, {"validator": "cat {file}", "sudo": False})  # not as root: allowed
    _check_validator(Policy(exec_mode="allowlist", allowed_commands=("sudo cat",)),
                     {"validator": "cat {file}", "sudo": True})


@pytest.mark.asyncio
async def test_sudo_edit_with_validator_refused_before_anything_runs(tmp_path, real_safe_edit) -> None:
    policy, target, _ = _setup(tmp_path, exec_mode="allowlist", allowed_commands=("cat",))
    # Deadline: if the check is gone the handler starts `sudo <helper>`, which may wait for a password.
    with pytest.raises(HandlerError) as exc:
        await asyncio.wait_for(
            _edit(policy, real_safe_edit, {"path": str(target), "mode": "write", "new_text": "new\n",
                                           "sudo": True, "validator": "cat /etc/shadow /nonexistent"}), 15)
    assert exc.value.code == "validator_not_allowed"
    assert target.read_text() == "old\n"
