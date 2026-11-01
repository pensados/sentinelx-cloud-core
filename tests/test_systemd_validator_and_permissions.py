"""systemd preset verifies units by their real name; PermissionError is a refusal.

sxrep_NQE9F1SJHP71: validator_preset=systemd verified the temp file
(<name>.<random>), a name systemd-analyze refuses, so no unit could be
validated, and a drop-in can't be verified on its own at all.
sxrep_TQ2C9Y22MWJP: a delete under an untraversable parent raised an uncaught
PermissionError and the agent logged "executor crashed on delete".
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from sentinelx_protocol import RequestMessage

from sentinelx_core import executor as EX
from sentinelx_core.executor import Executor
from sentinelx_core.vendored.pensa_safe_edit import EditSpec, SafeEditError, apply_edit

needs_systemd = pytest.mark.skipif(shutil.which("systemd-analyze") is None,
                                   reason="systemd-analyze not installed")

GOOD_UNIT = "[Unit]\nDescription=x\n[Service]\nExecStart=/bin/true\n"
BAD_UNIT = "[Unit]\nDescription=x\n[Service]\nType=simple\n"   # no ExecStart: verify refuses


def _verify_dirs():
    return {p.name for p in Path(tempfile.gettempdir()).glob("sx-verify-*")}


@needs_systemd
@pytest.mark.parametrize("dry_run", [True, False])
def test_a_valid_unit_passes_the_systemd_preset(tmp_path, dry_run):
    unit = tmp_path / "sxtest.service"
    unit.write_text(GOOD_UNIT.replace("Description=x", "Description=old"))
    before = _verify_dirs()
    res = apply_edit(EditSpec(path=str(unit), mode="write", new=GOOD_UNIT,
                              validator_preset="systemd", dry_run=dry_run,
                              backup_dir=str(tmp_path / "bk")))
    assert res.ok
    assert res.validator[-1].endswith("/sxtest.service")       # verified by its real name
    assert unit.read_text() == (GOOD_UNIT.replace("Description=x", "Description=old")
                                if dry_run else GOOD_UNIT)
    assert _verify_dirs() == before                             # nothing left behind


@needs_systemd
def test_an_invalid_unit_fails_validation_and_is_not_written(tmp_path):
    unit = tmp_path / "sxtest.service"
    unit.write_text(GOOD_UNIT)
    with pytest.raises(SafeEditError) as e:
        apply_edit(EditSpec(path=str(unit), mode="write", new=BAD_UNIT,
                            validator_preset="systemd", backup_dir=str(tmp_path / "bk")))
    assert e.value.code == "validation_failed" and "ExecStart" in str(e.value)
    assert unit.read_text() == GOOD_UNIT


@pytest.mark.parametrize("dry_run", [True, False])
def test_a_drop_in_is_refused_before_anything_changes(tmp_path, dry_run):
    d = tmp_path / "AdGuardHome.service.d"
    d.mkdir()
    conf = d / "30-self-healing.conf"
    conf.write_text("[Service]\nTasksMax=128\n")
    with pytest.raises(SafeEditError) as e:
        apply_edit(EditSpec(path=str(conf), mode="write", new="[Service]\nTasksMax=256\n",
                            validator_preset="systemd", dry_run=dry_run,
                            backup_dir=str(tmp_path / "bk")))
    assert e.value.code == "validator_unsupported"
    assert "daemon-reload" in str(e.value)
    assert conf.read_text() == "[Service]\nTasksMax=128\n"
    assert sorted(p.name for p in d.iterdir()) == ["30-self-healing.conf"]   # no temp left


# --- PermissionError ---------------------------------------------------------------------

def _executor_raising(exc, monkeypatch, op="delete"):
    async def handler(payload):
        raise exc

    ex = Executor(config_path=Path("/nonexistent/config.yaml"))
    monkeypatch.setattr(ex, "_get_handlers", lambda: {op: handler})
    recorded = []
    monkeypatch.setattr(EX.local_audit, "record", lambda *a, **k: recorded.append(k))
    return ex, recorded


async def test_a_permission_error_is_a_classified_refusal_not_a_crash(monkeypatch):
    err = PermissionError(13, "Permission denied", "/var/lib/adguard-audit/x.sh")
    ex, recorded = _executor_raising(err, monkeypatch)
    resp = await ex.dispatch(RequestMessage(id="r1", op="delete",
                                            payload={"path": "/var/lib/adguard-audit/x.sh"}))
    assert resp["ok"] is False
    assert resp["error"]["code"] == "permission_denied"
    assert resp["error"]["details"] == {"path": "/var/lib/adguard-audit/x.sh"}
    assert "parent directories" in resp["error"]["message"]
    assert recorded and recorded[0]["ok"] is False


async def test_a_permission_error_without_a_path_still_answers(monkeypatch):
    ex, _ = _executor_raising(PermissionError("nope"), monkeypatch, op="move")
    resp = await ex.dispatch(RequestMessage(id="r2", op="move", payload={}))
    assert resp["error"]["code"] == "permission_denied" and resp["error"]["details"] == {}
