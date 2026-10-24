"""edit with secret=true: what the hub's secret link pages send.

The user types a credential into a page so that it is recorded nowhere but in
the target file. Three places on the host would otherwise keep it:
  - the safe edit's <name>.bak.<ts> copy of the PREVIOUS content, next to the
    file (the old credential, maybe in a directory a web server serves);
  - a diff in the output;
  - the local audit, which records every payload as-is (and the dashboard's
    Activity page shows it through read_audit).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from sentinelx_protocol import RequestMessage

import sentinelx_core
from sentinelx_core import local_audit
from sentinelx_core.executor import Executor, HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import FileOpsPath, Policy
from sentinelx_core.vendored import pensa_safe_edit as pse

MARKER = "sk-MARKER-4f1d9c0e7b"
SRC = str(Path(sentinelx_core.__file__).resolve().parents[1])


@pytest.fixture(autouse=True)
def _audit_in_tmp(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(local_audit, "AUDIT_PATH", tmp_path / "audit.jsonl")
    local_audit._reset_retention_state()
    yield
    local_audit._reset_retention_state()


@pytest.fixture
def real_safe_edit(tmp_path: Path) -> Path:
    """The vendored safe edit, run as the handler runs a binary."""
    b = tmp_path / "safe-edit"
    b.write_text(f'#!/bin/bash\nPYTHONPATH="{SRC}" exec "{sys.executable}" -m '
                 f'sentinelx_core.vendored.pensa_safe_edit "$@"\n')
    b.chmod(0o755)
    return b


def _setup(tmp_path: Path, content: str = "OLD=old-value\n") -> tuple[Policy, Path]:
    d = tmp_path / "app"
    d.mkdir()
    target = d / ".env"
    target.write_text(content)
    p = Policy(file_ops_paths=(FileOpsPath(path=str(d), access="rw"),))
    up = tmp_path / "uploads"
    up.mkdir()
    object.__setattr__(p, "upload_base", up)
    return p, target


# --- the safe edit itself ----------------------------------------------------

def test_no_backup_leaves_no_copy(tmp_path: Path) -> None:
    _, target = _setup(tmp_path)
    pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new=MARKER, no_backup=True))
    assert target.read_text() == MARKER
    assert [p.name for p in target.parent.iterdir()] == [".env"]


def test_without_no_backup_the_copy_is_there(tmp_path: Path) -> None:
    """The control: the default keeps the .bak (which is the leak)."""
    _, target = _setup(tmp_path)
    res = pse.apply_edit(pse.EditSpec(path=str(target), mode="write", new=MARKER))
    assert Path(res.backup).exists()


# --- the handler -------------------------------------------------------------

@pytest.mark.asyncio
async def test_secret_edit_writes_with_no_backup_and_no_value_in_output(
        tmp_path: Path, real_safe_edit: Path) -> None:
    policy, target = _setup(tmp_path)
    with patch("sentinelx_core.handlers.edit._resolve_safe_edit_bin", return_value=str(real_safe_edit)):
        edit = build_registry(policy=policy)["edit"]
        res = await edit({"path": str(target), "mode": "write", "new_text": MARKER, "secret": True})
    assert res["ok"] is True, res
    assert target.read_text() == MARKER
    assert "--no-backup" in res["command"]
    assert "BACKUP: none" in res["output"]
    assert MARKER not in json.dumps(res)
    assert sorted(p.name for p in target.parent.iterdir()) == [".env"]
    # the staged new.txt is gone too
    assert not any(MARKER in p.read_text(errors="ignore")
                   for p in (tmp_path / "uploads").rglob("*") if p.is_file())


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [{"diff": True}, {"create": True}, {"backup_dir": "/tmp"}])
async def test_secret_edit_refuses_diff_create_and_backup_dir(tmp_path: Path, real_safe_edit: Path,
                                                              extra: dict) -> None:
    policy, target = _setup(tmp_path)
    with patch("sentinelx_core.handlers.edit._resolve_safe_edit_bin", return_value=str(real_safe_edit)):
        edit = build_registry(policy=policy)["edit"]
        with pytest.raises(HandlerError) as exc:
            await edit({"path": str(target), "mode": "write", "new_text": MARKER, "secret": True, **extra})
    assert exc.value.code == "invalid_payload"
    assert target.read_text() == "OLD=old-value\n"


# --- the local audit ---------------------------------------------------------

def _executor(handler) -> Executor:
    ex = Executor(config_path=Path("/nonexistent/config.yaml"))
    ex._get_handlers = lambda: {"edit": handler}  # type: ignore[method-assign]
    return ex


async def _ok(payload):
    return {"ok": True, "returncode": 0}


async def _boom(payload):
    raise HandlerError("write_failed", "no")


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [_ok, _boom])
async def test_local_audit_keeps_the_op_but_not_the_value(handler) -> None:
    payload = {"path": "/srv/app/.env", "mode": "regex", "pattern": "(?m)^KEY=[^\\r\\n]*$",
               "new_text": f"KEY={MARKER}", "secret": True}
    await _executor(handler).dispatch(RequestMessage(id="r1", op="edit", payload=payload))
    raw = local_audit.AUDIT_PATH.read_text()
    assert MARKER not in raw
    entry = json.loads(raw.splitlines()[0])
    assert entry["op"] == "edit"
    assert entry["payload"]["path"] == "/srv/app/.env"
    assert entry["payload"]["new_text"] == {"omitted": "secret", "chars": len(f"KEY={MARKER}")}
    assert payload["new_text"] == f"KEY={MARKER}", "the handler's own payload is untouched"


@pytest.mark.asyncio
async def test_local_audit_of_an_ordinary_edit_is_unchanged() -> None:
    payload = {"path": "/srv/app/x", "mode": "write", "new_text": MARKER}
    await _executor(_ok).dispatch(RequestMessage(id="r1", op="edit", payload=payload))
    assert MARKER in local_audit.AUDIT_PATH.read_text()


def test_the_hub_can_see_the_feature() -> None:
    assert "edit_secret" in _executor(_ok).capability_names()


def test_no_edit_no_secret_feature() -> None:
    """A host with edit disabled must not claim it can take secret writes."""
    ex = Executor(config_path=Path("/nonexistent/config.yaml"))
    ex._get_handlers = lambda: {"read": _ok}  # type: ignore[method-assign]
    assert "edit_secret" not in ex.capability_names()
