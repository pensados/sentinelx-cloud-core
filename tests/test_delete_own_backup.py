"""Deleting SentinelX's OWN backup is terminal -- no backup of a backup.

delete normally refuses to destroy without a recovery copy. That guarantee turns
against the user for .bak artifacts: backing up a backup just makes another .bak,
so space can never be reclaimed (a real feature request -- 5.2 GB of stranded
backups). For our own backup pattern only, delete skips the copy and removes it
directly. The risk to guard is over-matching: a user's own file that merely
contains ".bak" must NOT be treated as ours and must keep its mandatory backup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx_core.handlers.fsmutate import _is_own_backup, make_delete_handler
from sentinelx_core.policy import Policy


@pytest.fixture
def rw_root(tmp_path: Path) -> Path:
    d = tmp_path / "rw"
    d.mkdir()
    return d


@pytest.fixture
def policy(rw_root: Path) -> Policy:
    return Policy.from_dict(
        {"file_ops": {"paths": [{"path": str(rw_root), "access": "rw"}]}}
    )


# --- the pattern matcher (the safety-critical part) --------------------------

@pytest.mark.parametrize("name", [
    "model.gguf.bak.20260924-142530",           # file backup (make_backup)
    "model.gguf.bak.20260924-142530-123456",    # with microseconds
    "project.bak.20260924-142530.tar.gz",       # directory backup
])
def test_recognizes_our_backups(name):
    assert _is_own_backup(Path("/x") / name) is True


@pytest.mark.parametrize("name", [
    "config.bak",              # a user's own .bak
    "notes.bak.txt",           # .bak in the middle
    "backup.tar.gz",           # not our timestamped pattern
    "model.gguf",              # a real artifact
    "db.bak.2026",             # partial/wrong timestamp
    "x.bak.20260924",          # date only, no time -> not our pattern
])
def test_does_not_match_user_files(name):
    assert _is_own_backup(Path("/x") / name) is False


# --- behaviour ---------------------------------------------------------------

async def test_deleting_our_backup_is_terminal(policy, rw_root):
    """A .bak artifact is removed WITHOUT creating another backup."""
    bak = rw_root / "model.gguf.bak.20260924-142530-000001"
    bak.write_text("x" * 1000)
    h = make_delete_handler(policy)
    res = await h({"path": str(bak)})
    assert res["ok"] is True
    assert not bak.exists()
    assert res["backup"] is None
    assert res["terminal"] is True
    # crucially: no new .bak sibling was created
    leftovers = list(rw_root.glob("*.bak.*"))
    assert leftovers == []


async def test_deleting_a_normal_file_still_backs_up(policy, rw_root):
    """The mandatory-backup guarantee is unchanged for everything else."""
    f = rw_root / "important.txt"
    f.write_text("precious")
    h = make_delete_handler(policy)
    res = await h({"path": str(f)})
    assert res["ok"] is True
    assert res["backup"] is not None
    assert Path(res["backup"]).exists()
    assert res.get("terminal") is not True


async def test_deleting_a_user_bak_file_still_backs_up(policy, rw_root):
    """A user's file named like a backup but not matching our timestamped
    pattern keeps its safety net -- we must not delete it terminally."""
    f = rw_root / "config.bak"
    f.write_text("user data")
    h = make_delete_handler(policy)
    res = await h({"path": str(f)})
    assert res["ok"] is True
    assert res["backup"] is not None          # backed up, not terminal
    assert Path(res["backup"]).exists()
