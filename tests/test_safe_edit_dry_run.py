"""A dry run leaves no trace in the target's directory.

Reported on a QNAP CIFS share: a dry-run create made the parent directory and
an empty target, and the temp file holding the simulated content ended up in
the share's recycle bin. The safe editor created the parents up front, touched
the target before checking dry_run, and wrote its temp file next to the target.
On a normal disk that temp appears and disappears unseen; on a share with a
recycle bin, or under a directory watcher, it does not. A real run is
unchanged: its temp stays next to the target so os.replace remains atomic.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sentinelx_core.vendored import pensa_safe_edit as pse
from sentinelx_core.vendored.pensa_safe_edit import EditSpec, SafeEditError, apply_edit


@pytest.fixture
def temp_dirs(monkeypatch):
    """Record the directory of every temp file the editor creates."""
    used: list[str] = []
    real = tempfile.mkstemp

    def spy(*a, **k):
        used.append(str(Path(k.get("dir") or tempfile.gettempdir()).resolve()))
        return real(*a, **k)

    monkeypatch.setattr(pse.tempfile, "mkstemp", spy)
    return used


def test_dry_run_create_makes_no_directory_and_no_file(tmp_path, temp_dirs):
    target = tmp_path / "share" / "01_조교" / ".keep"
    res = apply_edit(EditSpec(path=str(target), mode="write", new="init\n",
                              create=True, dry_run=True, diff=True))
    assert res.dry_run is True
    assert "+init" in res.diff_text
    assert not target.exists()
    assert not target.parent.exists()           # no parent directories made
    assert not (tmp_path / "share").exists()
    assert str(tmp_path.resolve()) not in "".join(temp_dirs)


def test_dry_run_on_an_existing_file_writes_nothing_next_to_it(tmp_path, temp_dirs):
    target = tmp_path / "config.yaml"
    target.write_text("a: 1\n")
    before = sorted(p.name for p in tmp_path.iterdir())
    res = apply_edit(EditSpec(path=str(target), mode="write", new="a: 2\n",
                              dry_run=True, diff=True))
    assert res.dry_run is True and "+a: 2" in res.diff_text
    assert target.read_text() == "a: 1\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert str(tmp_path.resolve()) not in temp_dirs  # temp never lived beside it


def test_a_dry_run_leaves_no_scratch_directory_behind(tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("x\n")
    scratch_before = {p.name for p in Path(tempfile.gettempdir()).glob("sx-dryrun-*")}
    apply_edit(EditSpec(path=str(target), mode="write", new="y\n", dry_run=True))
    scratch_after = {p.name for p in Path(tempfile.gettempdir()).glob("sx-dryrun-*")}
    assert scratch_after == scratch_before


def test_a_real_edit_still_writes_its_temp_beside_the_target(tmp_path, temp_dirs):
    target = tmp_path / "f.txt"
    target.write_text("x\n")
    apply_edit(EditSpec(path=str(target), mode="write", new="y\n",
                        backup_dir=str(tmp_path / "bk")))
    assert target.read_text() == "y\n"
    assert str(tmp_path.resolve()) in temp_dirs  # same dir: atomic os.replace


def test_a_real_create_still_makes_the_parents_and_the_file(tmp_path):
    target = tmp_path / "new" / "dir" / "f.txt"
    apply_edit(EditSpec(path=str(target), mode="write", new="hello\n", create=True,
                        backup_dir=str(tmp_path / "bk")))
    assert target.read_text() == "hello\n"


def test_an_invalid_call_creates_nothing(tmp_path):
    target = tmp_path / "nope" / "f.txt"
    with pytest.raises(SafeEditError):
        apply_edit(EditSpec(path=str(target)))  # neither mode nor restore
    assert not target.parent.exists()


def test_a_missing_target_without_create_creates_no_parents(tmp_path):
    target = tmp_path / "nope" / "f.txt"
    with pytest.raises(SafeEditError) as err:
        apply_edit(EditSpec(path=str(target), mode="write", new="x\n"))
    assert err.value.code == "target_not_found"
    assert not target.parent.exists()


def test_a_dry_run_restore_writes_nothing_next_to_the_target(tmp_path, temp_dirs):
    target = tmp_path / "f.txt"
    target.write_text("current\n")
    backup = tmp_path / "bk" / "f.txt.bak"
    backup.parent.mkdir()
    backup.write_text("older\n")
    res = apply_edit(EditSpec(path=str(target), restore=str(backup), dry_run=True, diff=True))
    assert res.dry_run is True
    assert target.read_text() == "current\n"
    assert str(tmp_path.resolve()) not in temp_dirs
