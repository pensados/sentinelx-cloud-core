"""An edit changes the file's mtime, and keeps its permissions (0.23.29).

copy_metadata used shutil.copystat, which also copies atime/mtime, so a file
edited with sentinel_edit kept its OLD mtime. PHP OPcache with
validate_timestamps decides by mtime, and kept serving the old code until
PHP-FPM restarted (sxrep_HGZJZXHF7RD7).
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from sentinelx_core.vendored.pensa_safe_edit import EditSpec, apply_edit, copy_metadata

OLD = time.time() - 30 * 24 * 3600   # a month ago


def _old_file(path: Path, text: str, mode: int = 0o640) -> Path:
    path.write_text(text)
    path.chmod(mode)
    os.utime(path, (OLD, OLD))
    return path


def test_an_edit_gives_the_file_a_new_mtime_and_keeps_its_mode(tmp_path: Path) -> None:
    f = _old_file(tmp_path / "overview.php", "<?php echo 'old';\n")
    before = time.time()
    res = apply_edit(EditSpec(path=str(f), mode="replace", old="'old'", new="'new'"))
    assert res.ok and f.read_text() == "<?php echo 'new';\n"
    st = f.stat()
    assert st.st_mtime >= before - 1, "an edited file must not keep its old mtime"
    assert stat.S_IMODE(st.st_mode) == 0o640


def test_a_restore_also_moves_the_mtime(tmp_path: Path) -> None:
    f = _old_file(tmp_path / "a.php", "one")
    backup = apply_edit(EditSpec(path=str(f), mode="write", new="two")).backup
    os.utime(f, (OLD, OLD))
    before = time.time()
    res = apply_edit(EditSpec(path=str(f), restore=backup))
    assert res.action == "restore" and f.read_text() == "one"
    assert f.stat().st_mtime >= before - 1


def test_the_backup_keeps_the_originals_time(tmp_path: Path) -> None:
    f = _old_file(tmp_path / "b.php", "x")
    res = apply_edit(EditSpec(path=str(f), mode="write", new="y"))
    assert abs(Path(res.backup).stat().st_mtime - OLD) < 2


def test_copy_metadata_copies_mode_not_time(tmp_path: Path) -> None:
    src = _old_file(tmp_path / "src", "a", 0o600)
    dst = tmp_path / "dst"
    dst.write_text("b")
    copy_metadata(src, dst)
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert dst.stat().st_mtime > OLD + 3600
