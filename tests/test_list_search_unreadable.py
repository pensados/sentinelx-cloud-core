"""list/search on what the agent's user can't read (sxrep_919SQBDT9XD4).

Both returned ok with nothing in it for a directory the agent's OS user can't
read (---, --x) or can read but not enter (r--), on every Python: "empty" /
"no matches" that weren't true, and a reason to delete data. Now the requested
directory itself -> permission_denied; anything unreadable below it -> a
partial result that says so.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers.fileops import make_list_handler, make_search_handler
from sentinelx_core.policy import Policy

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "ew24"
    root.mkdir()
    (root / "README.md").write_text("hello needle\n")
    ev = root / "evidence"
    ev.mkdir()
    (ev / "C101_EVIDENCE.json").write_text('{"needle": 1}\n')
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"allowed_commands: []\nfile_ops:\n  paths:\n    - path: {root}\n      access: r\n")
    yield root, ev, Policy.from_file(cfg)
    for d in (root, ev):
        if d.exists():
            d.chmod(0o755)


@pytest.mark.parametrize("mode", [0o000, 0o300])        # nothing / enter but not read
async def test_list_of_an_unreadable_directory_is_an_error_not_empty(tree, mode):
    root, ev, pol = tree
    ev.chmod(mode)
    with pytest.raises(HandlerError) as exc:
        await make_list_handler(pol)({"path": str(ev)})
    assert exc.value.code == "permission_denied" and "not empty" in str(exc.value)


async def test_list_of_a_readable_but_not_enterable_directory_shows_the_names(tree):
    root, ev, pol = tree
    ev.chmod(0o400)                                       # r--: names yes, details no
    r = await make_list_handler(pol)({"path": str(ev)})
    assert r["total"] == 1 and r["partial"] is True
    assert r["entries"] == [{"name": "C101_EVIDENCE.json", "type": "unknown", "size": None, "mtime": None}]
    assert "Partial result" in r["note"]


async def test_recursive_list_marks_an_unreadable_subdirectory(tree):
    root, ev, pol = tree
    ev.chmod(0o000)
    r = await make_list_handler(pol)({"path": str(root), "depth": 2})
    names = {e["name"] for e in r["entries"]}
    assert {"README.md", "evidence"} <= names              # the rest is still listed
    assert r["partial"] is True and r["unreadable_dirs"] == ["evidence"]


async def test_a_normal_listing_is_unchanged(tree):
    root, ev, pol = tree
    r = await make_list_handler(pol)({"path": str(root), "depth": 2})
    assert "partial" not in r and "unreadable_dirs" not in r
    assert {e["name"] for e in r["entries"]} == {"README.md", "evidence", "evidence/C101_EVIDENCE.json"}


async def test_search_in_an_unreadable_directory_is_an_error_not_no_matches(tree):
    root, ev, pol = tree
    ev.chmod(0o000)
    with pytest.raises(HandlerError) as exc:
        await make_search_handler(pol)({"path": str(ev), "pattern": "needle"})
    assert exc.value.code == "permission_denied"


async def test_search_says_when_part_of_the_tree_was_unreadable(tree):
    root, ev, pol = tree
    ev.chmod(0o000)
    r = await make_search_handler(pol)({"path": str(root), "pattern": "needle"})
    assert [m["file"] for m in r["matches"]] == ["README.md"]
    assert r["partial"] is True and r["unreadable_dirs"] == ["evidence"]
    assert "not proof of absence" in r["note"]


async def test_search_counts_an_unreadable_file(tree):
    root, ev, pol = tree
    (ev / "C101_EVIDENCE.json").chmod(0o000)
    r = await make_search_handler(pol)({"path": str(root), "pattern": "needle"})
    assert r["partial"] is True and "1 file" in r["note"]


async def test_a_normal_search_is_unchanged(tree):
    root, ev, pol = tree
    r = await make_search_handler(pol)({"path": str(root), "pattern": "needle"})
    assert "partial" not in r and len(r["matches"]) == 2
