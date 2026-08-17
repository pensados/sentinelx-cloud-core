"""Tests for the Policy loader and its query methods."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinelx_core.policy import Policy


def test_empty_policy_denies_everything() -> None:
    p = Policy.empty()
    assert p.is_command_allowed("ls /") is False
    assert p.is_command_allowed("") is False
    assert p.get_service("nginx") is None
    assert p.is_service_action_allowed("nginx", "restart") is False


def test_allowlist_prefix_match() -> None:
    p = Policy(allowed_commands=("ls", "cat", "sudo systemctl status"))
    assert p.is_command_allowed("ls -la /tmp") is True
    assert p.is_command_allowed("cat /etc/hosts") is True
    assert p.is_command_allowed("sudo systemctl status nginx") is True
    assert p.is_command_allowed("rm -rf /") is False
    assert p.is_command_allowed("sudo systemctl restart nginx") is False


def test_allowlist_empty_string_matches_everything() -> None:
    """If someone puts '' in the allowlist they get everything (gotcha to be aware of)."""
    p = Policy(allowed_commands=("",))
    assert p.is_command_allowed("anything") is True


def test_allowlist_truly_empty_blocks_everything() -> None:
    p = Policy(allowed_commands=())
    assert p.is_command_allowed("ls") is False
    assert p.is_command_allowed("") is False


def test_from_dict_basic() -> None:
    data = {
        "agent": {"hostname_label": "test-host"},
        "allowed_commands": ["ls", "cat"],
        "services": {
            "nginx": {
                "unit": "nginx.service",
                "actions": ["status", "restart"],
                "requires_sudo": True,
            },
            "docker": {
                "actions": ["status"],
            },
        },
        "locations": {
            "home": {"path": "/home/test", "description": "test home"},
            "logs": "/var/log",  # short form
        },
    }
    p = Policy.from_dict(data)
    assert p.hostname_label == "test-host"
    assert p.allowed_commands == ("ls", "cat")
    assert p.services["nginx"].unit == "nginx.service"
    assert p.services["docker"].unit == "docker"  # defaults to name
    assert p.is_service_action_allowed("nginx", "restart") is True
    assert p.is_service_action_allowed("nginx", "kill") is False
    assert p.locations["home"].path == "/home/test"
    assert p.locations["logs"].path == "/var/log"
    assert p.locations["logs"].description == ""


def test_from_file(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(textwrap.dedent("""
        allowed_commands:
          - ls
          - tail
        services:
          nginx:
            actions: [status, reload]
    """))
    p = Policy.from_file(config)
    assert p.allowed_commands == ("ls", "tail")
    assert p.is_service_action_allowed("nginx", "reload") is True


def test_from_file_missing_returns_empty(tmp_path: Path) -> None:
    p = Policy.from_file(tmp_path / "does-not-exist.yaml")
    assert p.allowed_commands == ()


def test_from_file_invalid_yaml_returns_empty(tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text("not: valid: yaml: with: too: many: colons:")
    p = Policy.from_file(config)
    assert p.allowed_commands == ()


def test_exec_timeout_defaults() -> None:
    p = Policy.empty()
    assert p.exec_timeout_default == 60
    assert p.exec_timeout_max == 600

    p2 = Policy.from_dict({"exec": {"timeout_default": 30, "timeout_max": 120}})
    assert p2.exec_timeout_default == 30
    assert p2.exec_timeout_max == 120


# ---------------------------------------------------------------------------
# Unified file_ops r/rw model
# ---------------------------------------------------------------------------


def _write(p: Path, text: str = "x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_file_ops_legacy_allowed_read_paths_maps_to_read_only(
    tmp_path: Path,
) -> None:
    """A legacy config keeps working: allowed_read_paths -> access r.

    This is the zero-breakage guarantee. An agent that has only ever
    seen `file_ops.allowed_read_paths` must behave EXACTLY as before:
    reads resolve, writes are refused everywhere.
    """
    d = _write(tmp_path / "sub" / "f.txt").parent
    p = Policy.from_dict(
        {"file_ops": {"allowed_read_paths": [str(d)]}}
    )
    # read resolves (legacy behaviour preserved)
    assert p.resolve_read_path(str(d / "f.txt")) is not None
    assert p.resolve_path(str(d / "f.txt"), need_write=False) is not None
    # but it is read-only: no write anywhere under it
    assert p.resolve_path(str(d / "f.txt"), need_write=True) is None


def test_file_ops_paths_rw_allows_write(tmp_path: Path) -> None:
    rw_dir = _write(tmp_path / "rw" / "f.txt").parent
    r_dir = _write(tmp_path / "ro" / "g.txt").parent
    p = Policy.from_dict(
        {
            "file_ops": {
                "paths": [
                    {"path": str(rw_dir), "access": "rw"},
                    {"path": str(r_dir), "access": "r"},
                ]
            }
        }
    )
    # rw path: read and write both resolve
    assert p.resolve_path(str(rw_dir / "f.txt"), need_write=False) is not None
    assert p.resolve_path(str(rw_dir / "f.txt"), need_write=True) is not None
    # r path: read resolves, write refused
    assert p.resolve_path(str(r_dir / "g.txt"), need_write=False) is not None
    assert p.resolve_path(str(r_dir / "g.txt"), need_write=True) is None


def test_file_ops_access_defaults_to_r(tmp_path: Path) -> None:
    """Missing or unknown access degrades to r — never to rw."""
    d1 = _write(tmp_path / "a" / "x").parent
    d2 = _write(tmp_path / "b" / "y").parent
    p = Policy.from_dict(
        {
            "file_ops": {
                "paths": [
                    {"path": str(d1)},                       # access omitted
                    {"path": str(d2), "access": "readwrite"},  # typo
                ]
            }
        }
    )
    for d, fn in ((d1, "x"), (d2, "y")):
        assert p.resolve_path(str(d / fn), need_write=False) is not None
        assert p.resolve_path(str(d / fn), need_write=True) is None


def test_file_ops_bare_string_entry_is_read_only(tmp_path: Path) -> None:
    d = _write(tmp_path / "s" / "f").parent
    p = Policy.from_dict({"file_ops": {"paths": [str(d)]}})
    assert p.resolve_path(str(d / "f"), need_write=False) is not None
    assert p.resolve_path(str(d / "f"), need_write=True) is None


def test_file_ops_paths_wins_over_legacy_key(tmp_path: Path) -> None:
    """When both keys exist, `paths` is authoritative; legacy ignored."""
    new_dir = _write(tmp_path / "new" / "f").parent
    legacy_dir = _write(tmp_path / "legacy" / "g").parent
    p = Policy.from_dict(
        {
            "file_ops": {
                "paths": [{"path": str(new_dir), "access": "rw"}],
                "allowed_read_paths": [str(legacy_dir)],
            }
        }
    )
    assert p.resolve_path(str(new_dir / "f"), need_write=True) is not None
    # legacy dir was ignored entirely (not even read access)
    assert p.resolve_path(str(legacy_dir / "g"), need_write=False) is None


def test_file_ops_empty_allowlist_denies(tmp_path: Path) -> None:
    p = Policy.from_dict({"file_ops": {}})
    assert p.resolve_path(str(tmp_path / "x"), need_write=False) is None
    assert p.resolve_path(str(tmp_path / "x"), need_write=True) is None
    assert p.resolve_read_path(str(tmp_path / "x")) is None


def test_file_ops_path_traversal_is_defeated(tmp_path: Path) -> None:
    """`../` cannot climb out of an rw entry (resolve() canonicalizes)."""
    rw_dir = _write(tmp_path / "rw" / "f").parent
    outside = _write(tmp_path / "outside" / "secret").parent
    p = Policy.from_dict(
        {"file_ops": {"paths": [{"path": str(rw_dir), "access": "rw"}]}}
    )
    traversal = str(rw_dir / ".." / "outside" / "secret")
    assert p.resolve_path(traversal, need_write=True) is None
    assert p.resolve_path(traversal, need_write=False) is None
    # sanity: the legitimate path under rw_dir still works
    assert p.resolve_path(str(rw_dir / "f"), need_write=True) is not None
    _ = outside  # referenced for clarity


def test_file_ops_symlink_escape_is_defeated(tmp_path: Path) -> None:
    """A symlink inside an rw entry pointing outside does NOT bypass.

    Canonicalization resolves the symlink BEFORE the prefix check, so
    the resolved target must independently fall under an allowed entry.
    This is the core defense against A1/A2 (hostile hub/LLM): even a
    malicious caller cannot escape the rw subtree via a planted link.
    """
    rw_dir = tmp_path / "rw"
    rw_dir.mkdir()
    secret = _write(tmp_path / "outside" / "shadow", "TOPSECRET")
    link = rw_dir / "escape"
    link.symlink_to(secret)

    p = Policy.from_dict(
        {"file_ops": {"paths": [{"path": str(rw_dir), "access": "rw"}]}}
    )
    # The link lexically lives under rw_dir, but resolves to /outside.
    assert p.resolve_path(str(link), need_write=True) is None
    assert p.resolve_path(str(link), need_write=False) is None


def test_file_ops_prefix_not_substring(tmp_path: Path) -> None:
    """/etc must not match an allowlist entry of /etc-not-this-one."""
    allowed = tmp_path / "data"
    allowed.mkdir()
    sibling = tmp_path / "data-evil"
    _write(sibling / "f")
    p = Policy.from_dict(
        {"file_ops": {"paths": [{"path": str(allowed), "access": "rw"}]}}
    )
    assert p.resolve_path(str(sibling / "f"), need_write=False) is None


def test_file_ops_rw_subtree_under_r_parent(tmp_path: Path) -> None:
    """An rw subtree declared under a broader r parent grants write there.

    Operator declares /home as r and /home/carlos as rw. Writing under
    /home/carlos must succeed (explicit narrower grant), while writing
    elsewhere under /home (only r) must still be refused.
    """
    home = tmp_path / "home"
    carlos = home / "carlos"
    other = home / "other"
    _write(carlos / "f")
    _write(other / "g")
    p = Policy.from_dict(
        {
            "file_ops": {
                "paths": [
                    {"path": str(home), "access": "r"},
                    {"path": str(carlos), "access": "rw"},
                ]
            }
        }
    )
    assert p.resolve_path(str(carlos / "f"), need_write=True) is not None
    assert p.resolve_path(str(other / "g"), need_write=True) is None
    assert p.resolve_path(str(other / "g"), need_write=False) is not None


def test_preferred_profile_valid_values() -> None:
    """agent.preferred_profile accepts 'compact' and 'full' verbatim."""
    for value in ("compact", "full"):
        p = Policy.from_dict(
            {"agent": {"preferred_profile": value}, "allowed_commands": ["ls"]}
        )
        assert p.preferred_profile == value


def test_preferred_profile_absent_defaults_to_none() -> None:
    p = Policy.from_dict({"allowed_commands": ["ls"]})
    assert p.preferred_profile is None


def test_preferred_profile_invalid_degrades_to_none() -> None:
    """A bad value must degrade to None, never advertise something the hub's
    Literal would reject (which would fail the hello and take the host offline).
    """
    p = Policy.from_dict(
        {"agent": {"preferred_profile": "tiny"}, "allowed_commands": ["ls"]}
    )
    assert p.preferred_profile is None
