"""load_identity: field checks + enrollment-token sanitisation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelx_core.identity import Identity, IdentityError, load_identity

_GOOD = "aaa.bbb.ccc"


def _write(tmp_path: Path, **over) -> Path:
    data = {"host_id": "host_1", "token": _GOOD, "hub": "https://mcp.sentinelx.app"}
    data.update(over)
    p = tmp_path / "identity.json"
    p.write_text(json.dumps(data))
    return p


def test_valid(tmp_path):
    ident = load_identity(_write(tmp_path))
    assert isinstance(ident, Identity)
    assert ident.token == _GOOD
    assert ident.host_id == "host_1"


def test_missing_file(tmp_path):
    with pytest.raises(IdentityError, match="not found"):
        load_identity(tmp_path / "nope.json")


def test_missing_field(tmp_path):
    p = tmp_path / "identity.json"
    p.write_text(json.dumps({"host_id": "h", "hub": "x"}))  # token missing
    with pytest.raises(IdentityError, match="missing field"):
        load_identity(p)


def test_surrounding_whitespace_is_stripped(tmp_path):
    ident = load_identity(_write(tmp_path, token=f"  {_GOOD}\n"))
    assert ident.token == _GOOD


def test_non_ascii_rejected(tmp_path):
    bad = "aaa.bbb.cc\u200bc"  # zero-width space: classic translation corruption
    with pytest.raises(IdentityError, match="non-ASCII"):
        load_identity(_write(tmp_path, token=bad))


def test_internal_whitespace_rejected(tmp_path):
    with pytest.raises(IdentityError, match="whitespace"):
        load_identity(_write(tmp_path, token="aaa.bb b.ccc"))


def test_wrong_structure_rejected(tmp_path):
    with pytest.raises(IdentityError, match="well-formed"):
        load_identity(_write(tmp_path, token="aaa.bbb"))


def test_empty_token_rejected(tmp_path):
    with pytest.raises(IdentityError, match="empty"):
        load_identity(_write(tmp_path, token="   "))
