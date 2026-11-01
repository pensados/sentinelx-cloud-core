"""Agent credential rotation. The invariant: a bad rotation never strands a host.

Every path that could go wrong falls back to the original identity.json, which
is always a valid credential -- a corrupt or expired rotated file, a host
mismatch, no writable dir. Only a valid, unexpired, same-host rotated credential
is ever preferred.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from sentinelx_core import rotation
from sentinelx_core.identity import Identity


def _tok(exp_offset_s, iat_offset_s=None, host_id="h1"):
    hdr = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    claims = {"host_id": host_id, "exp": int(time.time() + exp_offset_s)}
    if iat_offset_s is not None:
        claims["iat"] = int(time.time() + iat_offset_s)
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{hdr}.{body}.sig"


@pytest.fixture
def base():
    return Identity(host_id="h1", token=_tok(300 * 86400), hub="https://hub")


# --- should_rotate ------------------------------------------------------------

def test_rotate_past_half_life():
    assert rotation.should_rotate(_tok(100 * 86400, iat_offset_s=-300 * 86400)) is True


def test_do_not_rotate_before_half_life():
    assert rotation.should_rotate(_tok(300 * 86400, iat_offset_s=-60 * 86400)) is False


def test_legacy_token_without_iat_rotates_when_old():
    # <182 days of a 365-day life left -> rotate (migrates to a typed cred).
    assert rotation.should_rotate(_tok(100 * 86400)) is True
    assert rotation.should_rotate(_tok(300 * 86400)) is False


def test_unreadable_token_is_left_alone():
    assert rotation.should_rotate("not-a-jwt") is False


# --- persist + load round trip ------------------------------------------------

def test_persist_then_load_prefers_rotated(tmp_path, base, monkeypatch):
    idp = tmp_path / "identity.json"
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    new = _tok(360 * 86400)
    assert rotation.persist_rotated(idp, "h1", new, "https://hub") is True
    eff = rotation.load_effective_identity(idp, base)
    assert eff.token == new


def test_no_rotated_file_uses_base(tmp_path, base, monkeypatch):
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    eff = rotation.load_effective_identity(tmp_path / "identity.json", base)
    assert eff.token == base.token


def test_corrupt_rotated_file_falls_back(tmp_path, base, monkeypatch):
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    (tmp_path / rotation.ROTATED_NAME).write_text("{ not json")
    eff = rotation.load_effective_identity(tmp_path / "identity.json", base)
    assert eff.token == base.token


def test_expired_rotated_file_falls_back(tmp_path, base, monkeypatch):
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    (tmp_path / rotation.ROTATED_NAME).write_text(
        json.dumps({"host_id": "h1", "token": _tok(-10), "hub": "https://hub"})
    )
    eff = rotation.load_effective_identity(tmp_path / "identity.json", base)
    assert eff.token == base.token


def test_host_mismatch_falls_back(tmp_path, base, monkeypatch):
    """A rotated file for a different host must never be adopted."""
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    (tmp_path / rotation.ROTATED_NAME).write_text(
        json.dumps({"host_id": "OTHER", "token": _tok(300 * 86400), "hub": "https://hub"})
    )
    eff = rotation.load_effective_identity(tmp_path / "identity.json", base)
    assert eff.token == base.token


def test_no_writable_dir_disables_persist(tmp_path, base, monkeypatch):
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", ("/nonexistent/xyz",))
    assert rotation.persist_rotated(tmp_path / "identity.json", "h1", _tok(1), "h") is False


def test_persist_is_atomic_no_temp_left(tmp_path, base, monkeypatch):
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    rotation.persist_rotated(tmp_path / "identity.json", "h1", _tok(360 * 86400), "h")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".idrot")]
    assert leftovers == []


def test_rotated_file_is_600(tmp_path, base, monkeypatch):
    import stat
    monkeypatch.setattr(rotation, "_DIR_CANDIDATES", (str(tmp_path),))
    rotation.persist_rotated(tmp_path / "identity.json", "h1", _tok(360 * 86400), "h")
    mode = stat.S_IMODE((tmp_path / rotation.ROTATED_NAME).stat().st_mode)
    assert mode == 0o600
