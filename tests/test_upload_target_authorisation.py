"""Chunked uploads can't write outside the allowed paths (GHSA-r2h3-76g7-m95x).

upload_file could stage a forged meta.json inside the staging area, and upload_complete
moved the assembled file to whatever target_path that meta named, with no re-check;
upload_chunk also accepted an upload_id containing '../'.
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

import pytest

from sentinelx_core.handlers import upload as u
from sentinelx_core.executor import HandlerError

b64 = lambda b: base64.b64encode(b).decode()


@pytest.fixture
def base(tmp_path):
    b = tmp_path / "uploads"
    b.mkdir()
    return b


async def test_upload_file_refuses_to_write_into_the_staging_area(base):
    up = u.make_upload_file_handler(None, base)
    with pytest.raises(HandlerError) as e:
        await up({"target_path": ".sentinelx_uploads/" + "a" * 32 + "/meta.json",
                  "content_base64": b64(b"{}"), "overwrite": True})
    assert e.value.code == "path_not_allowed"


async def test_upload_chunk_rejects_a_traversal_upload_id(base):
    (base / "x").mkdir(parents=True)
    with pytest.raises(HandlerError) as e:
        await u.make_upload_chunk_handler(base)({"upload_id": "../../x", "index": 0,
                                                 "content_base64": b64(b"Z")})
    assert e.value.code == "invalid_payload"
    assert not list(base.parent.rglob("*.part"))


async def test_complete_does_not_trust_a_forged_meta_target(base, tmp_path):
    outside = tmp_path / "OUTSIDE" / "pwned.txt"
    uid = "b" * 32
    d = base / ".sentinelx_uploads" / uid
    (d / "parts").mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"target_path": str(outside), "total_size": 0}))
    (d / "parts" / "00000000.part").write_bytes(b"DATA")
    with pytest.raises(HandlerError) as e:
        await u.make_upload_complete_handler(base, policy=None)({"upload_id": uid})
    assert e.value.code in ("path_traversal", "path_not_allowed")
    assert not outside.exists()


async def test_a_normal_chunked_upload_still_completes(base):
    uid = "c" * 32
    d = base / ".sentinelx_uploads" / uid
    (d / "parts").mkdir(parents=True)
    dest = base / "sub" / "file.bin"
    (d / "meta.json").write_text(json.dumps({"upload_id": uid, "target_path": str(dest),
                                             "resolved_target": str(dest), "landed_in_place": False,
                                             "overwrite": True, "total_size": 4, "filename": "file.bin"}))
    (d / "parts" / "00000000.part").write_bytes(b"DATA")
    out = await u.make_upload_complete_handler(base, policy=None)({"upload_id": uid})
    assert out["ok"] and dest.read_bytes() == b"DATA"
