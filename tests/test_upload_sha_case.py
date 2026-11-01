"""A correct SHA-256 in uppercase is a correct SHA-256.

hexdigest() is always lowercase, and the completion compared the caller's value
against it as a plain string. So a digest right in every way except letter case
was rejected as checksum_mismatch -- a message saying the bytes arrived wrong
when they arrived perfectly. Uppercase is the convention in many manifests.

Reported with a three-chunk reproduction of b"abcdefghi" and a lowercase control
of the identical payload that succeeded. Both are reproduced here THROUGH THE
REAL HANDLERS: an earlier version of this file reimplemented the comparison in
the test and therefore passed with the fix deleted.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy

PAYLOAD = b"abcdefghi"
LOWER = hashlib.sha256(PAYLOAD).hexdigest()
UPPER = LOWER.upper()


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    p = Policy()
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def _complete_with(policy: Policy, digest, name: str):
    """Run the reported three-chunk upload and complete it with `digest`."""
    handlers = build_registry(policy=policy)
    init = await handlers["upload_init"]({
        "target_path": f"{name}/payload.bin",
        "total_size": len(PAYLOAD),
        "filename": "payload.bin",
    })
    uid = init["upload_id"]
    for i, chunk in enumerate((PAYLOAD[0:3], PAYLOAD[3:6], PAYLOAD[6:9])):
        await handlers["upload_chunk"]({
            "upload_id": uid, "index": i,
            "content_base64": base64.b64encode(chunk).decode(),
        })
    return await handlers["upload_complete"]({"upload_id": uid, "sha256": digest})


def test_the_reported_digest_is_the_right_one():
    """Guards the fixture: the user's value was never wrong."""
    assert UPPER == "19CC02F26DF43CC571BC9ED7B0C4D29224A3EC229529221725EF76D021C8326F"


async def test_uppercase_completes(policy):
    res = await _complete_with(policy, UPPER, "upper")
    assert res["ok"] is True
    assert res["size"] == 9
    assert Path(res["target_path"]).read_bytes() == PAYLOAD


async def test_lowercase_still_completes(policy):
    res = await _complete_with(policy, LOWER, "lower")
    assert res["ok"] is True


async def test_mixed_case_completes(policy):
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(LOWER))
    assert (await _complete_with(policy, mixed, "mixed"))["ok"] is True


async def test_surrounding_whitespace_is_tolerated(policy):
    assert (await _complete_with(policy, f"  {UPPER}\n", "ws"))["ok"] is True


async def test_a_genuinely_different_digest_is_still_rejected(policy):
    other = hashlib.sha256(b"different").hexdigest().upper()
    with pytest.raises(HandlerError) as e:
        await _complete_with(policy, other, "other")
    assert e.value.code == "checksum_mismatch"


async def test_one_flipped_character_is_still_rejected(policy):
    """Case-insensitive must not mean lenient."""
    wrong = ("f" if LOWER[0] != "f" else "0") + LOWER[1:]
    with pytest.raises(HandlerError) as e:
        await _complete_with(policy, wrong.upper(), "flip")
    assert e.value.code == "checksum_mismatch"


async def test_a_non_hex_value_is_named_differently(policy):
    """"not valid hex" and "the bytes differ" need different responses."""
    with pytest.raises(HandlerError) as e:
        await _complete_with(policy, "zz" + "0" * 62, "nonhex")
    assert e.value.code == "invalid_sha256"


async def test_a_short_digest_is_named_differently(policy):
    with pytest.raises(HandlerError) as e:
        await _complete_with(policy, LOWER[:40], "short")
    assert e.value.code == "invalid_sha256"


async def test_the_mismatch_message_shows_both_digests(policy):
    """So the caller can see whether it is case, truncation or real corruption."""
    other = hashlib.sha256(b"different").hexdigest()
    with pytest.raises(HandlerError) as e:
        await _complete_with(policy, other, "msg")
    assert LOWER in str(e.value) and other in str(e.value)
