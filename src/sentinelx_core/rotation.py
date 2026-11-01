"""Agent-side credential rotation (phase 2).

Every host's session credential expires 365 days after it was issued and
nothing renewed it, so the whole fleet would age out (Aug-Sep 2027 for most).
This rotates the credential past its half-life, which also lets the hub revoke
a stolen copy at the next rotation.

The one rule that governs every choice here: a rotation that goes wrong must
NEVER leave a host unable to connect.

  - The rotated credential is written to a SEPARATE file
    (identity.rotated.json) in a directory the agent owns. identity.json --
    root-owned, the original enrolment credential -- is never touched.
  - On startup the agent prefers the rotated file IF it is present and valid,
    and otherwise falls back to identity.json, which is still a valid
    credential. A corrupt or half-written rotated file simply means "use the
    original".
  - The write is atomic: temp file in the same dir, fsync, os.replace. A crash
    mid-write leaves either the old rotated file or none -- never a truncated one.
  - If no writable directory exists, rotation is disabled with a warning and
    the host keeps running on its current credential (covered by the hub's
    legacy grace). Never worse than today.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from sentinelx_core.identity import Identity

logger = logging.getLogger(__name__)

ROTATED_NAME = "identity.rotated.json"

# Candidate directories the agent can write to, most-preferred first. The first
# one that exists and is writable wins; identity.json's own dir is intentionally
# NOT here (root-owned on Linux by design).
_DIR_CANDIDATES = ("/var/lib/sentinelx", None)  # None -> alongside identity.json (Windows)


def rotated_path(identity_path: Path) -> Path | None:
    """Where the rotated credential lives, or None if nowhere is writable."""
    for cand in _DIR_CANDIDATES:
        d = Path(cand) if cand else identity_path.parent
        try:
            if d.is_dir() and os.access(d, os.W_OK):
                return d / ROTATED_NAME
        except OSError:
            continue
    return None


def _claims(token: str) -> dict:
    """Decode a JWT payload without verifying. It is our own credential; we only
    read exp/iat to decide WHEN to rotate. The hub verifies on use."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:  # noqa: BLE001
        return {}


def load_effective_identity(identity_path: Path, base: Identity) -> Identity:
    """The credential to connect with: the rotated one if usable, else the base.

    `base` is whatever load_identity() returned from identity.json. This only
    ever UPGRADES to a rotated credential that parses and is not expired; any
    doubt falls back to base.
    """
    rp = rotated_path(identity_path)
    if rp is None or not rp.exists():
        return base
    try:
        data = json.loads(rp.read_text())
        token = str(data["token"]).strip()
        host_id = str(data.get("host_id") or base.host_id).strip()
    except (OSError, ValueError, KeyError):
        logger.warning("rotated_identity_unreadable; using original")
        return base
    exp = _claims(token).get("exp")
    if not isinstance(exp, (int, float)) or exp <= time.time():
        logger.warning("rotated_identity_expired_or_bad; using original")
        return base
    # Same host, and it must belong to the same account as the base credential.
    if host_id != base.host_id:
        logger.warning("rotated_identity_host_mismatch; using original")
        return base
    return Identity(host_id=host_id, token=token, hub=base.hub)


def should_rotate(token: str) -> bool:
    """True once the credential is past the midpoint of its lifetime.

    Legacy tokens (no iat) are rotated too -- issued >182 days ago they are past
    any 365-day midpoint, and rotating migrates them onto a typed, revocable
    credential. A token we cannot read is left alone (return False): the hub
    will reject it on connect if it is truly bad, which is the right place.
    """
    c = _claims(token)
    exp, iat = c.get("exp"), c.get("iat")
    if not isinstance(exp, (int, float)):
        return False
    if isinstance(iat, (int, float)):
        return time.time() >= iat + (exp - iat) / 2
    # No iat (legacy): rotate when less than half of a 365-day life remains.
    return exp - time.time() < 182 * 86400


def persist_rotated(identity_path: Path, host_id: str, token: str, hub: str) -> bool:
    """Atomically write the rotated credential. Returns False if it could not be
    written -- caller keeps using the current credential, no harm done."""
    rp = rotated_path(identity_path)
    if rp is None:
        logger.warning("no writable dir for rotated credential; rotation disabled")
        return False
    payload = json.dumps({"host_id": host_id, "token": token, "hub": hub}, indent=2)
    try:
        fd, tmp = tempfile.mkstemp(dir=str(rp.parent), prefix=".idrot.")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, rp)  # atomic on POSIX and Windows
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return True
    except OSError as exc:
        logger.warning("could not persist rotated credential: %s", exc)
        return False
