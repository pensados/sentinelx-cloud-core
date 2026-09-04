"""Identity: load /etc/sentinelx/identity.json (host_id + enrollment token)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Identity:
    """Loaded from identity.json — written by sentinelx-installer."""

    host_id: str
    token: str
    hub: str


class IdentityError(Exception):
    """Identity file is missing or malformed."""


def _validate_token(token: str, path: Path) -> str:
    """Reject a token that cannot possibly authenticate, loudly and early.

    The commonest field failure is a token corrupted on copy-paste: browser
    page translation rewrites the DOM and injects invisible / non-ASCII
    characters, or the token gets split across lines. Left alone, such a token
    is written to identity.json and the agent then loops forever on an opaque
    403 at /agent/connect. Failing here, at load, turns that into one clear
    line in the service log.
    """
    if not token:
        raise IdentityError(
            f"enrollment token in {path} is empty — re-run enrollment for this host"
        )
    if not token.isascii():
        raise IdentityError(
            f"enrollment token in {path} contains non-ASCII characters, which almost "
            "always means it was corrupted on copy-paste (browser page translation is "
            "the usual cause). Re-run enrollment and paste the token exactly, with page "
            "translation turned off."
        )
    if any(ch.isspace() for ch in token):
        raise IdentityError(
            f"enrollment token in {path} contains whitespace — copy the token as one "
            "unbroken string and re-run enrollment"
        )
    if token.count(".") != 2 or not all(token.split(".")):
        raise IdentityError(
            f"enrollment token in {path} is not a well-formed token (expected three "
            "dot-separated parts) — re-run enrollment and copy the whole token"
        )
    return token


def load_identity(path: Path) -> Identity:
    if not path.exists():
        raise IdentityError(
            f"identity file not found at {path} — run sentinelx-enroll to enroll this host"
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise IdentityError(f"could not read {path}: {exc}") from exc

    for required in ("host_id", "token", "hub"):
        if required not in data:
            raise IdentityError(f"identity file missing field: {required}")

    # Trim whitespace/newlines that ride along on copy-paste, then validate the
    # token so a corrupted paste fails here with a clear message instead of
    # looping on an opaque 403 forever.
    host_id = str(data["host_id"]).strip()
    hub = str(data["hub"]).strip()
    token = _validate_token(str(data["token"]).strip(), path)
    return Identity(host_id=host_id, token=token, hub=hub)
