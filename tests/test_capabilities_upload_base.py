"""capabilities reports where uploads actually land.

The agent resolves its staging directory at start-up: from the config, or the
first writable candidate (/var/lib/sentinelx/uploads, then the legacy
/home/sentinelx/uploads), or the system temp space. Nothing exposed which one
won, so anything host-side that resolves a bare filename had to hard-code our
path -- and broke silently when it guessed wrong. One operator reported it
after writing to three different directories trying to find the right one;
another asked for exactly this on the same day.
"""

from __future__ import annotations

from pathlib import Path


from sentinelx_core.handlers.basic import make_capabilities_handler
from sentinelx_core.handlers.progressive_help import summarize_capabilities


def _policy():
    from sentinelx_core.policy import Policy
    return Policy.from_dict({"allowed_commands": ["echo"]})


async def _caps(upload_base, detail=None):
    handler = make_capabilities_handler(_policy(), None, upload_base=upload_base)
    return await handler({"detail": detail} if detail else {})


async def test_the_resolved_directory_is_reported():
    caps = await _caps(Path("/var/lib/sentinelx/uploads"))
    assert caps["upload_base"] == "/var/lib/sentinelx/uploads"


async def test_a_non_default_directory_is_reported_as_is():
    """The whole point: a host that staged somewhere else must say so, rather
    than leaving the caller to assume the default."""
    caps = await _caps(Path("/srv/staging/sentinelx"))
    assert caps["upload_base"] == "/srv/staging/sentinelx"


async def test_the_legacy_directory_is_reported_too():
    caps = await _caps(Path("/home/sentinelx/uploads"))
    assert caps["upload_base"] == "/home/sentinelx/uploads"


async def test_it_is_null_rather_than_missing_when_unknown():
    """A caller must be able to tell 'not reported' from 'empty string', and
    the key has to be present either way so clients can rely on it."""
    caps = await _caps(None)
    assert "upload_base" in caps
    assert caps["upload_base"] is None


async def test_the_summary_keeps_it():
    """Clients on the compact view need it as much as the others."""
    caps = await _caps(Path("/var/lib/sentinelx/uploads"), detail="summary")
    assert caps.get("upload_base") == "/var/lib/sentinelx/uploads"


async def test_it_is_not_presented_as_a_writable_file_ops_path():
    """Staging there grants nothing under file_ops, and on most hosts it is not
    in that list at all. Conflating them would overstate the access."""
    caps = await _caps(Path("/var/lib/sentinelx/uploads"))
    file_ops = caps["file_ops"]
    assert caps["upload_base"] not in file_ops["writable_paths"]
    assert caps["upload_base"] not in file_ops["allowed_read_paths"]


async def test_summarize_does_not_invent_a_value():
    assert summarize_capabilities({"file_ops": {}}).get("upload_base") is None
