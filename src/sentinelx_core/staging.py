"""Where the agent stages content before writing it somewhere else.

`edit` and `script_run` do not write to the target directly: they first stage
the new content (or the script) in a workdir under `upload_base`. That makes
the staging directory a prerequisite for REPAIRING the agent's own config --
and `upload_base` is itself read from that config. Emptying config.yaml
therefore used to break `edit` too: the policy fell back to a default path the
service user could not write, staging failed with a bare permission error, and
the one tool that could have restored the config was the tool that stopped
working. A tempdir fallback keeps repair possible no matter what the config
says.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_STAGING_DIRNAME = ".sentinelx_uploads"
_warned: set[str] = set()


def fallback_root() -> Path:
    """Last-resort staging root: a private dir in the system temp space."""
    return Path(tempfile.gettempdir()) / "sentinelx-staging" / _STAGING_DIRNAME


def staging_root(upload_base: Path) -> Path:
    """Return a WRITABLE staging root, preferring the configured upload_base.

    Falls back to the system temp space when upload_base cannot be created or
    written, warning once per path so the misconfiguration stays visible
    without flooding the log on every call. Raises only if even the temp
    fallback is unusable, and then with a message naming both paths.
    """
    primary = upload_base / _STAGING_DIRNAME
    try:
        primary.mkdir(parents=True, exist_ok=True)
        return primary
    except OSError as exc:
        fallback = fallback_root()
        try:
            fallback.mkdir(parents=True, exist_ok=True)
        except OSError as exc2:
            raise OSError(
                f"no writable staging directory: {primary} ({exc}) and "
                f"{fallback} ({exc2}) both failed. Set `upload_base` in "
                f"/etc/sentinelx/config.yaml to a directory the agent user "
                f"can write."
            ) from exc2
        key = str(primary)
        if key not in _warned:
            _warned.add(key)
            logger.warning(
                "staging_fallback: cannot use %s (%s); staging under %s "
                "instead. Set `upload_base` in the agent config to a "
                "directory the agent user can write.",
                primary,
                exc,
                fallback,
            )
        return fallback
