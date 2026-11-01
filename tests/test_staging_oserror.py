"""A host condition while preparing the work area gets a name, not internal_error.

script_run stages into a work directory. A full disk surfaced there as a bare
"internal_error: [Errno 28] No space left on device", which reads like an agent
defect. An operator chased a duplicate_session symptom for hours -- the real
cause was ENOSPC restarting the agent in a loop, and each reconnect closing the
previous session. Naming the condition is what makes that chain visible.
"""

from __future__ import annotations

import errno

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers.script import _staging_oserror

PATH = "/var/lib/sentinelx/uploads/.sentinelx_uploads/script_job_x"


def _code(err: int) -> str:
    return _staging_oserror(OSError(err, "x"), PATH).code


def test_full_disk_is_no_space():
    assert _code(errno.ENOSPC) == "no_space"


def test_permission_is_permission_denied():
    assert _code(errno.EACCES) == "permission_denied"
    assert _code(errno.EPERM) == "permission_denied"


def test_read_only_mount_is_named():
    assert _code(errno.EROFS) == "read_only_filesystem"


def test_anything_else_is_staging_failed_not_internal():
    """Still named, still not a bare internal_error."""
    assert _code(errno.EIO) == "staging_failed"


def test_it_returns_a_handler_error():
    assert isinstance(_staging_oserror(OSError(errno.ENOSPC, "x"), PATH), HandlerError)


def test_the_path_is_in_the_message():
    msg = str(_staging_oserror(OSError(errno.ENOSPC, "x"), PATH))
    assert PATH in msg


def test_no_space_says_it_is_a_host_condition():
    """The operator must know to look at the host, not at their policy."""
    msg = str(_staging_oserror(OSError(errno.ENOSPC, "x"), PATH)).lower()
    assert "host condition" in msg
    assert "not a policy" in msg


def test_no_space_warns_that_other_errors_may_be_downstream():
    """The whole point of this report: a full disk destabilises the agent, so
    unrelated failures on the same host may be consequences."""
    msg = str(_staging_oserror(OSError(errno.ENOSPC, "x"), PATH)).lower()
    assert "unstable" in msg
