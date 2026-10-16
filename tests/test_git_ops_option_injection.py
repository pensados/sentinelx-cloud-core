"""git_ops rejects option-like remotes/refs (GHSA-r2h3-76g7-m95x).

`remote`/`ref`/`ref_pattern` went to git unvalidated and with no `--`, so a value like
--upload-pack=<cmd> made git run <cmd>.
"""

from __future__ import annotations

import pytest

from sentinelx_core.handlers import git_ops as g
from sentinelx_core.executor import HandlerError


@pytest.mark.parametrize("payload", [
    {"remote": "--upload-pack=touch /tmp/x"},
    {"remote": "-oProxyCommand=x"},
    {"remote": "origin", "ref_pattern": "--upload-pack=x"},
])
async def test_ls_remote_rejects_option_like_values(payload):
    with pytest.raises(HandlerError) as e:
        await g._op_ls_remote(None, payload)
    assert e.value.code == "invalid_payload"


async def test_fetch_rejects_option_like_remote_and_ref():
    with pytest.raises(HandlerError):
        await g._op_fetch(None, {"path": "/x", "remote": "--upload-pack=x"})


def test_dashes_before_positionals():
    # The guard function keeps a plain value and rejects a leading dash.
    assert g._reject_option_like("origin", "remote") == "origin"
    with pytest.raises(HandlerError):
        g._reject_option_like("--foo", "remote")
