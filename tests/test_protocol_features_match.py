"""Every advertised protocol feature must be one the agent can actually receive.

Executor.PROTOCOL_FEATURES goes out in the hello, and the hub sends a field only
to an agent that asked for it. RequestMessage is extra="forbid", so advertising
a field the pinned protocol does not define is worse than not advertising it:
the hub starts sending it and the agent rejects the WHOLE message, dropping the
operation rather than ignoring the extra.

That is exactly what a clean install of core 0.15.0 did. It advertised
opaque_ref while pyproject pinned protocol v1.11.0, where RequestMessage has no
such field, so every tagged request died with extra_forbidden before dispatch.
Found by FalconZip, who installed from the declared dependency rather than from
a working tree that happened to have a newer protocol sitting in it -- which is
why none of us saw it.

This test compares the advertisement against the INSTALLED protocol, so it fails
in the same environment a user would get.
"""

from __future__ import annotations

import pytest
from sentinelx_protocol import RequestMessage

from sentinelx_core.executor import Executor


def test_every_advertised_feature_exists_in_the_pinned_protocol():
    fields = set(RequestMessage.model_fields)
    missing = [f for f in Executor.PROTOCOL_FEATURES if f not in fields]
    assert not missing, (
        f"hello advertises {missing}, but the installed protocol's RequestMessage "
        f"has no such field. extra='forbid' means the hub would send it and this "
        f"agent would reject the entire message. Bump the protocol pin in "
        f"pyproject.toml, or stop advertising the feature."
    )


def test_opaque_ref_specifically_is_receivable():
    """The one that broke; named so a regression says what it is."""
    assert "opaque_ref" in RequestMessage.model_fields


def test_a_request_carrying_opaque_ref_actually_parses():
    """Field presence is not enough -- it has to survive validation."""
    msg = RequestMessage(
        id="req_1", op="exec", payload={}, opaque_ref="A7K2"
    )
    assert msg.opaque_ref == "A7K2"


def test_the_documented_bound_is_enforced():
    with pytest.raises(Exception):
        RequestMessage(id="req_1", op="exec", payload={}, opaque_ref="x" * 257)


def test_the_field_remains_optional():
    """An agent that never sets it must still build a valid request."""
    assert RequestMessage(id="req_1", op="exec", payload={}).opaque_ref is None


def test_unknown_fields_are_still_refused():
    """Guards the premise: if extra stopped being forbid, the test above is moot."""
    assert RequestMessage.model_config.get("extra") == "forbid"
    with pytest.raises(Exception):
        RequestMessage(id="req_1", op="exec", payload={}, not_a_real_field="x")
