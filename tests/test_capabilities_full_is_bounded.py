"""A large capabilities detail=full arrives trimmed, not as a bare note.

sxrep_W0RW3FVD97RJ / sxrep_95SMJC6TJ0CE: a host with ~400 services got
'result omitted: too large to bound field-wise' (166 KB -> 308 bytes). The bulk
of a real capabilities response is in dicts keyed by name (services, playbooks,
locations), which protocol 1.13.1 still could not trim. This builds the response
with the real handler and a large policy, then bounds it as the agent does.
"""

from __future__ import annotations

from sentinelx_protocol.bounding import RESPONSE_SOFT_LIMIT_BYTES as SOFT
from sentinelx_protocol.bounding import bound_response, serialized_size

from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


def _large_policy() -> Policy:
    services = {
        f"svc-{i:03d}": {
            "actions": ["status", "start", "stop", "restart"],
            "description": f"Workload {i}: " + "keeps the customer pipeline running " * 4,
        }
        for i in range(400)
    }
    playbooks = {
        f"runbook-{i}": {
            "description": "How to recover the service safely. " * 10,
            "steps": [f"Step {j}: check the state, then act. " * 3 for j in range(30)],
        }
        for i in range(13)
    }
    return Policy.from_dict({"allowed_commands": ["ls", "cat", "systemctl"],
                             "services": services, "playbooks": playbooks})


async def test_a_large_capabilities_full_is_trimmed_not_dropped():
    caps = await build_registry(policy=_large_policy())["capabilities"]({"detail": "full"})
    env = {"type": "response", "id": "caps", "ok": True, "result": caps}
    assert serialized_size(env) > SOFT                      # really over the limit
    out, meta = bound_response(env)
    got = out["result"]
    assert serialized_size(out) <= SOFT
    assert "note" not in got                                 # not the wholesale note
    assert got["version"] == caps["version"]
    assert got["ops_supported"] == caps["ops_supported"]
    assert got["allowed_commands"] == ["ls", "cat", "systemctl"]
    assert isinstance(got["services"], dict) and got["services"]
    paths = [e["path"] for e in meta.get("omitted", [])]
    assert any(p in ("/services", "/playbooks") for p in paths)
