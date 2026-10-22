"""`local_api` op: list, describe and call host-local structured endpoints.

Registered ONLY when the host declares `local_apis`. A host without that block
gets no handler and advertises no capability, so this is additive by
construction: nothing changes for the fleet that does not opt in.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinelx_core.local_api import LocalApiError, call_action
from sentinelx_core.policy import Policy

logger = logging.getLogger(__name__)


def _param_names(action: Any) -> list[str]:
    """Parameter names for one action, from whichever source it has.

    A declared schema wins because it is the richer statement; the template is
    the fallback and needs no declaring. Required names come first, since that
    is the order a caller cares about.
    """
    schema = getattr(action, "params_schema", None)
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            required = [r for r in (schema.get("required") or []) if r in props]
            rest = sorted(k for k in props if k not in required)
            return list(required) + rest
    return sorted(
        {
            seg.split("}")[0]
            for seg in (getattr(action, "request", None) or "").split("{")[1:]
            if "}" in seg
        }
    )


def make_local_api_handler(policy: Policy):
    """Build the handler over this host's configured endpoints."""

    async def handle_local_api(payload: dict[str, Any]) -> dict[str, Any]:
        operation = str(payload.get("operation") or "").strip()

        if operation == "list":
            return {
                "ok": True,
                "operation": "list",
                "endpoints": [
                    {
                        "name": e.name,
                        "protocol": e.protocol,
                        "transport": e.transport,
                        "action_count": len(e.actions),
                    }
                    for e in policy.local_apis.values()
                ],
            }

        name = str(payload.get("endpoint") or "").strip()
        endpoint = policy.local_apis.get(name)
        if endpoint is None:
            return {
                "ok": False,
                "error": "endpoint_not_configured",
                "message": (
                    f"no local endpoint named '{name}' on this host. "
                    f"Configured: {sorted(policy.local_apis)}"
                ),
            }

        if operation == "describe":
            # Mandatory, not a convenience. Without it the model has to guess
            # the shape of `params`, and a guessed call against an opaque
            # endpoint is exactly what the action allowlist exists to prevent.
            return {
                "ok": True,
                "operation": "describe",
                "endpoint": endpoint.name,
                "protocol": endpoint.protocol,
                "transport": endpoint.transport,
                # For stdio, what runs. The COUNT of args and not their values:
                # an operator may put a token or a private path there.
                **(
                    {
                        "path": endpoint.path,
                        "handshake": endpoint.handshake,
                        "arg_count": len(endpoint.args),
                    }
                    if endpoint.transport == "stdio"
                    else {}
                ),
                "actions": {
                    an: {
                        "request": a.request,
                        "method": a.method,
                        "returns": list(a.select) or "the endpoint's own shape",
                        "description": a.description,
                        # Names the caller must supply. Two sources, and the
                        # field stays a list of names either way so a consumer
                        # that only reads this keeps working:
                        #
                        #   HTTP     -> the {placeholders} in the request
                        #               template, which cannot drift from what
                        #               actually runs.
                        #   JSON-RPC -> the properties of the declared schema.
                        #               There is no template to read, so
                        #               without a declaration this was empty
                        #               for every such action.
                        "params": _param_names(a),
                        # The declared shape, verbatim, when the profile gives
                        # one. Nested objects, arrays and enums live here; the
                        # flat list above cannot express them. Absent when
                        # undeclared rather than null, so its presence means
                        # something.
                        **(
                            {"params_schema": a.params_schema}
                            if a.params_schema
                            else {}
                        ),
                    }
                    for an, a in sorted(endpoint.actions.items())
                },
            }

        if operation == "call":
            action = str(payload.get("action") or "").strip()
            params = payload.get("params") or {}
            if not isinstance(params, dict):
                return {
                    "ok": False,
                    "error": "invalid_payload",
                    "message": "params must be an object",
                }
            try:
                result = await call_action(endpoint, action, params)
            except LocalApiError as exc:
                logger.warning(
                    "local_api call failed: %s/%s: %s", name, action, exc.code
                )
                return {"ok": False, "error": exc.code, "message": exc.message}
            return {
                "ok": True,
                "operation": "call",
                "endpoint": endpoint.name,
                "action": action,
                "result": result,
            }

        return {
            "ok": False,
            "error": "invalid_payload",
            "message": f"unknown operation '{operation}'; expected list, describe or call",
        }

    return handle_local_api
