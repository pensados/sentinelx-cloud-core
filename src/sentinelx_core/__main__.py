"""Entrypoint: `python -m sentinelx_core` or `sentinelx-core`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from sentinelx_core.client import HubClient
from sentinelx_core.identity import IdentityError, load_identity


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelx-core")
    parser.add_argument("--hub", help="Hub URL (overrides identity.json)")
    parser.add_argument(
        "--identity",
        default="/etc/sentinelx/identity.json",
        type=Path,
        help="Path to identity.json (default: /etc/sentinelx/identity.json)",
    )
    parser.add_argument("--config", default="/etc/sentinelx/config.yaml", type=Path)
    parser.add_argument(
        "--verify-enrollment",
        action="store_true",
        help="Check that the hub accepts this host's enrollment token, then "
             "exit (0 accepted, 1 rejected or unreachable). Opens one "
             "connection and starts no session, so it is safe to run while "
             "the agent is running. Use it right after enrolling: a token "
             "altered while being copied is otherwise only visible as a "
             "background retry in the logs.",
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--log-file",
        default=None,
        type=Path,
        help="Log to this file instead of stderr (used by the windowless "
             "Windows user-mode Scheduled Task, which has no console).",
    )
    args = parser.parse_args()

    log_kwargs = {
        "level": args.log_level.upper(),
        "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
    }
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        log_kwargs["filename"] = str(args.log_file)
    else:
        log_kwargs["stream"] = sys.stderr
    logging.basicConfig(**log_kwargs)

    # On networks with a TLS-inspecting proxy (common in corporate/enterprise
    # setups), the hub's certificate is reissued by a private CA that the OS
    # trusts but Python's bundled OpenSSL may reject (e.g. a CA cert whose Basic
    # Constraints aren't marked critical). truststore delegates verification to
    # the OS trust store, which accepts it. Optional: only active if installed
    # (it ships in the Windows offline bundle); a harmless no-op everywhere else.
    try:
        import truststore
        truststore.inject_into_ssl()
        logging.getLogger("sentinelx_core").info("truststore active (OS trust store)")
    except Exception:
        pass

    try:
        identity = load_identity(args.identity)
    except IdentityError as exc:
        logging.getLogger("sentinelx_core").error("identity: %s", exc)
        sys.exit(1)
    hub_url = args.hub or identity.hub

    if args.verify_enrollment:
        from sentinelx_core.preflight import verify_enrollment

        result = asyncio.run(verify_enrollment(hub_url, identity.token))
        log = logging.getLogger("sentinelx_core")
        if result.ok:
            log.info("enrollment OK: %s accepts this host's token", hub_url)
            sys.exit(0)
        if result.reason == "unreachable":
            log.error(
                "could not reach the hub at %s (%s). This says nothing about "
                "the token; check network, DNS and TLS first.",
                hub_url,
                result.detail,
            )
        else:
            log.error(
                "enrollment REJECTED by %s (%s). The token in %s is not one "
                "the hub will accept -- it can be altered when copied. Re-run "
                "enrollment from the dashboard and install the fresh token. "
                "If instead this host was disabled in the dashboard, re-enable "
                "it there.",
                hub_url,
                result,
                args.identity,
            )
        sys.exit(1)

    client = HubClient(
        hub_url=hub_url,
        identity=identity,
        config_path=args.config,
    )

    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
