# Security Policy

This document is for users, operators, and reviewers of the SentinelX agent
(this repo, `sentinelx-cloud-core`). It explains what the agent is designed
to defend against, how to report vulnerabilities, and what the project
considers in-scope vs. out-of-scope.

For a deeper technical breakdown of the threats and trust boundaries, see
[`THREAT_MODEL.md`](./THREAT_MODEL.md).


## Reporting a vulnerability

**Please do NOT open public GitHub issues for security bugs.**

Use **GitHub's Private Vulnerability Reporting** for this repository:

  1. Go to <https://github.com/pensados/sentinelx-cloud-core/security>
  2. Click **"Report a vulnerability"**
  3. Fill in the form (title, description, affected version, severity)

This creates a private discussion between you and the maintainer, with no
public exposure until a fix is ready and the advisory is published.

If for any reason you cannot use GitHub Advisories, email
**carlos@pensa.com.ar** with `[security]` in the subject.

### What to include

A useful report typically contains:
  - A short description of the issue and the impact
  - Steps to reproduce (commands, payloads, agent version)
  - Affected files / functions if you've already located them
  - Suggested fix or mitigation if you have one (optional)

### Response timeline

  - **Acknowledgement:** within 72 hours
  - **Initial assessment** (triage, severity, scope): within 7 days
  - **Fix or mitigation:** target 30 days for high/critical, best-effort otherwise
  - **Public disclosure:** coordinated with the reporter; typically when a
    fix has shipped to the public installer (`get.sentinelx.app`)

### Safe-harbor

If you act in good faith — meaning you don't exfiltrate data beyond what's
needed to demonstrate the issue, you don't access other users' data, and you
report privately before public disclosure — the project will not pursue
legal action over your research.


## What the agent is designed to defend against

The agent runs as `sentinelx` on a user's host, with passwordless `sudo` for
specific operations (`sudo` for `pensa-safe-edit` and listed services). It
connects out to a hub via WebSocket and exposes operations as MCP tools.

The hard rules:

  1. **The agent only does what the operator's policy allows.**
     `/etc/sentinelx/config.yaml` is the security boundary, together with
     the unix user and sudo policy the agent runs under. For `exec`,
     `exec_mode` decides: in `allowlist` (the default) and `strict`, every
     command in a line must be covered by `allowed_commands`, so a
     malicious or compromised hub cannot make the agent run a command
     outside that list through `exec`; in `unrestricted`, `exec` runs
     anything the agent's account may run. `script_run` runs arbitrary
     scripts as the agent's user and is NOT limited by `allowed_commands`:
     where the allowlist must hold even against a compromised hub, disable
     it with `disabled_ops: [script_run]` and keep `exec_mode` at
     `allowlist` or `strict`.

  2. **The agent has no inbound listening ports.**
     Only one outbound WebSocket to the hub. There is no way to reach the
     agent from the public internet, the LAN, or the host itself except
     through that single connection.

  3. **One compromised host does not compromise others.**
     Each host has its own JWT identity, signed by the hub at enrollment.
     There is no shared secret. The hub authorizes operations per-user, not
     per-host-class.

  4. **`upload_file` with a URL respects an explicit allowlist.**
     `security.trusted_fetch_hosts` gates the hostname; the resolved IP is
     then validated against loopback / RFC1918 / link-local ranges.
     Redirects are disabled. https only. The default allowlist is empty
     (`file_url` effectively disabled until the operator opts in). See
     [`THREAT_MODEL.md`](./THREAT_MODEL.md#ssrf-via-file_url) for the
     attacker's view.

  5. **File operations are confined to safe paths.**
     All `target_path` arguments to upload and edit operations are resolved
     under `upload_base` via `safe_path_under()` (in
     `src/sentinelx_core/executor_engine.py`). Path traversal attempts
     (`..`, absolute paths escaping the base) are rejected before any I/O.

  6. **No telemetry.**
     The agent emits nothing about the host or its activity to anyone but
     the hub it's explicitly enrolled to. No analytics, no third-party
     SDKs, no calls home.


## Defenses, by code reference

Reviewers can audit each defense at the linked path:

| Defense | Code |
|---|---|
| Command allowlist (whole-word match, every command in a chain, `exec_mode`) | `src/sentinelx_core/policy.py`, `src/sentinelx_core/segment_check.py`, `src/sentinelx_core/handlers/exec.py` |
| Path-traversal rejection | `src/sentinelx_core/executor_engine.py` (`safe_path_under`) |
| `file_url` SSRF defense | `src/sentinelx_core/handlers/upload.py` (`_validate_fetch_url`, `_is_safe_ip`, `_NoRedirectHandler`) |
| `file_url` allowlist + timeout config | `src/sentinelx_core/policy.py` (`trusted_fetch_hosts`, `file_url_timeout_seconds`) |
| Service action allowlist | `src/sentinelx_core/policy.py` (`ServiceSpec.actions`) |
| Hub JWT validation | `src/sentinelx_core/identity.py` |
| WebSocket reconnection (no inbound) | `src/sentinelx_core/ws_client.py` |
| Tests covering the above | `tests/test_handlers_upload.py`, `tests/test_policy.py` |


## Known limitations and out-of-scope

These are deliberate design choices, not vulnerabilities. We document them
so reviewers can decide whether they're acceptable for their threat model.

### What we DON'T defend against

  - **A malicious operator.** If the operator allowlists `sudo rm -rf /` in
    `config.yaml`, the agent will happily run `sudo rm -rf /`. The
    allowlist is a tool the operator uses to constrain the LLM; it's not a
    safety net against the operator misusing it.

  - **A compromised host kernel or sudo binary.** The agent runs in a
    standard Linux user-space environment. If `/usr/bin/sudo` is replaced
    by something malicious, or the kernel is rootkit-ed, the agent's
    boundaries don't help.

  - **Exfiltration via legitimate operations.** If the operator allows
    `cat` and the LLM is convinced to run `cat /etc/passwd`, the contents
    flow back through the hub to the LLM. The defense against this is the
    allowlist (don't allow tools that read sensitive paths), not anything
    in the agent's code.

  - **Resource exhaustion (DoS).** A malicious hub can cause many tool
    invocations and tie up agent resources. Rate limiting on the hub side
    is the appropriate mitigation; the agent itself does not currently
    rate-limit.

  - **Side channels.** Timing, error-message length, and similar oracles
    are not actively mitigated. We minimize obvious leaks (e.g., we don't
    return raw stack traces to the hub) but we don't claim
    constant-time behavior.

### Things that might be assumed but aren't

  - **There is no sandbox.** The agent shells out to real binaries via
    `subprocess.run`. There is no chroot, no namespace isolation, no
    seccomp filter beyond what the OS gives `sentinelx` by default. The
    allowlist is the boundary; if it allowlists `bash`, you've just
    allowlisted everything.

  - **`sudo NOPASSWD` is opt-in but on by default.** The installer's
    default grants `sentinelx` passwordless `sudo` for a small set of
    binaries (`pensa-safe-edit`, listed services). To install with no
    sudo at all, set `SENTINELX_SKIP_SUDO=1` during install — the agent
    still works, but operations that require root will fail.

  - **The hub is trusted with respect to message contents.** The agent
    verifies the hub's TLS certificate and signs/verifies messages at
    the protocol layer, but it executes whatever (allowlisted) command
    the hub asks it to. If the hub is compromised, the attacker can
    invoke any allowlisted operation. The 4 defenses above (allowlist,
    no inbound, JWT identity, SSRF allowlist) cap the blast radius but
    don't reduce it to zero.


## Updates and disclosure

  - Security fixes are released as patch-level versions on the `main`
    branch and tagged (e.g., `v0.2.1`).
  - Hosts running the standard installer can update with:
    ```bash
    cd /opt/sentinelx-cloud-core && git pull && \
        sudo systemctl restart sentinelx-cloud-core
    ```
  - Security advisories are published at
    <https://github.com/pensados/sentinelx-cloud-core/security/advisories>.
  - High-severity issues are also announced via the SentinelX hub admin
    channel; affected operators receive a notice in their dashboard.


## Hall of fame

Reporters who help improve the project's security are credited here (with
their permission) once a published advisory closes the issue.

_(no public reports yet — the project is young; this section will grow)_
