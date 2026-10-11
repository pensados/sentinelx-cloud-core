# Threat Model — sentinelx-cloud-core

This document describes the threat model the agent is designed against. It's
the "deeper" companion to [`SECURITY.md`](./SECURITY.md), aimed at people
auditing the code, integrating SentinelX into their stack, or evaluating it
for compliance review.

The structure is roughly:
  1. What we're protecting (assets)
  2. Who we're protecting it from (adversaries)
  3. Where the trust boundaries are (architecture diagram)
  4. Specific threats and how we mitigate them
  5. Residual risks we accept


## 1. Assets

The agent sits on a host belonging to the operator. The assets it could
plausibly leak or damage:

| Asset | Where it lives | Loss impact |
|---|---|---|
| Host filesystem (read) | `/`, `/etc`, `/var`, user homes | Confidentiality of secrets, configs, code |
| Host filesystem (write) | Same, gated by sudo + allowlist | Integrity / availability — files modified, services downed |
| Service control | systemd units listed in `services:` | Availability — services stopped or restarted at attacker timing |
| Cloud metadata credentials | `169.254.169.254` (AWS/GCP/Azure) | If the host is in a cloud, IAM credentials can pivot to cloud account compromise |
| Internal network | RFC1918 routes the host can reach | Lateral movement (DBs, internal admin panels, VPN-reachable corp networks) |
| The agent's JWT identity | `/etc/sentinelx/identity.json` | Impersonation of this host to the hub |
| The hub's trust in this host | `host_id` registered at hub | Could let attacker route hub-bound queries to a different host |
| Operator credentials transiting through tools | e.g., `cat ~/.aws/credentials` if allowed | Direct credential theft |


## 2. Adversaries

We model three concrete adversary personas. The agent's defenses target the
first two; the third is mostly out-of-scope and noted for completeness.

### A1 — Compromised hub (or hub operator turned malicious)

The hub at `mcp.sentinelx.app` is operated by Pensa (project owner). An
attacker who compromises the hub — or an insider who turns malicious — has
full control over what messages reach each agent. The agent **must defend
itself against its own hub**, because:

  - If a hub compromise meant total host compromise, the failure mode of
    the entire SentinelX system would be unbounded.
  - Reviewers (Anthropic, OpenAI) need to be able to assert that an agent
    install does not give Pensa root on the user's box.

**Capabilities of A1:**
  - Send arbitrary WebSocket messages to the agent
  - Choose any operation the protocol supports
  - Provide attacker-controlled values for any parameter
  - Observe responses
  - Time tool invocations

**NOT capabilities of A1:**
  - Forge another host's identity (each host has its own JWT)
  - Bypass TLS to the agent (cert pinning at hub URL)
  - Read or write the host's local filesystem outside what tools expose
  - Execute commands not in the operator's allowlist


### A2 — Compromised LLM client / malicious tool client

The MCP client (Claude.ai, ChatGPT, or any other) calls tools through the
hub. A compromised LLM or a malicious user driving the LLM to do harm is
indirectly an adversary against the agent. They can invoke any tool the
operator's allowlist permits, with any argument.

**Capabilities of A2:** same as A1 in practice — the hub forwards their
calls to the agent. The agent does not distinguish hub-originated from
client-originated calls; both are treated as untrusted input.

**The defense is identical to A1's:** allowlist, parameter validation,
SSRF allowlist.


### A3 — Local attacker on the host (out of scope)

If an attacker already has a shell on the host, the agent's defenses are
moot — they can read `identity.json`, modify `config.yaml`, install a
keylogger in `/usr/bin`, etc. We don't attempt to defend against this.

The reasonable thing to do if you suspect host compromise is to revoke the
host's enrollment from the hub admin panel, then reinstall.


## 3. Trust boundaries

```
                                        Trust boundary 1: TLS + WebSocket
                                                       │
   ┌────────────────────────────────┐                  │     ┌────────────────────────────────────┐
   │  Hub (mcp.sentinelx.app)       │   outbound WSS   │     │  Host running this agent            │
   │  Operated by Pensa             │ ◄────────────────┼───► │                                     │
   │                                │                  │     │  ┌─────────────────────────────┐    │
   │  - Receives MCP from clients   │                  │     │  │  agent (sentinelx user)     │    │
   │  - Authenticates via Keycloak  │                  │     │  │                             │    │
   │  - Routes messages to agents   │                  │     │  │  • allowlist enforcement   ◄─── Trust boundary 2:
   │                                │                  │     │  │  • SSRF check on file_url  ◄─── allowlist + safe_path
   │  ASSUMED HOSTILE in this model │                  │     │  │  • path-traversal rejection │    │
   └────────────────────────────────┘                  │     │  │                             │    │
                                                       │     │  └──────┬──────────────────────┘    │
                                                       │     │         │ subprocess.run             │
                                                       │     │         │ (sudo NOPASSWD for         │
                                                       │     │         │  vetted binaries only)     │
                                                       │     │         ▼                            │
                                                       │     │  ┌─────────────────────────────┐    │
                                                       │     │  │  OS / kernel / sudo binary  │    │
                                                       │     │  │  ASSUMED TRUSTED            │    │
                                                       │     │  └─────────────────────────────┘    │
                                                       │     └────────────────────────────────────┘
```

**Boundary 1 (network):** the agent uses TLS with hostname verification
and the hub's domain pinned in the agent's config. The agent will not talk
to a different hub even if DNS lies. If the TLS cert chain fails to
validate, the connection is dropped.

**Boundary 2 (process):** the agent is a single Python process running as
the unprivileged `sentinelx` user. Operations that require root go
through `sudo` for a small set of binaries explicitly listed in the
sudoers fragment installed by `install.sh`. **The allowlist sits on top
of this** — even if `sudo` is misconfigured wider than intended, the
allowlist still constrains what the agent can ask sudo to run.


## 4. Threats and mitigations

We use a STRIDE-style enumeration. Each threat has: severity, attack
vector, mitigation, and residual risk.

### 4.1 — Tampering with command via crafted payload

| | |
|---|---|
| **STRIDE category** | Tampering / Elevation of Privilege |
| **Attacker** | A1, A2 |
| **Vector** | Send `exec` op with `command="../../../bin/rm -rf /"` or a command with shell metacharacters meant to escape |
| **Severity** | High if exploitable |
| **Mitigation** | `exec` runs the command string through a shell (`bash -lc`), and `allowed_commands` is a PREFIX match on that string. So the allowlist constrains what a command may START with, not the whole of what runs: by design it is not a hard sandbox. Operators who need a per-segment boundary turn on `exec_strict`, which splits the command on `;`, `\|`, `&&`, `\|\|` and a lone `&`, refuses newlines/control characters, command and process substitution, and file redirections, and requires every segment to be covered by the allowlist. A fixed set of read-only filters (`grep`, `head`, `sort`, `cut`, ...) is allowed after a pipe, but only without a file-path operand and without their write/execute options; filters that execute or write (`sed`, `awk`, `jq`, `tee`) are not in that set and must be allowlisted by name. `script_run` is the explicit path for a real workflow. |
| **Residual risk** | `exec` without `exec_strict` is a prefix allowlist over a shell: an operator who relies on it as a sandbox, or who allowlists `bash`/`sh -c`/a shell-invoking interpreter, gets no real boundary. `exec_strict` narrows this to vetted single commands and read-only pipelines; anything beyond that belongs in `script_run` or an OS-level boundary (dedicated user, sudoers, namespaces). SentinelX does not yet offer a shell-free argv exec mode. |

### 4.2 — Path traversal in upload / edit / mutation target

| | |
|---|---|
| **STRIDE category** | Tampering |
| **Attacker** | A1, A2 |
| **Vector** | `upload_file` with `target_path="../../../etc/passwd"`, or `edit`/`move`/`copy`/`delete`/`chmod`/`chown` with a `path` (or `src`/`dst`) that escapes the allowlist via `..` or a planted symlink |
| **Severity** | Critical (arbitrary write/destroy as `sentinelx`, then `sudo` if applicable) |
| **Mitigation** | Two layers. (1) `executor_engine.py::safe_path_under()` resolves the candidate path against the upload base, walks symlinks, and rejects escapes — applied to upload handlers. (2) The unified r/rw path model: `Policy.resolve_path()` canonicalizes symlinks *before* the prefix check and is called with `need_write=True` by every mutating op. `edit` (both `handle_edit` and `edit_upload_complete`) and the five destructive ops (`move`/`copy`/`delete`/`chmod`/`chown`) all funnel every path argument through it; for `move`/`copy` BOTH `src` and `dst` are checked independently, so a copy cannot exfiltrate to an unlisted destination. A path that is only `access: r` (not `rw`), outside the allowlist, or that resolves outside it, is rejected with `path_not_allowed`. Tests: `test_handlers_upload.py::test_upload_file_rejects_path_traversal`, `test_policy.py` (traversal/symlink-escape/prefix-not-substring), `test_handlers_edit.py` (edit path-enforce), `test_handlers_fsmutate.py` (traversal escape defeated, dst-outside-rw refused, src-in-readonly refused). |
| **Residual risk** | TOCTOU: if the operator's `upload_base` itself is a symlink an attacker can swap, the check could be bypassed. We don't defend against attackers with prior write access (see §4.7). The rw model is only as good as the operator's `file_ops.paths` — see §5.1. |

### 4.2.1 — `sudo` does not lift the rw allowlist on `edit` (carve-out removed in 0.11.18)

| | |
|---|---|
| **STRIDE category** | Elevation of Privilege |
| **Attacker** | A2 (compromised LLM / tool client) |
| **History** | Until 0.11.17, `edit`/`edit_upload_complete` with `sudo=true` skipped the file_ops rw check, on the assumption that the installer's sudoers fragment bounded what a sudo edit could touch. The installer granted `NOPASSWD:ALL`, so no such bound existed: any request could write any file as root, including the agent's own `/etc/sentinelx/config.yaml`. An agent that can rewrite its own allowlist does not have one. Reported by OpenAI Security; removed in 0.11.18 (2026-09-08), on both the single-call and the chunked-upload path. |
| **Today** | The rw verdict applies to every edit, with or without sudo; `sudo` only changes which user performs a write the policy already allows. Paths are canonicalized as before (symlinks and `..` resolved). The agent's config is not rw by default, so the agent cannot change its own policy: `edit` of `/etc/sentinelx/config.yaml` is refused with `path_not_allowed`. |
| **Policy administration** | The owner changes the policy outside the assistant: as root over SSH, or with Edit config on the host's card in the dashboard, then restarts the agent. The current `add_allowed_command` / `add_allowed_read_path` playbooks have the assistant show the exact lines and leave applying them to the owner. Configs written by older installers can still carry the old playbook text describing a sudo edit of the config; those steps now fail by design (seen 2026-10-06, sxrep_FA72D2Y86WCR). An owner who wants the agent to maintain its own policy can declare the config file in file_ops with `access: rw`, which makes it a visible choice in their config rather than a property of a flag. |
| **Residual risk** | (1) Declaring `/etc/sentinelx` (or `/`) as rw reopens policy rewriting; that is an explicit owner decision. (2) The rw model governs `edit`; it does not bound `script_run`, which runs arbitrary bash as the agent's user (with sudo when the sudoers allows it) and is not gated by `allowed_commands`. An owner who wants a narrow allowlist to mean something must also disable `script_run` (`disabled_ops: [script_run]`) and keep the sudoers fragment narrow (see §4.7, §5.1). Tests: `test_handlers_edit.py::{test_edit_sudo_does_not_bypass_the_rw_gate, test_edit_sudo_upload_path_is_gated_too}`. |

### 4.3 — SSRF via `file_url`

| | |
|---|---|
| **STRIDE category** | Information Disclosure / Spoofing |
| **Attacker** | A1, A2 |
| **Vector** | `upload_file` with `file_url=https://169.254.169.254/...` (cloud metadata), or `https://10.0.0.5/admin` (LAN service), or `https://attacker.com` (recon) |
| **Severity** | Critical on cloud hosts (IAM credential theft); High on others (LAN recon / pivot) |
| **Mitigation** | Layered, in `handlers/upload.py::_validate_fetch_url`: <br>1. https-only scheme. <br>2. Hostname must be in `security.trusted_fetch_hosts` allowlist (default empty). <br>3. Resolved IP must pass `_is_safe_ip()` — rejects loopback, RFC1918, link-local, multicast, reserved. <br>4. Redirects disabled via `_NoRedirectHandler`. <br>5. Default timeout reduced to 15s. <br>Tests cover each bypass attempt. |
| **Residual risk** | DNS rebinding between the validation lookup and urllib's lookup is theoretically possible; in practice it requires the attacker to also be in `trusted_fetch_hosts`, which already requires operator opt-in. |

### 4.4 — Unauthorized service control

| | |
|---|---|
| **STRIDE category** | Denial of Service / Tampering |
| **Attacker** | A1, A2 |
| **Vector** | `service stop docker` to disrupt the host; `restart sshd` to lock the operator out |
| **Severity** | Medium-High |
| **Mitigation** | `services:` block in `config.yaml` is an allowlist not just of unit names but of which **actions** are permitted per unit. Stopping `sshd` is impossible unless the operator listed it. The agent's `service` handler (in `handlers/service.py`) checks both the unit and the action against the spec. |
| **Residual risk** | Operator misconfiguration. Default starter config doesn't include `sshd`. |

### 4.5 — Identity replay / forgery

| | |
|---|---|
| **STRIDE category** | Spoofing |
| **Attacker** | A1, A2, network observer |
| **Vector** | Stolen `identity.json` used to impersonate the host |
| **Severity** | High (ranks alongside host compromise) |
| **Mitigation** | `identity.json` is signed by the hub at enrollment. Agent presents it on connect, hub validates. File permissions: owned by `sentinelx`, mode 0600. Stolen identity = compromised host (see A3 — out of scope). On compromise: revoke from hub admin panel, re-enroll. |
| **Residual risk** | No automatic revocation if the host goes silent — operator must notice. |

### 4.6 — Information disclosure via error messages

| | |
|---|---|
| **STRIDE category** | Information Disclosure |
| **Attacker** | A1, A2 |
| **Vector** | Crafted inputs designed to elicit verbose errors that reveal local paths, env vars, or internal state |
| **Severity** | Low |
| **Mitigation** | `executor.py::HandlerError` is the only exception type that reaches the wire. Other exceptions are caught and logged locally; the wire-level response is a generic `internal_error` with a short, sanitized message. Stack traces stay in `/var/log/sentinelx/core.log` on the host only. |
| **Residual risk** | Some `HandlerError` messages do include path fragments (e.g., `"file exists: /var/lib/sentinelx/uploads/foo"`). This is an intentional UX trade-off and considered low severity given how `upload_base` is structured. |

### 4.7 — Local privilege escalation via the agent

| | |
|---|---|
| **STRIDE category** | Elevation of Privilege |
| **Attacker** | A3 (already on the host as a non-root user) |
| **Vector** | A regular host user finds they can talk to the agent's local files and pivot through the agent's `sudo` |
| **Severity** | Considered out of scope (see §2 — A3) |
| **Mitigation** | The agent doesn't expose any local socket or named pipe. There is no IPC for local users to abuse. `identity.json` is mode 0600 and `config.yaml` is mode 0644 (readable but writes need sudo). The sudoers fragment is locked to specific binaries (`pensa-safe-edit`, listed services), not a wildcard. |
| **Residual risk** | Acknowledged. If you don't trust the local users on a host, don't enroll that host. |


## 5. Residual risks we accept

These are conscious choices, documented so reviewers know we know:

  1. **Operator misconfiguration is the dominant risk.** Almost every
     "what if" scenario above ends with "if the operator allowlists X,
     this defense doesn't help." The mitigation is documentation
     (`config.example.yaml` has extensive guidance) and conservative
     defaults (empty allowlists, narrow service action lists).

  2. **No sandbox.** The agent runs commands directly via `subprocess`.
     A sandbox layer (firejail, bubblewrap, namespaces) would add
     defense-in-depth but also installation complexity and platform
     fragility. We chose the simpler model and accept that the allowlist
     is load-bearing.

  3. **No DoS mitigation in the agent.** The hub does rate limiting
     for tool invocations per user. The agent itself does not. A
     compromised hub could flood it. We accept this — a compromised
     hub is already game-over for many reasons.

  4. **TLS trust is bootstrapped via the OS cert store.** We don't
     pin the hub's certificate fingerprint (only the hostname). An
     attacker who can issue a valid cert for `mcp.sentinelx.app`
     through any CA the host trusts can MITM. CT logs and the hub's
     known-issuer should make this detectable post-hoc.

  5. **Limited audit log on the agent side.** All operations are
     logged centrally on the hub (Redis ring buffer) — that remains
     the authoritative trail. Additionally, every *successful mutating*
     op (`move`/`copy`/`delete`/`chmod`/`chown`) now appends one
     JSON line to `/var/log/sentinelx/mutations.log` (op, paths, ts).
     This is a forensic aid, NOT a security control: it is best-effort
     (a write failure never blocks the operation) and an attacker who
     controls the agent can also tamper with or truncate the file, so
     it does not survive the very adversary (A1/A2) most relevant here.
     It does help post-incident reconstruction when the hub's view is
     unavailable or disputed. The agent's general logs in
     `/var/log/sentinelx/core.log` are still operator-managed
     (logrotate) and not protected against rotation gaps. For
     high-assurance environments, ship both logs to a separate,
     append-only aggregator the agent user cannot reach.


## Maintenance

This document is reviewed at every minor release (e.g., `v0.2.x → v0.3.0`)
and when any of the listed mitigations change in code. Discrepancies between
this document and the code should be reported as security issues — see
[`SECURITY.md`](./SECURITY.md).

Last reviewed: 2026-05-08 (v0.2.0 — SSRF defense added).
