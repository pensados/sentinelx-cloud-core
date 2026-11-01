# Threat Model — sentinelx-cloud-core

This document describes the threat model the agent is designed against. It's
the "deeper" companion to [`SECURITY.md`](./SECURITY.md), aimed at people
auditing the code, integrating SentinelX into their stack, or evaluating it
for compliance review. It is also the scope reference for security reports and
for the automated review of every change: a finding is in scope when it breaks
one of the properties in §5 under the conditions §2 and §7 describe.

The structure is:
  1. What we're protecting (assets)
  2. Who we're protecting it from (adversaries)
  3. Where the trust boundaries are
  4. Specific threats and how we mitigate them
  5. Properties the agent must always hold
  6. Residual risks we accept
  7. Out of scope


## 1. Assets

The agent sits on a host belonging to the operator. The assets it could
plausibly leak or damage:

| Asset | Where it lives | Loss impact |
|---|---|---|
| Host filesystem (read) | `/`, `/etc`, `/var`, user homes | Confidentiality of secrets, configs, code |
| Host filesystem (write) | Same, gated by `file_ops` paths and, for commands, by `exec_mode` | Integrity / availability — files modified, services downed |
| Integrity of files the agent replaces | Targets of edit, move, copy, upload | A failed operation that destroys or half-writes what was there |
| Secrets the assistant edits | Files edited with `secret` (no backup, content kept out of logs) | Credential disclosure or corruption |
| Service control | systemd units listed in `services:` | Availability — services stopped or restarted at attacker timing |
| Cloud metadata credentials | `169.254.169.254` (AWS/GCP/Azure) | If the host is in a cloud, IAM credentials can pivot to cloud account compromise |
| Internal network | RFC1918 routes the host can reach | Lateral movement (DBs, internal admin panels, VPN-reachable corp networks) |
| The agent's JWT identity | `identity.json` | Impersonation of this host to the hub |
| The hub's trust in this host | `host_id` registered at hub | Could let attacker route hub-bound queries to a different host |
| Operator credentials transiting through tools | e.g., `cat ~/.aws/credentials` if allowed | Direct credential theft |


## 2. Adversaries

We model three adversary personas. The agent's defenses target the first two;
the third is out of scope and noted for completeness.

### A1 — Compromised hub (or hub operator turned malicious)

The hub at `mcp.sentinelx.app` is operated by Pensa Software (project owner). An
attacker who compromises the hub — or an insider who turns malicious — has
full control over what messages reach each agent. The agent **must defend
itself against its own hub**, because:

  - If a hub compromise meant total host compromise, the failure mode of
    the entire SentinelX system would be unbounded.
  - Reviewers (Anthropic, OpenAI) need to be able to assert that an agent
    install does not give Pensa Software more than the operator's policy allows.

**Capabilities of A1:**
  - Send arbitrary WebSocket messages to the agent
  - Choose any operation the protocol supports
  - Provide attacker-controlled values for any parameter
  - Observe responses
  - Time tool invocations

**NOT capabilities of A1:**
  - Forge another host's identity (each host has its own JWT)
  - Break the TLS connection to the hub (hostname-verified; see §6.4)
  - Read or write the host's filesystem outside what the policy exposes
  - Run commands the operator's `exec_mode` and `allowed_commands` do not allow

### A2 — The assistant, and whoever can steer it

Calls reach the agent from an MCP client (Claude, ChatGPT or another) through
the hub. The agent does not distinguish hub-originated from client-originated
calls; both are untrusted input. This persona covers, in decreasing order of
how often it matters in practice:

  - **A well-meaning assistant that gets it wrong** — a mistaken command, a
    wrong path, a misread instruction. This is the case the `exec` allowlist is
    designed for (§4.1).
  - **Prompt injection** — an assistant steered by content it reads: a file on
    the host, a web page, the output of another tool. It then issues calls the
    owner did not intend, with the owner's authority.
  - **A malicious person driving the assistant**, including a member of a host
    the owner shared: the hub enforces what that member's role allows, and the
    calls it lets through reach the agent as authorized calls under the same
    host policy.

**Capabilities of A2:** any tool the host's policy permits, with any argument.
**The defense is the same as against A1:** the policy (`exec_mode`,
`allowed_commands`, `file_ops` paths, `services`, `disabled_ops`), parameter
validation, and the properties in §5.

### A3 — Local attacker on the host (out of scope)

If an attacker already has a shell on the host, the agent's defenses are
moot — they can read `identity.json`, modify `config.yaml`, install a
keylogger in `/usr/bin`, etc. We don't attempt to defend against this.

The reasonable thing to do if you suspect host compromise is to revoke the
host's enrollment from the dashboard, then reinstall.


## 3. Trust boundaries

```
  MCP client ──► Hub (mcp.sentinelx.app) ──── outbound WSS ────► Agent (sentinelx user) ──► OS / sudo
  (Claude,       authenticates the user,   Boundary 1: TLS,       Boundary 2: the policy     ASSUMED
   ChatGPT)      enforces roles on shared  hostname-verified;     (exec_mode, allowed_       TRUSTED
                 hosts, routes the call.   no inbound ports       commands, file_ops,
                 ASSUMED HOSTILE here.     on the host            services, disabled_ops)
```

**Boundary 1 (network):** the agent opens one outbound WebSocket to the hub
URL in its config (and the alternate entry derived from that same URL); there
are no inbound ports. TLS uses hostname verification through the OS
certificate store; the certificate is not pinned (§6.4). A failed validation
drops the connection.

**Boundary 2 (policy):** the agent is a single Python process running as the
unprivileged `sentinelx` user. **By default the installer grants that user
passwordless sudo for everything (`NOPASSWD:ALL`)**, so sudo is not what
contains it: the agent's own checks are. Each tool is bounded by its own part
of the policy — `exec` by `exec_mode` and `allowed_commands`, the file tools by
`file_ops` paths, `service` by `services` — and `disabled_ops` removes a tool
entirely. `script_run`, and `exec` in `exec_mode: unrestricted`, run whatever
they are given by design; with them enabled the real boundary is the agent's
OS account and its sudo rule. An install with `SENTINELX_SKIP_SUDO=1` has no
sudo rule at all.


## 4. Threats and mitigations

We use a STRIDE-style enumeration. Each threat has: severity, attack
vector, mitigation, and residual risk.

### 4.1 — Running a command the policy does not allow

| | |
|---|---|
| **STRIDE category** | Tampering / Elevation of Privilege |
| **Attacker** | A1, A2 |
| **Vector** | An `exec` command line built so that something other than an allowed program runs: shell metacharacters, chaining, substitution, changing the variables that decide what runs (`PATH`, `IFS`, `BASH_ENV`…), or state the shell loads before the command (profile files, `BASH_ENV`/`ENV`, exported functions) |
| **Severity** | High if exploitable |
| **What `allowlist` promises** | A guardrail for a well-meaning assistant: it keeps it from running what the owner did not authorize, by mistake or by a wrong turn of reasoning. It is not a sandbox against someone deliberately trying to escape; a full shell has more ways to change its own behaviour than any checker can model (README, "What `exec_mode: allowlist` promises"). |
| **Mitigation** | What `exec` may run depends on the host's `exec_mode`. In `allowlist` (the default) `allowed_commands` matches whole words, and every command in the line must be covered, not only the first: the line is split outside quotes on `;`, `\|`, `&&`, `\|\|`, `&` and newlines; the inside of `$(...)`, backticks, `<(...)`/`>(...)`, `$((...))` and unquoted here-doc bodies is checked by the same rules; shell grammar words and a few side-effect-free builtins are skipped; read-only filters (`grep`, `head`, `sort`, `cut`, ...) are allowed after the first command only without a file operand and without their write/execute options; and anything that cannot be analysed with certainty (a `case` statement, unbalanced quotes, parentheses or backticks) is refused. A command preceded by an assignment (`VAR=value cmd`) is matched as written. The line then runs after a prelude that drops empty and relative `PATH` entries and makes `PATH`, `IFS`, `PS4`, `BASH_ENV`, `ENV`, `CDPATH` and every exported variable read-only (0.23.39, 0.23.41), in a non-login shell (`bash --noprofile --norc -c`) whose environment carries none of the variables bash acts on at startup (`BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, the prompts, `IFS`, `GLOBIGNORE`, `EXECIGNORE`…) and no exported functions (0.23.50, 0.23.52). `strict` additionally refuses newlines, command/process substitution and file redirections. `unrestricted` runs any command line under the agent's identity, as `script_run` does, for trusted hosts. History: prefix matching until 0.23.22 (GHSA-r2h3-76g7-m95x); over-broad exempt segments until 0.23.34 (GHSA-25mg-7f9r-fpr4); variables and shell startup state until 0.23.50 (GHSA-c3pc-p6pj-94c4). |
| **Residual risk** | `allowed_commands` is a boundary only for `exec`, and only as far as its own entries allow: an entry such as `bash`, `sh`, `python3`, `php` or `node` lets a quoted payload run anything, because the payload is one argument. Escapes that need deliberate manipulation of the shell are outside what the allowlist promises (§7). `script_run` runs arbitrary scripts and is not governed by `allowed_commands`: operators who need the allowlist to hold set `disabled_ops: [script_run]` and keep `exec_mode` at `allowlist` or `strict`. In allowlist mode `PATH` is not extended by the agent user's profile files, so a command found only in a directory a profile adds must be on the agent's own `PATH`. On Windows only the whole-word match applies; the chain check does not model PowerShell grammar. |

### 4.2 — Path traversal in upload / edit / mutation target

| | |
|---|---|
| **STRIDE category** | Tampering |
| **Attacker** | A1, A2 |
| **Vector** | `upload_file` with `target_path="../../../etc/passwd"`, or `edit`/`move`/`copy`/`delete`/`chmod`/`chown` with a `path` (or `src`/`dst`) that escapes the allowlist via `..` or a planted symlink |
| **Severity** | Critical (arbitrary write/destroy as `sentinelx`, then `sudo` if applicable) |
| **Mitigation** | Two layers. (1) `executor_engine.py::safe_path_under()` resolves the candidate path against the upload base, walks symlinks, and rejects escapes — applied to upload handlers. (2) The unified r/rw path model: `Policy.resolve_path()` canonicalizes symlinks *before* the prefix check and is called with `need_write=True` by every mutating op. `edit` and the five destructive ops (`move`/`copy`/`delete`/`chmod`/`chown`) funnel every path argument through it; for `move`/`copy` BOTH `src` and `dst` are checked independently, so a copy cannot exfiltrate to an unlisted destination. A path that is only `access: r`, outside the allowlist, or that resolves outside it, is rejected with `path_not_allowed`. Tests: `test_handlers_upload.py`, `test_policy.py`, `test_handlers_edit.py`, `test_handlers_fsmutate.py`. |
| **Residual risk** | TOCTOU: if the operator's `upload_base` itself is a symlink an attacker can swap, the check could be bypassed. We don't defend against attackers with prior write access (A3). The rw model is only as good as the operator's `file_ops.paths` (§6.1). |

### 4.2.1 — `sudo` does not lift the rw allowlist on `edit` (carve-out removed in 0.11.18)

| | |
|---|---|
| **STRIDE category** | Elevation of Privilege |
| **Attacker** | A2 |
| **History** | Until 0.11.17, `edit`/`edit_upload_complete` with `sudo=true` skipped the file_ops rw check, on the assumption that the installer's sudoers fragment bounded what a sudo edit could touch. The installer granted `NOPASSWD:ALL`, so no such bound existed: any request could write any file as root, including the agent's own `/etc/sentinelx/config.yaml`. An agent that can rewrite its own allowlist does not have one. Reported by OpenAI Security; removed in 0.11.18 (2026-09-08), on both the single-call and the chunked-upload path. |
| **Today** | The rw verdict applies to every edit, with or without sudo; `sudo` only changes which user performs a write the policy already allows. The agent's config is not rw by default, so the agent cannot change its own policy: `edit` of `/etc/sentinelx/config.yaml` is refused with `path_not_allowed`. |
| **Policy administration** | The owner changes the policy outside the assistant: as root over SSH, or with Edit config on the host's card in the dashboard, then restarts the agent. An owner who wants the agent to maintain its own policy can declare the config file in file_ops with `access: rw`, which makes it a visible choice in their config rather than a property of a flag. |
| **Residual risk** | (1) Declaring `/etc/sentinelx` (or `/`) as rw reopens policy rewriting; that is an explicit owner decision. (2) The rw model governs `edit`; it does not bound `script_run` (§4.1). Tests: `test_handlers_edit.py::{test_edit_sudo_does_not_bypass_the_rw_gate, test_edit_sudo_upload_path_is_gated_too}`. |

### 4.3 — SSRF via `file_url`

| | |
|---|---|
| **STRIDE category** | Information Disclosure / Spoofing |
| **Attacker** | A1, A2 |
| **Vector** | `upload_file` with `file_url=https://169.254.169.254/...` (cloud metadata), `https://10.0.0.5/admin` (LAN service), or a trusted name whose DNS answers differently between validation and connection (rebinding) |
| **Severity** | Critical on cloud hosts (IAM credential theft); High on others (LAN recon / pivot) |
| **Mitigation** | In `handlers/upload.py`: https only; the hostname must be in `security.trusted_fetch_hosts` (default empty, so `file_url` is off until the operator opts in); every resolved address must pass `_is_safe_ip()` (no loopback, RFC1918, link-local, multicast, reserved); the connection goes to an address that was validated, not to a second lookup, with the certificate still verified against the hostname (0.23.48); redirects are not followed; timeout 15 s by default. Cancelling the call shuts the transfer down and removes the partial file (0.23.48). Tests: `test_handlers_upload.py`, `test_file_url_fetch.py` (rebinding, cancel during a stuck TLS handshake). |
| **Residual risk** | Through an HTTPS proxy (`HTTPS_PROXY`) the tunnel is opened to the validated address, not the name (0.23.52); a proxy that refuses CONNECT to an address makes the fetch fail. |

### 4.4 — Unauthorized service control

| | |
|---|---|
| **STRIDE category** | Denial of Service / Tampering |
| **Attacker** | A1, A2 |
| **Vector** | `service stop docker` to disrupt the host; `restart sshd` to lock the operator out |
| **Severity** | Medium-High |
| **Mitigation** | `services:` in `config.yaml` is an allowlist not just of unit names but of which **actions** are permitted per unit. The `service` handler checks both the unit and the action against the spec. |
| **Residual risk** | Operator misconfiguration. The default starter config doesn't include `sshd`. |

### 4.5 — Identity replay / forgery

| | |
|---|---|
| **STRIDE category** | Spoofing |
| **Attacker** | A1, A2, network observer |
| **Vector** | Stolen `identity.json` used to impersonate the host |
| **Severity** | High (ranks alongside host compromise) |
| **Mitigation** | `identity.json` is signed by the hub at enrollment. The agent presents it on connect, the hub validates. File permissions: owned by `sentinelx`, mode 0600. Stolen identity = compromised host (A3). On compromise: revoke from the dashboard, re-enroll. |
| **Residual risk** | No automatic revocation if the host goes silent — the operator must notice. |

### 4.6 — Information disclosure via error messages

| | |
|---|---|
| **STRIDE category** | Information Disclosure |
| **Attacker** | A1, A2 |
| **Vector** | Crafted inputs designed to elicit verbose errors that reveal local paths, env vars, or internal state |
| **Severity** | Low |
| **Mitigation** | `executor.py::HandlerError` is the only exception type that reaches the wire with its own message. Other exceptions are logged locally; the wire-level response is a generic `internal_error` with a short message. Stack traces stay in the host's log. |
| **Residual risk** | Some `HandlerError` messages include path fragments (e.g. the kept workdir of a `script_run` with `cleanup=false`). Intentional, for the caller to act on; low severity. |

### 4.7 — Local privilege escalation via the agent

| | |
|---|---|
| **STRIDE category** | Elevation of Privilege |
| **Attacker** | A3 (already on the host as a non-root user) |
| **Vector** | A regular host user pivots through the agent's sudo |
| **Severity** | Out of scope (A3) |
| **Mitigation** | The agent exposes no local socket or named pipe; there is no IPC for local users to abuse. `identity.json` is mode 0600 and `config.yaml` is writable only by root. The sudo rule belongs to the `sentinelx` user only; by default it is `NOPASSWD:ALL` (§3), so a local user who can act as `sentinelx` has root. |
| **Residual risk** | Acknowledged. If you don't trust the local users on a host, don't enroll that host, or install with `SENTINELX_SKIP_SUDO=1`. |

### 4.8 — `local_api` with transport stdio runs a declared binary (0.23.31)

| | |
|---|---|
| **STRIDE category** | Elevation of Privilege / Tampering |
| **Attacker** | A1, A2; A3 for the binary-replacement vector |
| **Vector** | (1) Craft `params` so they reach the binary's argv or a shell. (2) Replace the declared binary, or a directory entry on its path, so the agent runs something else. (3) Leave a child running after the call. (4) Reach tools of an MCP server the operator did not mean to expose. |
| **Severity** | High if (1) or (2) were possible; Medium for (4) |
| **Mitigation** | The binary is declared by the host's owner in `config.yaml` (absolute path, fixed `args`); the caller only picks an allowlisted action. (1) No shell: argv `[path, *args]`, and the call's parameters go into the JSON-RPC message only. (2) `binary_problem()` refuses a binary that is, or sits in a directory that is, writable by anyone but its owner, at load and again before every call. (3) One process per call, in its own session, bounded by `timeout_s`; the `run_as` relay runs through `run_process` (§4.9). (4) Documented: the allowlist is of methods, so `tools/call` reaches every tool of that server. Tests: `test_local_api_stdio.py`, `test_process_contract.py`. |
| **Residual risk** | Whatever the declared binary does with its input is the binary's responsibility. Per-tool allowlisting inside an MCP server is not implemented. With `run_as`, the child runs as another user and the agent may not be able to signal it; that is reported as `left_running`. |

### 4.9 — Work that outlives a cancellation or a timeout

| | |
|---|---|
| **STRIDE category** | Tampering / Repudiation |
| **Attacker** | A2 (and plain accidents) |
| **Vector** | A call is cancelled or times out, the caller believes it stopped, and a child keeps going: an edit that still commits, a `git` hook or a script's background process that keeps writing, a descendant that left the process group with `setsid` |
| **Severity** | High: the owner's view of what happened on the host is wrong |
| **Mitigation** | Every child the agent starts goes through `executor_engine.run_process` (0.23.45–0.23.47): its own process group (session on POSIX); on timeout or cancellation the whole tree is killed, including descendants that left the group (from a `/proc` snapshot), with `sudo kill` for a root-owned tree; the wait is bounded; and the result says `left_running` when something survived. `tests/test_process_contract.py` holds every caller (`exec`, `script_run` plain and with sudo, edit, `git`, `project_snapshot`, the `local_api` relay) to it. |
| **Residual risk** | A process running as another user, or as root without a working sudo rule, can outlive the kill; it is reported, not hidden. On Windows the tree kill is `taskkill /T`. |

### 4.10 — Integrity when an operation fails part way

| | |
|---|---|
| **STRIDE category** | Tampering |
| **Attacker** | A2 (and plain accidents: full disks, permissions, races) |
| **Vector** | An operation that destroys or replaces first and only then finds out whether it can finish |
| **Severity** | High: data loss on the files the owner asked to change |
| **Mitigation** | `move`/`copy` with `overwrite=true` stage the new content beside the destination and keep the old one until the new one is in place (0.23.43); `upload_file` and chunked uploads with `overwrite=false` commit with a hard link that fails atomically if the destination appeared meanwhile; chunked uploads require the complete chunk set and a reused `upload_id` starts a fresh session; an `edit` with `create=true` writes nothing at the target until its content is validated and never replaces a file that appeared meanwhile (0.23.52); a `secret` edit that can't keep the file's owner is refused rather than written in place without a backup (0.23.42). Tests: `test_failure_atomic_ops.py`, `test_jan_followups_1031b.py`. |
| **Residual risk** | A source directory removed part way during a cross-filesystem move is reported as `partial_move` (the destination is complete). Without hard-link support (some FUSE, SMB or FAT mounts) the name is reserved with `O_EXCL` before it is replaced (0.23.52). |

### 4.11 — Resource exhaustion through outputs

| | |
|---|---|
| **STRIDE category** | Denial of Service |
| **Attacker** | A1, A2 |
| **Vector** | Requests whose results, errors or audit entries grow without bound: filling the host's disk through the local audit log, or oversizing responses |
| **Severity** | Medium |
| **Mitigation** | Each local audit entry is capped at 64 KiB as written, whole entry included (0.23.50). Responses are bounded by `bound_response` (protocol 1.13.3) on both the agent and the hub, error messages included, under a hard frame limit. Uploads are capped in size. |
| **Residual risk** | A compromised hub can still flood the agent with requests (§6.3). |


## 5. Properties the agent must always hold

These are the claims a review, human or automated, tries to break. A way to
violate one of them, under the adversaries of §2 and outside §7, is a defect.

  1. A call cannot run a program in `exec` that the host's `exec_mode` and
     `allowed_commands` do not allow, short of deliberate shell manipulation
     in `allowlist` mode (§4.1, §7).
  2. A file tool cannot read outside `r`/`rw` paths, or write outside `rw`
     paths, after symlinks and `..` are resolved; `sudo` never widens that.
  3. An upload never lands outside `upload_base` or the `rw` path it was
     authorized for.
  4. The agent cannot change its own policy unless the owner declared the
     config file `rw`.
  5. A service action runs only if that unit and that action are listed.
  6. `file_url` reaches only trusted hosts, over https, at public addresses,
     and never follows a redirect.
  7. When a call ends — answered, timed out or cancelled — nothing it started
     is still running, or the answer says `left_running`.
  8. An operation that fails leaves the previous content in place, or says
     exactly what it changed (`partial_move`).
  9. No local audit entry exceeds its cap, and no response exceeds the frame
     limit.
 10. A disabled tool (`disabled_ops`) cannot be reached by any other name or
     path.


## 6. Residual risks we accept

These are conscious choices, documented so reviewers know we know:

  1. **Operator misconfiguration is the dominant risk.** Almost every
     "what if" above ends with "if the operator allows X, this defense
     doesn't help." The mitigation is documentation (`config.example.yaml`)
     and conservative defaults (empty allowlists, narrow service actions).

  2. **No sandbox in the agent.** It runs commands directly. A sandbox
     layer (firejail, bubblewrap, namespaces) would add defense-in-depth
     but also installation complexity and platform fragility. When the
     assistant, or whoever can steer it, must not be able to affect a host
     at all, the answer is isolation: a disposable VM (the compute tools
     create and enroll one; with `grant_sudo` it gets root on a machine with
     nothing on it the owner cares about).

  3. **No DoS mitigation in the agent.** The hub rate-limits tool
     invocations per user; the agent does not. A compromised hub could
     flood it.

  4. **TLS trust is bootstrapped via the OS cert store.** The hub's
     certificate is not pinned (only the hostname is verified). An attacker
     who can issue a valid certificate for the hub's name through any CA the
     host trusts can MITM. CT logs make this detectable after the fact.

  5. **The agent-side audit is a forensic aid, not a control.** The
     authoritative trail is the hub's audit (Postgres). The agent also keeps
     a local audit log (capped entries) and a mutations log; an attacker who
     controls the agent can tamper with both. For high-assurance
     environments, ship them to an append-only aggregator the agent user
     cannot reach.


## 7. Out of scope

  - A3: an attacker who already has a shell on the host, or root.
  - Someone with access to the owner's SentinelX account, or to the owner's
    MCP client.
  - In `exec_mode: allowlist`, escapes that need deliberate manipulation of the
    shell beyond the variables and startup state listed in §4.1.
  - What `script_run` and `exec_mode: unrestricted` run: arbitrary by design.
  - What a binary the owner declared for `local_api` does with its input.


## Maintenance

Reviewed whenever a mitigation listed here changes in code, and at every
release that changes a property in §5. Discrepancies between this document and
the code should be reported as security issues — see [`SECURITY.md`](./SECURITY.md).

Last reviewed: 2026-11-01 (agent 0.23.51, protocol 1.13.3).
