# Changelog

Notable changes to `sentinelx-cloud-core`. Human-readable, date-stamped
entries; releases before 0.3.0 predate this file — see the git history.

## 0.11.2 — Fix #32: `capabilities.ops_supported` is derived from the op registry — 2026-08-21

`ops_supported` was a hand-maintained literal in the capabilities
handler and had drifted from `build_registry()`: `file_export_init`,
`file_export_chunk`, `file_export_complete` and `project_snapshot`
were registered and dispatchable but never advertised, so a client
introspecting capabilities could not discover them (and hub-side
capability-aware dispatch was weakened). The guard test
`test_ops_supported_matches_registry` had been failing on `main`.

The list is now derived from the registry itself: `build_registry()`
attaches the capabilities handler after the dict is complete and
injects a callable that reads the registry's keys at request time, so
the advertised ops are always exactly the dispatchable ops, sorted. A
newly registered op needs no second edit. This is the second time the
hand-maintained list drifted (the first was move/copy/delete/chmod/
chown), which is why the fix removes the class of bug rather than the
instance. The guard test stays, now guarding the derivation.

No protocol change and no new tool: the response shape is unchanged,
four op names simply appear where they should always have been.

## 0.11.1 — Fix #26: safe-edit renders Unicode diffs without reporting failure after commit — 2026-08-21

`sentinelx-pensa-safe-edit` committed the mutation and could then
exit nonzero while rendering the diff, when the console encoding
could not represent the diff's characters (Windows cp1252). The
caller saw a failure AFTER the state had already changed, and
retrying a non-idempotent edit (`append`, `prepend`) duplicated the
mutation.

The CLI now installs a non-throwing UTF-8 text layer on stdout and
stderr before parsing arguments, and rendering the result can no
longer turn a committed edit into a reported failure.

Trade-off, deliberate: forcing the stream to UTF-8 guarantees that
rendering never raises, but it does not guarantee that the output
*renders* legibly everywhere — on a genuine cp1252 console the UTF-8
bytes appear as mojibake, and `errors="backslashreplace"` almost never
fires because UTF-8 can encode everything. That is the right call for
the primary consumer: `handlers/edit.py` captures the CLI's stdout over
a pipe and ships it across MCP, where UTF-8 is exactly what is wanted.
Only a human running the CLI by hand in a legacy console sees the
mojibake, and that beats an exception after the file has changed. The
alternative — keeping the console's own encoding and setting only
`errors="backslashreplace"` — would print readable ASCII escapes
everywhere but lose correct rendering on UTF-8-capable terminals.

Reported by @mcip3301.

## 0.11.0 — Response bounding (issue #24, repro C) — 2026-08-20

Outbound sends are now bounded before they hit the WebSocket frame limit.
`bound_response()` (from sentinelx-cloud-protocol >= 1.11.0) runs before the
send in `_handle_request` (normal response and executor-crash error) and
before the `job_completed` event in `_run_job_and_report`: an oversized
result is truncated to a head+tail slice with truncation metadata
(`response_truncated`, `original_bytes`, `delivered_bytes`,
`continuation_available=false`, `execution_status`) instead of tripping the
hub frame limit and closing with code 1009 ("message too big"). An executed
operation is never turned into a delivery failure. No wire/protocol change;
protocol re-pin to v1.11.0 lands with the release tag.

## 0.10.0 — Progressive, profile-neutral help & bounded capabilities — 2026-08-17

`help` and `capabilities` now accept optional selectors for progressive, bounded
introspection (contributed by @FalconZip, #23). `help({topic|path|playbook, offset,
limit})` returns a small index or one exact leaf instead of the whole tree, and
`capabilities({detail:"summary"})` returns discovery metadata without command/service
values or playbook bodies. Empty payloads (`help({})`, `capabilities({})`) are
unchanged, so existing callers are unaffected. Scoped help responses normalize
full-profile `sentinel_*` names to profile-neutral `op:<name>` (with a
`tool_reference_map` back to the source), so the compact profile's context savings
aren't handed back on the first introspection call. Logic isolated in a new
`handlers/progressive_help.py`; 15 new tests.

## 0.9.3 — Document preferred_profile in stock examples — 2026-08-17

Documentation only. `agent.preferred_profile` (added in 0.9.0) was only shown in
`config.orion.example.yaml`; it is now documented as a commented, optional
`agent:` block in all stock examples (Linux/macOS/Windows), with the advisory /
dashboard-wins / unanimity / sanitized-invalid semantics inline. No behaviour
change.

## 0.9.2 — sync_sentinelx_config playbook fix — 2026-08-17

The bundled `sync_sentinelx_config` playbook no longer uses the local config
file's mtime as a "last sync" signal — a local edit bumps that mtime and could
mask an upstream `config.example.yaml` change the operator never adopted, so the
diff (empty = in sync) is now the authoritative signal. The YAML sanity-check
step also moves from `sentinel_exec` (which rejected its shell pipe) to
`sentinel_script_run`. Config-example only; no agent code changed.

## 0.9.1 — Self-update playbook fix — 2026-08-17

The bundled `update_sentinelx_code` playbook in `config.example.yaml` now uses
`sentinel_script_run` for its inspection and reinstall steps instead of
`sentinel_exec` — the old steps used shell pipes and a bare `sudo`, which the
default command policy rejects, so the canonical self-update playbook could not
run end-to-end as written. Behaviour is otherwise unchanged. No agent code
changed; this only updates the shipped default config, so existing installs are
unaffected until they re-sync their config.

## 0.9.0 — Advertise preferred toolset profile — 2026-08-17

The agent can now advertise, in its `hello`, which MCP toolset profile it
prefers, via a new optional `agent.preferred_profile` config knob (`compact` |
`full`). Stock hosts leave it unset and advertise no preference (the full
catalog). The hub treats it as an advisory default only — an explicit dashboard
choice always wins, and `compact` is chosen only when ALL of a user's connected
agents agree. An invalid value is sanitized to "no preference" with a loud
warning, so a typo can't fail the hello and take the host offline. Protocol
pinned to **v1.10.0** (adds the optional `HelloMessage.preferred_profile`).

## 0.8.0 — Structured Git operations (sentinel_git) — 2026-08-17

A new agent op `git` backs the `sentinel_git` tool, with two operations:
`diff` (a bounded, structured repo diff — one call instead of many
`git status` / `git diff` round-trips) and `apply_patch` (an atomic
multi-file unified-diff apply, validated up front with `git apply --check`,
offered as a `dry_run`, and applied all-or-nothing). Git runs with fixed
argv (never a shell), a hardened env, and paths bounded by the agent's
`file_ops` policy — `diff` is read-only, `apply_patch` requires a writable
path. Protocol pinned to **v1.9.0** (adds the `git` op).

## 0.7.0 — Background jobs

Long-running `exec` / `script_run` can now run detached with `background=true`:
the agent acks immediately (returning a `job_id`) and reports completion as a
`job_completed` event over the existing agent→hub channel — no protocol change.
The wall-clock ceiling for a background op is raised to 3600s, and the timeout
branch is marked so the hub can distinguish `succeeded` / `failed` / `timeout`.
This is the agent half of the notifications feature; the hub surfaces results
via a notifications pool and optional Telegram/email pushes.

## 0.4.0 — Windows support

SentinelX now runs natively on **Windows**, alongside Linux (systemd) and
macOS (launchd). One PowerShell installer (`install.ps1`, served from
`get.sentinelx.app`) covers two modes:

- **Service mode** (admin) — the agent runs as a Windows service via WinSW,
  as LocalSystem, started at boot. The analogue of the systemd unit / macOS
  LaunchDaemon.
- **User mode** (`-User`, no admin) — the agent runs as a per-user Scheduled
  Task at logon (windowless, via `pythonw`), as *you*. The right fit for
  locked-down corporate machines where you are not a local admin; the
  analogue of a macOS per-user LaunchAgent.

Designed and validated end-to-end on a locked-down corporate laptop, where
three obstacles each got a first-class answer: no admin (`-User` + Scheduled
Task), PyPI blocked (`-Bundle` offline install), and a TLS-inspecting proxy
(`truststore`, below).

### Added
- Native Windows agent: PowerShell `exec` + `script_run`, all read/write
  file ops (`edit`, `move`, `copy`, `delete`), `chown` via `icacls`, and
  service control via the `*-Service` cmdlets (service mode) or `schtasks`
  (user mode). `sentinel_service backend: "service" | "task"` selects which.
- `install.ps1` flags: `-User` (no-admin install), `-Bundle` (offline
  install), `-ImportFrom` (reuse identity/config), `-Source` (editable dev
  install), `-Check` (no-admin dry-run). The installer enrolls, writes a
  per-machine tailored config, and registers the service or task.
- **Offline install bundle** — a prebuilt wheel bundle (agent + protocol +
  all dependencies) installs with `--no-index --no-deps`, so no PyPI access
  is needed. For corporate networks that block PyPI. Published per release
  (`win-bundle-*`).
- **`truststore`** — on networks with a TLS-inspecting proxy (corporate
  MITM), the agent verifies the hub certificate against the OS trust store,
  so a private/corporate CA is accepted without disabling verification.
  Active when installed (ships in the Windows bundle); a no-op elsewhere.
- `--log-file` — route logging to a file instead of stderr (used by the
  windowless user-mode Scheduled Task, which has no console).
- Three Windows diagnostic playbooks: `windows_service_debug`,
  `network_debug`, `system_debug`.
- `config.example.windows.yaml` — an operational Windows default:
  read-only cmdlet allowlist plus `git`, the `sentinelx` service, the
  playbooks, and file-scoped self-management of `config.yaml`.

### Fixed
- Windows self-restart: `sentinel_service restart` on the agent's own
  service/task spawns a **detached** WMI helper (net stop/start for a
  service, `schtasks /End`+`/Run` for a task) so the restart survives the
  agent being stopped.
- The install one-liner is download-then-run rather than `iwr | iex`, which
  ran the script in the caller's session and closed the user's terminal on
  the script's `exit`.
- UTF-16 / BOM-prefixed files are read as text instead of being misflagged
  as binary.
- Windows portability across the file, exec, edit, and service handlers:
  path canonicalization, `icacls` ownership, validator presets using
  `sys.executable`, and the mutation log under `%PROGRAMDATA%`.

## 0.3.0 — macOS support

Native **macOS** support (launchd): a macOS installer, system-mode
LaunchDaemon with scoped passwordless sudo, an OS-detecting dispatcher at
`get.sentinelx.app`, platform-aware `sentinel_service` (launchctl), a macOS
starter config, and macOS-native playbooks.

## Earlier

Linux (systemd) agent, the allowlist/audit security model, structured file
ops, hub enrollment, and the one-line installer. See the git history.
