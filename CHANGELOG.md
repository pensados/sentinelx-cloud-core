# Changelog

Notable changes to `sentinelx-cloud-core`. Human-readable, date-stamped
entries; releases before 0.3.0 predate this file — see the git history.

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
