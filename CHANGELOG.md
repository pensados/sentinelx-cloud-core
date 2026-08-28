# Changelog

Notable changes to `sentinelx-cloud-core`. Human-readable, date-stamped
entries; releases before 0.3.0 predate this file — see the git history.

## 0.11.12 — WebSocket liveness and reconnect recovery (#37) — 2026-08-28

- Native WebSocket keepalive is now enabled on the hub connection (`ping_interval=30`,
  `ping_timeout=60`); it was previously disabled (`ping_interval=None`). The existing
  application-level `PingMessage` heartbeat sent messages but enforced no response deadline,
  so a half-open connection (local TCP socket still `ESTABLISHED` while the hub has already
  dropped the agent) could go undetected. The native ping/pong now closes such a dead
  connection and triggers a reconnect. The application heartbeat is preserved.

- Reconnect backoff is reset after a successful `welcome`. Previously the retry counter only
  ever increased, so a long healthy session that ended with a `1006` could inherit an old
  30/60/120/300s backoff and reconnect slowly. A session that reached `welcome` now restarts
  from the short retry interval, while failures before a successful `welcome` keep escalating
  on the existing schedule. The prompt `1012` hub-restart behavior is unchanged.

- Contributed by @rogal73.

## 0.11.11 — Backend-aware config path in guidance (#7 follow-up) — 2026-08-25

- Guidance now points the operator at the agent's ACTUAL config file. 0.11.10 made the
  restart command, log paths and host wording backend-aware, but `edit_config_via()` still
  used the platform default (`C:\ProgramData\SentinelX\config.yaml`). On a per-user
  (`-User` / Scheduled Task) Windows install the policy lives under
  `%LOCALAPPDATA%\SentinelX\config.yaml` — the agent's only writable config — so following
  the old guidance would hit `path_not_allowed`. The agent now pins the guidance config
  path to its real `--config` argument at startup (`set_config_path`, wired in
  `build_registry`), matching what `capabilities.locations.config` already reports. No
  change for the default service install, whose `--config` is the ProgramData path.

## 0.11.10 — Windows non-SYSTEM hardening: LocalService restart (#19), user-mode task restart (#4), backend-aware guidance (#7) — 2026-08-25

- Windows SCM self-restart, LocalService case (#19, follow-up to 0.11.9). 0.11.9's
  tree-kill + `net start` works when the service runs as LocalSystem, but on a LocalService
  (or any non-SYSTEM) install the detached WMI helper inherits the same underprivileged
  token, so its `net start` is denied (System error 5) and the service is left down. The
  restart op now branches by service account (`sc.exe qc`): a SYSTEM install keeps the
  unchanged tree-kill + `net start` path (`method=taskkill_tree`); a non-SYSTEM install
  force-kills the tree ONLY and lets the service's own SCM RESTART recovery action bring it
  back (`method=scm_recovery_self_kill`). If no SCM RESTART recovery action exists (or the
  wrapper PID can't be resolved) the op FAILS CLOSED (`service_restart_unsafe`) and kills
  nothing, rather than leaving the service down with no way back.

- Windows user-mode (Scheduled Task) self-restart (#4). The no-admin `-User` install runs
  the agent as a per-user Scheduled Task; a plain `schtasks /End` killed the agent (and
  could orphan its child tree) before `/Run`, so restarts didn't take. The task backend now
  gets the same detached, verified treatment: a detached helper force-kills the agent's
  whole process tree, ends the task instance, then `/Run` starts a fresh generation,
  returning a structured `restart_started` ack (`method=task_treekill_run`).

- Backend-aware capabilities and guidance (#7). A `-User` (task-backend) install was
  described to the model as a WinSW service, so the restart command, log paths and host
  wording it emitted were wrong. `capabilities.services[*]` now reports each service's
  `backend`, and the platform guidance (restart command, log location, host kind) adapts
  when the agent's own install is a per-user Scheduled Task instead of a WinSW service.

## 0.11.9

- Windows self-restart hardening (#19): the SCM/WinSW restart now force-terminates the
  whole service-owned process tree (`taskkill /F /T` on the resolved wrapper PID) before
  starting a fresh generation, instead of relying on `net stop` -- which on some installs
  (LocalService / during an update) could leave the old Python agent tree orphaned and
  cause a duplicate_session split-brain. The restart op now returns a structured
  `restart_started` ack (never "completed") with `expected_disconnect`/`verification_required`.

## 0.11.8 — Fix #28 completed: PowerShell output encoding fixed in the child — 2026-08-22

0.11.6 fixed the Windows PowerShell *source* encoding (a UTF-8 BOM) and
then tried to undo the *output* corruption on our side. With a real
Windows 11 / PowerShell 5.1 host finally connected, that half turned out
to be insufficient: 5.1 encodes redirected output in the console code
page (437 on this host), where anything outside it is destroyed at the
source. `Write-Output 'ñandú — 汉'` came back as bytes decoding to
`ñandú - ?` — the em dash best-fitted to a hyphen, the CJK character
replaced by a question mark, before we ever saw them. No capture-side
decoding brings those back; the reporter was right that it has to be
fixed in the child.

The reason 0.11.6 avoided their bootstrap was exit-code fidelity, and
that concern was real. Measured on the same host:

| invocation | explicit `exit 7` | handled native 7 | `throw` |
|---|---:|---:|---:|
| `-File` (reference) | 7 | 0 | 1 |
| bootstrap + `& $script` | 7 | **7** | 1 |
| bootstrap + inner `-File` | 7 | 0 | 1 |

So Windows PowerShell now runs through a bootstrap that sets the
process's output encoding to UTF-8 and invokes the user's script as an
**inner** `powershell -File`. The inner process is a native command, so
its exit code is unambiguous and `-File` semantics survive exactly.

Two consequences worth naming. The bootstrap sets a console code page,
and measurement showed that landing on the console the agent inherits —
leaking 65001 into every later child. Windows children are therefore
spawned with `CREATE_NO_WINDOW`, giving each its own console: the change
dies with the child, the workstation's code page is untouched (verified:
437 before and after), and the mechanism no longer depends on inheriting
a console, which is what makes it work under a service. And because the
bootstrap adds an inner process, a timed-out script would have left it
orphaned — the timeout path now kills the tree with `taskkill`, falling
back to `kill()`.

`pwsh` keeps the direct path; PowerShell Core already speaks UTF-8. The
capture-side decode stays as a safety net for children that still emit
legacy bytes.

Verified by loading this exact module on the Windows host and driving the
handler: PowerShell round-trips `ñandú — 汉 🚀` exactly; exit codes match
`-File` in all four cases; args with spaces and `;`/`|` survive with
`using namespace` intact; `python3` round-trips the same string; a
caller-pinned `PYTHONIOENCODING` still wins. Suite 211 → 214 tests.

## 0.11.7 — Fix #29: `search` streams candidate files instead of loading them whole — 2026-08-22

`search` read each accepted text file completely before looking at it —
the probe bytes, the rest, the concatenation, the decoded text and the
split line list, all alive at once. On a 19.51 MiB / 220,000-line file
that cost **88.19 MiB** of peak traced allocation to find nothing, and
scans over a large allowed workspace root are routine, not hypothetical.

Files are now streamed a block at a time: the binary probe is unchanged,
the file is rewound, and lines are yielded one at a time through an
incremental decoder. Peak allocation on the same fixture drops to
**0.34 MiB** — bounded by one block plus at most one in-progress line.

Line breaking deliberately matches `str.splitlines()`, which is what the
whole-file path used, so line **numbering is identical for every file**:
CRLF, bare CR, form feed and the Unicode separators all still start a new
line. This is intentionally *not* the newline-only iterator that ranged
reads use (#27) — there, agreeing with `total_lines` mattered more; here,
not renumbering anyone's search results does. A block boundary landing
inside a `\r\n` holds the `\r` back rather than emitting it, so it cannot
be mistaken for a lone CR and split one line into two.

Traversal order, matcher semantics, globs, previews, the result cap,
`files_searched` and binary handling are untouched. Wall time is
unchanged: 98 ms vs 97 ms median over five warm runs (a single
cold-cache run was 617 ms vs 665 ms), against the ~11% regression the
report measured.

Reported by @mcip3301. No protocol change and no new tool. Suite 201 →
211 tests, all green.

## 0.11.6 — Fix #28: `script_run` round-trips Unicode on Windows — 2026-08-21

Three Windows boundaries broke ordinary text under one user-facing
contract. Each is now handled where it belongs, and none of them touches
invocation, arguments, exit codes or the shared console code page.

`python3` inherited the console's legacy stdio encoding and raised
`UnicodeEncodeError` the moment a script printed accented text or an
emoji. The child now gets `PYTHONIOENCODING=utf-8`, via `setdefault` so
an explicit caller value — or one the operator set for the service —
stays authoritative.

Windows PowerShell 5.1 reads a BOM-less `.ps1` through the ANSI code
page, mojibaking non-ASCII literals before the script even runs. `.ps1`
files are now written with a UTF-8 BOM on Windows; PowerShell Core reads
that happily too, and nothing changes off Windows.

The same shell encodes *redirected* output in the console code page,
while we decoded captured bytes as UTF-8. On Windows the bytes are now
decoded as UTF-8 strictly first, falling back to the host's code page
(`GetConsoleOutputCP`, then `GetACP`, then the locale) and finally to
replacement. Accented Latin-1/1252 bytes are not valid UTF-8, so the
fallback fires exactly where it should, and a child that emits UTF-8 is
never re-read as a code page.

Deliberate deviation on that third point: the report suggests a
PowerShell bootstrap that sets the process encoding and then invokes the
user script. That changes how every `.ps1` is invoked, and a wrapper
cannot reproduce `-File` exit semantics for one of the cases the report
itself lists as a constraint — after `& $script`, an explicit `exit 7`
and a merely-handled native failure both leave 7 in `$LASTEXITCODE`, so
the wrapper must either lose the explicit exit or turn a handled failure
into one. Decoding on our side fixes the same corruption without taking
that risk. The question is open with the reporter.

Reported by @mcip3301. The Windows-only paths are covered by structural
regressions (argv, child environment, bytes on disk) rather than live
execution, because no Windows host is connected — issue #28 stays open
until it runs on a real 5.1 host. Suite 189 → 201 tests, all green.

## 0.11.5 — Fix #30: a failed `script_run` child is visible in the local audit — 2026-08-21

`Executor.dispatch` recorded `ok=true` whenever a handler returned
normally, and `script_run` reports a failed child as a normal nested
result — `{"ok": false, "returncode": 7}` — rather than raising. The
caller correctly saw a failed script while `read_audit` showed the same
operation as `ok=true`, with nothing to indicate the child had failed.

Repaired additively. `ok` keeps its historical meaning — the handler
completed, i.e. dispatch-level success — and is not redefined. The
nested outcome travels in two new optional fields lifted from the
handler result when it has them:

```json
{"op":"script_run","ok":true,"result_ok":false,"result_returncode":7}
```

Exactly two scalars are lifted, and only when present and correctly
typed; nothing reaches into stdout, stderr or any other result body, so
the audit's payload policy is unchanged. A bool is explicitly rejected
as a return code, since in Python it would otherwise pass an int check.
Both fields are omitted when absent, so entries written before this stay
valid and readers that ignore them keep working.

Three outcomes now have three shapes: dispatch failure (`ok=false` with
an error), a failed child (`ok=true`, `result_ok=false`,
`result_returncode=N`), and plain success (`ok=true`, `result_ok=true`).

Reported by @mcip3301. No protocol change and no new tool. Suite 182 →
189 tests, all green.

## 0.11.4 — Fix #27: `max_bytes` is a hard ceiling and `view_range` reaches the file — 2026-08-21

Two correctness defects in `read`, both from the same coupling: the 8 KiB
binary probe was also the buffer returned as content, and `view_range`
was applied to that buffer afterwards.

So `max_bytes: 257` on a 14,000-byte file returned 8192 bytes — about 32x
the requested ceiling — and `view_range: [900, 905]` in a 122 KiB file
could not be reached at all, because the range was applied to the 64 KiB
response prefix rather than to the file. The prefix's line count was
reported as though it were the file's total.

Three concerns are now separate. The probe classifies (BOM/binary) and
may read up to 8 KiB however small `max_bytes` is, but that buffer is
never handed back. Returned content obeys `max_bytes`, enforced on the
output in UTF-8 bytes — which also closes the case where UTF-16 source
expands when re-encoded. And a ranged read streams the file through an
incremental decoder in 64 KiB blocks, so it can reach line 900 of a
multi-gigabyte log without materializing it.

Ranged scanning stops one line past a finite range: that lookahead is
exactly enough to know the file continues, and it avoids scanning the
remainder of a huge log purely to produce a total. On a 23.84 MiB /
250,000-line file, `[10, 20]` takes 0.25 ms against 44.55 ms for a scan
to EOF, returning identical requested content. When the scan stops that
way, `total_lines` is a lower bound and the new additive
`total_lines_exact: false` says so; `[start, -1]` scans to EOF and
reports an exact total while the content stays byte bounded.

One deliberate consistency change: `view_range` now uses the same
definition of a line that `total_lines` always did — text terminated by a
newline — where it previously used `str.splitlines()`, which also breaks
on CR, vertical tab and the Unicode line/paragraph separators. A file
with bare-CR line endings will range differently; in exchange the two
counts no longer disagree with each other.

Reported by @mcip3301. Additive response field only; no protocol change
and no new tool. Suite 169 → 182 tests, all green.

## 0.11.3 — Fixes #25 and #31: blocking filesystem and audit I/O off the event loop — 2026-08-21

Two fixes in the same family: work that scales with the filesystem was
being done where the agent could least afford it.

**#25 — `read` / `list` / `search` no longer monopolize the loop.** The
three ops were async handlers doing synchronous filesystem work, so a
slow open, a deep enumeration or a recursive content scan held the
event loop for its whole duration — and with it the WebSocket control
plane. Each op is now a plain synchronous `_*_blocking` function that
the async handler hands to `asyncio.to_thread` (the default bounded
pool; no per-request threads). Policy checks, canonical path
resolution, symlink-escape protection, binary handling, glob/regex
semantics, result ceilings and response shape are all untouched — the
operations take exactly as long as before, they just no longer take the
loop with them. A 250 ms injected filesystem delay used to stall an
independent 10 ms ticker for ~260 ms; it now stays under 100 ms.

**#31 — local audit I/O is bounded on both ends.** Every audited op
appended one row and then rescanned the whole JSONL log to count lines
for retention, and `read_audit(limit=N)` loaded the entire file before
slicing the tail, synchronously on the loop. Since the audit keeps full
payloads, that is megabytes per operation. Retention is now checked on
the first write after process start and every 100 writes thereafter,
and the tail is read backwards from EOF in 64 KiB blocks, through the
default executor.

Deliberate trade-offs in #31: the retention cadence is kept in memory
rather than cached to disk, so every check still measures the real file
and external rotation or truncation is picked up at the next check
instead of being masked by stale state; the cost is a bounded overshoot
of at most 99 rows beyond the existing hysteresis. And the tail read
keeps the historical read semantics exactly — only the newest N
physical lines are inspected, and a malformed line among them is
skipped rather than backfilled from further back, because the caller
asked for the last N rows, not for N parseable rows.

Measured on orion against a 5.93 MiB / 5000-row log: 100 audited writes
420.5 ms → 8.2 ms; `read_recent(50)` 22.6 ms / 6.22 MiB peak → 0.95 ms
/ 0.14 MiB peak.

Both reported by @mcip3301. No protocol change and no new tool. Suite
155 → 169 tests, all green.

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
