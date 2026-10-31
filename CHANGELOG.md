# Changelog

Notable changes to `sentinelx-cloud-core`. Human-readable, date-stamped
entries; releases before 0.3.0 predate this file — see the git history.

## 0.23.42 - Follow-ups: secret edits refused without a backup, raw failures keep paths, kill_pids, byte cap - 2026-10-31

Jan's follow-ups on tonight's fixes.

- secret edits (sxrep_YW9E73QKVSQC): 0.23.40's recovery copy could outlive a crash in the temp dir.
  When the owner can't be preserved and there is no backup, the edit is now refused before anything is
  touched (run with sudo=true, or let the agent own the file). No in-place write, no copy.
- script_run (sxrep_69N1GEHNAN1K): env names with '=' or NUL, empty names and NUL in values are refused
  before staging; with cleanup=false, any failure after staging (not only HandlerError) carries workdir
  and script_path, with the code it would have had.
- kill_pids (sxrep_AZ931A9557MC): a failed sudo kill of escaped descendants falls back to each pid and
  reports whether all were signalled.
- local audit (sxrep_YC39MPSTA6S2): the whole-entry cap is in UTF-8 bytes as written (MAX_ENTRY_BYTES),
  with a smaller summary if even the summary is too big.
- tests/test_jan_followups_1031b.py; the two 0.23.40 recovery-copy tests replaced. 5 sabotages caught.
  Suite passes on 3.12 and 3.14.

## 0.23.41 - SECURITY: allowlist mode makes the variables that decide what runs read-only - 2026-10-31

After 0.23.39, Jan reached PATH through printf -v (sxrep_NBEA83P4PV36), a mechanism the chain check
doesn't model. Rather than enumerating every way bash can set a variable, allowlist mode now runs the
chain after a prelude: PATH loses empty and relative entries, then PATH, IFS, PS4, BASH_ENV, ENV, CDPATH
and every exported variable (except PWD, OLDPWD, SHLVL, _) become read-only. Programs still get the
normal environment. Unrestricted mode and Windows are unchanged.

- README: what exec_mode allowlist promises (a guardrail against mistakes, not a sandbox against
  deliberate escapes; for that, a disposable VM).
- tests/test_exec_allowlist_prelude.py: Jan's printf -v chain through the real handler, relative PATH
  entries, read-only exported variables, ordinary chains without noise, unrestricted mode untouched.
  3 sabotages caught. The two gate test files that pin the exact command reaching run_shell disable the
  prelude with a fixture. Suite passes on 3.12 and 3.14.

## 0.23.40 - Secret edits recoverable, audit entries capped, kill fallbacks, alternate hub URL - 2026-10-31

Jan's reports of 2026-10-31.

- secret edits (sxrep_YW9E73QKVSQC): when the owner can't be preserved, the edit writes in place, which
  isn't atomic and relied on the backup that secret=... skips on purpose. Without a backup, a 0600
  recovery copy is kept in the temp dir for the length of the write and put back if it fails; if even
  the copy fails, the file is left unchanged. (vendored pensa_safe_edit: _write_over, _recovery_copy.)
- local audit (sxrep_YC39MPSTA6S2): an entry over MAX_ENTRY_CHARS (64 KiB) keeps only a summary of the
  payload (size, SHA-256, keys, head). Per-field compaction let many small strings through.
- script_run (sxrep_AZ931A9557MC): a failed taskkill or sudo kill falls back to proc.kill(), as exec's
  does; that last resort no longer raises on a process the agent can't signal.
- alternate hub URL (sxrep_058HW8X403G3, sxrep_C8GHQR7WEGKS): huburl.hub_bases() accepts http(s):// or
  ws(s)://, with or without /agent/connect, for connect, verify and rotate. The README sample is a base URL.
- tests/test_jan_reports_1031.py. 4 sabotages caught. Suite passes on 3.12 (twice) and 3.14.

## 0.23.39 - SECURITY: allowlist chains can't assign variables that steer programs - 2026-10-31

Reported by Jan (sxrep_NBEA83P4PV36): in allowlist mode, with only `ls` allowed, `PATH=<dir>:$PATH; ls`
and `for PATH in <dir>; do ls; done` ran an attacker's `ls`. Assignment-only segments and for/select
headers were exempt, and `read` is a safe builtin (`while read -r PATH; do ls; done` passed too). The
same class reached through HOME (git reads ~/.gitconfig: core.pager, core.sshCommand) and PS4 with set -x.

- segment_check: plain assignments, for/select variables and read targets must be lower-case names
  that are not proxy variables. Variables that steer programs are upper case by convention (PATH, HOME,
  LD_*, PS4, IFS, BASH_ENV, PAGER, GIT_*); a chain's own variables are lower case. export, declare,
  PATH+=, array elements, VAR=x cmd prefixes and here-strings were already refused.
- tests/test_exec_chain_assignments.py: every vector above, ordinary loops and reads still pass, and
  Jan's two repros run the fake ls in bash and are refused by the gate. 4 sabotages caught. 3.12, 3.14.

## 0.23.38 - Escaped descendants, uninterruptible cleanup, safe env-file cleanup - 2026-10-31

Jan's follow-ups on 0.23.36, each reproduced on 3.11-3.14.

- Cancellation and timeout (sxrep_E7RCC1FKQC7P): exec and script_run kill descendants that left the
  process group with setsid, from a /proc snapshot of the tree taken before the group dies (Linux). The
  cleanup after a cancellation runs to the end even if the task is cancelled again (finish_cleanup), in
  the three exec runners and in script_run. left_running now covers what is out of reach: an orphan
  already reparented out of the tree, or a root process the agent can't signal.
- env with sudo (sxrep_5CE1B15G691J): the elevated sh removes the env file right after loading it; the
  agent's backstop removal never raises, so a script that locks its workdir no longer turns success into
  PermissionError, skips the cleanup or leaves the secret on disk.
- cleanup=false (sxrep_69N1GEHNAN1K): sudo env names are checked before anything is staged, and every
  HandlerError after staging carries workdir and script_path.
- tests: test_script_run_followups.py (8); the two left_running tests now use an orphan, the case
  left_running exists for. 6 sabotages caught. Suite passes on 3.12 and 3.14.

## 0.23.37 - left_running detection works on Python 3.14 - 2026-10-31

Reported by Jan after 0.23.36 (sxrep_9GWKAWPTXZWM): the new escaped-descendant test passed on 3.12 and
failed on 3.14.9 in CI. On 3.12 asyncio's Process.wait() also waits for the pipes to close; on 3.14 it
returns as soon as the process exits, so a descendant that left the group (or a root process the agent
can't signal) and still held stdout went unnoticed, in script_run and in exec alike.

- executor_engine.wait_gone(): wait at most the grace for the process to exit AND both pipes to reach
  EOF. Used by exec's _stop_process_tree and script_run's _stop_tree.
- tests/test_wait_gone.py: exec reports left_running for an escaped descendant, and a plain timeout
  does not. Suite passes on 3.12 and 3.14 locally; the sabotage (waiting for the process only) is
  caught on 3.14, where the behaviour differs.

## 0.23.36 - script_run: cancellation, bounded timeout cleanup, env with sudo, kept paths - 2026-10-31

Four script_run defects reported by Jan (codeandsolder, author of a Rust reimplementation), each verified
against 0.23.35. script_run had its own, older process handling; exec already got cancellation and a
bounded timeout cleanup right.

- Cancellation (sxrep_E7RCC1FKQC7P): a cancelled script_run kills its process tree before the
  cancellation goes through. Before, the finally removed the workdir while the script kept running.
- Timeout (sxrep_9GWKAWPTXZWM): after the kill, wait at most STOP_GRACE_SECONDS (5 s, as exec); if a
  descendant that left the group still holds the pipes, close our end and report left_running.
- env with sudo (sxrep_5CE1B15G691J): sudo resets the environment, so payload.env never reached the
  script and the call still returned ok. The variables go into a 0600 file in the workdir that the
  elevated sh loads before exec (never on the command line), removed after the run even with
  cleanup=false. With sudo, env names must be shell identifiers.
- cleanup=false and a missing interpreter (sxrep_69N1GEHNAN1K): workdir and script_path are returned on
  a timeout and in the interpreter_missing error, which a missing interpreter now raises (it escaped as
  a raw FileNotFoundError: the clause that named it was unreachable).
- tests/test_script_run_lifecycle.py (7). 5 sabotages caught.

## 0.23.35 - A refused move names the destination, not the staging file - 2026-10-29

An upload to /home/alex/Downloads failed with "permission denied: '.../.sentinelx_uploads/<id>/assembled.bin'"
(sxrep_0XCP6WETXRRH). The staging file was fine: the agent's OS user couldn't write into the destination
directory. A refused os.replace or copy carries the source in .filename and the destination in .filename2,
and the executor's permission_denied message used only the first.

- executor: when a PermissionError has filename2, the message names the destination and its directory and
  says the user needs write and execute permission there; details are {path: destination, source}.
  Single-path errors are unchanged.
- tests/test_permission_denied_destination.py: a real refused rename into a read-only directory. 1 sabotage caught.

## 0.23.34 - exec allowlist bypass: deny-all and concession segments - 2026-10-26

An empty allowed_commands under allowlist or strict mode is deny-all, but a POSIX exec chain built only
of exempt segments still ran: cd (any position), a SAFE_BUILTINS no-op, or a READ_ONLY_FILTERS filter
after a separator. Three gaps let such a chain read files, and reach writes and program execution, that
the exec allowlist is meant to bound (sxrep_CY0WMZK7W01F; private report). The relative-name gap also
reached strict mode and, with a non-empty allowlist, dates back to 0.23.22.

- handlers/exec: an empty allowed_commands now refuses every command up front in allowlist/strict mode,
  before the segment exemptions are considered.
- segment_check._filter_reads_a_file: a concession filter may not be handed ANY file operand, a RELATIVE
  name (`cat passwd`, `base64 secret.key`) as well as a path-shaped one; the grep/rg PATTERN and the
  set/string/format filters (tr, echo, printf, seq, date, true, false) are the only exceptions.
  File-reading or program-running OPTIONS are refused too: grep -f/--file, wc/sort --files0-from,
  date -f, rg --pre/--pre-glob/--hostname-bin. Redirection operators and here-string data are no longer
  mistaken for file operands.
- segment_check.unauthorised_chain: a redirection on a concession segment (cd, builtin or filter) is
  refused in the default mode as well, so a write cannot be smuggled onto an unauthorised-but-exempt
  command (`true > f`, `echo k >> authorized_keys`). A redirection on an allowlisted command is
  unchanged (it is the operator's choice).
- tests/test_exec_deny_all_bypass.py: 32 tests (the reported chains, the write/exec escalations found
  while reproducing, strict and non-empty-allowlist variants, legitimate read-only pipelines still
  pass). 4 sabotages caught, one per defence.

## 0.23.33 - edit takes secret=true, for the hub's secret links - 2026-10-24

The hub's new secret links (hub 0.57.29) let a user type a credential into a page so it is written
into a file on the host without entering the conversation. Writing it with a plain edit would have kept
it in three places on the host: the safe edit's <name>.bak.<ts> copy of the PREVIOUS content, next to
the file; a diff, if one were asked for; and the local audit, which records every payload as-is and
which the dashboard's Activity page shows through read_audit.

- edit: payload secret=true forces --no-backup and refuses diff, create and backup_dir
  (invalid_payload).
- pensa_safe_edit: --no-backup (EditSpec.no_backup) skips make_backup; the result says BACKUP: none.
- local_audit: a payload with secret=true keeps op, path, mode and pattern, but new_text and old are
  recorded as {"omitted": "secret", "chars": N}. No hash: a hash of a short secret can be guessed.
- executor: capability_names() adds edit_secret while edit is enabled (PAYLOAD_FEATURES, kept apart
  from PROTOCOL_FEATURES, which must be RequestMessage fields). The hub refuses secret links for an
  agent that does not advertise it. No protocol change.
- tests/test_edit_secret.py: 11 tests (no copy left, value absent from output and staging, refusals,
  audit redacted on success and on handler error, ordinary edits unchanged, the capability follows
  edit). 6 sabotages caught.

## 0.23.32 - Connect through whichever hub address answers - 2026-10-23

mcp-direct.sentinelx.app has two relays since 2026-10-23 (orion, and venus on DigitalOcean), so the
name resolves to two addresses. Some networks can't reach one of them: packets are dropped and the TCP
connect hangs. loop.create_connection tries addresses one by one, so the whole websockets open_timeout
(10 s) ran out on the first and the second was never tried; a host whose resolver always sorted the
unreachable address first might never connect.

- client: websockets.connect passes happy_eyeballs_delay=0.25 (RFC 8305) and interleave=1 to
  create_connection: the next address is raced after 250 ms and the first to answer wins.
- tests/test_happy_eyeballs.py: a local server behind a fake two-address resolver whose first address
  never answers connects in under 2 s, and times out without the race. tests/test_client.py asserts the
  kwargs. 1 sabotage caught.

## 0.23.31 - local_api speaks JSON-RPC to a declared binary over stdio - 2026-10-22

Policy accepted `transport: stdio` on a local_apis endpoint since 0.12.0, and the docstring said only
stdio had a binary at `path`, but no version implemented it: call_action chose by protocol alone, so
every call opened `path` as a unix socket and failed with a misleading endpoint_unreachable (reported
2026-10-22). It now works, and with it local_api works on Windows, which has no unix sockets.

- local_api.call_stdio_jsonrpc: one process per call, started without a shell as [path, *args];
  one JSON-RPC request per line on stdin, stdout read until the response with the same id
  (notifications and other ids skipped, requests from the server answered -32601). stdin closed
  after the answer, process group killed after a 2 s grace; timeout_s covers the whole call. stdout
  capped at MAX_RESPONSE_BYTES (too_large), stderr kept to its last 8 KiB for error messages. The
  child gets a minimal environment plus the declared `env`. Exiting before answering is bad_response
  with the exit code and the stderr tail.
- handshake: mcp sends initialize and notifications/initialized first, so an MCP server over stdio
  can be declared directly (tools/list, tools/call).
- run_as goes through `sudo -n -u <user> -- <path> <args>`; a refused sudo answers
  run_as_not_permitted with the exact sudoers line.
- binary_problem: a binary, or a directory holding it, writable by anyone but its owner is skipped at
  load and refused before each call (unsafe_binary). A binary not installed yet still registers.
- Compatibility: the probe goes over the same transport, and for stdio the epoch is the binary itself
  (inode, size, mtime), so an upgraded binary is probed again instead of inheriting the old verdict.
- policy: stdio needs protocol jsonrpc and an absolute path; new optional fields args (fixed list),
  cwd, env (not with run_as: sudo would drop it), handshake (none | mcp). Set on a unix endpoint they
  are ignored with a warning.
- describe shows transport, and for stdio path, handshake and the number of args (not their values).
- config.example.yaml (stdio section, MCP example, the tools/call caveat), README (sentinel_local_api
  row), THREAT_MODEL §4.8.
- tests/test_local_api_stdio.py (33, real child processes) and test_local_api_stdio_windows.py (2,
  skipped off Windows). 16 sabotages, 16 caught.

## 0.23.30 - Uploads to another drive work on Windows - 2026-10-21

When an upload's destination is on another filesystem than the staging area (0.23.17), _finalize
copies the file and fsyncs the copy before renaming it. It opened the copy read-only; on Windows
fsync (_commit) needs a handle open for writing and failed with "[Errno 9] Bad file descriptor".
Every upload to another drive (staging on C:, target on G:) failed at the very end, after every
byte had arrived: seen as internal_error from sentinel_file_upload_attachment, the upload links and
sentinel_transfer_file.

- handlers/upload._finalize: open the copy r+b for the fsync (POSIX accepts either).
- tests/test_upload_finalize_other_drive.py (2; emulates Windows' rule on POSIX). 1 sabotage caught.

## 0.23.29 - An edited file gets a new mtime - 2026-10-21

sentinel_edit replaces a file atomically and copied the original's metadata onto the new one with
shutil.copystat, which also copies atime and mtime. An edited file kept its OLD mtime, so anything
that decides by mtime missed the change: PHP OPcache with validate_timestamps kept serving the old
code until PHP-FPM restarted; make, rsync -u and file watchers the same (sxrep_HGZJZXHF7RD7).

- vendored/pensa_safe_edit.copy_metadata: after copystat (mode, flags, extended attributes such as the
  SELinux label) and chown, set the times to now. Applies to an edit and to a restore, both of which
  write new content. Backups are still made with copy2 and keep the original's times.
- tests/test_edit_advances_mtime.py (4). 1 sabotage caught.

## 0.23.28 - `uptime; ls` is no longer refused for the ';' touching `uptime` - 2026-10-19

Since 0.23.22 an allowed_commands entry matches as a whole word: whitespace or the end of the string
after it. On POSIX the whole command line was checked that way before the chain check, so a first
command without arguments followed directly by ; | or & (`uptime; ls`, `pwd&& ls`) was refused even
with every command allowed, with an outdated message about prefixes. Found testing an Android/PRoot
host.

- handlers/exec: on POSIX each segment, the first included, answers on its own (the chain check, or
  the strict check); the whole-string check stays on Windows only, where exec runs PowerShell and
  there is no segment check, so `ls;rm x` is still refused there.
- The chain check's refusal now carries the same how-to-add guidance (edit the config with the
  operator's approval, reload the agent, confirm) the old refusal gave.
- tests/test_exec_first_command_boundary.py (12). 1 sabotage caught.

## 0.23.27 - The macOS restart hint matches how the agent was installed - 2026-10-18

On macOS, the hint in a command_not_allowed refusal (and anywhere else MANUAL_RESTART is used) always
said 'sudo launchctl kickstart -k system/app.sentinelx.core', the command for the optional
LaunchDaemon. install-macos.sh defaults to a per-user LaunchAgent, where that command is wrong
(sxrep_R8S7B8ARNM54).

- platform_guidance._mac_manual_restart(): system/... when /Library/LaunchDaemons/app.sentinelx.core.plist
  exists, otherwise 'launchctl kickstart -k gui/$(id -u)/app.sentinelx.core' (both modes run as the same
  user, so the plist is what tells them apart).
- tests/test_macos_manual_restart.py (2). 1 sabotage caught.

## 0.23.26 - Reconnect within a minute after a network outage - 2026-10-17

The reconnect curve topped out at 120 and 300 s (with full jitter), so an agent that went through a
network outage of a few minutes kept sleeping up to 5 minutes after the network came back. orion on
2026-10-15: last failed attempt 20:07:35, a 265 s wait, connected at 20:12:01. Across the fleet this
showed up as a bump of hosts returning 12-17 minutes after a drop, on every agent version.

- client.BACKOFF_SCHEDULE now tops out at 60 s: [0, 1, 2, 5, 10, 20, 30, 60]. Jitter, the early
  steps, the deploy path (1012 + the hub's hint) and MAX_RETRY_AFTER_SECONDS (300, the hub's brake)
  are unchanged. With full jitter, ~3100 agents return at ~50 connections/s after a real hub outage,
  the same wave every deploy absorbs.
- tests/test_backoff_retry.py: test_the_tail_is_a_minute replaces test_the_tail_stays_long. 1 sabotage caught.

## 0.23.25 - Restarting another Windows task or service no longer kills the agent - 2026-10-17

On Windows, every Scheduled-Task restart used the hardened self-restart, which force-kills the
agent's own process tree before /End and /Run: restarting Desktop Commander also disconnected
SentinelX (sxrep_7AJZFT1VGEG5). Service restarts of other services likewise took the tree-kill path
meant for the agent's own service, and their result said the agent would disconnect.

- handlers/service: the hardened restarts (_windows_task_restart, _windows_service_restart) run only
  for the agent's own unit, "SentinelX" (install.ps1 $SvcId), compared case-insensitively. Other tasks
  and services use the ordinary detached commands that already existed (schtasks /End + /Run;
  a detached Restart-Service).
- tests/test_windows_restart_target.py (6). 1 sabotage caught.

## 0.23.24 - exec_mode: allowlist, strict or unrestricted - 2026-10-16

A customer with a development fleet asked, before moving to 0.23.22, for a way to say "allow shell
execution under this identity and let Linux enforce the rest" on trusted development hosts instead
of maintaining an ever-growing allowed_commands, while keeping the strict per-command profile on
production (issue #57).

- policy.exec_mode, from config.yaml: allowlist (default; the 0.23.23 chain check), strict (what
  exec_strict: true always meant; that key still works) or unrestricted (any command line under the
  agent's identity, as script_run does; allowed_commands is ignored for exec). An explicit exec_mode
  wins over exec_strict; an unknown value falls back to allowlist with a warning instead of keeping
  the agent from starting. disabled_ops: [exec] still turns exec off whatever the mode.
- sentinel_capabilities reports exec_mode.
- config.example.yaml explains the three modes (the old text still described the prefix match).
- tests/test_exec_mode.py (12). 1 sabotage caught.

## 0.23.23 - The exec chain check understands loops and conditionals - 2026-10-16

0.23.22 checked shell grammar words as programs, so every `for ...; do ...; done` and
`if ...; then ...; fi` in an exec was refused unless those words were in allowed_commands. Found
by running a customer's 30 days of exec history through the 0.23.22 rules before they upgraded.

- segment_check._command_part(): leading do/then/else/elif/if/while/until/!/{/time are skipped and
  what follows is checked; done/fi/} and the `for VAR in WORDS` header run no command ($(...) in
  them is still checked); a subshell's '(' and closing ')' are dropped so the command inside is
  matched as written. `case` is refused as unparseable: its arms can't be told apart with certainty.
- SAFE_BUILTINS allowed in any position: set, test, [, [[, true, false, :, read, shift, break,
  continue, exit, return, wait. NOT export (export LD_PRELOAD=... changes what runs next), source,
  eval, exec or command.
- tests/test_exec_chain_shell_grammar.py (15). 1 sabotage caught.

## 0.23.22 - Every command in an exec chain must be allowed, by default (GHSA-r2h3-76g7-m95x) - 2026-10-16

allowed_commands matched the whole string by prefix and exec_strict was off by default, so with `ls`
allowed, `ls; id`, `ls $(id)`, `lsof`, `ls` + newline + `id` and `ls && id` all ran (reported
privately). exec_strict (0.23.16) already checked every segment, but also refuses newlines,
substitutions and file redirections outright, which measured at 10% of successful exec calls.

- policy.is_command_allowed: whole-word match. `ls` allows `ls -la`, not `lsof`. An entry ending in
  '/' keeps its directory-prefix meaning; an empty entry still matches everything (known gotcha,
  kept so no one is locked out). Measured cost: 0.19% of successful calls.
- segment_check: split_top_level also splits on newlines; strip_heredoc_bodies drops here-doc
  bodies (data) but returns unquoted-delimiter bodies, whose $(...) bash still runs;
  mask_substitutions replaces $(...), backticks and <( )/>( ) with a placeholder so the outer
  chain splits correctly, keeps $((...)) arithmetic, and returns the bodies; unauthorised_chain
  checks every segment and, recursively, every body. Anything it can't analyse with certainty
  (unbalanced parentheses or backticks, an unterminated here-doc) raises UnparseableCommand and
  is refused: a gap must be a false rejection, never a false permission.
- handlers/exec: with exec_strict off and outside Windows, unauthorised_chain runs after the
  usual check; the error names the missing command and how to allow it. exec_strict is unchanged.
  Windows: only the whole-word match (exec runs PowerShell there, whose grammar this does not
  model).
- Measured on 1.24M successful exec calls (7 days, allowlists reconstructed from use plus the
  default template, an upper bound): segment check 5.08%, substitutions 0.36%; newlines, the
  biggest exec_strict cost (7.05%), are now split instead of refused.
- tests/test_exec_chain_check.py (28). 5 sabotages caught.

## 0.23.21 - Harden uploads and git_ops against path/option injection (GHSA-r2h3-76g7-m95x) - 2026-10-16

Reported privately. Two write-side issues fixed; the exec prefix allowlist is a separate change.

- handlers/upload: chunked uploads can no longer write outside the allowed paths. upload_complete
  re-authorises the destination (upload_init's rules) instead of trusting meta['target_path'];
  upload_chunk and upload_complete validate upload_id (no '..'); upload_file refuses to write into
  the reserved .sentinelx_uploads/ staging area, which was the lever for a forged meta.json. A
  well-formed but unknown id still reports not_found; a malformed id now reports invalid_payload.
- handlers/git_ops: _op_ls_remote and _op_fetch reject remote/ref/ref_pattern values starting with
  '-' and pass '--' before positionals, so --upload-pack=<cmd> can't make git run <cmd>; fetch
  validates these before resolving the path.
- tests: test_upload_target_authorisation.py (4), test_git_ops_option_injection.py (5), plus the
  upload_chunk id test split into well-formed/malformed. 3 sabotages caught. All three issues
  reproduced on 0.23.20 before the fix and refused after.
- tests/test_exec_timeout_survivor.py (from 0.23.18) no longer requires left_running on every
  Python. CI failed on 3.14 only: there asyncio's Process.wait() returns at process exit instead
  of also waiting for the pipes (checked with the official images: 3.12 waited 5.5 s for a
  grandchild holding stdout, 3.14 returned in 0.0 s), so the call already comes back on time and
  there is no survivor to report. The time bound is asserted everywhere; the note only when the
  survivor was detected.

## 0.23.20 - sentinel_edit works on Windows with App Control (WDAC) - 2026-10-16

GitHub issue #56: on Windows 11 with Windows Defender Application Control, every sentinel_edit
failed with WinError 4551 (Code Integrity events 3077/3033). The agent started pensa-safe-edit
through pip's console-script launcher, sentinelx-pensa-safe-edit.exe, which is unsigned; the
python.exe already running the agent is signed by the PSF and allowed.

- handlers/edit._helper_command(): on Windows the helper runs as
  `<agent's sys.executable> -m sentinelx_core.vendored.pensa_safe_edit`; elsewhere the binary
  stays, because a sudo edit is authorised by sudoers for that exact path. Same code and the same
  checks: path authorisation happens in the handler before the helper starts.
- tests/test_edit_helper_on_windows.py (4), one runs the module command for real. 1 sabotage
  caught. Checked on a Windows 11 Pro host with the agent's own interpreter: the launcher .exe is
  NotSigned, python.exe is Valid (PSF), and the new command edited a file with its backup.
  Thanks to the reporter for the analysis and the workaround.

## 0.23.19 - The python edit validator writes nothing next to the file - 2026-10-15

sxrep_N318DCSMDYWE: sentinel_edit with validator_preset='python' ran py_compile on the candidate,
which sits next to the target, so Python tried to save bytecode into that directory's __pycache__.
Where the agent can't write there (/opt/dunia-native/state) a valid edit was rejected with Errno 13;
where it can, stray <name>.cpython-XY.pyc files were left behind.

- vendored/pensa_safe_edit.build_validator_preset('python'): runs compile(source, path, 'exec') in a
  child Python instead of py_compile: the same checks ('return' outside a function included), no
  bytecode written.
- tests/test_python_validator_writes_nothing.py (5): valid code passes in a read-only directory with
  no __pycache__ created; invalid code is still rejected. 1 sabotage caught (py_compile).

## 0.23.18 - A command's time limit holds even when something it started can't be stopped - 2026-10-15

sxrep_64T9VXZEVC61: exec with a 300 s limit ran `sudo python3 bridge.py`. At 300 s the agent killed
the shell, but bridge.py ran as root, so the unprivileged agent couldn't signal it, and it still held
the shell's stdout. asyncio's proc.wait() also waits for the pipes to close, so the call (a
background job) came back only when bridge.py exited on its own, at 900 s, after the hub had already
marked it orphaned. Reproduced on 0.23.17: a 2 s limit returned after 12 s.

- executor_engine._stop_process_tree(): after the kill, waits at most STOP_GRACE_SECONDS (5 s); if
  something outlived it and still holds the pipes, closes our end, logs a warning and returns False
  instead of waiting for it. The survivor keeps running on its own.
- run_shell / run_shell_split: in that case the result says so (LEFT_RUNNING_NOTE after the timeout
  marker) and carries left_running: true. get_command_help gets the bounded wait too.
- tests/test_exec_timeout_survivor.py (3): a grandchild in its own session (setsid) stands in for
  the root process. 1 sabotage caught (unbounded wait).

## 0.23.17 - A finished upload or transfer lands across filesystems - 2026-10-11

sxrep_XW9FTRHAH0H7: a transfer to a WSL host writing under /mnt/... moved every byte and then
failed with '[Errno 18] Invalid cross-device link'. The finished file is assembled in the staging
area under upload_base and renamed into place, and a rename can't cross filesystems (WSL drives,
a second disk, bind mounts).

- handlers/upload._finalize(): rename as before; on EXDEV, copy into a temp file in the
  destination's directory, fsync, and rename that, so the final name never points at a
  half-written file. Other errors are raised unchanged. Used by upload_complete (chunked uploads
  and cross-host transfers) and upload_file.
- tests/test_upload_cross_device.py (3), rename simulated to fail with EXDEV. 1 sabotage caught.

## 0.23.16 - exec_strict: an allowed command can't carry another one, or a file - 2026-10-11

Security, sxrep_4XCNXWP2A3VY (reported from a careful read of the installed code, no live
exploit): with exec_strict on, a newline after an allowed command passed the per-segment check
and bash ran the next line as a second command. Checking the rest of bash's grammar the same way
found more that passed: a lone '&', process substitution <( ) and >( ), and redirections, which
overwrote any file the agent's user can write, or read one through the `cat` filter that is only
allowed after a pipe so that it can't open files. Only hosts with exec_strict were affected;
without it the allowlist is a documented prefix match.

- segment_check.control_character(): newlines, CR and other control characters are refused (the
  command is trimmed first, and the trimmed string is what runs).
- split_top_level(): a lone '&' is a separator, so the next command is checked too; &> / >& / <&
  stay part of their redirection.
- has_substitution(): <( and >( outside quotes, like $( and backticks.
- segment_check.file_redirection(): strict mode refuses redirection to or from files; /dev/null,
  descriptor copies (2>&1, >&2) and heredocs/herestrings stay allowed.
- tests/test_exec_strict_bypasses.py (27) on the real exec handler: 14 constructs refused with
  nothing run, 12 legitimate commands run exactly as checked, no change without strict mode.
  The 27 existing exec_strict tests unchanged. 5 sabotages caught.

### Follow-up on the same report: after-a-pipe filters can't execute, write or open a file

The reporter's second note: READ_ONLY_FILTERS held sed/awk/jq/tee/sort/xxd/column, which for some
arguments execute (awk system, sed s///e) or write (sed -i, tee, sort -o), and any filter could
be handed a file to read (| cat /etc/shadow). Measured first: of ~9700 piped commands on
exec_strict hosts in 14 days, ~6100 use only the safe filters and keep working; ~750 (sed/jq/awk)
now need an explicit allowlist entry.

- READ_ONLY_FILTERS keeps only filters that cannot run or write; sed/awk/jq/tee removed (add by
  name to allow). A filter segment is refused if it carries a file-path operand (| cat /etc/shadow,
  | grep x /etc/passwd) or a write/execute option (sort -o, --compress-program). grep/rg keep
  their one PATTERN operand.
- THREAT_MODEL.md 4.1 rewritten to describe the real design (bash -lc + prefix match, what
  exec_strict does and doesn't cover, no shell-free argv mode yet) instead of the old
  shell=False/argv text. config.example.yaml names the excluded filters.
- tests/test_exec_strict_filters.py (24): executors and writers refused, file operands refused,
  ordinary read-only pipelines unchanged, operator re-allowlisting works. 3 sabotages caught.

## 0.23.15 - config.yaml is read as UTF-8 on every platform - 2026-10-11

sxrep_XGNWXC3Q6ZVR (+2): an assistant added a file_ops path with a Korean folder name with
sentinel_edit (which writes UTF-8) and restarted the agent. Policy.from_file read config.yaml
with path.read_text(), the platform default encoding (cp949 on a Korean Windows, cp1252 on an
English one), so it raised UnicodeDecodeError, which escaped from_file (only YAML and OS errors
were caught) and crashed the agent at every start: 174 failed hellos in two hours, service
'Running', no way to fix it remotely. Any non-ASCII character written by sentinel_edit did this
on any Windows host.

- policy.read_config_text(): UTF-8 (utf-8-sig, so Notepad's BOM is fine), and the locale
  encoding only as a fallback for a file saved by an ANSI editor.
- An undecodable config is now handled like invalid YAML: logged, and the agent starts with an
  empty policy, connected and diagnosable, instead of crash-looping.
- tests/test_config_encoding.py (6): Path.read_text patched to decode like Windows (cp949 and
  cp1252), so the tests fail on the old loader on any OS. 2 sabotages caught.

## 0.23.14 - Partial output on timeouts; config-edit guidance that works on the host - 2026-10-10

### What a process wrote before its timeout comes back with it (sxrep_AY8JPBQKSAXR)

exec (run_shell), the service ops (run_shell_split) and script_run ran communicate() inside
wait_for(): on a timeout everything already written was discarded and only '⏱️ Timeout' came
back, even from a script that flushed its progress precisely to leave a trace.

- executor_engine.communicate_partial() reads stdout and stderr as they arrive and returns
  what it has on a timeout; the caller still stops the process tree. timeout_text() keeps the
  marker first ('⏱️ Timeout. Output written before the timeout:' + the partial output), and is
  exactly '⏱️ Timeout' when nothing was written. run_shell_split now also says timed_out.
- Agent-only: the hub forwards output as is (jobs store it; its timeout guidance adds a
  separate field; the 0.56.39 spawn check keys on the '❌ Error:' marker, not this one).
- tests/test_partial_output_on_timeout.py (5, real processes); 3 sabotages caught. The fake
  process in test_script_windows_encoding.py gained stdout/stderr/wait() like a real one
  (the full suite caught that it only had communicate()).

### Config-edit guidance that works on the host it's given on (sxrep_092628RDH38B)

sxrep_092628RDH38B: service_not_allowed, exec's 'not in allowlist', fileops' path_not_allowed
and the capabilities playbook hints told the assistant to 'call sentinel_edit on
/etc/sentinelx/config.yaml with sudo=true'. Since 0.11.18 edit refuses a path that isn't under
an rw file_ops path, even with sudo, which is the default Linux install: the assistant followed
the steps and got path_not_allowed. The reload step also named 'sentinel_service
action=restart', a retired tool.

- build_registry records whether the agent's own config is writable, with the check edit uses
  (Policy.resolve_path(need_write=True); it returns None, it doesn't raise). When it isn't,
  the guidance says to ask the operator to edit the file on the host from a terminal or the
  dashboard's 'Edit config' if the host allows it. When it is, sentinel_edit as before; when
  unknown (no policy), as before.
- platform_guidance: config_edit_step() (an instruction) next to edit_config_via() (a means),
  so both read right; reload_agent() names sentinel_restart.
- tests/test_config_edit_guidance.py (5): a real build_registry with and without an rw config,
  the service and exec messages, the tool name. 3 sabotages caught, including the first draft's
  'no exception = writable', found reading resolve_path before the tests ran.

## 0.23.13 - list and search no longer report an unreadable directory as empty - 2026-10-10

sxrep_919SQBDT9XD4 (severity high): sentinel_list returned ok, total 0, entries [] for a
directory the agent's OS user couldn't read, while root saw files in it; an 'empty' that isn't
can lead to deleting data. Reproduced on Python 3.12 and 3.14 as an unprivileged user, with all
three permission cases: --- and --x (iterdir raises; the 'skip it silently, the parent already
showed it' branch also applied to the requested directory itself) and r-- (the sort key's
is_dir() raises on a directory that can't be entered, and children whose lstat fails were
dropped). search had the same silences: 'no matches' for files it never opened.

- The requested directory can't be read -> permission_denied ('contents are unknown, not empty').
- r-- (names visible, details not) -> the names are listed with type 'unknown'.
- Unreadable subdirectories in a recursive list/search, and files search can't open -> the
  result carries partial: true, unreadable_dirs (first 50) and a note that absence there is
  not proof. An entry that vanished between listing and lstat (ENOENT) is still just skipped.
- search's defensive 'except Exception' re-raises HandlerError, or it would swallow the error.
- tests/test_list_search_unreadable.py (9, skipped as root): list/search on ---/--x, r--,
  nested unreadable dirs and files, and unchanged output for readable trees. 4 sabotages caught.

## 0.23.12 - systemd user units in `services` - 2026-10-10

An app that runs as its own user (~/.config/systemd/user) couldn't be managed: `services`
always ran `systemctl <action> <unit>` against the system manager (sxrep_01JGTNPRKSS8).

- `services.<name>.user` (Linux; ignored on macOS/Windows, like domain/backend): the unit is
  managed with `systemctl --user` against that user's manager.
  - The agent runs as that user: plain `systemctl --user <action> <unit>`, no privileges, with
    XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS set from the user's uid (a service process
    has neither, and without them: 'Failed to connect to bus: No medium found').
  - Another user: `sudo systemctl --user --machine=<user>@.host <action> <unit>`, always with
    sudo, reads included ('Permission denied' without root). systemd 248+.
  - Checked on systemd 255 before writing: both modes work, and the two failures above are
    exactly what happens without the env / without root.
- `user` is interpolated into a shell command, so it must match [A-Za-z_][A-Za-z0-9_.-]{0,31};
  otherwise THAT service is skipped with a warning (not downgraded to a system unit of the same
  name). A user that doesn't exist on the host -> service_user_not_found.
- capabilities: `user` shown for user units only. config.example.yaml: commented example.
- service_not_allowed (Linux) now says to add `user: <owner>` for a systemd user unit: it is
  the message an assistant follows to declare a missing service, and without the hint it would
  declare a user unit as a system one. Not shown on macOS/Windows, where `user` is ignored.
  Existing hosts keep their config.yaml on update, so this message is how they learn it.
- tests/test_service_user_units.py (17): both modes, sudo on reads, env, unknown user, unsafe
  names incl. 'alice; rm -rf /' and '$(id)', system units unchanged, capabilities. 5 sabotages
  caught. Full suite on Python 3.12 and 3.14. No protocol or hub change needed.

## 0.23.11 - A directory the agent can't enter is 'permission denied' again on Python 3.14 - 2026-10-09

On Python 3.14, read and list reported 'path does not exist' for files under a directory the
agent's user can't enter, which sudo could read fine (sxrep_C3Q86CHYQ292, Ubuntu 26.04). From
3.14, pathlib.Path.exists() returns False on EACCES instead of raising PermissionError, and
fileops._probably_missing relied on the exception to tell 'missing' from 'can't look'. 469 of
3,421 hosts run Ubuntu 26.04, which ships 3.14.

- _probably_missing decides on os.stat's errno, which is the same on every version: only
  ENOENT, ENOTDIR, ELOOP and EBADF (what Path.exists() treated as absent up to 3.13) mean
  missing; anything else is reported as the permission problem it is.
- tests/test_unreadable_parent.py already caught it on 3.14 (4 of 7 failed) but CI never ran
  the tests. Two new tests pin the behaviour on any Python (one simulates 3.14's exists()).
  Full suite: 630 passed on 3.12 and on 3.14. Sabotage (back to Path.exists()) caught on 3.12.
- CI: a pytest job on Python 3.12 and 3.14. Not in the release job's `needs`, so a runner
  difference can't block a release; the suite never ran on GitHub before.
- Also ships the config change below (update playbooks, 2026-10-07).

## Released with 0.23.11 - The Linux update playbooks no longer run git in the root-owned checkout - 2026-10-07

Config-only (config.example.yaml); no code change and no version bump, on purpose: the
hub updates a host whose version differs from latest_agent_version, so a version on main
ahead of the hub's would make sentinel_agent_update reinstall the same build in a loop.

- update_sentinelx_code (Linux) ran git fetch / git pull in /opt/sentinelx-cloud-core as
  the agent's user. The standard install keeps that checkout owned by root, so it failed
  at the fetch (FETCH_HEAD: Permission denied) on every normal install, and an assistant
  went on to change ownership and add safe.directory to force it (sxrep_JYGA3J9A3Z9S).
  It now uses sentinel_agent_update (or the dashboard), says to wait rather than retry
  when that returns not_confirmed, and says not to touch the checkout.
- sentinelx_meta ran git log / git fetch there for the version and update check, which
  the same ownership defeats (git refuses a repo owned by another user). It now reads
  'version' and 'update_available' from sentinel_capabilities. Its notes no longer say
  the checkout is owned by the sentinelx user.
- Hosts keep the playbooks they were installed with (the installer never rewrites
  /etc/sentinelx/config.yaml): this reaches new installs; existing hosts can copy the
  two blocks (or use sync_sentinelx_config).
- tests/test_config_example_update_playbooks.py: no Linux playbook step runs git inside
  the checkout; the update playbook uses sentinel_agent_update. Fails on the old file.

## 0.23.10 - Large capabilities really arrive trimmed now (protocol 1.13.2) - 2026-10-06

- 0.23.9 (protocol 1.13.1) did not fix the reported case: a real capabilities
  detail=full keeps services, locations and playbooks as dicts, which 1.13.1 could
  not trim, so a host with a large config still got 'result omitted: too large to
  bound field-wise' (sxrep_95SMJC6TJ0CE, follow-up of sxrep_W0RW3FVD97RJ).
- Protocol 1.13.2 trims dicts as well as strings and lists (never the result's own
  keys), inserts nothing into trimmed containers, and lists what was left out in
  _truncation['omitted'] (JSON Pointer path, kept, omitted).
- New test test_capabilities_full_is_bounded.py builds the response with the real
  capabilities handler and 400 services / 13 large playbooks (171 KB): 1.13.0 and
  1.13.1 deliver a 276-byte note, 1.13.2 a trimmed result with every top-level key.

## 0.23.9 - Oversized results keep what fits instead of becoming a note - 2026-10-06

- Protocol 1.13.0 -> 1.13.1. The agent bounds every response to 128 KiB before
  sending it, and the bounding could only shorten strings: a result whose bulk was
  lists of small entries came back as 'result omitted: too large to bound
  field-wise', with ok=true. Reported by dater.network (sxrep_W0RW3FVD97RJ:
  capabilities detail=full of ~166 KB delivered as 308 bytes); in a week it hit 5
  users, one of them 311 times.
- With 1.13.1 the longest lists are trimmed too, keeping their first items and a
  '\u2026[sentinelx: N more items omitted]\u2026' marker; the rest of the result arrives
  intact. Example: a 225 KB result with 1,500 playbooks now delivers 124 KB with the
  first 825 and the marker.
- Agent suite: 631 passed against 1.13.1; the pinned tag installs 1.13.1 with the fix.

## 0.23.8 - The local audit keeps what was done, not the bytes moved - 2026-10-05

- Reported by chupin74 (sxrep_1G8KEZHMGKBA) on 0.11.15, still true on 0.23.7: the
  on-host audit log stored each upload_chunk's content_base64 in full (~1.4 MB a
  line). Retention counts lines (MAX_LINES 5000), so one host's log reached ~1.7 GB
  in an hour; the worst case was ~7 GB.
- local_audit.record writes a compacted copy of the payload: content_base64 becomes
  its decoded size and SHA-256, and any text field over 64 KB its size, SHA-256 and
  first 2 KB. Commands and scripts stay whole, nothing is redacted, and the
  original payload is untouched.
- 5 tests; 2 sabotages caught (without it, one chunk line is 1,398,282 bytes).

## 0.23.7 - What the agent starts no longer inherits its priority and OOM protection - 2026-10-03

- Reported by exceltransportpl (sxrep_E6VEFQ602FAF) on 0.23.4: processes started
  through SentinelX stay in the agent's cgroup and inherit what systemd grants the
  agent, Nice=-5 and OOMScoreAdjust=-500. On that host ~20 GB of project processes
  carried the agent's OOM protection, so the kernel would kill everything else
  first.
- spawn_kwargs (the one helper every spawn site uses: exec, script_run, edit, git,
  local_api, project_snapshot) now adds a preexec_fn on POSIX that sets the child's
  nice back to 0 and its oom_score_adj back to 0 when they are negative. Raising
  both needs no privilege. A positive nice set by the operator is kept, and a
  caller's own preexec_fn still runs. The function uses plain syscalls only
  (preexec_fn runs between fork and exec).
- Paired with the installer setting KillMode=process (sentinelx-cloud-installer
  3373945), so stopping or restarting the agent no longer kills those processes.
  Isolating them in their own cgroup needs root (systemd-run) and is left to the
  operator.
- 5 tests with real processes (a stand-in agent with the unit's values; a control
  without the helper shows the child inheriting -5/-500); the off-Windows test of
  spawn_kwargs moved to the new contract; 3 sabotages caught.

## 0.23.6 - An edit never hands a file to the agent's user - 2026-10-03

- Reported by m.schiemann (sxrep_916B3X4TFK4K) on 0.23.4: edits in a user's project
  replaced its files with files owned by the agent's user. For a mode-660 test
  file that took away its owner's read access, and the user's tests failed with
  PermissionError.
- safe-edit writes a temp file and renames it over the target. Running
  unprivileged, the agent can't chown the temp file to the original owner;
  copy_metadata recorded that (chown_skipped) and the rename went ahead anyway.
  Now, when the owner can't be kept, the new content goes into the existing
  file instead (same inode: owner, group, mode and ACLs stay), as editors do.
  The backup is taken before that write. When chown works, or on Windows (no
  POSIX owner), the atomic rename is unchanged. Edits and backup restores both
  go through the same path.
- A file the agent's user can't write is now refused (not_writable) and left
  untouched; before, the rename replaced it through the directory's permission.
- The output says 'written in place to keep the file's owner, group and
  permissions' instead of 'chown_skipped'.
- 6 tests (chown made to fail, since the suite runs as root); the existing
  chown-skip test moved to the new contract; 4 sabotages caught.

## 0.23.5 - systemd validation works; a permission error is a refusal, not a crash - 2026-10-02

- validator_preset=systemd could never pass (sxrep_NQE9F1SJHP71, on 0.23.4): safe-edit
  verified its temp file, <name>.<random>, and systemd-analyze refuses any name it
  doesn't recognize ('Failed to prepare filename ...: Invalid argument'), for unit
  files as much as for drop-ins. Units are now verified as a copy with their exact
  name in a private directory (sx-verify-*, removed afterwards). A drop-in or any
  other file is refused before it is touched (validator_unsupported) with the way
  to check it instead (daemon-reload, systemctl cat/show): systemd-analyze can't
  verify a drop-in on its own, and verifying the unit with the drop-in in place
  only warns about invalid values and still exits 0. The preset catches what
  systemd-analyze refuses; values systemd merely ignores still pass.
- A PermissionError from any handler is now answered as permission_denied, with
  the path, instead of 'executor crashed' (sxrep_TQ2C9Y22MWJP: delete on a path the
  policy allows, under a parent the agent's OS user can't traverse). Caught once in
  the executor, so move, copy, chmod and chown, which had the same unguarded
  exists() checks, are covered too.
- 7 tests (the systemd ones use the real systemd-analyze); 4 sabotages caught.

## 0.23.4 - The scan budget counts the wait for a worker - 2026-10-01

- Reported by FalconZip on issue #53, reproduced against 9a01337 with the real
  handlers and pool: 0.23.2's 50 s budget for search and recursive list started
  inside the worker, so a scan queued behind the four scan workers got a fresh
  budget once one freed up. Queue time plus traversal could still pass the hub's
  60 s wait, which is what the budget was for.
- The deadline is now set when the request arrives and passed to the worker as an
  argument (never through the payload, which a caller controls). A scan that
  reaches a worker with its budget already spent doesn't walk at all: it returns
  truncated, truncated_reason "time_budget", not_started=true and a note to retry
  or narrow the path, instead of being granted another 50 s.
- Cancelling a scan while it is still queued already kept it from running; a
  test now pins that.
- 4 tests (a fifth scan behind four busy workers, for search and list; one that
  gets a worker in time and runs; queued cancellation never walks); the sabotage
  that moves the deadline back into the worker fails both queue tests.

## 0.23.3 - A job that finishes after a reconnect delivers its result without waiting for another one - 2026-10-01

- Reported by FalconZip on issue #38, with an isolated reproduction against the
  real method bodies: a background job sends its completion on the socket it
  started on. If that socket died and the replacement connection had already run
  its one opening replay, the result was recorded to disk and stayed there until
  the NEXT disconnect, while the agent sat healthy and connected; the hub saw an
  orphaned job.
- The live connection is tracked. When a job can't send on its own dead socket,
  the held results are replayed on the live connection at once; and every
  heartbeat also replays whatever is held, which covers any other ordering.
- One replay at a time (a lock), and a replay skips a result whose own job is
  sending it at that moment, so nothing goes out twice. The job id of a held
  event lives under data (the first version of this change looked for it at the
  top level and its guard never fired; the existing replay test's fixture showed
  the real shape).
- Not in this change: clearing a held result only once the hub acknowledges it
  (send success is not acceptance), and agent-side digests. Both need a protocol
  change and belong to the result-durability design.
- 5 tests (FalconZip's ordering, the heartbeat drain, no double send); 4 sabotages
  caught.

## 0.23.2 - Reads no longer starve behind scans; scans stop when nobody is waiting - 2026-09-29

- Reported by dater.network (sxrep_TCWAAH5ATMFH) on 0.23.1, with measurements: small
  reads waiting 345-608 s behind recursive searches. read, list and search all ran
  in asyncio's default thread pool (5-8 threads on a small VPS), and search had no
  time limit. A thread can't be cancelled, so searches the hub had stopped waiting
  for (it gives up at 60 s; ChatGPT then re-issues the call) kept scanning and
  holding their threads until small reads queued for minutes. Fleet-wide over 24 h:
  3,503 searches (212 users), 560 reads and 331 lists without an answer.
- search and recursive list now stop after FILEOPS_TIME_BUDGET_SECONDS (50 s, below
  the hub's 60 s wait), checked per directory, per file and every 4,096 lines inside
  a file, and return what they found so far: truncated=true,
  truncated_reason="time_budget", and a note telling the model to narrow the path,
  depth or glob. A cap hit now says truncated_reason="max_results"/"max_entries".
- read runs in its own pool (_READ_POOL, 4 threads) and list/search in another
  (_SCAN_POOL, 4 threads), so a read never waits behind a scan.
- 6 tests (a read answers in <0.5 s with every scan thread busy); 5 sabotages
  caught. The event-loop responsiveness tests from #25 still pass.

## 0.23.1 - Windows: the refused instance can read who holds the lock - 2026-09-28

- Verified on a real Windows 11 host: a second instance exits with code 3, and
  after the first is killed with its whole tree the lock is free again. But the
  message read "pid ?": msvcrt locked byte 0, and a locked byte can't be read by
  other processes on Windows. The lock now sits 1 MiB into the file, past the pid.

## 0.23.0 - One running agent per host on a machine - 2026-09-28

- Two agents with the same identity drop each other on every connect: the hub
  keeps the newest session and closes the other, which reconnects at once. On a
  Windows service install, restarts could leave the previous agent running (the
  venv's python.exe is a launcher whose child interpreter could outlive the
  service's process); win-acer ran ~44,000 such reconnects in 2.5 hours
  (sxrep_NVKZAMSWX6XJ, diagnosed by the user after our first, wrong guess).
- At startup the agent now takes an exclusive OS lock (flock on POSIX, msvcrt on
  Windows) and holds it for its whole life. A second instance for the same host
  logs why and exits with code 3; non-zero on purpose, so WinSW and systemd retry
  and it takes over once the other process is gone. The OS releases the lock
  when the holder dies, so a crash never leaves it stuck.
- The lock is per host id, in the directory the agent owns for its rotated
  credential, so different agents on one machine (a prod and a dev agent) never
  block each other. With no writable directory the agent runs unprotected rather
  than not at all. --verify-enrollment exits before the lock and still runs
  alongside a live agent.
- Behaviour change: a second copy of the agent for the same host no longer runs.
  Duplicates across different machines (a copied identity) are not covered here.

## 0.22.1 - exec kills the whole process tree on timeout and cancellation - 2026-09-28

- Contributed by @Bl0ck154 (PR #51, sxrep_WDBZY235Y77Z): exec, run_shell_split and
  command help start the shell in its own process group on POSIX and kill the
  whole group on timeout and on cancellation (re-raising the cancellation);
  Windows keeps a tree-aware taskkill /T /F. Before, only the shell was killed,
  and its descendants survived: in production a timed-out exec left a sqlite3
  reparented to PID 1 using a full core for over 30 minutes.
- Review found a second form of the same defect: when the children kept the
  output pipes open, the old code waited for them to exit, so the exec timeout
  was ignored (a 0.5 s timeout returned after 20 s). Fixed by the same change.
- Behaviour change: when exec times out, everything the command started dies,
  including jobs it put in the background with &. For long-running work use
  systemd-run, or start the job with its output redirected so exec returns at
  once instead of timing out.
- Follow-up: taskkill goes through spawn_kwargs (no console window on per-user
  Windows installs); tests that follow the children's real PIDs, since the
  process-group ones also passed against the old code.

## 0.22.0 - A dry-run edit leaves no trace in the target's directory - 2026-09-26

- sentinel_edit with dry_run=true was not side-effect free (reported on a QNAP CIFS
  share, sxrep_7N7TJGYKFS4W). The safe editor created the parent directories up
  front, touched a missing target when create=true before checking dry_run, and
  wrote its temp file next to the target. So a dry-run create left the directory
  and an empty file behind, and on any dry run the temp file was created and
  deleted beside the target: invisible on a normal disk, but a share with a
  recycle bin kept it, and directory watchers saw it.
- Now arguments are validated before anything touches the disk; a dry run never
  creates directories or the target (a missing target is simulated as empty, in
  memory) and keeps its temp file, validation and diff in a private scratch dir
  that is removed afterwards. Restore dry runs get the same treatment. Real runs
  are unchanged: the temp stays beside the target so os.replace remains atomic.
- A missing target without create, or an invalid call, no longer creates parents.
- 8 tests; against the old editor 5 fail (the side effects), with the fix all pass.

## 0.21.0 - Deleting a SentinelX backup is terminal (reclaim disk space) - 2026-09-24

- delete always backs up before destroying, and refuses if it can't -- good, but
  it turned against users for .bak artifacts: deleting a backup made another
  backup, so space could never be reclaimed (feature request: 5.2 GB of stranded
  .bak files on an 79 GB volume, no supported way to release it).
- Now, deleting one of OUR OWN backups (name.bak.<ts> for a file,
  name.bak.<ts>.tar.gz for a directory) is terminal: the copy is skipped and the
  artifact is removed directly. The result carries terminal=true and a note so
  the caller knows there is no recovery copy.
- Matched by the exact timestamped pattern make_backup/_dir_backup_targz
  produce, so a user's own file that merely contains '.bak' (config.bak,
  notes.bak.txt) is NOT treated as ours and keeps the mandatory backup.
- Agent-only; no hub or protocol change. 12 tests, incl. the over-match guard
  (a lax pattern that would delete config.bak terminally fails).

## 0.20.0 - Credential rotation (phase 2, agent side) - 2026-09-23

- Past its credential's half-life, the agent calls POST /agent/rotate (urllib,
  no HTTP dependency) after a proven-good session, writes the new credential to
  a SEPARATE file (identity.rotated.json) in a dir it owns, and uses it from the
  next reconnect. It never touches identity.json.
- The invariant: a bad rotation never strands a host. On startup the agent
  prefers the rotated file only if it is present, parses, is unexpired and is
  for the same host; ANY doubt falls back to identity.json, still a valid
  credential. The write is atomic (temp + fsync + os.replace, 600). If no dir
  is writable, rotation disables itself with a warning.
- Legacy tokens rotate too (issued >182 days ago), migrating onto a typed,
  revocable credential -- which is exactly the fleet facing the 2027 wall.
- 12 tests: half-life logic, and every fallback (corrupt, expired, host
  mismatch, no writable dir), plus atomicity and 600 perms.

## 0.19.3 - script_run names an unusable cwd - 2026-09-23

- Without sudo, the parent chdirs into cwd as the agent's own user before the
  script runs. A directory that user cannot enter raised a bare PermissionError,
  reported as 'internal_error: [Errno 13]'. It is now permission_denied, saying
  that rw in file_ops does not grant Unix access and offering both ways out:
  sudo=true (entered after elevation since 0.12.2) or +x for the agent's user.
  A missing cwd is not_found, a file is not_a_directory.
- Only the cwd case is renamed. FileNotFoundError also means a missing
  interpreter, so the handler checks the exception's filename against cwd and
  re-raises anything else untouched. Sabotage: dropping that check makes a
  missing interpreter read as 'cwd does not exist' and fails a test.
- Reported by a paying operator running agent 0.11.19 with sudo=true -- that
  half was already fixed in 0.12.2; this closes the no-sudo half of the same
  message. Their assistant ran diagnose first, got inconclusive, and reported:
  the first real case of diagnose correctly routing a genuine defect to us.

## 0.19.2 - Host conditions while staging get a name - 2026-09-22

- script_run prepares a work directory before running. A full disk failed there
  as a bare 'internal_error: [Errno 28] No space left on device', which reads
  like an agent defect rather than the host filling up.
- ENOSPC is now no_space, EACCES/EPERM permission_denied, EROFS
  read_only_filesystem, anything else staging_failed -- each with the path and
  what to do. no_space also says plainly that a full disk destabilises the agent,
  so unrelated failures on the same host may be downstream of it.
- That last line is the point. An operator reported exec/script_run returning
  duplicate_session while ping stayed healthy, and suspected stale session
  routing in the hub. The records showed ENOSPC eight hours earlier: the full
  disk was restarting the agent in a loop, and each reconnect closed the previous
  session -- duplicate_session being the CLOSE REASON, not a rejection. The
  symptom was three layers from the cause, and a named error at the bottom would
  have shortened that.
- 8 tests, sabotage: unmapping ENOSPC fails three.

## 0.19.1 - An unreadable parent gives permission_denied, not internal_error - 2026-09-22

- read and list already had a detailed permission_denied message for a path the
  agent's user cannot reach -- explaining it is a Unix permission issue rather
  than an allowlist one, and how to fix it. Callers were not getting it: they
  got a bare 'internal_error: [Errno 13] Permission denied'.
- Cause: after _stat_safe returns None, both handlers probe with Path.exists()
  to tell 'missing' from 'no permission'. exists() traverses parents too, so on
  a directory the agent cannot enter THE PROBE ITSELF raised PermissionError and
  escaped -- two lines above the message it was trying to choose.
- _probably_missing() now answers only when it can actually look; when the probe
  cannot traverse, 'missing' is unproven and the handler falls through to
  permission_denied, which is the accurate answer when we cannot even look.
  Applied to read and list, which shared the flaw verbatim.
- Reported by an operator whose target sat under a directory the agent's user
  could not traverse: every read and list against it surfaced as internal_error.
- 7 tests (the permission ones skip as root, where traversal always succeeds).
  Sabotage: restoring the bare probe reproduces the exact internal_error.

## 0.19.0 - upload_init can land a file at its real path under an rw entry - 2026-09-22

- New opt-in land_in_place on upload_init. When set AND the target resolves
  under a file_ops rw entry, the file is written at that real path instead of
  under upload staging. Used by host-to-host transfer so a caller can land
  bytes directly in an authorized workspace rather than transfer-then-move.
- ADDITIVE. Without the flag, or when the target is not under an rw entry, it
  falls back to staging exactly as before -- no existing flow changes, and a
  non-writable target is NOT an error, just a staged landing. Verified: default
  stays staging even for an rw path; a read-only entry never lands; '..'
  traversal is still refused.
- The rw check is policy.resolve_path(need_write=True) -- the identical gate
  move and delete use, canonicalising symlinks and defeating '..' before the
  prefix check. This opens nothing the operator has not already declared rw.
- upload_init now takes the policy (optional) to run that check; the registry
  passes it. The meta records landed_in_place so the result can report it.
- Requested by a report with transfer_id/sha256/requested-vs-actual paths.
- 6 tests, two sabotages: dropping need_write lets a read-only path land
  (fails), and ignoring the flag lands by default (fails).

## 0.18.4 - help stops recommending disabled operations - 2026-09-21

- On a deny-all host -- disabled_ops covering read/list/edit/exec/service, no
  file_ops paths, no playbooks -- help(topic='operations') listed every op and
  help(topic='access') recommended op:edit, op:service and playbooks that do not
  exist there. It pointed the operator straight at locked doors.
- navigation now shows only LIVE operations: an op that is in disabled_ops, or
  whose prerequisite is absent (exec with no allowed_commands, read with no
  paths, service with no services), is omitted rather than advertised.
- extending_access now leads with an honest note when the host cannot edit its
  own config remotely (edit disabled or no writable path): the change has to be
  made on the host, not through SentinelX -- instead of recommending an edit the
  host will refuse.
- Reported on a Windows host where only ping/help/capabilities were live.
- 8 tests, verified by sabotage: making navigation ignore the live-op check
  fails the deny-all case. The 31 existing help tests still pass.

## 0.18.3 - Windows service detection no longer depends on sc.exe text - 2026-09-21

- 0.18.1 fixed the optional colon in sc.exe qc, and it was not enough. The same
  operator's non-English host returns sc.exe output that is BOTH localized (the
  label is not the English SERVICE_START_NAME) AND OEM-encoded (decoded as UTF-8
  it is mojibake). So _win_service_account still returned None and
  _win_has_scm_restart_recovery still returned False on a host whose CIM plainly
  showed LocalSystem and RESTART/10000 -- and the self-restart was refused
  again, one layer down.
- Account resolution now reads Win32_Service.StartName via CIM: a structured
  object property, so there is no console codepage in the path and no localized
  label to match. sc.exe qc stays only as a fallback, with the 0.18.1 parsing,
  for the rare host where CIM is unavailable.
- SCM restart-recovery detection now reads the registry FailureActions blob -- a
  fixed binary layout, language-independent -- and looks for a type-1
  (SC_ACTION_RESTART) action, instead of grepping localized sc.exe qfailure text
  for the word RESTART. qfailure text remains the fallback.
- Reported by a paying operator who cited the exact 0.18.1 commit and proved the
  gap with CIM output beside the garbled sc.exe output. Structured data was the
  right call and they said so.
- 8 new tests, verified by sabotage: making account resolution skip CIM, or
  recovery skip the registry, each fails the cases where sc.exe is garbage --
  which is the reported host. The 0.18.1 tests were updated to stub CIM empty so
  they exercise the sc.exe fallback they were written for.

## 0.18.2 - exec resolves a PowerShell the service account can launch - 2026-09-21

- sentinel_exec failed on a Windows LocalSystem service with WinError 1920 while
  script_run on the same host worked. _shell_argv trusted shutil.which('pwsh'),
  which under a service resolves to the per-user WindowsApps execution alias --
  a reparse stub in a user profile that LocalSystem cannot execute.
- Resolution now probes, in order: concrete PowerShell 7 paths in Program
  Files, shutil.which('pwsh') ONLY if it is not a WindowsApps alias, Windows
  PowerShell 5.1 at its System32 absolute path, and finally the bare name. Each
  candidate is checked as a real file; the WindowsApps path is excluded
  outright.
- Reported by a paying operator already on 0.18.0, with the alias path and the
  working Program Files path side by side -- the defect survives the update, so
  it had to be found by a host that reproduced it.
- The resolved interpreter is cached, except the bare-name fallback, so a
  later-installed shell is still picked up.
- 10 tests, verified by sabotage. The first version had a coverage hole: the
  alias test still passed with the exclusion removed, because System32 was
  present as a fallback. Added the sharp case -- alias present as the only file
  -- which fails without the exclusion, exactly the reported host.

## 0.18.1 - Parse sc.exe SERVICE_START_NAME with or without a colon - 2026-09-21

- The Windows self-restart preflight refused a LocalSystem service with
  service_restart_unsafe, claiming a non-SYSTEM account and no SCM recovery --
  a message the host's own `sc.exe qc` contradicted, showing LocalSystem and
  FAILURE_ACTIONS=RESTART.
- Cause: _win_service_account required a colon after SERVICE_START_NAME. sc.exe
  aligns columns with whitespace and the colon is present or absent depending
  on Windows version and locale. On a host that omits it, the account resolved
  to None, _win_is_system_account(None) was False, and a LocalSystem service
  fell into the underprivileged branch and was refused.
- The label is now stripped whether or not a colon follows it. LocalSystem in
  both forms is privileged; LocalService and NetworkService stay
  underprivileged, unchanged.
- Reported by a paying operator with the full sc.exe qc / qfailure readback. It
  had blocked a governed 0.14.1 -> 0.18.0 update that fails closed on a refused
  restart, so the parse bug was holding the fix for every other bug off that
  host.
- 13 tests, verified by sabotage: restoring the colon requirement fails the two
  no-colon cases, which is precisely the reported host.

## 0.18.0 - The agent reports when it received and finished a request - 2026-09-20

- Two timestamps, carried inside `result` under `_sx_timing`: when the request
  reached this agent, and when the handler finished.
- WHY. The hub could only ever measure hub-out to hub-back, so "this call took
  57 seconds" was unanswerable: the wire, queueing here and the work itself
  were one number. An operator reported seconds-long calls whose host-side work
  was milliseconds, and the honest answer was that we could not tell.
- Inside `result` rather than as a new top-level field on purpose:
  ResponseMessage is extra="forbid", so a field the hub's pinned protocol did
  not know would make it reject the whole message. That mismatch cost an outage
  once already (issue #21), and this needs no protocol change at all.
- The hub removes the key before the caller sees the result, so no response
  shape changes for anyone.
- Not added to binary transfer results, which leave the JSON path entirely.

## 0.17.1 - capabilities evidences the policy, not only its effect - 2026-09-20

- capabilities now reports `disabled_ops` and `exec_strict` alongside
  `ops_supported`.
- ops_supported is the permitted set and a disabled op is simply not in it,
  which is correct but not sufficient for an audit: an old agent that never had
  the op and a current one where the operator deliberately turned it off look
  identical from outside. Asked for by an operator running a governance audit
  who needed to evidence the difference rather than infer it.
- disabled_ops is echoed from the config rather than derived from the registry,
  so a name that matched nothing still appears. A typo in a deny list otherwise
  reads as protection that was never applied -- the worst possible answer to an
  auditor.
- exec_strict is reported for the same reason: whether chained commands are
  checked segment by segment is part of what this host is willing to run, and
  should not require reading config.yaml off the machine to establish.
- 7 tests. Sabotage: filtering the list down to recognised op names fails four.

## 0.17.0 - exec_strict: check every segment, not just the first - 2026-09-20

- allowed_commands matches what a command STARTS with, and the matched string
  then goes to `bash -lc`. So `allowed-probe; id` passed the check and the
  shell ran both halves: the allowlist bounded the prefix, not the execution.
  Reported with working demonstrations using ';', '&&' and '|'.
- The obvious remedy -- refuse compound operators -- was MEASURED against 48
  hours of fleet traffic before being rejected: it would have failed every
  chained call, 87,281 of them across more than a thousand hosts, including
  patterns as ordinary as `cd /srv/app && make`. A security fix reverted within
  the hour protects nobody.
- So: opt-in `exec_strict`, which checks each segment against the allowlist.
  Two concessions, neither widening reach: `cd` in any position (90% of what
  strict checking otherwise rejected), and read-only filters after a pipe but
  never as the first segment -- `cat /etc/shadow` reads a file, `| cat` cannot.
  Measured with those: 68.5% of chained traffic passes rather than 23.4%.
- Command substitution is refused outright under exec_strict. Our own
  verification found that gap on the first run: `probe $(id)` is ONE segment,
  starts with an allowed prefix, and passes every check while the shell runs
  the substitution first. A strict mode that permits it answers "checked" to a
  question it did not ask, which is worse than no strict mode at all.
- Splitting is quote-aware. A naive split reported a false 100% breakage when
  this was first measured, because `find . -name '*.py;'` was cut into
  fragments. A separator inside quotes is data, not structure.
- OFF BY DEFAULT and documented as such. What still fails under it is `git`,
  `npm`, `for` loops and substitutions -- things a prefix allowlist cannot
  express. Those belong in script_run.
- 27 tests, four sabotages: first-segment-only fails six, filters anywhere
  fails one, no substitution check fails three, quote-blind splitting fails
  one.

## 0.16.0 - An operator can switch an op off - 2026-09-20

- New `disabled_ops` in config.yaml. An op named there is not built into the
  registry at all, so it disappears from capabilities and any call to it is
  answered unsupported_op -- as if this agent had never shipped it.
- WHY. allowed_commands governs `exec` and only `exec`; that is what its own
  heading says and always has. script_run hands a script body to an interpreter
  and was never bound by it. Reasonable operators read an empty allowlist as
  "this host executes nothing" and were surprised. Two reported it
  independently, one after a governance audit on a Windows host where the
  service runs as LocalSystem, which makes the gap between expectation and
  behaviour considerably more expensive. Being documented did not make the
  surprise unreasonable, and there was no supported way to say no.
- Removal rather than a guard inside each handler, deliberately: capabilities
  DERIVES ops_supported from the registry keys and dispatch answers
  unsupported_op for anything absent, so one deletion makes an op invisible AND
  unreachable with no second enforcement path to drift. A per-handler guard
  would have to be remembered everywhere and forgotten in one place.
- ping, capabilities, state and help cannot be disabled. An agent that cannot
  say what it is or whether it is alive still holds a slot and still looks
  connected, which is worse than one that is absent. Naming them logs a warning
  and is ignored; the rest of the list still applies.
- A name this agent does not have is ignored and logged as not recognised: a
  typo in a deny list otherwise reads as protection that is not there.
- config.example.yaml now states the scope of allowed_commands explicitly and
  points to disabled_ops for the stronger statement.
- 13 tests, three sabotages: dropping the core protection fails two, deleting
  names without intersecting the registry fails the same two, and skipping the
  filter entirely fails six.

## 0.15.2 - A directory we cannot enter is not a missing repository - 2026-09-20

- `git rev-parse` exits 128 for `cannot change to '<path>': Permission denied`
  exactly as it does for "there is no repo here". We read only the rc, so an
  EACCES surfaced as not_a_git_repo -- whose text tells the caller the directory
  is not a checkout, that the repository must be elsewhere, and that retrying is
  pointless. The first two are false. The third is true for the wrong reason,
  which is worse than being wrong: it tells the model to stop looking at a
  problem the operator can fix in one command.
- Same shape as the 0.13.x dubious-ownership fix, different cause. That one
  already carries a comment saying not_a_git_repo is "actively wrong here"; this
  is the second member of the family, and stderr distinguished them all along.
- Found on a host where /home/<user> is 0750 and the agent runs as its own
  account: every repo underneath answered "not a git repository" while
  sentinel_read on a file inside the same tree correctly said "Permission
  denied". Two tools, one cause, contradictory diagnoses.
- The new error names the account the agent runs as, says the refusal is the
  HOST's file permissions rather than SentinelX's file_ops allowlist -- naming a
  path there permits work, it does not grant access the kernel refuses -- and
  points at sentinel_exec running as the owner as the route that works
  meanwhile. Applied at both sites that resolve a git root (diff and
  apply_patch).
- "Permission denied (publickey)" is excluded: that is a transport failure from
  the network operations and sends the operator to a deploy key, not a chmod.
- Tests cover the predicate and the handler behaviour. Verified against the
  pre-fix handler, which returns not_a_git_repo for the same stderr.

## 0.15.1 - Pin the protocol that actually has opaque_ref - 2026-09-20

- Executor advertised the opaque_ref capability while pyproject pinned protocol
  v1.11.0, whose RequestMessage has no such field. RequestMessage is
  extra="forbid", so the hub -- which only sends the field to an agent that
  asked for it -- would send it and the agent would reject the ENTIRE message.
  Advertising it was worse than not advertising it: the operation died with
  extra_forbidden before dispatch instead of merely losing the correlation.
- The field arrived in protocol v1.12.0; the pin is now v1.13.0.
- Reported by FalconZip (issue #21), who installed from the declared dependency
  rather than from a tree that already had a newer protocol in it. That is why
  none of us saw it: every working environment here was fine, and only a clean
  install reproduced it.
- A test now compares Executor.PROTOCOL_FEATURES against the INSTALLED
  RequestMessage, so the advertisement and the dependency cannot drift apart
  again. It fails against v1.11.0 and passes against v1.13.0, which is how it
  was verified.
- Full suite re-run against v1.13.0: 426 passing, so the two-version bump
  carries nothing else with it.

## 0.15.0 - A job's answer outlives the connection meant to carry it - 2026-09-19

- A background job's completion was sent over the very socket the request
  arrived on. If that socket had gone by the time the work finished -- our
  deployment, the operator's network, anything -- the send failed and the answer
  was lost. Work done, result built, nobody listening. The code even said so:
  'even an emit failure is only logged'.
- Three users reported that shape of loss in one day, and 98 job records were
  sitting at running fleet-wide with nothing ever coming back for them.
- The event is now written to disk BEFORE the send, cleared once the send
  succeeds, and replayed on the next connection. Safe to repeat: the hub matches
  a completion by job id and owning user rather than by session, and applying
  one twice leaves the same record.
- Bounded on purpose: 500 files and a 24h TTL, oldest dropped first so the most
  recent answer -- the one someone is still waiting on -- survives. Beyond that
  the hub has expired the job anyway.
- Written beside the upload base, not inside it: those directories are the
  operator's. Write-then-rename, and the job id is sanitised before it reaches
  the filesystem.
- WHAT THIS IS NOT: a job registry. The work still runs inside the agent and
  still dies with it. What survives is the ANSWER, which is the failure everyone
  actually hit; surviving an agent restart needs detached execution and is a
  separate change.
- Five sabotages, and one of them earned its keep: removing the record() call
  left every test passing, because they all began from an already-written file.
  Three tests now drive the emit path itself.

## 0.14.7 - An uppercase SHA-256 is a correct SHA-256 - 2026-09-19

- upload_complete compared the caller's digest against hexdigest() as a plain
  string. hexdigest() is always lowercase, so a digest correct in every way but
  letter case was rejected as checksum_mismatch -- a message that says the bytes
  arrived wrong when they arrived perfectly. Uppercase is the convention in
  plenty of manifests and record systems.
- Reported with a three-chunk reproduction of b"abcdefghi" and a lowercase
  control of the identical payload that completed successfully. Cause and fix
  both named correctly in the report.
- Hex is now normalised before comparison, and a malformed value is told apart
  from a wrong one: invalid_sha256 for "that is not hex" versus
  checksum_mismatch for "the bytes differ". Those call for different responses
  and the old code gave them the same name.
- The mismatch message now shows both digests, so a caller can see at a glance
  whether they are looking at truncation, the wrong file, or real corruption.
- VERIFIED BY SABOTAGE, and the first attempt did not survive it: that version
  reimplemented the comparison inside the test, so it passed with the fix
  deleted. The tests now drive the real init/chunk/complete handlers. Removing
  the normalisation fails three of them; accepting everything fails three more.

## 0.14.6 - A checkout owned by another user is no longer "not a git repo" - 2026-09-19

- git refuses to read a repository owned by a different user than the process
  running it, and exits non-zero -- the same rc as "there is no repo here". We
  read only the rc, so both became not_a_git_repo, whose text then told the
  caller the directory was not a checkout or the repository was elsewhere. For
  this case both halves are false, and the suggested `find -name .git` finds the
  repo that was never missing.
- Reported on /var/www, where the checkout belongs to the web account and the
  agent runs as its own -- which is also why the same commands succeeded over
  sentinel_exec, running as the owner.
- sentinel_git now raises git_dubious_ownership, naming git's safety check as
  the cause and giving the operator the two real ways out: ownership, or a
  deliberate `git config --global --add safe.directory` as the agent's user. We
  do not add that exception ourselves -- the check exists to stop a repository
  you do not control from running its config and hooks.
- project_snapshot had the same blind spot for a different reason: its _run_git
  sends stderr to DEVNULL, so it silently downgraded a real repository to
  kind=directory. It now reports the directory summary WITH a git_unavailable
  note explaining why the git view is missing.
- Both modules share substrate and have drifted before -- yesterday's locale fix
  was present in both and found in one. A parity test now asserts they detect
  the same condition.
- Verified as the agent's own user against a repository owned by root: the
  ownership refusal and a plain non-repo both return rc=128 and are now told
  apart by stderr.

## 0.14.5 - The empty command prefix no longer kills capabilities - 2026-09-19

- On a NoNewPrivileges host, `allowed_commands: [""]` made every capabilities
  request fail with IndexError: the unusable-commands scan called `c.split()[0]`
  on each entry, and "".split() is []. The crash is caught per request, so the
  session and exec kept working -- the hub simply never heard back about that
  host's capabilities.
- The empty prefix is a first-class entry: matching is `cmd.startswith(allowed)`,
  so "" is how an operator grants any command within the host account. It had to
  keep working, not be rejected.
- Reported by danshapiro in issue #47, with the traceback, the cause and a fix.
- The suggested `if c` would have fixed the reported case and left a
  whitespace-only entry crashing identically: " " is truthy and " ".split() is
  also []. Our test for that failed on the first attempt, so the guard is on the
  split result rather than on the string.
- Introduced in 0.14.3, which added unusable_commands. Six tests cover it.

## 0.14.4 - No console windows flash on Windows - 2026-09-18

- A console application launched from a process with no console of its own
  gets a new one allocated, and that console comes with a VISIBLE window. The
  agent runs as a service or a pythonw scheduled task, so it has none: exec,
  git, project_snapshot, edit and local_api each painted a brief black box on
  the operator's desktop. Reported with the spawn sites already identified.
- CREATE_NO_WINDOW was applied in exactly one handler and nowhere else -- what
  happens when the knowledge lives in one file's comments instead of a shared
  helper. It now lives in sentinelx_core.winspawn, used at every spawn site,
  merging rather than overwriting flags the caller already set.
- The nested PowerShell 5.1 bootstrap gets -WindowStyle Hidden as well: the
  outer process is covered by the flag, but PowerShell launches the inner one
  itself and the flag does not carry across.
- A test walks every create_subprocess_exec/Popen call in the package via the
  AST and fails if one does not suppress the window, with a guard so it cannot
  pass by finding nothing. It immediately caught script.py building a local
  dict that shadowed the helper's name -- now unified.

## 0.14.3 - Say which allowlisted commands the host cannot run - 2026-09-18

- An operator allowlisted an exact sudo command on a host installed with
  NoNewPrivileges. The kernel guarantees sudo fails there regardless of
  sudoers, but capabilities listed the command like any other, so the only way
  to find out was to run it and read the error. Their words: it should execute,
  or it should not be advertised as executable.
- We cannot make it execute. The bit is the operator's security decision and
  the right one -- it is also our own hardened default. So capabilities now
  reports unusable_commands: which entries cannot run, why, and what to do
  instead (a service action, or a helper the agent can call directly).
- Silent and cheap on the common case: one small read of /proc/self/status,
  and nothing reported unless the host really is hardened AND the allowlist
  really contains something needing privileges. No /proc means no such bit,
  which is the correct answer on Windows and macOS.
- Verified in both real conditions with the reporter's own command, using
  systemd-run --property=NoNewPrivileges=yes to reproduce their host.

## 0.14.2 - Git diagnostics no longer depend on the host's language - 2026-09-18

- The --recount retry branches on git's stderr, looking for "corrupt patch".
  Git translates that text, so on a localized host the branch never fired and
  the malformed-hunk recovery silently stopped existing -- no error, just a
  feature that was not there.
- Reported from a pl_PL.UTF-8 host with the exact message git produces there,
  the failing upstream tests, the cause and the fix. Reproduced in a container
  with the Polish translation installed: the old environment misses the
  condition, the pinned one catches it and --recount then applies the patch.
- LC_ALL=C in _GIT_ENV, which is merged OVER os.environ so an inherited locale
  cannot win. C rather than C.UTF-8: the latter is absent on musl and older
  glibc, and we only need the messages untranslated -- paths travel as bytes
  and are never decoded through the locale.
- Applied to project_snapshot.py as well, which git_ops copied its substrate
  from and which its own header says must not diverge. A test holds the two
  environments identical, because a key added to one and not the other is
  exactly how the next one of these gets in.

## 0.14.1 - Reading a service's state no longer asks for sudo - 2026-09-17

- requires_sudo is a property of the SERVICE, set by the operator because
  restarting needs root. It was applied to every action, so plain status,
  is-active and is-enabled reads were prefixed with sudo as well.
- On a host installed with NoNewPrivileges -- our own hardened default -- sudo
  cannot run at all, so asking whether a service was up failed on exactly the
  hosts that had followed our security advice. Reported by an operator who
  declined the obvious workaround of weakening the install, and was right to.
- Verified on a real host as the agent's unprivileged user before changing
  anything: status, is-active and is-enabled return 0; restart and stop fail
  with "Interactive authentication required". The split follows that
  measurement.
- The launchd path is left alone: launchctl print on the system domain does
  appear to need root, and we have no macOS host to confirm it on.

## 0.14.0 — git over the network — 2026-09-18

- `sentinel_git` gains ls_remote, fetch, clone and push. Measured over 7 days,
  distinct users already doing this through exec: fetch 489, push 399,
  ls-remote 374, clone 359.
- A forced push MUST carry `expected_remote_sha`, making it a compare-and-swap.
  189 users force-pushed without a lease against 56 who used one; a bare force
  silently discards whatever someone else pushed in between.
- No `pull`: it is fetch plus merge, and the merge is worth doing explicitly.
- clone refuses a non-empty destination, requires rw, and removes its own
  partial tree if it runs out of time rather than leaving a dest_not_empty
  failure for the next attempt.
- Transport errors say whether retrying helps.

## 0.13.2 — sentinel_git failure modes — 2026-09-18

- `apply_patch` retries once with `--recount` when git rejects a patch as
  corrupt, which is the signature of hunk header counts a model got wrong.
  ~3,100 calls from 240 users failed that way in 14 days. A correct patch is
  untouched; a recounted one reports `recounted: true` rather than passing
  silently.
- `not_a_git_repo` now says that retrying the same path will keep returning the
  same thing, and gives the `find` invocation that locates a checkout. 46% of
  those 5,523 failures came from retry loops, worst case 65 attempts on one
  directory.

## 0.13.1 - capabilities reports where uploads land - 2026-09-17

- The staging directory is resolved at start-up: from the config, or the first
  writable candidate (/var/lib/sentinelx/uploads, then the legacy
  /home/sentinelx/uploads), or the system temp space. Nothing exposed which
  one won, so host-side tooling that resolves a bare filename had to hard-code
  our path and failed silently when it guessed wrong.
- capabilities now reports it as `upload_base`, and the summary view keeps it.
  Read-only: it says where staging happens, it does not move it. Deliberately
  separate from file_ops -- staging there grants nothing under file_ops, and on
  most hosts the directory is not in that list at all.
- Two operators asked for this on the same day. One had written to three
  different directories trying to find the right one; upload_file had been
  returning the resolved absolute path all along, but only after the upload,
  which is too late to configure a wrapper with.

## 0.13.0 — declared parameter schemas for local_api actions — 2026-09-16

- An action can declare `params:` as a JSON-Schema-like shape. `describe`
  returns it verbatim and now also derives parameter NAMES from it, so a
  JSON-RPC action no longer reports an empty parameter list (core#45).
- Declared rather than probed: a probe cannot be the baseline, since Herdr's
  schema is reachable only through its CLI and Docker has no introspection.
  An optional probe can still be added later for endpoints that can answer.
- The agent never interprets the schema. Nesting, arrays and enums mean
  whatever the endpoint says they mean.

## 0.12.5 - Quote service and task names on Windows - 2026-09-16

- Service and task names are operator-chosen and were interpolated straight
  into PowerShell and cmd command lines. A name containing a space split into
  two arguments, so the command addressed something other than what was asked
  for -- silently, since schtasks and Get-Service simply act on the wrong
  name.
- It matters most on the self-restart, whose sequence is kill, end, start: the
  kill half always works and the start half is the one that would address
  nothing, leaving the agent down with nothing left to bring it back. The
  operator then loses remote access to that host precisely because the tool
  they manage it with is what died.
- Names are now quoted for whichever shell receives them: single quotes for
  PowerShell, with an embedded quote doubled per its own rule, and double
  quotes for a cmd argument nested inside a PowerShell literal. A name
  containing a double quote is refused rather than mangled; Windows does not
  permit one in a task name.
- Found while investigating a report of a Windows host that did not come back
  after a restart. Whether it was the cause there is not established -- that
  host runs a custom install and we have asked for its task name. The default
  install uses "SentinelX", which has no space, which is why this never
  surfaced in our own testing.

## 0.12.4 — local_apis is a recognised config key — 2026-09-16

- A valid `local_apis` block no longer triggers `policy_unknown_keys`. It was
  parsed and working while the warning told the operator it was unrecognised.
  Reported from a real deployment (core#45). Warning-only, but a correct config
  should not warn about itself.

## 0.12.3 - A timed-out script no longer leaks its descendants - 2026-09-16

- On POSIX, a timeout killed only the process we spawned. Anything it had
  started kept running: a timed-out `docker run` left the docker client and
  its root-owned wrapper alive for hours, one pair per attempt, until the
  host was cleaned by hand. Windows was already handled.
- Scripts now start in their own session, so the whole tree shares one
  process group and a single signal reaches all of it.
- Two details found by experiment rather than reasoning. A tree started under
  sudo is root-owned and the agent user cannot signal it -- killpg raises
  PermissionError and everything survives -- so those go through `sudo kill`.
  And `kill -9 -<pgid>` is parsed as an option, not a group: it exits 0 and
  kills nothing, which is the worst way to fail. The `--` separator is what
  makes it a process group, and a test holds that.

## 0.12.2 - sudo changes directory after it gains privileges - 2026-09-16

- script_run passed cwd to the subprocess call, which makes the PARENT chdir
  before exec -- as the agent's own user. Asking for sudo=true on a directory
  only root can enter therefore failed with PermissionError before sudo ran
  at all: the one case where the privileges were requested precisely because
  the directory needs them. Reported against an 0700 worktree.
- With sudo and a cwd, the chdir now happens inside the elevated process.
  Everything else is unchanged: no sudo, or sudo without a cwd, behaves
  exactly as before.
- The directory travels as a positional argument rather than an environment
  variable. sudo strips the environment, and an empty value would make the
  cd a silent no-op that ran the script in / instead of failing. As a
  positional it is also inert: a value containing shell metacharacters is
  just a directory name that does not exist, which exits 126 without running
  anything.
- Not solved with `sudo --chdir`, which needs CWD=* in the sudoers policy. We
  had just asked 1,290 operators to review and tighten that file; asking them
  to widen it again would be a poor trade.

## 0.12.1 — run_as, and two Herdr integration fixes — 2026-09-15

- `run_as` now actually reaches a socket owned by another Unix user. It parsed
  and was never applied, so a 0600 socket stayed unreachable while the config
  said otherwise. The connect happens in a small relay invoked through
  `sudo -n -u`; running the agent as root is not a substitute, because root
  connects but identifies as uid 0 rather than the owner.
- Refused sudo reports `run_as_not_permitted` and names the exact sudoers line,
  instead of being wrapped as a compatibility problem by the probe.
- The JSON-RPC request id is a string, which satisfies both the 2.0 spec and a
  receiver that declares it as one.

## 0.12.0 — local_api — 2026-09-15

- New `local_api` op: list, describe and call host-local endpoints that already
  speak a structured protocol (core#45). Only hosts declaring `local_apis`
  register it, so nothing changes for the rest of the fleet.
- The action allowlist is the entire security boundary and is required; an
  endpoint declaring none is not registered.
- Actions declare their own field projection. Measured on a real host: 712
  bytes of `docker ps` text, 20,340 raw, 1,811 projected.
- Compatibility constraints are evaluated once per connection epoch and fail
  closed. Never inferred from `new_version >= configured`.
- Requires protocol 1.13.0.

## 0.11.19 - Reconnect sooner, and not all at once - 2026-09-14

- The backoff curve jumped 5 -> 30 seconds, so a momentary break on an
  otherwise healthy path cost close to a minute offline: one second, a failed
  handshake, five seconds, another failed handshake, thirty. For a host whose
  connection drops every couple of minutes that is a quarter of its life spent
  reconnecting. The early steps are now gentle (1, 2, 5, 10, 20) and the tail
  stays long for the case the curve was written for, a hub that is genuinely
  down and should not be hammered on the way back up.
- Delays are now jittered. Every agent sees the same hub restart at the same
  instant and used to wait the identical time, so roughly 1700 of them came
  back in one spike, precisely while the hub was starting. Spreading each
  delay over its own window turns that into a trickle.
- The hub can now suggest when to come back, via `retry_after=<seconds>` in
  the close reason. It knows what the agent cannot: how many are reconnecting
  at once. The agent caps the value and ignores anything malformed -- a
  suggestion, not an instruction, so a buggy or hostile hub cannot tell the
  fleet to go quiet. Agents that do not understand the field ignore it.

## 0.11.18 - sudo no longer exempts an edit from the writable allowlist - 2026-09-08

- `edit` treated `sudo=true` as an exemption from the file_ops rw check, on
  the stated assumption that a sudo edit was bounded by the installer's
  sudoers fragment. The installer granted NOPASSWD:ALL, so no such bound
  existed: any request could write any file as root, including this agent's
  own config. An agent that can rewrite its own allowlist does not have one,
  which made the rw model advisory rather than enforced. Reported by OpenAI
  Security.
- The rw check now applies regardless of sudo, on both the single-call and
  the chunked-upload path (fixing only the first would have moved the bypass
  rather than closed it). Canonicalization is unchanged. Operators who do
  want the agent to maintain its own policy can add the config file to
  file_ops with access: rw, which makes it a visible choice in their config
  instead of an invisible property of a flag.
- The policy-editing playbooks now hand the change to the user instead of
  attempting it, and say why.
- Corrected a false statement in config.example.yaml: it claimed every
  command inside a sentinel_script_run script is allowlist-checked. Script
  contents are not checked at all. Users were choosing a conservative
  allowlist believing it bounded scripts; what bounds a script is what the
  agent's user account may do on the host.

## 0.11.17 - An emptied config no longer blocks its own repair - 2026-09-08

- `edit` and `script_run` stage content in a workdir under `upload_base`
  before writing anything, and `upload_base` is read from the agent config.
  So a host whose config.yaml lost that setting fell back to a hardcoded
  /home/sentinelx/uploads, which on most installs does not exist or belongs
  to root: staging failed with a bare `Permission denied: /home/sentinelx`,
  and the one tool that could have restored the config was the tool that had
  stopped working. A real user hit this and needed manual recovery.
- The default is now resolved instead of hardcoded (first writable of
  /var/lib/sentinelx/uploads, the legacy /home/sentinelx/uploads, then the
  system temp space), and staging falls back to the temp space at runtime if
  the configured base cannot be written, warning once with the setting to
  fix. An explicit `upload_base` is still honoured exactly as before, so
  healthy hosts are unaffected.
- If even the fallback fails, the error now names both paths and the setting
  to change rather than surfacing a bare permission error.

## 0.11.16 - Say when the hub refuses this host - 2026-09-08

- A refused enrollment was indistinguishable from a network blip. The hub
  sends an error frame and closes with 1008, but it closes immediately, so
  whether we read that frame was a race: winning it raised a fatal error and
  the agent stopped for good, losing it logged 'connection closed' and retried
  in silence. Same refusal, two different behaviours, neither of them useful.
  One host retried 919 times over four days with the reason sitting in its
  journal.
- Both paths now report the same thing: a single actionable line naming the
  two possible causes (a token altered while being copied, or the host
  disabled by its owner) and what fixes each. Retries continue at the normal
  cadence on purpose, so re-enabling a host or fixing something hub-side heals
  without touching the machine.
- New `--verify-enrollment`: opens one connection, reports whether the hub
  accepts this host's token, exits 0 or 1. Starts no session, so it is safe to
  run alongside the agent. Being unable to reach the hub is reported
  separately from a refused token, so a network fault is not mistaken for one.
- Close reasons now read through `.rcvd` where available (`.reason` is
  deprecated since websockets 13.1) with a fallback for older releases.

## 0.11.15 - Contain WebSocket task failures during teardown - 2026-09-06

- Merged #43 (thanks @Galactus-Prime; fixes #42): connection-scoped
  request/binary/background tasks are retained until completion and their
  exceptions are consumed deterministically, and the read/heartbeat loop tasks
  are gathered with return_exceptions=True during teardown, so transport
  disconnects (1006/1012/keepalive timeout) no longer leak `Task exception was
  never retrieved`. An in-flight foreground operation is not cancelled merely
  because its response socket closed, so replay/idempotency stays authoritative.
- Hardened the teardown regression test so the task is collected while the
  custom loop exception handler is still installed, making it a real guard.

## 0.11.14 — Fail loud on a corrupted enrollment token — 2026-09-04

- `load_identity` now validates the enrollment token when it reads
  identity.json: surrounding whitespace is trimmed, and a token with
  non-ASCII characters, internal whitespace, or the wrong structure is
  rejected with a clear, actionable `IdentityError` instead of being handed
  to the hub and looping forever on an opaque 403. The usual cause is a token
  corrupted on copy-paste by browser page translation; the message says so
  and tells the operator to re-enroll with translation off. `__main__`
  catches it and exits with one clean log line instead of a traceback.

## 0.11.13 — Carry enrollment token in the Authorization header (#34) — 2026-08-29

- The WS handshake now sends the enrollment token in an `Authorization: Bearer`
  header and uses a short `/agent/connect` URL, instead of a long `?token=`
  query string. Some edges and proxies reject the request with HTTP 400 when the
  query string is long (issue #34), before it reaches the origin. The hub reads
  the header, with a query-string fallback (hub 0.22.2), so existing agents keep
  working unchanged.

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
