# Changelog

Notable changes to `sentinelx-cloud-core`. Human-readable, date-stamped
entries; releases before 0.3.0 predate this file — see the git history.

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
