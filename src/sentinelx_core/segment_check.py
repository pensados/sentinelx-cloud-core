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

import re

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

# Filters whose operands are character sets, strings or formats -- never a file to
# open. `tr a-z A-Z`, `echo x`, `printf %s y`, `seq 1 10`, `date -d ...` read no
# file through an operand (date's file-reading -f is caught as an option below).
_FILTER_OPERANDS_NOT_FILES = frozenset({
    "tr", "echo", "printf", "true", "false", "seq", "date",
})

# Options that make an otherwise read-only filter read from, or execute, a file
# named as the option value. Matched on the part before '=' so --file and
# --file=F both hit. rg's preprocessor options run a program.
_FILTER_FILE_OPTS = {
    "grep": ("-f", "--file"), "egrep": ("-f", "--file"), "fgrep": ("-f", "--file"),
    "rg": ("-f", "--file", "--pre", "--pre-glob", "--hostname-bin"),
    "wc": ("--files0-from",), "sort": ("--files0-from",),
    "date": ("-f", "--file"),
}

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


# A token that begins with a redirection operator and carries the target/data
# attached (`>file`, `<<<data`, `2>&1`, `>>log`). Shell redirection is judged by
# file_redirection; here such a token is simply not a file operand.
_ATTACHED_REDIR = re.compile(r"^(?:\d*(?:>>|<<<|<<|>|<)|&>|>&|<&).")


def _looks_like_path(tok: str) -> bool:
    """A token that would name a file to open: absolute, home, or has a slash."""
    return tok.startswith("/") or tok.startswith("~") or "/" in tok


def _filter_reads_a_file(segment: str) -> bool:
    """True if a (whitelisted) filter segment would open, read or execute a file.

    A filter after a pipe reads stdin, but handed an operand it opens that path
    instead -- and the name may be RELATIVE (`cat passwd`, `base64 secret.key`),
    not only path-shaped, so any bare non-option operand counts. grep/rg take a
    PATTERN first, which is not a file. A few filters take operands that are
    never files (character sets, strings, formats): those are listed apart. Some
    OPTIONS read or execute a file given as their value (`grep -f FILE`,
    `wc --files0-from=FILE`, `rg --pre=PROG`); those are refused too.
    """
    import shlex

    name = first_word(segment)
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return True  # unparseable: refuse rather than guess
    if not tokens:
        return False

    # An option that reads from, or executes, a file named as its value.
    for tok in tokens[1:]:
        head = tok.split("=", 1)[0]
        if head in _FILTER_FILE_OPTS.get(name, ()):
            return True

    # Filters whose operands are sets/strings/formats, not files to open.
    if name in _FILTER_OPERANDS_NOT_FILES:
        return False

    opts_with_value = _OPTS_WITH_VALUE.get(name, ())
    operands = []
    expecting_value = False
    redir_target = False
    for tok in tokens[1:]:
        if expecting_value:
            expecting_value = False
            continue
        if redir_target:
            redir_target = False  # the token after `< >` etc. is a target/data, not an operand
            continue
        if tok == "--":
            continue
        # A redirection's target is judged by file_redirection, and a here-string's
        # data is stdin, not a file this filter opens: neither is a file operand.
        if tok in ("<", ">", ">>", "<<", "<<<", "2>", "&>", "<&", ">&"):
            redir_target = True
            continue
        if _ATTACHED_REDIR.match(tok):  # <<<data, >file, 2>&1, >>log
            continue
        if tok.startswith("-") and tok != "-":
            if "=" not in tok and tok in opts_with_value:
                expecting_value = True
            continue
        operands.append(tok)
    # grep/rg/fgrep/egrep take a PATTERN operand that is not a file; allow exactly
    # one non-option operand for them. Every other filter opens any operand it is
    # given, relative or absolute, so any remaining operand is a file read.
    if name in ("grep", "egrep", "fgrep", "rg") and operands:
        operands = operands[1:]
    return len(operands) > 0


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
        if ch in ";|\n":
            # A newline outside quotes separates commands exactly like ';' does.
            # (Strict mode refuses newlines before it gets here; the default chain
            # check relies on this.)
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


# --------------------------------------------------------------------------
# Default chain check (GHSA-r2h3-76g7-m95x). Not a shell parser: it finds where
# each command starts and asks the allowlist about it. What it cannot analyse
# with certainty raises UnparseableCommand, and the caller REFUSES: a gap in the
# analysis must be a false rejection, never a false permission.
# --------------------------------------------------------------------------

class UnparseableCommand(ValueError):
    """A command structure the chain check cannot analyse with certainty."""


_SUB_MARK = "__SX_SUBST__"
_MAX_NESTING = 8
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_HEREDOC_OP = re.compile(
    r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|(\\?[^\s;&|<>()'\"]+))"
)


def _match_close(s: str, i: int) -> int:
    """i is just after an opening '('. Return the index of its matching ')'."""
    depth, n, quote = 1, len(s), None
    while i < n:
        ch = s[i]
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
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise UnparseableCommand("unbalanced parentheses in a substitution")


def mask_substitutions(command: str, literal_quotes: bool = False) -> tuple[str, list[str]]:
    """Replace $(...), `...`, <(...) and >(...) with a placeholder word.

    Returns (masked command, bodies). The outer structure can then be split
    without cutting a pipe that lives INSIDE a substitution, and every body is
    checked on its own. $((...)) is arithmetic, not a command, but substitutions
    inside it are collected. Single quotes hide everything; double quotes do not
    stop $(...) or backticks. With literal_quotes (an unquoted here-doc body),
    quotes are plain text and hide nothing.
    """
    out: list[str] = []
    bodies: list[str] = []
    i, n, quote = 0, len(command), None
    while i < n:
        ch = command[i]
        if not literal_quotes:
            if quote == "'":
                out.append(ch)
                if ch == "'":
                    quote = None
                i += 1
                continue
            if ch == "\\" and i + 1 < n:
                out.append(command[i:i + 2])
                i += 2
                continue
            if quote == '"' and ch == '"':
                quote = None
                out.append(ch)
                i += 1
                continue
            if quote is None and ch in "'\"":
                quote = ch
                out.append(ch)
                i += 1
                continue
        elif ch == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if command.startswith("$((", i):
            j = _match_close(command, i + 2)          # matches the outer '('
            _, inner = mask_substitutions(command[i + 3:j - 1], literal_quotes)
            bodies.extend(inner)
            out.append("0")
            i = j + 1
            continue
        if command.startswith("$(", i):
            j = _match_close(command, i + 2)
            bodies.append(command[i + 2:j])
            out.append(_SUB_MARK)
            i = j + 1
            continue
        if ch == "`":
            j = i + 1
            while j < n and command[j] != "`":
                j += 2 if command[j] == "\\" else 1
            if j >= n:
                raise UnparseableCommand("unbalanced backtick")
            bodies.append(command[i + 1:j].replace("\\`", "`"))
            out.append(_SUB_MARK)
            i = j + 1
            continue
        if quote is None and not literal_quotes and (
            command.startswith("<(", i) or command.startswith(">(", i)
        ):
            j = _match_close(command, i + 2)
            bodies.append(command[i + 2:j])
            out.append(_SUB_MARK)
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), bodies


def strip_heredoc_bodies(command: str) -> tuple[str, list[str]]:
    """Remove here-document bodies, which are input data, not commands.

    Returns (command without bodies, bodies whose delimiter was NOT quoted).
    Those still need their substitutions checked: bash runs $(...) inside a
    `<<EOF` body, but not inside a `<<'EOF'` one.
    """
    out: list[str] = []
    live: list[str] = []
    pending: list[tuple[str, bool, bool]] = []
    i, n, quote = 0, len(command), None
    while i < n:
        ch = command[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                out.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if command.startswith("<<", i) and not command.startswith("<<<", i):
            m = _HEREDOC_OP.match(command, i)
            if not m:
                raise UnparseableCommand("a here-document whose delimiter can't be read")
            dash, sq, dq, bare = m.groups()
            if sq is not None:
                delim, is_live = sq, False
            elif dq is not None:
                delim, is_live = dq, False
            else:
                is_live = not bare.startswith("\\")
                delim = bare.lstrip("\\")
            pending.append((delim, bool(dash), is_live))
            out.append(m.group(0))
            i = m.end()
            continue
        if ch == "\n" and pending:
            out.append("\n")
            i += 1
            for delim, tabs, is_live in pending:
                body: list[str] = []
                while True:
                    if i >= n:
                        raise UnparseableCommand(f"here-document not terminated (missing {delim!r})")
                    j = command.find("\n", i)
                    j = n if j == -1 else j
                    line = command[i:j]
                    i = j + 1 if j < n else n
                    cand = (line.lstrip("\t") if tabs else line).rstrip("\r")
                    if cand == delim:
                        break
                    body.append(line)
                if is_live:
                    live.append("\n".join(body))
            pending = []
            continue
        out.append(ch)
        i += 1
    if pending:
        raise UnparseableCommand("a here-document with no body")
    return "".join(out), live


# Shell grammar words that are not programs (0.23.23). 0.23.22 checked them as
# commands, so every `for ...; do ...; done` and `if ...; then ...; fi` was refused.
_LEADING_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "!", "{", "time"})
_CLOSING_KEYWORDS = frozenset({"done", "fi", "}"})
_HEADER_KEYWORDS = frozenset({"for", "select"})   # `for VAR in WORDS`: no command; $(...) is checked apart
# Builtins that run nothing else and change nothing outside the shell. NOT export
# (export LD_PRELOAD=... hijacks what follows), source/., eval, exec, command.
SAFE_BUILTINS = frozenset({"set", "test", "[", "[[", "true", "false", ":", "read",
                           "shift", "break", "continue", "exit", "return", "wait"})


def _command_part(segment: str) -> str | None:
    """The segment without leading grammar words, or None if it runs no command.

    Raises UnparseableCommand for `case`: its arms (`pat) cmd ;;`) can't be told
    apart from commands with certainty, and skipping them would leave them
    unchecked.
    """
    rest = segment.lstrip()
    while True:
        rest = rest.lstrip("(").lstrip()      # subshell: check what runs inside
        word = first_word(rest)
        if word in _LEADING_KEYWORDS:
            rest = rest[len(word):].lstrip()
            continue
        break
    word = first_word(rest)
    if not word or word in _CLOSING_KEYWORDS or word in _HEADER_KEYWORDS:
        return None
    if word in ("case", "esac"):
        raise UnparseableCommand("a case statement")
    # `(cd x && ls)` splits into `(cd x` and `ls)`: drop the ')' that closes the
    # subshell so the command is matched as written.
    while rest.endswith(")") and rest.count(")") > rest.count("("):
        rest = rest[:-1].rstrip()
    return rest or None


def _only_assignments(segment: str) -> bool:
    toks = segment.split()
    return bool(toks) and all(_ASSIGNMENT.match(t) for t in toks)


def unauthorised_chain(policy, command: str, _depth: int = 0) -> str | None:
    """Default check: every command in a chain must be allowed, not just the first.

    Splits on ; | && || & and newlines outside quotes, ignores here-doc bodies
    (data), and checks the inside of every substitution on its own. Returns the
    first segment the allowlist does not cover, or None. Raises
    UnparseableCommand when it can't be sure; the caller refuses.
    """
    if _depth > _MAX_NESTING:
        raise UnparseableCommand("substitutions nested too deeply")
    stripped, live_bodies = strip_heredoc_bodies(command)
    masked, bodies = mask_substitutions(stripped)
    for body in live_bodies:
        bodies.extend(mask_substitutions(body, literal_quotes=True)[1])
    for index, raw in enumerate(split_top_level(masked)):
        segment = _command_part(raw)
        if segment is None or _only_assignments(segment) or policy.is_command_allowed(segment):
            continue
        word = first_word(segment)
        if word in POSITION_FREE or word in SAFE_BUILTINS:
            # cd and the no-op builtins execute nothing, but a redirection on
            # them still writes or truncates a file (`true > ~/.bashrc`,
            # `cd /tmp > out`). A redirection is the operator's business only on
            # a command they allowlisted; on a concession segment, refuse it.
            if file_redirection(raw) is not None:
                return segment
            continue
        # Inside a substitution the head is in filter position too: `$(date)`
        # can't reach anything the outer command couldn't, and a file operand is
        # still refused by the read-only checks below.
        if (index > 0 or _depth > 0) and word in READ_ONLY_FILTERS:
            if _filter_reads_a_file(segment) or _filter_has_unsafe_option(segment):
                return segment
            # A filter may read stdin but not write a file through a redirection.
            if file_redirection(raw) is not None:
                return segment
            continue
        return segment
    for body in bodies:
        offending = unauthorised_chain(policy, body, _depth + 1)
        if offending is not None:
            return offending
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
