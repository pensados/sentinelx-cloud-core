"""exec handler: run a whitelisted command via bash -lc.

Allowlist comes from policy (loaded from /etc/sentinelx/config.yaml). Empty
allowlist = deny-all. Match is by prefix, identical to legacy SentinelX 0.3.5.

When a command is rejected, the handler tries to produce a HELPFUL error
rather than a blunt one. The goal: an LLM caller, on reading the message,
should know exactly what to do next — either pick a different op (e.g.
script_run for multi-line) or stop trying entirely.
"""

from __future__ import annotations

import re
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.executor_engine import run_shell
from sentinelx_core.jobs import BACKGROUND_TIMEOUT_MAX
from sentinelx_core.policy import Policy
from sentinelx_core import platform_guidance as _pg


# bash control-flow keywords. When a command starts with one of these,
# "first word" doesn't identify the program being run — it identifies a
# language construct. The user almost certainly meant a multi-statement
# script, which belongs in script_run, not exec.
_BASH_KEYWORDS = frozenset({
    "for", "while", "until", "if", "case", "select", "function",
    "do", "done", "then", "else", "elif", "fi", "esac",
    "{", "(",
})

# Tokens that signal a multi-statement / piped / redirected command. The
# `exec` op runs everything through `bash -lc`, so technically these all
# work, but they almost never represent the LLM's intent — and they
# obscure what should have been in the allowlist. Recommend script_run
# when we see them.
_SHELL_COMPOUND_TOKENS = ("|", "&&", "||", ";", ">", "<")


def _classify_rejection(command: str) -> tuple[str, str]:
    """Decide WHY a command was rejected, and return a helpful message.

    Returns:
        (problem_summary, suggestion) — both human-readable strings.
        problem_summary is short (under 60 chars), goes in the error code
        message. suggestion is longer, goes in details.

    The classification cases (in priority order):

      1. Multi-line input.
         The agent's exec is single-line by design. Multi-line = script.

      2. Starts with a bash keyword (for/while/if/case/etc).
         "first word" is misleading. Suggest script_run.

      3. Contains shell compound tokens (| && ; etc).
         Pipelines/chains usually mean "I have a workflow"; script_run
         makes that explicit.

      4. Bare command not in allowlist.
         The plain case — operator needs to add this prefix to the
         allowlist if it's safe and routine.
    """
    if "\n" in command:
        return (
            "multi-line input",
            "exec runs single-line commands only. For multi-statement "
            "scripts (with newlines, loops, or local variables), use "
            "script_run with interpreter='bash' or 'python3'. It accepts "
            "the full script as one payload and runs it via a temp file.",
        )

    stripped = command.lstrip()
    first_word = stripped.split(maxsplit=1)[0] if stripped else ""

    if first_word in _BASH_KEYWORDS:
        return (
            f"starts with bash keyword '{first_word}'",
            f"'{first_word}' is a bash control-flow keyword, not a "
            "command. exec was designed for single binaries with their "
            "args (like 'systemctl status nginx'). For loops, "
            "conditionals, or any script-like logic, use script_run "
            "with interpreter='bash'.",
        )

    for token in _SHELL_COMPOUND_TOKENS:
        if token in command:
            return (
                f"contains shell operator '{token}'",
                f"the operator '{token}' is part of a shell pipeline or "
                "redirection. exec's allowlist matches command PREFIXES "
                "(e.g. 'ls', 'systemctl status'); a pipeline is several "
                "commands chained together and won't match any single "
                "prefix. For chained commands, use script_run with "
                "interpreter='bash' — you can pipe and redirect freely "
                "inside the script body.",
            )

    # Bare command, just not in the allowlist.
    return (
        f"command not in allowlist: {first_word}",
        f"the prefix '{first_word}' isn't in the agent's allowed_commands. "
        "If it's safe and routine, you can add it with the operator's "
        f"approval, in three steps: (1) call {_pg.edit_config_via()}, "
        f"inserting a new line '  - {first_word}' under the "
        "'allowed_commands:' list (anchor on an existing '  - ...' entry so "
        f"the YAML stays valid); (2) {_pg.reload_agent()}; (3) confirm with "
        f"the capabilities op that '{first_word}' now appears in "
        "allowed_commands. For a one-off that leaves the policy unchanged, "
        "use script_run instead.",
    )


def make_exec_handler(policy: Policy):
    """Return an async handler bound to the given policy."""

    async def handle_exec(payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command")
        timeout = float(payload.get("timeout", policy.exec_timeout_default))

        if not command or not isinstance(command, str):
            raise HandlerError("invalid_payload", "missing or non-string 'command'")

        # Background ops get a higher wall-clock ceiling (the whole point of
        # running detached); interactive exec stays bounded by policy.
        if payload.get("background"):
            ceiling = max(policy.exec_timeout_max, BACKGROUND_TIMEOUT_MAX)
        else:
            ceiling = policy.exec_timeout_max
        timeout = min(timeout, ceiling)

        if not policy.is_command_allowed(command):
            problem, suggestion = _classify_rejection(command)
            raise HandlerError(
                "command_not_allowed",
                f"{problem}. {suggestion}",
                details={
                    "command": command,
                    "problem": problem,
                    "allowed_commands": list(policy.allowed_commands),
                },
            )

        return await run_shell(command, timeout=timeout)

    return handle_exec

