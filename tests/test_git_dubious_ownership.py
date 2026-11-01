"""A checkout owned by another user is not "not a git repository".

Git refuses to read a repository owned by a different user than the process
running it, and exits non-zero -- the same rc as "there is no repo here". We
read only the rc, so both became not_a_git_repo, whose text then tells the
caller the directory is not a checkout or the repo is elsewhere. For this case
both halves are false: the checkout is exactly where they said, and the same
commands work over sentinel_exec when that runs as the owner.

Reported by a user on /var/www, where the checkout belongs to the web account
and the agent runs as its own. stderr is what separates the two cases.
"""

from __future__ import annotations

from sentinelx_core.handlers.git_ops import _dubious_ownership


def test_the_ownership_refusal_is_recognised():
    err = (b"fatal: detected dubious ownership in repository at "
           b"'/var/www/edonusum-product-structure'\n")
    assert _dubious_ownership(err) is True


def test_a_plain_directory_is_not_mistaken_for_it():
    assert _dubious_ownership(b"fatal: not a git repository (or any parent)\n") is False


def test_empty_stderr_is_not_it():
    """A timeout path returns no stderr; it must not be read as ownership."""
    assert _dubious_ownership(b"") is False


def test_other_git_failures_are_not_it():
    for err in (b"fatal: your current branch appears to be broken\n",
                b"error: object file is empty\n",
                b"fatal: unable to read tree\n"):
        assert _dubious_ownership(err) is False


def test_the_match_survives_gits_rewordings():
    """Matched on the stable token, not the full sentence."""
    for err in (b"fatal: detected dubious ownership in repository at '/x'",
                b"fatal: unsafe repository ('/x' is owned by someone else)\n"
                b"fatal: detected dubious ownership"):
        assert _dubious_ownership(err) is True


def test_both_handlers_agree_on_the_signal():
    """git_ops and project_snapshot share substrate and have drifted before.

    The parity check exists because the locale bug fixed yesterday was present
    in both modules and found in only one.
    """
    import inspect

    from sentinelx_core.handlers import project_snapshot as ps

    src = inspect.getsource(ps)
    assert b"dubious ownership".decode() in src, (
        "project_snapshot must detect the same condition git_ops does"
    )
