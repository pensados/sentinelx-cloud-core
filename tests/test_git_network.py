"""git operations that touch the network.

WHY THESE EXIST AT ALL. Measured over 7 days, distinct users reaching for git
through exec: fetch 489, push 399, ls-remote 374, clone 359. The work is already
happening; it just happens as free-form command lines the model assembles, where
nothing can check what it assembled.

WHY THERE IS NO `pull`. It is fetch plus merge, and a merge can conflict, leave
a dirty tree, or move HEAD somewhere the caller did not intend. One verb that
sounds atomic hiding all of that is worse than two that are honest.

THE POINT OF push. 189 users force-pushed through exec without a lease against
56 who used one. A bare force silently discards whatever someone else pushed in
between, and an assistant cannot notice. Here a force MUST carry the SHA it
expects to replace, which turns it into a compare-and-swap.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


@pytest.fixture
def workspace(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"allowed_commands: []\nfile_ops:\n  paths:\n"
        f"    - {{path: {tmp_path}, access: rw}}\n",
        encoding="utf-8",
    )
    handler = build_registry(policy=Policy.from_file(cfg))["git"]
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    return tmp_path, handler, origin


def _commit(work: Path, text: str, msg: str) -> None:
    (work / "a.txt").write_text(text, encoding="utf-8")
    for args in (["add", "a.txt"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", msg]):
        subprocess.run(["git", "-C", str(work), *args], check=True,
                       capture_output=True)


async def test_clone_refuses_a_destination_that_is_not_writable(workspace) -> None:
    # clone creates a tree, so readability is not enough. The message names the
    # writable paths rather than only saying no.
    _, h, origin = workspace
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "clone", "url": str(origin), "dest": "/root/nope"})
    assert exc.value.code == "path_not_allowed"
    assert "rw" in str(exc.value)


async def test_clone_refuses_a_non_empty_destination(workspace) -> None:
    # Cloning into an existing tree is how work gets lost. Refusing is cheap.
    tmp, h, origin = workspace
    busy = tmp / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "clone", "url": str(origin), "dest": str(busy)})
    assert exc.value.code == "dest_not_empty"
    assert (busy / "keep.txt").read_text(encoding="utf-8") == "mine"


async def test_clone_then_push_then_fetch(workspace) -> None:
    tmp, h, origin = workspace
    work = tmp / "work"
    r = await h({"operation": "clone", "url": str(origin), "dest": str(work)})
    assert r["ok"] is True
    _commit(work, "one\n", "one")
    r = await h({"operation": "push", "path": str(work), "branch": "master"})
    assert r["ok"] is True and r["forced"] is False
    r = await h({"operation": "fetch", "path": str(work)})
    assert r["ok"] is True


async def test_a_force_without_a_lease_is_refused(workspace) -> None:
    # The whole reason this operation exists rather than leaving it to exec.
    tmp, h, origin = workspace
    work = tmp / "work"
    await h({"operation": "clone", "url": str(origin), "dest": str(work)})
    _commit(work, "one\n", "one")
    await h({"operation": "push", "path": str(work), "branch": "master"})
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "push", "path": str(work), "branch": "master",
                 "force": True})
    assert exc.value.code == "force_requires_lease"
    assert "expected_remote_sha" in str(exc.value)


async def test_a_stale_lease_overwrites_nothing(workspace) -> None:
    # The case the lease exists for: the remote moved since it was read.
    tmp, h, origin = workspace
    work = tmp / "work"
    await h({"operation": "clone", "url": str(origin), "dest": str(work)})
    _commit(work, "one\n", "one")
    await h({"operation": "push", "path": str(work), "branch": "master"})
    before = subprocess.run(["git", "-C", str(origin), "rev-parse", "master"],
                            capture_output=True, text=True).stdout.strip()
    _commit(work, "two\n", "two")
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "push", "path": str(work), "branch": "master",
                 "force": True, "expected_remote_sha": "0" * 40})
    assert exc.value.code == "lease_stale"
    after = subprocess.run(["git", "-C", str(origin), "rev-parse", "master"],
                           capture_output=True, text=True).stdout.strip()
    assert after == before, "a refused lease must not have moved the remote"


async def test_a_correct_lease_publishes(workspace) -> None:
    tmp, h, origin = workspace
    work = tmp / "work"
    await h({"operation": "clone", "url": str(origin), "dest": str(work)})
    _commit(work, "one\n", "one")
    await h({"operation": "push", "path": str(work), "branch": "master"})
    refs = await h({"operation": "ls_remote", "remote": str(origin),
                    "path": str(work)})
    sha = next(x["sha"] for x in refs["refs"] if x["ref"].endswith("master"))
    _commit(work, "two\n", "two")
    r = await h({"operation": "push", "path": str(work), "branch": "master",
                 "force": True, "expected_remote_sha": sha})
    assert r["ok"] is True and r["forced"] is True


async def test_pull_is_not_an_operation_and_says_why(workspace) -> None:
    _, h, _ = workspace
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "pull", "path": "/tmp"})
    assert "fetch plus a merge" in str(exc.value)


# --- a clone that runs out of time ----------------------------------------
#
# The hub cuts a tool call at 60s by default, so the agent's own budget is 50s:
# anything longer is time the caller never sees, while git keeps running on the
# host and the answer is already lost. A big repository legitimately needs more
# than that, so what matters is what the failure leaves behind.


async def test_a_timed_out_clone_leaves_nothing_behind(workspace, monkeypatch) -> None:
    # Without the cleanup the next attempt hits dest_not_empty, which reads as a
    # completely different problem and sends the caller looking in the wrong
    # place for a fault that was only ever a timeout.
    from sentinelx_core.handlers import git_ops

    tmp, h, origin = workspace
    dest = tmp / "slow"

    # Since 0.23.46 git runs through run_process: simulate the timeout there
    # (patching asyncio.wait_for also hit run_process's own use of it).
    async def _timed_out(argv, **kw):
        from sentinelx_core.executor_engine import ProcResult
        return ProcResult(-1, b"", b"", timed_out=True)

    monkeypatch.setattr(git_ops, "_NET_TIMEOUT", 1)
    monkeypatch.setattr(git_ops, "run_process", _timed_out)

    with pytest.raises(HandlerError) as exc:
        await h({"operation": "clone", "url": str(origin), "dest": str(dest)})
    assert exc.value.code == "clone_timeout"
    assert not dest.exists(), "a partial clone must not survive its own failure"


@pytest.fixture
def always_times_out(monkeypatch):
    from sentinelx_core.executor_engine import ProcResult
    from sentinelx_core.handlers import git_ops

    async def _timed_out(argv, **kw):
        return ProcResult(-1, b"", b"", timed_out=True)

    monkeypatch.setattr(git_ops, "run_process", _timed_out)


async def test_the_first_suggestion_is_depth(workspace, always_times_out) -> None:
    # depth keeps the caller INSIDE this operation, where the destination is
    # validated and a failure cleans up after itself. That is worth trying
    # before sending anyone to a free-form command line.
    tmp, h, origin = workspace
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "clone", "url": str(origin), "dest": str(tmp / "s2")})
    msg = str(exc.value)
    assert "depth" in msg
    assert "script_run" not in msg, "do not send them away on the first failure"


async def test_a_shallow_clone_that_still_times_out_gets_the_exact_call(
    workspace, always_times_out
) -> None:
    # Second rung, and only now. A model told merely to "use another tool" will
    # invent a command line; the whole point of this operation is that it does
    # not have to. So the call is spelled out, with the url and destination
    # already in it, and the cost of leaving is stated.
    tmp, h, origin = workspace
    dest = tmp / "s3"
    with pytest.raises(HandlerError) as exc:
        await h({"operation": "clone", "url": str(origin), "dest": str(dest),
                 "depth": 1})
    msg = str(exc.value)
    assert "background=True" in msg
    assert str(dest) in msg and str(origin) in msg
    assert "notifications" in msg
    assert "not validated" in msg
