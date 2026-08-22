"""Issue #28: script_run must round-trip Unicode on Windows.

Three separate Windows boundaries break ordinary text, and each is pinned
here at the boundary it belongs to:

  * Python inherits the console's legacy stdio encoding and raises
    UnicodeEncodeError -> PYTHONIOENCODING=utf-8 for the child;
  * Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI -> .ps1 files get
    a UTF-8 BOM on Windows;
  * the same shell encodes redirected output in the console code page ->
    captured bytes are decoded as UTF-8 first, host code page second.

The suite runs on Linux, so the Windows paths are exercised by patching
sys.platform and intercepting the spawn: what is asserted is the argv, the
environment and the bytes on disk — the things the fix actually changes.
The tests that need no Windows (exit codes, argument semantics, non-Windows
decoding) run for real.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sentinelx_core.handlers import build_registry, script as script_mod
from sentinelx_core.policy import Policy

UNICODE_SAMPLE = "Ľubomír ñandú — 🚀"


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    p = Policy()
    object.__setattr__(p, "upload_base", tmp_path)
    return p


class _FakeProc:
    """A child that produced `out` and exited with `returncode`."""

    def __init__(self, out: bytes = b"", err: bytes = b"", returncode: int = 0):
        self._out, self._err = out, err
        self.returncode = returncode

    async def communicate(self):
        return self._out, self._err

    def kill(self):  # pragma: no cover - only used on the timeout path
        pass


@pytest.fixture
def spawned(monkeypatch):
    """Intercept the spawn; record argv/env/cwd and skip the real child."""
    calls: list[dict] = []

    async def fake_exec(*argv, **kwargs):
        calls.append({"argv": list(argv), **kwargs})
        return _FakeProc(out=UNICODE_SAMPLE.encode("utf-8"))

    monkeypatch.setattr(
        script_mod.asyncio, "create_subprocess_exec", fake_exec
    )
    return calls


def _as_windows(monkeypatch):
    monkeypatch.setattr(script_mod.sys, "platform", "win32")
    # shutil.which consults real Win32 APIs once sys.platform says win32, so
    # stand in for the interpreter lookup while we are pretending.
    monkeypatch.setattr(
        script_mod.shutil, "which", lambda name: f"C:\\Windows\\{name}.exe"
    )


# ---------------------------------------------------------------------------
# Python: stdio encoding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_windows_python_child_gets_utf8_stdio(policy, spawned, monkeypatch):
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    await handlers["script_run"](
        {"interpreter": "python3", "content": f"print('{UNICODE_SAMPLE}')"}
    )

    assert spawned[0]["env"]["PYTHONIOENCODING"] == "utf-8"


@pytest.mark.asyncio
async def test_caller_supplied_stdio_encoding_still_wins(policy, spawned, monkeypatch):
    """Acceptance #3."""
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    await handlers["script_run"](
        {
            "interpreter": "python3",
            "content": "print(1)",
            "env": {"PYTHONIOENCODING": "cp1250"},
        }
    )

    assert spawned[0]["env"]["PYTHONIOENCODING"] == "cp1250"


@pytest.mark.asyncio
async def test_non_windows_python_child_is_left_alone(policy, spawned):
    """Nothing is injected where nothing was broken."""
    handlers = build_registry(policy=policy)

    await handlers["script_run"]({"interpreter": "python3", "content": "print(1)"})

    assert "PYTHONIOENCODING" not in spawned[0]["env"]


# ---------------------------------------------------------------------------
# PowerShell: script source encoding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_windows_powershell_script_is_written_with_a_bom(
    policy, spawned, monkeypatch
):
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {
            "interpreter": "powershell",
            "content": f"Write-Output '{UNICODE_SAMPLE}'",
            "cleanup": False,
        }
    )

    raw = Path(result["script_path"]).read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "PS 5.1 needs the BOM to read UTF-8"
    assert raw.decode("utf-8-sig") == f"Write-Output '{UNICODE_SAMPLE}'"


@pytest.mark.asyncio
async def test_windows_powershell_runs_through_the_utf8_bootstrap(
    policy, spawned, monkeypatch
):
    """5.1 encodes redirected output in the console code page, so the fix has
    to reach the child. The bootstrap runs the user's script as an inner
    `-File`, which is what keeps exit-code semantics (measured on 5.1:
    `& $script` turns a handled native failure into a failure; an inner
    -File does not)."""
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {
            "interpreter": "powershell",
            "content": "using namespace System.Text\nWrite-Output 'x'",
            "args": ["arg with spaces", "a;b|c"],
            "cleanup": False,
        }
    )

    argv = spawned[0]["argv"]
    assert argv[1:5] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
    assert argv[5] == "-File"
    bootstrap = Path(argv[6])
    assert bootstrap.name == "sentinelx_bootstrap.ps1"
    assert bootstrap.parent == Path(result["workdir"])
    # The user's script is the bootstrap's first argument, the caller's args
    # follow it untouched.
    assert argv[7] == result["script_path"]
    assert argv[8:] == ["arg with spaces", "a;b|c"]

    body = bootstrap.read_text(encoding="utf-8-sig")
    assert "[Console]::OutputEncoding" in body
    assert "-File $SentinelXScript @SentinelXArgs" in body
    assert body.rstrip().endswith("exit $LASTEXITCODE")

    # The user's text is written verbatim: no prologue, so `using namespace`
    # stays the first statement of their script.
    assert Path(result["script_path"]).read_text(encoding="utf-8-sig").startswith(
        "using namespace"
    )


@pytest.mark.asyncio
async def test_windows_children_get_their_own_console(policy, spawned, monkeypatch):
    """Acceptance #5. Measured: without this flag the bootstrap's code-page
    change lands on the console the agent inherits and leaks 65001 into
    every later child."""
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    await handlers["script_run"](
        {"interpreter": "powershell", "content": "Write-Output 'x'"}
    )

    assert spawned[0]["creationflags"] == script_mod._CREATE_NO_WINDOW


@pytest.mark.asyncio
async def test_pwsh_is_left_on_the_direct_path(policy, spawned, monkeypatch):
    """PowerShell Core already speaks UTF-8; no bootstrap, no extra process."""
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {"interpreter": "pwsh", "content": "Write-Output 'x'", "cleanup": False}
    )

    argv = spawned[0]["argv"]
    assert argv[5] == "-File"
    assert argv[6] == result["script_path"]


@pytest.mark.asyncio
async def test_non_windows_spawn_is_unchanged(policy, spawned):
    handlers = build_registry(policy=policy)

    await handlers["script_run"]({"interpreter": "bash", "content": "echo hi"})

    assert "creationflags" not in spawned[0]


@pytest.mark.asyncio
async def test_bash_and_python_files_have_no_bom(policy, spawned, monkeypatch):
    _as_windows(monkeypatch)
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {"interpreter": "python3", "content": "print(1)", "cleanup": False}
    )

    assert not Path(result["script_path"]).read_bytes().startswith(b"\xef\xbb\xbf")


# ---------------------------------------------------------------------------
# Output decoding
# ---------------------------------------------------------------------------


def test_windows_output_decodes_utf8_first(monkeypatch):
    """A child that emits UTF-8 must never be re-read as a code page."""
    _as_windows(monkeypatch)
    monkeypatch.setattr(script_mod, "_windows_legacy_encoding", lambda: "cp1252")

    assert script_mod._decode_output(UNICODE_SAMPLE.encode("utf-8")) == UNICODE_SAMPLE


def test_windows_legacy_output_is_decoded_with_the_code_page(monkeypatch):
    """The PowerShell 5.1 case: redirected output in the console code page."""
    _as_windows(monkeypatch)
    monkeypatch.setattr(script_mod, "_windows_legacy_encoding", lambda: "cp1252")

    raw = "año — señor".encode("cp1252")
    assert script_mod._decode_output(raw) == "año — señor"


def test_undecodable_output_never_raises(monkeypatch):
    _as_windows(monkeypatch)
    monkeypatch.setattr(script_mod, "_windows_legacy_encoding", lambda: None)

    assert script_mod._decode_output(b"\xff\xfe\x00bad") == "��\x00bad"


def test_non_windows_decoding_is_unchanged():
    raw = "año".encode("cp1252")
    assert script_mod._decode_output(raw) == raw.decode(errors="replace")


# ---------------------------------------------------------------------------
# Semantics that must survive all of the above (run for real)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_explicit_exit_code_is_unchanged(policy):
    """Acceptance #2, exercised against a real child."""
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {"interpreter": "python3", "content": "import sys; sys.exit(7)"}
    )

    assert result["ok"] is False
    assert result["returncode"] == 7


@pytest.mark.asyncio
async def test_unicode_round_trips_through_a_real_child(policy):
    """Acceptance #1 on this platform: no caller boilerplate needed."""
    handlers = build_registry(policy=policy)

    result = await handlers["script_run"](
        {"interpreter": "python3", "content": f"print({UNICODE_SAMPLE!r})"}
    )

    assert result["ok"] is True
    assert UNICODE_SAMPLE in result["output"]
