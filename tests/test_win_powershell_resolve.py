r"""On Windows, resolve a PowerShell the service account can actually launch.

shutil.which('pwsh') was trusted directly. Under a LocalSystem service it
resolves to the per-user WindowsApps execution alias
(C:\Users\<someone>\AppData\Local\Microsoft\WindowsApps\pwsh.EXE) -- a reparse
stub in a user profile that LocalSystem cannot execute, failing WinError 1920.
script_run worked and exec did not, on the same host, for this reason. Reported
with the alias path and the working Program Files path side by side.

These tests exercise the resolver's candidate logic directly, since the CI host
is not Windows: the point under test is the ORDERING and the alias exclusion,
both of which are plain path logic.
"""

from __future__ import annotations


import pytest

from sentinelx_core import executor_engine as ee


@pytest.fixture(autouse=True)
def _clear_cache():
    ee._WIN_PS_CACHE = None
    yield
    ee._WIN_PS_CACHE = None


def _run(monkeypatch, *, present: set[str], which: str | None, env: dict | None = None):
    """Resolve with a canned filesystem and which()."""
    monkeypatch.setattr(ee.sys, "platform", "win32", raising=False)
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("ProgramFiles(x86)", r"C:\Program Files (x86)")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    if env:
        for k, v in env.items():
            monkeypatch.setenv(k, v)

    import ntpath
    import shutil

    # The resolver builds paths with os.path.join; on this Linux CI host that
    # would use "/", so force Windows join semantics to mirror the real target.
    monkeypatch.setattr(ee.os.path, "join", ntpath.join)
    monkeypatch.setattr(ee.os.path, "isfile", lambda p: p in present)
    monkeypatch.setattr(shutil, "which", lambda name: which)
    return ee._win_powershell()


PF7 = r"C:\Program Files\PowerShell\7\pwsh.exe"
ALIAS = r"C:\Users\comus\AppData\Local\Microsoft\WindowsApps\pwsh.EXE"
WPS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def test_program_files_pwsh_is_preferred(monkeypatch):
    got = _run(monkeypatch, present={PF7, WPS}, which=ALIAS)
    assert got == PF7


def test_the_windowsapps_alias_is_never_used(monkeypatch):
    """The exact reported failure: which() returns the alias, nothing in PF."""
    got = _run(monkeypatch, present={WPS}, which=ALIAS)
    assert "WindowsApps" not in got
    assert got == WPS


def test_the_alias_is_rejected_even_when_it_is_the_only_present_file(monkeypatch):
    """The sharp case, and what the exclusion is FOR: the alias exists on disk
    and which() points at it, with no Program Files pwsh and no System32 entry
    present. Without the WindowsApps exclusion the resolver would hand back the
    alias -- the very path that fails WinError 1920 under LocalSystem. It must
    fall through to the bare name instead."""
    got = _run(monkeypatch, present={ALIAS}, which=ALIAS)
    assert "WindowsApps" not in got
    assert got == "powershell"


def test_a_real_which_pwsh_is_used_when_not_an_alias(monkeypatch):
    real = r"D:\tools\pwsh\pwsh.exe"
    got = _run(monkeypatch, present={real, WPS}, which=real)
    assert got == real


def test_falls_back_to_windows_powershell(monkeypatch):
    """No pwsh anywhere usable -> the always-present 5.1 absolute path."""
    got = _run(monkeypatch, present={WPS}, which=None)
    assert got == WPS


def test_last_resort_bare_name_when_nothing_resolves(monkeypatch):
    got = _run(monkeypatch, present=set(), which=ALIAS)
    assert got == "powershell"


def test_the_result_is_cached(monkeypatch):
    calls = {"n": 0}
    import shutil
    monkeypatch.setattr(ee.sys, "platform", "win32", raising=False)
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")

    def _which(name):
        calls["n"] += 1
        return None
    monkeypatch.setattr(shutil, "which", _which)
    import ntpath
    monkeypatch.setattr(ee.os.path, "join", ntpath.join)
    monkeypatch.setattr(ee.os.path, "isfile", lambda p: p == WPS)

    a = ee._win_powershell()
    b = ee._win_powershell()
    assert a == b == WPS
    assert calls["n"] == 1  # second call served from cache


def test_bare_name_is_not_cached(monkeypatch):
    """A later-installed shell must be found, so the fallback stays unpinned."""
    _run(monkeypatch, present=set(), which=None)
    assert ee._WIN_PS_CACHE is None


def test_posix_is_unchanged(monkeypatch):
    monkeypatch.setattr(ee.sys, "platform", "linux", raising=False)
    assert ee._shell_argv("whoami") == ["bash", "-lc", "whoami"]


def test_windows_argv_shape(monkeypatch):
    monkeypatch.setattr(ee.sys, "platform", "win32", raising=False)
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    import shutil
    monkeypatch.setattr(shutil, "which", lambda n: None)
    import ntpath
    monkeypatch.setattr(ee.os.path, "join", ntpath.join)
    monkeypatch.setattr(ee.os.path, "isfile", lambda p: p == WPS)
    argv = ee._shell_argv("whoami")
    assert argv[0] == WPS
    assert argv[1:] == ["-NoProfile", "-NonInteractive", "-Command", "whoami"]
