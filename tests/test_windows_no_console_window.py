"""Nothing we spawn should paint a window on the operator's desktop.

On Windows a console application launched from a process with no console of
its own gets a new one allocated, and that console comes with a VISIBLE
window. The agent runs as a service or from a pythonw scheduled task, so it
has no console: every child briefly flashed a black box. An operator counted
several in a row during ordinary work and traced it to the spawn sites.

CREATE_NO_WINDOW was applied in exactly one handler and nowhere else -- which
is what happens when the knowledge lives in one file's comments instead of in
a shared helper. Hence winspawn, and hence this test walking every spawn site
rather than trusting that the next one will remember.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from sentinelx_core import winspawn

SRC = pathlib.Path(winspawn.__file__).parent


def _spawn_sites():
    """Every create_subprocess_exec call in the package, with its file."""
    for path in sorted(SRC.rglob("*.py")):
        if "vendored" in path.parts or path.name == "winspawn.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = getattr(fn, "attr", None) or getattr(fn, "id", None)
            if name in ("create_subprocess_exec", "create_subprocess_shell", "Popen"):
                yield path, node


def test_there_are_spawn_sites_to_check():
    """Guard against the walker silently finding nothing and passing.

    0.23.46 folded exec, edit, git and the local_api relay into run_process, so
    there are fewer sites; run_process itself must be one of them (and is held
    to spawn_kwargs by the test below like every other).
    """
    sites = list(_spawn_sites())
    assert len(sites) >= 3
    assert any(path.name == "executor_engine.py" for path, _ in sites)


@pytest.mark.parametrize("path,node", list(_spawn_sites()), ids=lambda x: getattr(x, "name", ""))
def test_every_spawn_site_goes_through_the_helper(path, node):
    """Either it unpacks spawn_kwargs(...), or it sets creationflags itself."""
    uses_helper = any(
        isinstance(kw.value, ast.Call)
        and (getattr(kw.value.func, "id", None) == "spawn_kwargs"
             or getattr(kw.value.func, "attr", None) == "spawn_kwargs")
        for kw in node.keywords if kw.arg is None
    )
    sets_flags = any(kw.arg == "creationflags" for kw in node.keywords)
    assert uses_helper or sets_flags, (
        f"{path.name}:{node.lineno} spawns a process without window suppression"
    )


def test_the_helper_adds_the_flag_on_windows(monkeypatch):
    monkeypatch.setattr(winspawn.sys, "platform", "win32")
    assert winspawn.spawn_kwargs()["creationflags"] == winspawn.CREATE_NO_WINDOW


def test_the_helper_preserves_flags_the_caller_already_set(monkeypatch):
    """Merging, not overwriting: script.py sets its own for the process group."""
    monkeypatch.setattr(winspawn.sys, "platform", "win32")
    out = winspawn.spawn_kwargs(creationflags=0x00000200)
    assert out["creationflags"] == (0x00000200 | winspawn.CREATE_NO_WINDOW)


def test_off_windows_the_helper_only_adds_the_priority_reset(monkeypatch):
    # Off Windows nothing about consoles changes; the one addition is the
    # preexec_fn that drops the agent's raised priority in children
    # (sxrep_E6VEFQ602FAF). The caller's own arguments come back untouched.
    monkeypatch.setattr(winspawn.sys, "platform", "linux")
    kw = winspawn.spawn_kwargs(stdout=1)
    assert kw.pop("preexec_fn") is winspawn._shed_agent_priority
    assert kw == {"stdout": 1}


def test_the_nested_powershell_is_hidden_too():
    """The outer process gets CREATE_NO_WINDOW, but PowerShell launches the
    inner one itself and the flag does not carry across."""
    from sentinelx_core.handlers.script import _POWERSHELL_BOOTSTRAP

    assert "-WindowStyle Hidden" in _POWERSHELL_BOOTSTRAP
    assert _POWERSHELL_BOOTSTRAP.index("-WindowStyle Hidden") < _POWERSHELL_BOOTSTRAP.index("-File")
