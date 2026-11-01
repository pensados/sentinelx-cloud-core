r"""Service account and recovery come from structured sources, not sc.exe text.

0.18.1 fixed the optional colon in sc.exe qc output, and it was not enough: the
same user's non-English host returns sc.exe text that is both LOCALIZED (the
label is not SERVICE_START_NAME) and OEM-encoded (decoded as UTF-8 it is
mojibake). _win_service_account returned None and _win_has_scm_restart_recovery
returned False on a host whose CIM plainly showed LocalSystem and RESTART/10000,
and the self-restart was refused.

The fix reads Win32_Service.StartName via CIM (an object property, no console
codepage, no localized label) and the SCM restart action from the registry
FailureActions blob (fixed binary layout, language-independent). sc.exe stays
only as a last-ditch fallback.
"""

from __future__ import annotations

import asyncio

from sentinelx_core.handlers import service


def _stub_shell(monkeypatch, responses: dict):
    """responses maps a substring of the command to a canned result dict."""
    async def _fake(cmd, timeout=10.0, **kw):
        for needle, result in responses.items():
            if needle in cmd:
                return result
        return {"stdout": "", "stderr": "", "returncode": 1}
    monkeypatch.setattr(service, "run_shell_split", _fake)


def _run(coro):
    return asyncio.run(coro)


def test_account_comes_from_cim_first(monkeypatch):
    """CIM answers, so sc.exe is never consulted."""
    _stub_shell(monkeypatch, {
        "Get-CimInstance": {"stdout": "LocalSystem\n", "returncode": 0},
        "sc.exe qc": {"stdout": "GARBAGE", "returncode": 0},
    })
    assert _run(service._win_service_account("SentinelX")) == "LocalSystem"


def test_localized_mojibake_sc_exe_no_longer_decides(monkeypatch):
    """The reported host: sc.exe is garbage, but CIM carries the truth."""
    _stub_shell(monkeypatch, {
        "Get-CimInstance": {"stdout": "LocalSystem\n", "returncode": 0},
        "sc.exe qc": {"stdout": "\ufffd\ufffd_\ufffd\ufffd : LocalSystem", "returncode": 0},
    })
    acc = _run(service._win_service_account("SentinelX"))
    assert acc == "LocalSystem"
    assert service._win_is_system_account(acc) is True


def test_falls_back_to_sc_exe_when_cim_empty(monkeypatch):
    """CIM unavailable (empty) -> the 0.18.1 sc.exe parse still works."""
    _stub_shell(monkeypatch, {
        "Get-CimInstance": {"stdout": "", "returncode": 1},
        "sc.exe qc": {"stdout": "        SERVICE_START_NAME   LocalSystem", "returncode": 0},
    })
    assert _run(service._win_service_account("SentinelX")) == "LocalSystem"


def test_recovery_from_registry_restart(monkeypatch):
    """The registry probe prints RESTART when a type-1 action exists."""
    _stub_shell(monkeypatch, {
        "FailureActions": {"stdout": "RESTART\n", "returncode": 0},
    })
    assert _run(service._win_has_scm_restart_recovery("SentinelX")) is True


def test_recovery_from_registry_none(monkeypatch):
    _stub_shell(monkeypatch, {
        "FailureActions": {"stdout": "NONE\n", "returncode": 0},
    })
    assert _run(service._win_has_scm_restart_recovery("SentinelX")) is False


def test_recovery_falls_back_to_sc_exe(monkeypatch):
    """Registry read fails -> qfailure text is the fallback."""
    _stub_shell(monkeypatch, {
        "FailureActions": {"stdout": "", "returncode": 1},
        "sc.exe qfailure": {"stdout": "RESET_PERIOD 86400\nRESTART -- Delay 10000ms", "returncode": 0},
    })
    assert _run(service._win_has_scm_restart_recovery("SentinelX")) is True


def test_recovery_registry_beats_a_broken_qfailure(monkeypatch):
    """Registry says RESTART even if qfailure text is mojibake -- the whole point."""
    _stub_shell(monkeypatch, {
        "FailureActions": {"stdout": "RESTART\n", "returncode": 0},
        "sc.exe qfailure": {"stdout": "\ufffd\ufffd\ufffd", "returncode": 0},
    })
    assert _run(service._win_has_scm_restart_recovery("SentinelX")) is True


def test_cim_field_helper_trims_and_nulls(monkeypatch):
    _stub_shell(monkeypatch, {"Get-CimInstance": {"stdout": "  LocalSystem \n", "returncode": 0}})
    assert _run(service._win_cim_service_field("X", "StartName")) == "LocalSystem"
    _stub_shell(monkeypatch, {"Get-CimInstance": {"stdout": "\n", "returncode": 0}})
    assert _run(service._win_cim_service_field("X", "StartName")) is None
