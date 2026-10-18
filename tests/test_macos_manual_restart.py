"""The manual restart command on macOS matches how the agent was installed.

install-macos.sh defaults to a per-user LaunchAgent; the hint always said
system/..., the command for the optional LaunchDaemon (sxrep_R8S7B8ARNM54).
"""

from __future__ import annotations

from sentinelx_core import platform_guidance as pg


def test_default_user_install_gets_the_gui_domain(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    cmd = pg._mac_manual_restart()
    assert cmd == "launchctl kickstart -k gui/$(id -u)/app.sentinelx.core"
    assert "sudo" not in cmd


def test_system_install_gets_the_system_domain(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/Library/LaunchDaemons/app.sentinelx.core.plist")
    assert pg._mac_manual_restart() == "sudo launchctl kickstart -k system/app.sentinelx.core"
