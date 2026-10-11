"""config.yaml is read the same on every platform (sxrep_XGNWXC3Q6ZVR).

sentinel_edit writes UTF-8; the policy loader read it with the platform default
encoding. On a Korean Windows (cp949), a folder name like 코덱스작품 written by
sentinel_edit raised UnicodeDecodeError at start-up and the agent crashed in a
loop, unreachable for a remote fix. Path.read_text is patched here to behave like
Windows (decode with a legacy code page when no encoding is given), so these
tests fail on the old loader on any OS.
"""

from __future__ import annotations

import locale
from pathlib import Path

import pytest

from sentinelx_core.policy import Policy

FOLDER = "코덱스작품"
CONFIG = (
    "file_ops:\n  paths:\n"
    f"    - path: 'C:/Users/PC/Desktop/{FOLDER}/순간이동/EP02'\n      access: rw\n"
)


def _paths(pol):
    return [p.path for p in pol.file_ops_paths]


@pytest.fixture(params=["cp949", "cp1252"])
def windows_default(request, monkeypatch):
    """Path.read_text() without an encoding decodes like that Windows would."""
    original = Path.read_text

    def read_text(self, encoding=None, errors=None):
        return original(self, encoding=encoding or request.param, errors=errors)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: request.param)
    return request.param


def test_a_non_ascii_path_written_as_utf8_loads_on_windows(tmp_path, windows_default):
    cfg = tmp_path / "config.yaml"
    cfg.write_bytes(CONFIG.encode("utf-8"))                  # what sentinel_edit writes
    paths = _paths(Policy.from_file(cfg))
    assert len(paths) == 1 and FOLDER in paths[0]            # loaded, and the name is intact


def test_a_notepad_bom_is_accepted(tmp_path, windows_default):
    cfg = tmp_path / "config.yaml"
    cfg.write_bytes(b"\xef\xbb\xbf" + CONFIG.encode("utf-8"))
    paths = _paths(Policy.from_file(cfg))
    assert len(paths) == 1 and FOLDER in paths[0]


def test_a_file_saved_in_the_ansi_code_page_still_loads(tmp_path, monkeypatch):
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: "cp949")
    cfg = tmp_path / "config.yaml"
    cfg.write_bytes(CONFIG.encode("cp949"))                  # an editor that writes cp949
    paths = _paths(Policy.from_file(cfg))
    assert len(paths) == 1 and FOLDER in paths[0]


def test_undecodable_bytes_do_not_crash_the_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: "ascii")
    cfg = tmp_path / "config.yaml"
    cfg.write_bytes(CONFIG.encode("utf-8")[:-4] + b"\xff\xfe\x80\n")
    assert _paths(Policy.from_file(cfg)) == []               # logged as invalid, like bad YAML
