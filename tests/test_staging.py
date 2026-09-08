"""upload_base resolution and staging fallback.

Regression guard for the case that left a real user stuck: an emptied
config.yaml gave the policy a hardcoded default upload_base the service user
could not write, so `edit` -- the tool that would have restored the config --
failed while staging, with a bare permission error.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sentinelx_core import policy as policy_mod
from sentinelx_core import staging
from sentinelx_core.policy import Policy, default_upload_base


class DefaultUploadBaseTests(unittest.TestCase):
    def test_prefers_the_first_writable_candidate(self):
        writable = Path(tempfile.mkdtemp()) / "uploads"
        policy_mod._UPLOAD_BASE_CANDIDATES = (Path("/nonexistent/root/uploads"), writable)
        self.addCleanup(
            setattr, policy_mod, "_UPLOAD_BASE_CANDIDATES",
            policy_mod._UPLOAD_BASE_CANDIDATES,
        )
        self.assertEqual(default_upload_base(), writable)

    def test_falls_back_to_temp_when_no_candidate_is_usable(self):
        policy_mod._UPLOAD_BASE_CANDIDATES = (
            Path("/nonexistent/a/uploads"), Path("/nonexistent/b/uploads"),
        )
        self.addCleanup(
            setattr, policy_mod, "_UPLOAD_BASE_CANDIDATES",
            policy_mod._UPLOAD_BASE_CANDIDATES,
        )
        base = default_upload_base()
        self.assertEqual(base, Path(tempfile.gettempdir()) / "sentinelx-uploads")

    def test_never_returns_an_unwritable_default(self):
        # The whole point: whatever comes back must be usable, so an agent
        # with no configured upload_base can still stage a repair.
        base = default_upload_base()
        base.mkdir(parents=True, exist_ok=True)
        self.assertTrue(os.access(base, os.W_OK), f"{base} is not writable")

    def test_empty_config_still_yields_a_writable_upload_base(self):
        cfg = Path(tempfile.mkdtemp()) / "empty.yaml"
        cfg.write_text("")
        p = Policy.from_file(cfg)
        p.upload_base.mkdir(parents=True, exist_ok=True)
        self.assertTrue(os.access(p.upload_base, os.W_OK))

    def test_explicit_upload_base_is_honoured(self):
        target = Path(tempfile.mkdtemp()) / "mine"
        cfg = Path(tempfile.mkdtemp()) / "c.yaml"
        cfg.write_text(f"upload_base: {target}\nallowed_commands:\n  - echo\n")
        self.assertEqual(Policy.from_file(cfg).upload_base, target.resolve())


class StagingRootTests(unittest.TestCase):
    def test_uses_the_configured_base_when_writable(self):
        base = Path(tempfile.mkdtemp())
        self.assertEqual(staging.staging_root(base), base / ".sentinelx_uploads")

    def test_falls_back_to_temp_when_the_base_is_unwritable(self):
        staging._warned.clear()
        unwritable = Path("/proc/nonexistent-staging")  # cannot be created
        with self.assertLogs("sentinelx_core.staging", level="WARNING") as cm:
            root = staging.staging_root(unwritable)
        self.assertEqual(root, staging.fallback_root())
        self.assertTrue(os.access(root, os.W_OK))
        text = "\n".join(cm.output)
        self.assertIn("upload_base", text)  # actionable: says what to fix

    def test_warns_only_once_per_path(self):
        staging._warned.clear()
        unwritable = Path("/proc/nonexistent-staging")
        with self.assertLogs("sentinelx_core.staging", level="WARNING"):
            staging.staging_root(unwritable)
        with self.assertRaises(AssertionError):  # no second warning
            with self.assertLogs("sentinelx_core.staging", level="WARNING"):
                staging.staging_root(unwritable)

    def test_staged_directory_is_actually_writable(self):
        root = staging.staging_root(Path("/proc/nonexistent-staging"))
        probe = root / "probe.txt"
        probe.write_text("ok")
        self.addCleanup(probe.unlink)
        self.assertEqual(probe.read_text(), "ok")


if __name__ == "__main__":
    unittest.main()
