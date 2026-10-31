"""A background job's answer must outlive the connection meant to carry it.

The completion is sent over the very socket the request arrived on. If that
socket is gone by the time the work finishes, the send fails and the answer is
lost -- the work done, the result built, nobody listening. Three users reported
that shape of loss in a single day, and 98 job records fleet-wide were sitting
at "running" with nothing ever coming back.

So the event is written down before the send and replayed on the next
connection. These tests drive the real module, not a copy of its logic.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


from sentinelx_core import pending_results as pr

EVENT = {"kind": "job_completed", "data": {"job_id": "job_abc", "status": "failed"}}


def _base(tmp_path: Path) -> Path:
    """Mimic the real layout: pending lives beside the upload base."""
    up = tmp_path / "uploads"
    up.mkdir()
    return up


def test_a_recorded_result_is_returned_again(tmp_path):
    base = _base(tmp_path)
    pr.record(base, "job_abc", EVENT)
    out = list(pr.drain(base))
    assert len(out) == 1
    assert out[0][1] == EVENT


def test_clearing_it_means_it_is_not_replayed(tmp_path):
    base = _base(tmp_path)
    path = pr.record(base, "job_abc", EVENT)
    pr.clear(path)
    assert list(pr.drain(base)) == []


def test_nothing_recorded_means_nothing_to_replay(tmp_path):
    assert list(pr.drain(_base(tmp_path))) == []


def test_it_does_not_write_inside_the_user_facing_upload_base(tmp_path):
    """Those directories are the operator's; this is ours."""
    base = _base(tmp_path)
    pr.record(base, "job_abc", EVENT)
    assert list(base.iterdir()) == []
    assert pr.pending_dir(base).is_dir()


def test_an_expired_result_is_dropped_rather_than_replayed(tmp_path):
    """The hub has forgotten the job by then; replaying it lands nowhere."""
    base = _base(tmp_path)
    path = pr.record(base, "job_old", EVENT)
    data = json.loads(path.read_text())
    data["at"] = time.time() - pr.PENDING_TTL_SECONDS - 10
    path.write_text(json.dumps(data))
    assert list(pr.drain(base)) == []
    assert not path.exists()


def test_a_corrupt_file_is_removed_not_retried_forever(tmp_path):
    base = _base(tmp_path)
    d = pr.pending_dir(base)
    d.mkdir(parents=True)
    bad = d / "job_bad.json"
    bad.write_text("{ this is not json")
    assert list(pr.drain(base)) == []
    assert not bad.exists()


def test_a_job_id_cannot_escape_the_directory(tmp_path):
    """job_id arrives from the hub and reaches the filesystem."""
    base = _base(tmp_path)
    pr.record(base, "../../etc/passwd", EVENT)
    written = list(pr.pending_dir(base).glob("*.json"))
    assert len(written) == 1
    assert written[0].parent == pr.pending_dir(base)
    assert "/" not in written[0].name and ".." not in written[0].name


def test_the_backlog_is_capped(tmp_path):
    """An agent that cannot reach the hub must not fill the disk."""
    base = _base(tmp_path)
    for i in range(pr.MAX_PENDING_FILES + 20):
        pr.record(base, f"job_{i:04d}", EVENT)
    assert len(list(pr.pending_dir(base).glob("*.json"))) <= pr.MAX_PENDING_FILES


def test_the_newest_result_survives_the_cap(tmp_path):
    """Someone is still waiting on the most recent one."""
    base = _base(tmp_path)
    for i in range(pr.MAX_PENDING_FILES + 5):
        pr.record(base, f"job_{i:04d}", EVENT)
    names = {p.stem for p in pr.pending_dir(base).glob("*.json")}
    assert f"job_{pr.MAX_PENDING_FILES + 4:04d}" in names


def test_recording_twice_does_not_duplicate(tmp_path):
    base = _base(tmp_path)
    pr.record(base, "job_abc", EVENT)
    pr.record(base, "job_abc", {"kind": "job_completed", "data": {"job_id": "job_abc"}})
    assert len(list(pr.drain(base))) == 1


def test_an_unwritable_base_does_not_raise(tmp_path):
    """A result we cannot record is still worth attempting to send."""
    assert pr.record(Path("/proc/nonexistent/deep"), "job_abc", EVENT) is None


def test_clear_tolerates_none(tmp_path):
    pr.clear(None)


def test_no_half_written_file_is_left_behind(tmp_path):
    """Write-then-rename: a crash mid-write must not leave a parseable stub."""
    base = _base(tmp_path)
    pr.record(base, "job_abc", EVENT)
    assert list(pr.pending_dir(base).glob("*.tmp")) == []
