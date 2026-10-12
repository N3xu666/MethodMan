"""Integration tests for cmd_start and cmd_reclean.

cmd_start is exercised with subprocess.run() mocked, so the test runs on
any platform (no script(1) needed). cmd_reclean is exercised end-to-end
against a hand-built session directory - no shell involved.
"""

import argparse
import json
from pathlib import Path
from unittest import mock

from Session_Report import (
    cmd_reclean,
    cmd_start,
)


def _fake_start_args(tmp_path, machine="FakeBox", language="en"):
    return argparse.Namespace(
        machine=machine,
        target="10.10.10.10",
        language=language,
        output=str(tmp_path),
        raw_shell=False,
    )


def _write_raw(session_dir: Path, text: str) -> None:
    (session_dir / "raw.txt").write_text(text, encoding="utf-8")


def _write_meta(session_dir: Path, machine="FakeBox", language="en",
                target="10.10.10.10", shell="bash --noprofile --norc"):
    meta = {
        "tool": "Session_Report.py",
        "tool_version": "0.0.0-test",
        "machine": machine,
        "target": target,
        "started": "2026-10-12T00:00:00+00:00",
        "host": "testhost",
        "operator": "tester",
        "language": language,
        "shell": shell,
        "raw_shell": False,
    }
    (session_dir / "metadata.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )


# ---------- cmd_start (subprocess mocked) ----------

class TestCmdStart:
    def test_cmd_start_creates_session_and_draft(self, tmp_path, monkeypatch):
        monkeypatch.setattr("Session_Report.check_platform", lambda: None)

        def fake_run(cmd, *a, **kw):
            # cmd is ["script", "-a", "-q", "-f", "<raw>", "-c", "<inner>"].
            # Simulate script(1) writing a minimal transcript.
            raw_path = Path(cmd[cmd.index("-f") + 1])
            raw_path.write_text(
                "Script started on 2026-10-12\n"
                "bash-5.3$ whoami\n"
                "whoami\n"
                "root\n"
                "bash-5.3$ exit\n"
                "exit\n"
                "Script done on 2026-10-12\n",
                encoding="utf-8",
            )
            return mock.Mock(returncode=0)

        monkeypatch.setattr("Session_Report.subprocess.run", fake_run)

        args = _fake_start_args(tmp_path)
        rc = cmd_start(args)
        assert rc == 0

        # Exactly one session directory was created.
        session_dirs = [p for p in tmp_path.iterdir() if p.is_dir()]
        assert len(session_dirs) == 1
        sd = session_dirs[0]

        assert (sd / "metadata.json").exists()
        assert (sd / "raw.txt").exists()
        draft = (sd / "walkthrough-draft.md").read_text(encoding="utf-8")

        # Draft contains the AI prompt header (machine, target).
        assert "FakeBox" in draft
        assert "10.10.10.10" in draft
        assert "<TODO" in draft
        # Draft ends with the footer marker.
        assert "End of raw transcript" in draft
        # Real output survived cleaning.
        assert "root" in draft

    def test_cmd_start_removes_temp_rc(self, tmp_path, monkeypatch):
        monkeypatch.setattr("Session_Report.check_platform", lambda: None)

        captured = {}

        def fake_run(cmd, *a, **kw):
            raw_path = Path(cmd[cmd.index("-f") + 1])
            raw_path.write_text(
                "Script started on x\n$ exit\nScript done on x\n",
                encoding="utf-8",
            )
            captured["raw_path"] = raw_path
            return mock.Mock(returncode=0)

        monkeypatch.setattr("Session_Report.subprocess.run", fake_run)

        args = _fake_start_args(tmp_path)
        rc = cmd_start(args)
        assert rc == 0
        # The .clean-rc.sh helper must be deleted in the finally block.
        sd = captured["raw_path"].parent
        assert not (sd / ".clean-rc.sh").exists()

    def test_cmd_start_returns_1_when_raw_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("Session_Report.check_platform", lambda: None)

        # subprocess.run does NOT create raw.txt -> cmd_start must fail.
        monkeypatch.setattr(
            "Session_Report.subprocess.run",
            lambda cmd, *a, **kw: mock.Mock(returncode=0),
        )

        args = _fake_start_args(tmp_path)
        rc = cmd_start(args)
        assert rc == 1

    def test_cmd_start_handles_keyboard_interrupt(self, tmp_path, monkeypatch):
        monkeypatch.setattr("Session_Report.check_platform", lambda: None)

        def fake_run(cmd, *a, **kw):
            # Simulate Ctrl-C: no raw written, raise KeyboardInterrupt.
            raise KeyboardInterrupt()

        monkeypatch.setattr("Session_Report.subprocess.run", fake_run)

        args = _fake_start_args(tmp_path)
        # KeyboardInterrupt is caught, then raw.txt is missing -> rc 1.
        rc = cmd_start(args)
        assert rc == 1


# ---------- cmd_reclean (end-to-end, no shell) ----------

class TestCmdReclean:
    def _make_session(self, tmp_path, raw_text):
        sd = tmp_path / "FakeBox-20261012T000000Z"
        sd.mkdir()
        _write_meta(sd)
        _write_raw(sd, raw_text)
        return sd

    def test_reclean_rebuilds_draft(self, tmp_path):
        sd = self._make_session(
            tmp_path,
            "Script started on 2026-10-12\n"
            "bash-5.3$ id\n"
            "id\n"
            "uid=0(root) gid=0(root)\n"
            "Script done on 2026-10-12\n",
        )
        args = argparse.Namespace(session_dir=str(sd))
        rc = cmd_reclean(args)
        assert rc == 0

        draft = (sd / "walkthrough-draft.md").read_text(encoding="utf-8")
        assert "FakeBox" in draft
        assert "uid=0(root)" in draft
        assert "End of raw transcript" in draft

    def test_reclean_overwrites_existing_draft(self, tmp_path):
        sd = self._make_session(tmp_path, "$ whoami\nwhoami\nroot\n")
        # Pre-existing stale draft.
        (sd / "walkthrough-draft.md").write_text("STALE\n", encoding="utf-8")

        args = argparse.Namespace(session_dir=str(sd))
        rc = cmd_reclean(args)
        assert rc == 0

        draft = (sd / "walkthrough-draft.md").read_text(encoding="utf-8")
        assert "STALE" not in draft
        assert "root" in draft

    def test_reclean_missing_dir_returns_1(self, tmp_path):
        args = argparse.Namespace(session_dir=str(tmp_path / "does-not-exist"))
        rc = cmd_reclean(args)
        assert rc == 1

    def test_reclean_missing_raw_returns_1(self, tmp_path):
        sd = tmp_path / "FakeBox-20261012T000000Z"
        sd.mkdir()
        _write_meta(sd)
        # No raw.txt.
        args = argparse.Namespace(session_dir=str(sd))
        rc = cmd_reclean(args)
        assert rc == 1

    def test_reclean_missing_meta_returns_1(self, tmp_path):
        sd = tmp_path / "FakeBox-20261012T000000Z"
        sd.mkdir()
        _write_raw(sd, "$ whoami\nroot\n")
        # No metadata.json.
        args = argparse.Namespace(session_dir=str(sd))
        rc = cmd_reclean(args)
        assert rc == 1
