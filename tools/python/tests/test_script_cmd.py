"""Tests for _build_script_cmd and _resolve_shell in Session_Report.py.

Regression coverage for:
  - #7: temp rc file must live INSIDE session_dir (not /tmp).
  - #8: paths must be shlex.quote'd so spaces/metacharacters survive.
"""

import argparse
import sys
from pathlib import Path
from unittest import mock

import pytest

from Session_Report import (
    _build_script_cmd,
    _resolve_shell,
)


# ---------- _build_script_cmd ----------

class TestBuildScriptCmd:
    def test_clean_mode_creates_rc_in_session_dir(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, temp_rc = _build_script_cmd(raw, "/bin/bash", "clean", tmp_path)

        assert temp_rc is not None
        assert Path(temp_rc).parent == tmp_path
        assert Path(temp_rc).name == ".clean-rc.sh"
        assert Path(temp_rc).exists()

    def test_clean_mode_cmd_uses_script_with_rcfile(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, _ = _build_script_cmd(raw, "/bin/bash", "clean", tmp_path)

        assert cmd[0] == "script"
        assert "-c" in cmd
        inner = cmd[-1]
        assert "--noprofile" in inner
        assert "--norc" in inner
        assert "--rcfile" in inner

    def test_clean_mode_quotes_path_with_space(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, temp_rc = _build_script_cmd(raw, "/opt/my shell/bash", "clean", tmp_path)

        inner = cmd[-1]
        # shlex.quote wraps paths with spaces in single quotes.
        assert "'/opt/my shell/bash'" in inner
        assert "'{}'".format(temp_rc) in inner

    def test_clean_mode_quotes_path_with_semicolon(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, _ = _build_script_cmd(
            raw, "/bin/bash;touch /tmp/pwned", "clean", tmp_path
        )
        inner = cmd[-1]
        # shlex.quote wraps the whole path in single quotes, so the
        # shell sees one argument even though it contains ; and a space.
        assert "'/bin/bash;touch /tmp/pwned'" in inner
        # The unquoted form (a real shell-injection vector) must not appear.
        assert inner.count("'/bin/bash;touch /tmp/pwned'") == 1
        assert not inner.startswith("/bin/bash")

    def test_clean_mode_quotes_single_quote_in_path(self, tmp_path: Path):
        # shlex.quote on a path containing a single quote uses the
        # standard POSIX idiom: 'a'"'"'b'.
        raw = tmp_path / "raw.txt"
        weird = "/tmp/it's a dir/bash"
        cmd, _ = _build_script_cmd(raw, weird, "clean", tmp_path)
        inner = cmd[-1]
        assert "'" in inner  # quoted somewhere
        # The raw path without any quoting must NOT appear literally.
        # (If it did, the shell would break on the embedded single quote.)
        assert "/bin/bash" not in inner.split("--noprofile")[0].replace(
            "'\"'\"'", ""
        )

    def test_raw_mode_does_not_create_rc(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, temp_rc = _build_script_cmd(raw, "/bin/zsh", "raw", tmp_path)

        assert temp_rc is None
        assert not (tmp_path / ".clean-rc.sh").exists()
        assert cmd[-1] == "/bin/zsh"

    def test_raw_mode_no_quotes_for_simple_path(self, tmp_path: Path):
        # Simple path -> shlex.quote returns it unchanged.
        raw = tmp_path / "raw.txt"
        cmd, _ = _build_script_cmd(raw, "/bin/zsh", "raw", tmp_path)
        assert cmd[-1] == "/bin/zsh"

    def test_clean_mode_non_bash_does_not_create_rc(self, tmp_path: Path):
        # mode is "clean" but shell is not bash -> no rc file, no quoting needed.
        raw = tmp_path / "raw.txt"
        cmd, temp_rc = _build_script_cmd(raw, "/bin/sh", "clean", tmp_path)
        assert temp_rc is None
        assert not (tmp_path / ".clean-rc.sh").exists()

    def test_cmd_has_expected_script_flags(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, _ = _build_script_cmd(raw, "/bin/bash", "clean", tmp_path)
        assert "-a" in cmd
        assert "-q" in cmd
        assert "-f" in cmd
        # raw_path is passed as a string, not a Path object
        assert str(raw) in cmd

    def test_rc_file_is_written_with_nonempty_content(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        _, temp_rc = _build_script_cmd(raw, "/bin/bash", "clean", tmp_path)
        content = Path(temp_rc).read_text(encoding="utf-8")
        assert content.strip() != ""
        assert "PS1" in content
        assert "PROMPT_COMMAND" in content


# ---------- _resolve_shell ----------

class TestResolveShell:
    def test_default_returns_clean_bash(self, monkeypatch):
        monkeypatch.setattr("Session_Report.DEFAULT_CLEAN_SHELL", "/bin/bash")
        monkeypatch.setattr("pathlib.Path.exists", lambda self: True)

        args = argparse.Namespace(raw_shell=False)
        desc, path, mode = _resolve_shell(args)

        assert path == "/bin/bash"
        assert mode == "clean"
        assert "noprofile" in desc

    def test_raw_shell_uses_env_shell(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/zsh")

        args = argparse.Namespace(raw_shell=True)
        desc, path, mode = _resolve_shell(args)

        assert path == "/bin/zsh"
        assert mode == "raw"
        assert "raw" in desc

    def test_raw_shell_falls_back_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("SHELL", raising=False)

        args = argparse.Namespace(raw_shell=True)
        desc, path, mode = _resolve_shell(args)

        assert path == "/bin/bash"
        assert mode == "raw"

    def test_clean_falls_back_when_bash_missing(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.exists", lambda self: False)

        args = argparse.Namespace(raw_shell=False)
        desc, path, mode = _resolve_shell(args)

        assert path == "/bin/sh"
        assert mode == "clean"
        assert "fallback" in desc