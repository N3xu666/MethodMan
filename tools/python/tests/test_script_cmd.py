"""Tests for _build_script_cmd and _resolve_shell in Session_Report.py.

Regression coverage for:
  - #7: temp rc file must live INSIDE session_dir (not /tmp).
  - #8: paths must be shlex.quote'd so spaces/metacharacters survive.

The quoting tests use shlex.split() as the authoritative check: it
simulates what the shell does with the -c <inner> string, so a broken
quote (path split on a metacharacter) fails the assertion instead of
passing on a coincidental substring match.
"""

import argparse
import shlex
from pathlib import Path

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

        toks = shlex.split(inner)
        assert "/opt/my shell/bash" in toks
        assert toks.count("/opt/my shell/bash") == 1
        assert temp_rc in toks

    def test_clean_mode_quotes_path_with_semicolon(self, tmp_path: Path):
        # The injected shell path must survive as ONE token when the
        # shell re-parses <inner>. shlex.split() is the authoritative
        # check: if the quoting is wrong, the semicolon splits the
        # argument and the path is not preserved.
        raw = tmp_path / "raw.txt"
        evil = "/bin/bash;touch /tmp/pwned"
        cmd, _ = _build_script_cmd(raw, evil, "clean", tmp_path)
        inner = cmd[-1]

        toks = shlex.split(inner)
        assert evil in toks, f"path split by shell metachar: {toks}"
        assert toks.count(evil) == 1
        # Sanity: the unquoted form must not be a token on its own.
        assert "/bin/bash" not in toks

    def test_clean_mode_quotes_single_quote_in_path(self, tmp_path: Path):
        # A path containing a single quote must be quoted with the POSIX
        # idiom '"'"' so that shlex.split() round-trips it back to the
        # original path as a single argv token.
        raw = tmp_path / "raw.txt"
        weird = "/tmp/it's a dir/bash"
        cmd, temp_rc = _build_script_cmd(raw, weird, "clean", tmp_path)
        inner = cmd[-1]

        toks = shlex.split(inner)
        assert weird in toks, f"weird path not preserved: {toks}"
        assert toks.count(weird) == 1
        assert temp_rc in toks

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

    def test_raw_mode_quotes_path_with_semicolon(self, tmp_path: Path):
        # $SHELL is user-controlled. Raw mode must quote it too, or the
        # shell splits on ; and runs an injected command.
        raw = tmp_path / "raw.txt"
        evil = "/bin/zsh;touch /tmp/pwned"
        cmd, temp_rc = _build_script_cmd(raw, evil, "raw", tmp_path)
        assert temp_rc is None
        inner = cmd[-1]

        toks = shlex.split(inner)
        assert evil in toks, f"path split by shell metachar: {toks}"
        assert toks.count(evil) == 1
        assert "/bin/zsh" not in toks

    def test_raw_mode_quotes_path_with_space(self, tmp_path: Path):
        raw = tmp_path / "raw.txt"
        cmd, _ = _build_script_cmd(raw, "/opt/my shell/zsh", "raw", tmp_path)
        inner = cmd[-1]

        toks = shlex.split(inner)
        assert "/opt/my shell/zsh" in toks
        assert toks.count("/opt/my shell/zsh") == 1

    def test_clean_mode_non_bash_does_not_create_rc(self, tmp_path: Path):
        # mode is "clean" but shell is not bash -> no rc file.
        raw = tmp_path / "raw.txt"
        cmd, temp_rc = _build_script_cmd(raw, "/bin/sh", "clean", tmp_path)
        assert temp_rc is None
        assert not (tmp_path / ".clean-rc.sh").exists()
        assert cmd[-1] == "/bin/sh"

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
