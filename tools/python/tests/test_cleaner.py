"""Tests for the transcript cleaner in Session_Report.py.

Covers: ANSI stripping, backspace handling, prompt-echo dedupe
(only immediate next line), whitespace collapsing, and the public
clean_transcript entry point.
"""

import pytest

from Session_Report import (
    _apply_backspaces,
    _clean_heuristic,
    _dedupe_command_echo,
    _strip_ansi,
    clean_transcript,
)


# ---------- _apply_backspaces ----------

class TestApplyBackspaces:
    def test_simple_backspace(self):
        assert _apply_backspaces("abc\x08d") == "abd"

    def test_backspace_at_line_start_is_ignored(self):
        assert _apply_backspaces("\x08abc") == "abc"

    def test_backspace_after_newline_is_ignored(self):
        assert _apply_backspaces("abc\n\x08def") == "abc\ndef"

    def test_multiple_backspaces(self):
        assert _apply_backspaces("abc\x08\x08\x08") == ""

    def test_backspace_does_not_cross_lines(self):
        # c is removed by the first backspace; the next two hit the
        # newline and are ignored (do not eat into the previous line).
        assert _apply_backspaces("ab\ncd\x08\x08\x08") == "ab\n"


# ---------- _strip_ansi ----------

class TestStripAnsi:
    def test_simple_color_sequence(self):
        assert _strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_cursor_movement(self):
        assert _strip_ansi("\x1b[2Ja\x1b[1;1Hb") == "ab"

    def test_osc_sequence(self):
        assert _strip_ansi("\x1b]0;title\x07after") == "after"

    def test_script_banner_removed(self):
        raw = "Script started on 2026-10-12 08:00:00+04:00 [COMMAND]\nreal output"
        assert "real output" in _strip_ansi(raw)
        assert "Script started" not in _strip_ansi(raw)

    def test_crlf_normalized(self):
        assert _strip_ansi("a\r\nb\rc") == "a\nb\nc"


# ---------- _dedupe_command_echo ----------

class TestDedupeCommandEcho:
    """Regression: previous version used a session-wide seen_prompt set,
    which wrongly deleted real output that happened to equal an earlier
    command. New version only drops the echo line if it is the IMMEDIATE
    next line after its prompt."""

    def test_immediate_echo_is_dropped(self):
        lines = ["bash-5.3$ ls", "ls", "file1.txt"]
        assert _dedupe_command_echo(lines) == ["bash-5.3$ ls", "file1.txt"]

    def test_real_output_equal_to_earlier_command_is_kept(self):
        lines = [
            "bash-5.3$ cat notes.txt",
            "cat notes.txt",
            "important: use ls carefully",
            "bash-5.3$ ls",
            "ls",
            "file1.txt",
        ]
        # The string "ls" appears in the output of cat, and again as a
        # prompt body later. Both must survive except the immediate echo.
        expected = [
            "bash-5.3$ cat notes.txt",
            "important: use ls carefully",
            "bash-5.3$ ls",
            "file1.txt",
        ]
        assert _dedupe_command_echo(lines) == expected

    def test_no_echo_no_change(self):
        lines = ["bash-5.3$ whoami", "root", "bash-5.3$ id", "uid=0(root)"]
        assert _dedupe_command_echo(lines) == lines

    def test_prompt_without_body_is_kept(self):
        lines = ["$ ", "some output"]
        assert _dedupe_command_echo(lines) == lines

    def test_prompt_is_last_line(self):
        lines = ["bash-5.3$ whoami"]
        assert _dedupe_command_echo(lines) == lines

    def test_empty_input(self):
        assert _dedupe_command_echo([]) == []

    def test_next_line_is_normal_output(self):
        # Next line is not identical to the command body -> keep it.
        lines = ["bash-5.3$ echo hello", "hello", "bash-5.3$ echo world", "world"]
        assert _dedupe_command_echo(lines) == lines

    def test_sh_prompt_style(self):
        lines = ["sh-5.2$ ls", "ls", "output"]
        assert _dedupe_command_echo(lines) == ["sh-5.2$ ls", "output"]

    def test_bare_dollar_prompt(self):
        lines = ["$ whoami", "whoami", "root"]
        assert _dedupe_command_echo(lines) == ["$ whoami", "root"]


# ---------- _clean_heuristic ----------

class TestCleanHeuristic:
    def test_strips_trailing_whitespace(self):
        raw = "line1   \nline2\t\n"
        assert _clean_heuristic(raw) == "line1\nline2\n"

    def test_collapses_triple_newlines(self):
        raw = "a\n\n\n\nb\n"
        assert _clean_heuristic(raw) == "a\n\nb\n"

    def test_keeps_double_newlines(self):
        raw = "a\n\nb\n"
        assert _clean_heuristic(raw) == "a\n\nb\n"

    def test_ends_with_single_newline(self):
        assert _clean_heuristic("abc").endswith("\n")
        assert not _clean_heuristic("abc").endswith("\n\n")

    def test_empty_input(self):
        assert _clean_heuristic("") == "\n"


# ---------- clean_transcript (public API) ----------

class TestCleanTranscript:
    def test_clean_transcript_basic(self):
        raw = (
            "Script started on 2026-10-12\n"
            "bash-5.3$ whoami\r\n"
            "whoami\r\n"
            "root\r\n"
            "bash-5.3$ exit\r\n"
            "exit\r\n"
            "Script done on 2026-10-12\n"
        )
        cleaned = clean_transcript(raw)
        assert "root" in cleaned
        assert "Script started" not in cleaned
        assert "Script done" not in cleaned
        # No \r left.
        assert "\r" not in cleaned

    def test_use_pyte_is_ignored_with_warning(self, capsys):
        raw = "bash-5.3$ ls\nls\nfile\n"
        cleaned = clean_transcript(raw, use_pyte=True)
        captured = capsys.readouterr()
        assert "deprecated" in captured.err
        assert "file" in cleaned