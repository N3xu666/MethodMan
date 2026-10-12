# Session_Report.py

> Linux-only terminal session recorder that produces a MethodMan walkthrough
> draft in the section 3.2 format. Records in a clean `bash` subshell by
> default, so the transcript is readable regardless of your own shell config.

---

## Purpose

Record a live terminal session (Hack The Box, OSCP lab, or local practice)
and turn it into a structured walkthrough draft. The draft is written to a
per-session directory together with the raw transcript and a metadata file.

Use case: during a pentest or CTF session, run the recorder once at the
start, work normally in the subshell, exit when done. The result is a
`walkthrough-draft.md` with the MethodMan section 3.2 skeleton, ready to be
finished by hand (or by an AI assistant) into a full writeup.

---

## Quick start (standalone)

If you only want the tool and not the whole repository:

```bash
mkdir -p ~/tools && cd ~/tools
curl -fsSL -o Session_Report.py \
  https://raw.githubusercontent.com/N3xu666/MethodMan/main/tools/python/Session_Report.py
python3 Session_Report.py --version
```

The script is self-contained (standard library only). No `git clone`, no
`pip install`, no dependencies required for the default mode.

To also fetch the documentation:

```bash
curl -fsSL -o Session_Report.md \
  https://raw.githubusercontent.com/N3xu666/MethodMan/main/tools/python/Session_Report.md
```

---

## Requirements

- **Linux only.** The recorder relies on `script(1)` from `util-linux`.
  macOS and Windows are not supported (macOS `script(1)` has different flags
  and no `-f`; Windows has no equivalent).
- **Python 3.9+** (uses `list[str]` in annotations, `datetime.timezone.utc`,
  `tempfile.mkstemp`, all available since 3.9).
- **`util-linux`** installed (`script` binary in `$PATH`).
  - Debian / Ubuntu: `sudo apt install util-linux`
  - Fedora / RHEL: `sudo dnf install util-linux`
  - Arch: `sudo pacman -S util-linux`
- **`/bin/bash`** for the default clean-shell mode (present on virtually
  every Linux distribution). If missing, the tool falls back to `/bin/sh`.
- Standard library only for the default mode. No pip dependencies required.

### Optional: pyte for `--raw-shell` mode

If you pass `--raw-shell`, the recorder runs inside your own `$SHELL` with
its user configs. Shells like zsh, fish, and powerlevel10k redraw the prompt
on every keystroke, which leaves artifacts in the transcript.

Install `pyte` (a small pure-Python terminal emulator) and pass `--use-pyte`
to resolve those artifacts correctly:

```bash
pip install pyte        # or: pip install --user pyte
```

For the default clean-shell mode, `pyte` is not needed.

---

## How recording works

The tool starts `script(1)` with an explicit child command:

- **Default (`clean` mode):** `bash --noprofile --norc --rcfile <temp>` where
  `<temp>` is a minimal rc that sets `PS1='$ '` and disables bracketed paste.
  Your own `.bashrc`, `.zshrc`, oh-my-zsh, powerlevel10k, and syntax
  highlighting are **not** loaded. The transcript contains only commands and
  their output.
- **`--raw-shell` mode:** your `$SHELL` with its own configs. Prompt redraws
  and color escapes end up in the transcript. Use `--use-pyte` to clean it.

The chosen mode is recorded in `metadata.json` (field `shell`).

---

## Usage

### Record a session

```
python Session_Report.py start --machine <name> [--target <ip>]
                               [--language en|ru|az] [--output <dir>]
                               [--raw-shell] [--use-pyte]
```

### Rebuild a draft from an existing session

```
python Session_Report.py reclean <session_dir> [--use-pyte]
```

Use `reclean` after installing `pyte`, or after upgrading the tool, to
regenerate `walkthrough-draft.md` from the saved `raw.txt` without
re-recording the session.

### Arguments (start)

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--machine` | yes | - | Machine name (e.g. `Layover`). Used for the session directory name. |
| `--target` | no | empty | Target IP or hostname. Stored in metadata and in the draft. |
| `--language` | no | `en` | Walkthrough language. One of `en`, `ru`, `az`. |
| `--output` | no | `sessions` | Output root directory. Created if missing. |
| `--raw-shell` | no | off | Record in your own `$SHELL` with its user configs. |
| `--use-pyte` | no | off | Use pyte for cleanup (requires `pyte`). Recommended with `--raw-shell`. |

### Example (default, clean shell)

```
$ python Session_Report.py start --machine Layover --target 10.10.11.10 --language en
[Session_Report] Session directory: /home/op/MethodMan/sessions/Layover-20261012T143012Z
[Session_Report] Metadata:          /home/op/MethodMan/sessions/Layover-20261012T143012Z/metadata.json
[Session_Report] Draft:             /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md
[Session_Report] Shell:             /bin/bash --noprofile --norc (clean, no user configs)
[Session_Report] Cleaner:           heuristic
[Session_Report] Starting script(1). Type 'exit' to stop recording.

$ nmap -p- --min-rate 5000 10.10.11.10
...
$ exit

[Session_Report] Transcript cleaned: 8432 -> 6211 bytes.
[Session_Report] Final draft: /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md
```

### Example (`--raw-shell` with pyte)

```
$ python Session_Report.py start --machine Layover --raw-shell --use-pyte
[Session_Report] Shell:             /usr/bin/zsh (raw, user configs loaded)
[Session_Report] Cleaner:           pyte
...
```

---

## Output layout

```
sessions/
+-- <machine>-<UTC timestamp>/
    +-- metadata.json          # machine, target, started, host, operator, language, shell
    +-- raw.txt                # raw script(1) output
    +-- walkthrough-draft.md   # cleaned draft in MethodMan section 3.2 format
```

`raw.txt` is kept for reference. The `.md` draft is the cleaned version with
the AI prompt block, the walkthrough skeleton, and the raw transcript
appended under `## Raw Transcript`.

**Note:** `sessions/` is listed in `.gitignore`. Drafts are local-only until
you decide to publish them (after masking, per section 3).

---

## Transcript cleanup

Cleanup runs on the raw `script(1)` output before appending to the `.md`.
Two levels are available:

### Default: heuristic cleaner (stdlib only)

Steps:

1. **ANSI escape sequences** stripped (CSI, OSC, two-character escapes).
   This removes color codes, bracketed-paste toggles (`ESC[?2004h/l`),
   reverse-video echo (`ESC[7m`, `ESC[27m`), and cursor-forward (`ESC[C`).
2. **`script(1)` banner** lines removed (`Script started on ...`,
   `Script done on ...`, `Script started, output file is ...`).
3. **Line endings** normalized: `\r\n` and lone `\r` -> `\n`.
4. **Whitespace-only lines** converted to empty lines.
5. **Blank runs collapsed**: 3+ consecutive newlines -> 2.

Sufficient for the default clean-shell mode.

### Optional: pyte terminal emulator (`--use-pyte`)

For `--raw-shell` mode, the user's shell may emit cursor-move sequences
(`ESC[<n>D`, `ESC[<n>G`) and per-keystroke syntax highlighting. These cannot
be correctly resolved by a regex. `pyte` replays the stream through a real
terminal emulator and yields the exact final visible buffer.

Behavior:

- `--use-pyte` and `pyte` installed: use the emulator (correct).
- `--use-pyte` and `pyte` missing: warning to stderr, fall back to heuristic.

### Rebuild an existing draft

```
python Session_Report.py reclean sessions/Layover-20261012T143012Z
python Session_Report.py reclean sessions/Layover-20261012T143012Z --use-pyte
```

Reads `metadata.json` and `raw.txt` from the session directory, regenerates
`walkthrough-draft.md` from the header down. The existing `.md` is
overwritten.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Session recorded / recleaned successfully. |
| 1 | Runtime failure (e.g. `script(1)` failed to launch, `raw.txt` missing). |
| 2 | Platform check failed: not Linux, or `script(1)` not found in `$PATH`. |

---

## Safety

- **No keylogger.** The tool does not read `/dev/input/event*`, does not hook
  the kernel, does not intercept syscalls. It only invokes `script(1)` in a
  child process, exactly as a user would run it manually.
- **No network.** The recorder is fully offline. `pyte` (if installed) is
  used purely in-process for parsing, not for network access.
- **No telemetry.** The tool does not phone home, does not write outside the
  chosen output directory.

See `../../SECURITY.md` for the project-wide policy on authorized use.

---

## Limitations

- **Linux only.** See Requirements.
- **Single terminal.** One invocation = one recording session. Multiple
  parallel terminals are not merged.
- **Default mode has no shell conveniences.** No aliases, no tab completion,
  no `~/.bashrc`. This is intentional: the walkthrough should show the raw
  commands. If you need your usual environment, use `--raw-shell`.
- **No masking.** Real secrets (flags, passwords, hashes) are captured as-is.
  Mask them manually before publishing, per section 3 of `_WORKFLOW.md`.

---

## Tests

CI runs `python -m py_compile tools/python/Session_Report.py` to catch
syntax errors. Full functional tests require a Linux environment and are
not part of the CI matrix.

To run a smoke test locally on Linux:

```
$ python Session_Report.py --version
Session_Report.py 0.3.0

$ python Session_Report.py start --machine Test --target 127.0.0.1
# ... type a few commands, then 'exit'
$ ls sessions/Test-*/
metadata.json  raw.txt  walkthrough-draft.md

# Rebuild with pyte (only relevant for --raw-shell):
$ pip install pyte
$ python Session_Report.py reclean sessions/Test-*/ --use-pyte
```

---

## See also

- `_WORKFLOW.md` section 3.2 - walkthrough standard the draft follows.
- `_WORKFLOW.md` section 6.2 - placeholder scheme for masking.
- `../../SECURITY.md` - authorized use policy.
- `../../methodology/OSCP-Reporting.md` - OSCP report evidence rules.