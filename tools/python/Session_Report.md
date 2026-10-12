# Session_Report.py

> Linux-only terminal session recorder that produces a MethodMan walkthrough
> draft in the section 3.2 format.

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
`pip install`, no dependencies required for the basic mode.

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
  and `str.removeprefix`-free code - all available since 3.9).
- **`util-linux`** installed (`script` binary in `$PATH`).
  - Debian / Ubuntu: `sudo apt install util-linux`
  - Fedora / RHEL: `sudo dnf install util-linux`
  - Arch: `sudo pacman -S util-linux`
- Standard library only for the default mode. No pip dependencies required.

### Optional: pyte for better cleanup

The default transcript cleaner is a stdlib-only heuristic. It removes ANSI
escape sequences and common shell prompt redraw artifacts, but it cannot
perfectly emulate a terminal.

For high-fidelity cleanup (especially with zsh and other shells that redraw
the prompt), install `pyte` and pass `--use-pyte`:

```bash
pip install pyte        # or: pip install --user pyte
```

`pyte` is a small pure-Python terminal emulator. When available and requested,
it replays the raw session through a virtual screen and yields the exact
final visible buffer.

---

## Usage

### Record a session

```
python Session_Report.py start --machine <name> [--target <ip>]
                               [--language en|ru|az] [--output <dir>]
                               [--use-pyte]
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
| `--use-pyte` | no | off | Use pyte for transcript cleanup (requires `pyte` installed). |

### Example

```
$ python Session_Report.py start --machine Layover --target 10.10.11.10 --language en
[Session_Report] Session directory: /home/op/MethodMan/sessions/Layover-20261012T143012Z
[Session_Report] Metadata:          /home/op/MethodMan/sessions/Layover-20261012T143012Z/metadata.json
[Session_Report] Draft:             /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md
[Session_Report] Cleaner:           heuristic
[Session_Report] Starting script(1). Type 'exit' to stop recording.

Script started, output log file is '/home/op/MethodMan/sessions/Layover-20261012T143012Z/raw.txt'.
op@kali:~$ nmap -p- --min-rate 5000 10.10.11.10
...
op@kali:~$ exit

[Session_Report] Transcript cleaned: 8432 -> 6211 bytes.
[Session_Report] Final draft: /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md
```

---

## Output layout

```
sessions/
+-- <machine>-<UTC timestamp>/
    +-- metadata.json          # machine, target, started, host, operator, language
    +-- raw.txt                # raw script(1) output (ANSI escapes, banner, \r)
    +-- walkthrough-draft.md   # cleaned draft in MethodMan section 3.2 format
```

`raw.txt` is kept for reference (it contains ANSI escapes and the script(1)
banner). The `.md` draft is the cleaned version with the AI prompt block,
the walkthrough skeleton, and the raw transcript appended under
`## Raw Transcript`.

**Note:** `sessions/` is listed in `.gitignore`. Drafts are local-only until
you decide to publish them (after masking, per section 3).

---

## Transcript cleanup

Two modes are available:

### Default: heuristic cleaner (stdlib only)

```
python Session_Report.py start --machine Foo --target 10.0.0.1
```

Steps performed on the raw transcript:

1. **ANSI escape sequences** stripped (CSI, OSC, two-character escapes).
2. **`script(1)` banner** lines removed (`Script started on ...`,
   `Script done on ...`, `Script started, output file is ...`).
3. **Line endings** normalized: `\r\n` and lone `\r` -> `\n`.
4. **Whitespace-only lines** converted to empty lines.
5. **Prompt redraw rollbacks** collapsed: if two adjacent lines share a
   long prefix (>= 6 chars) and the second is longer by >= 3 chars, the
   first is dropped. This handles the common zsh/bash redraw artifact
   where the same line appears twice after ANSI stripping.
6. **Blank runs collapsed**: 3+ consecutive newlines -> 2.

Best-effort. Handles most sessions cleanly. Some shells emit unusual
escape sequences that the heuristic cannot fully resolve.

### Optional: pyte terminal emulator

```
pip install pyte
python Session_Report.py start --machine Foo --target 10.0.0.1 --use-pyte
```

When `pyte` is available and `--use-pyte` is passed, the raw byte stream is
fed through a real terminal emulator (200 columns, 200 lines, 10000-line
scrollback). Cursor moves, erase-line, and redraw sequences are applied to
a virtual screen, and the final visible buffer is used as the transcript.

This produces a **correct** rendering for any shell (zsh, bash, fish), at
the cost of one small pure-Python dependency.

If `--use-pyte` is passed but `pyte` is not installed, the tool prints a
warning and falls back to the heuristic cleaner.

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
- **Interactive only.** The recorder runs an interactive subshell. It does
  not wrap a single command; use `script -c "cmd" raw.txt` directly for that.
- **No masking.** Real secrets (flags, passwords, hashes) are captured as-is.
  Mask them manually before publishing, per section 3 of `_WORKFLOW.md`.
- **Heuristic cleaner is best-effort.** For perfect results with shells that
  redraw the prompt aggressively, install `pyte` and use `--use-pyte`.

---

## Tests

CI runs `python -m py_compile tools/python/Session_Report.py` to catch
syntax errors. Full functional tests require a Linux environment and are
not part of the CI matrix.

To run a smoke test locally on Linux:

```
$ python Session_Report.py --version
Session_Report.py 0.2.0

$ python Session_Report.py start --machine Test --target 127.0.0.1
# ... type a few commands, then 'exit'
$ ls sessions/Test-*/
metadata.json  raw.txt  walkthrough-draft.md

# Rebuild after installing pyte:
$ pip install pyte
$ python Session_Report.py reclean sessions/Test-*/ --use-pyte
```

---

## See also

- `_WORKFLOW.md` section 3.2 - walkthrough standard the draft follows.
- `_WORKFLOW.md` section 6.2 - placeholder scheme for masking.
- `../../SECURITY.md` - authorized use policy.
- `../../methodology/OSCP-Reporting.md` - OSCP report evidence rules.