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

## Requirements

- **Linux only.** The recorder relies on `script(1)` from `util-linux`.

&#x20; macOS and Windows are not supported (macOS `script(1)` has different flags

&#x20; and no `-f`; Windows has no equivalent).

- **Python 3.9+** (uses `list[str]` in annotations, `datetime.timezone.utc`,

&#x20; and `str.removeprefix`-free code - all available since 3.9).

- **`util-linux`** installed (`script` binary in `$PATH`).

&#x20; - Debian / Ubuntu: `sudo apt install util-linux`

&#x20; - Fedora / RHEL: `sudo dnf install util-linux`

&#x20; - Arch: `sudo pacman -S util-linux`

- Standard library only. No pip dependencies.

---

## Usage

```

python Session_Report.py start --machine <name> [--target <ip>]

&#x20;                              [--language en|ru|az] [--output <dir>]

```

### Arguments

| Flag | Required | Default | Description |

|------|----------|---------|-------------|

| `--machine` | yes | - | Machine name (e.g. `Layover`). Used for the session directory name. |

| `--target` | no | empty | Target IP or hostname. Stored in metadata and in the draft. |

| `--language` | no | `en` | Walkthrough language. One of `en`, `ru`, `az`. |

| `--output` | no | `sessions` | Output root directory. Created if missing. |

### Example

```

$ python Session_Report.py start --machine Layover --target 10.10.11.10 --language en

[Session_Report] Session directory: /home/op/MethodMan/sessions/Layover-20261012T143012Z

[Session_Report] Metadata:          /home/op/MethodMan/sessions/Layover-20261012T143012Z/metadata.json

[Session_Report] Draft:             /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md

[Session_Report] Starting script(1). Type 'exit' to stop recording.

Script started, output log file is '/home/op/MethodMan/sessions/Layover-20261012T143012Z/raw.txt'.

op@kali:\~$ nmap -p- --min-rate 5000 10.10.11.10

...

op@kali:\~$ exit

[Session_Report] Transcript cleaned: 8432 -> 6211 bytes.

[Session_Report] Final draft: /home/op/MethodMan/sessions/Layover-20261012T143012Z/walkthrough-draft.md

```

---

## Output layout

```

sessions/

+-- <machine>-<UTC timestamp>/

&#x20;   +-- metadata.json          # machine, target, started, host, operator, language

&#x20;   +-- raw.txt                # raw script(1) output (ANSI escapes, banner, \\r)

&#x20;   +-- walkthrough-draft.md   # cleaned draft in MethodMan section 3.2 format

```

`raw.txt` is kept for reference (it contains ANSI escapes and the script(1)

banner). The `.md` draft is the cleaned version with the AI prompt block,

the walkthrough skeleton, and the raw transcript appended under

`## Raw Transcript`.

**Note:** `sessions/` is listed in `.gitignore`. Drafts are local-only until

you decide to publish them (after masking, per section 3).

---

## Transcript cleanup

Before appending to the `.md`, the raw transcript is cleaned:

1. **ANSI escape sequences** stripped (CSI, OSC, two-character escapes).

&#x20;  Covers SGR colors (`\\x1b[31m`), cursor movement, title updates, and reset

&#x20;  sequences emitted by `ls`, `nmap`, `curl`, `metasploit`, etc.

2. **`script(1)` banner** lines removed (`Script started on ...`,

&#x20;  `Script done on ...`, `Script started, output file is ...`).

3. **Line endings** normalized: `\\r\\n` and lone `\\r` -> `\\n`.

4. **Blank runs collapsed**: 3+ consecutive newlines -> 2.

The cleanup is best-effort. If a tool emits unusual escape sequences, the

result may still contain artifacts - review the draft before publishing.

---

## Exit codes

| Code | Meaning |

|------|---------|

| 0 | Session recorded successfully. |

| 1 | Runtime failure (e.g. `script(1)` failed to launch, `raw.txt` missing after exit). |

| 2 | Platform check failed: not Linux, or `script(1)` not found in `$PATH`. |

---

## Safety

- **No keylogger.** The tool does not read `/dev/input/event*`, does not hook

&#x20; the kernel, does not intercept syscalls. It only invokes `script(1)` in a

&#x20; child process, exactly as a user would run it manually.

- **No network.** The recorder is fully offline.

- **No telemetry.** The tool does not phone home, does not write outside the

&#x20; chosen output directory.

See `../../SECURITY.md` for the project-wide policy on authorized use.

---

## Limitations

- **Linux only.** See Requirements.

- **Single terminal.** One invocation = one recording session. Multiple

&#x20; parallel terminals are not merged.

- **Interactive only.** The recorder runs an interactive subshell. It does

&#x20; not wrap a single command; use `script -c "cmd" raw.txt` directly for that.

- **No masking.** Real secrets (flags, passwords, hashes) are captured as-is.

&#x20; Mask them manually before publishing, per section 3 of `_WORKFLOW.md`.

---

## Tests

CI runs `python -m py_compile tools/python/Session_Report.py` to catch

syntax errors. Full functional tests require a Linux environment and are

not part of the CI matrix.

To run a smoke test locally on Linux:

```

$ python Session_Report.py --version

Session_Report.py 0.1.0

$ python Session_Report.py start --machine Test --target 127.0.0.1

# ... type a few commands, then 'exit'

$ ls sessions/Test-*/

metadata.json  raw.txt  walkthrough-draft.md

```

---

## See also

- `_WORKFLOW.md` section 3.2 - walkthrough standard the draft follows.

- `_WORKFLOW.md` section 6.2 - placeholder scheme for masking.

- `../../SECURITY.md` - authorized use policy.

- `../../methodology/OSCP-Reporting.md` - OSCP report evidence rules.

