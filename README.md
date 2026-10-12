# MethodMan

[![Validate](https://github.com/N3xu666/MethodMan/actions/workflows/validate.yml/badge.svg?style=flat-square)](https://github.com/N3xu666/MethodMan/actions/workflows/validate.yml)
[![Last commit](https://img.shields.io/github/last-commit/N3xu666/MethodMan?style=flat-square&label=last&v=4)](https://github.com/N3xu666/MethodMan/commits/main)
[![Repo size](https://img.shields.io/github/repo-size/N3xu666/MethodMan?style=flat-square&label=repo&v=5)](https://github.com/N3xu666/MethodMan)
[![Docs: CC BY-NC 4.0](https://img.shields.io/badge/Docs-CC%20BY--NC%204.0-lightgrey.svg?style=flat-square)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Code: MIT](https://img.shields.io/badge/Code-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)

![MethodMan - trilingual HTB writeups, web application security reference, methodology and tools](./social-preview.png)

New machines and platforms will be added as they are completed,  
while methodologies and cheatsheets are updated regularly.

Writeups available in Az/En/Ru. Currently: **14 published (retired) + 3 active stubs** = **17 completed machines**.

> The `(Now: M machines)` counter counts **only published walkthroughs** (machines retired on Hack The Box). Writeups for active machines are withheld per HTB ToS and stored as stubs (`Status: Completed`) until retirement.

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Structure

```
MethodMan/
+-- 01 HTB/
|   +-- 01 All Machines/
|   |   +-- 01 Season 12 (Aero, Sep - Nov 2026)/
|   |       +-- 01 Az/   # Azerbaijani writeups
|   |       +-- 02 En/   # English writeups
|   |       +-- 03 Ru/   # Russian writeups
|   +-- 02 OSCP/
|       +-- 01 Linux/
|       |   +-- 01 Az/
|       |   +-- 02 En/
|       |   +-- 03 Ru/
|       +-- 02 Windows/
|       +-- 03 Active Directory and Networks/
+-- 02 Web/                # web app testing cheatsheet (English only)
|   +-- 01 Recon/
|   +-- 02 Frameworks/
|   +-- 03 Languages/
|   +-- 04 Servers/
|   +-- 05 CMS/
|   +-- 06 Technologies/
|   +-- 07 Vulnerabilities/
```

---

## Contents

| Section | Description | Az | En | Ru |
|---------|-------------|-----|-----|-----|
| [HTB / Season 12 Aero](./01%20HTB/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/) | Special HTB season, Sep - Nov 2026 | [Az](./01%20HTB/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/01%20Az/) | [En](./01%20HTB/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/02%20En/) | [Ru](./01%20HTB/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/03%20Ru/) |
| [HTB / OSCP / Linux](./01%20HTB/02%20OSCP/01%20Linux/) | Linux machines for OSCP prep | [Az](./01%20HTB/02%20OSCP/01%20Linux/01%20Az/) | [En](./01%20HTB/02%20OSCP/01%20Linux/02%20En/) | [Ru](./01%20HTB/02%20OSCP/01%20Linux/03%20Ru/) |
| [HTB / OSCP / Windows](./01%20HTB/02%20OSCP/02%20Windows/) | Windows machines for OSCP prep | - | - | - |
| [HTB / OSCP / Active Directory and Networks](./01%20HTB/02%20OSCP/03%20Active%20Directory%20and%20Networks/) | AD and networks | - | - | - |

**Note:** files marked with `Status: Completed` are **stubs** for machines still active on HTB. Full writeups are published after retirement.

---

## Quality & Automation

Validation is split across three independent layers:

- **Pre-commit hook (`check.ps1`)** - LOCAL only, opt-in. Lives in `.git/hooks/pre-commit`, which is not tracked by git (git does not clone hooks). To install, add a one-line invocation of `check.ps1` to `.git/hooks/pre-commit` and make it executable. Fast (13 checks, ~2 seconds).

  **Blocking errors (commit is refused):**
  - real 32-hex flags,
  - leaks from the local masking dictionary,
  - missing ethical note in a walkthrough,
  - long dashes, broken UTF-8 chars, masking artifacts,
  - unreplaced placeholder markers in docs,
  - backslash-escaped Markdown in docs.

  **Advisory warnings (commit is allowed):**
  - heuristic suspicious passwords,
  - Exploitation section without a CVE reference,
  - broken relative links in docs,
  - counter drift in root README,
  - CVE table rows without a version range.
- **Manual audit (`audit.ps1`)** - LOCAL only, run by the operator before important pushes. Covers git state, tracked files, walkthrough structure, Attack Chain, note placement, flags, dict leaks, dashes, encoding, placeholders, documentation, scripts, hook, origin sync, dynamic machine count, language-pair verification. Not run in CI.
- **CI (`.github/workflows/validate.yml`)** - runs `check.ps1` and `tests/run-tests.ps1` on every push to any branch (Windows runner, pinned actions, read-only permissions). Uses a placeholder `masking-dict.ps1` (the real dict is not in git). Does NOT run `audit.ps1`.

The masking pipeline (`mask.ps1` + a local-only `masking-dict.ps1` with known sensitive values) detects and masks flags (32-hex pattern), values listed in the dictionary, and heuristic password shapes. Detection is dictionary- and pattern-based, not exhaustive - manual review remains part of the workflow.

---

## Conventions

- **`01 Az/`** - Azerbaijani writeups.
- **`02 En/`** - English writeups.
- **`03 Ru/`** - Russian writeups.
- Each writeup follows a unified structure: Attack Chain -> Machine Briefing -> Recon -> Foothold -> Lateral Movement -> Privilege Escalation -> Flags -> Key Takeaways.
- All sensitive data (flags, passwords, hashes) is masked.

---

## License

This repository uses a **dual-license model**:

- **Documentation** (walkthroughs, `02 Web/`, `METHODOLOGY.md`, `CHEATSHEET.md`, `README.md`, `SECURITY.md`, and other prose/Markdown content) - [Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](./LICENSE).
- **Source code** (`.py`, `.go`, `.sh`, `.ps1`, `.yml`) - MIT License, applies to `tools/` and to the root scripts (`check.ps1`, `mask.ps1`, `audit.ps1`, `tests/run-tests.ps1`). Full text: [tools/LICENSE](./tools/LICENSE).

See [LICENSE](./LICENSE) for the full text and the file-type rules.

---

*Personal project. For educational purposes only.*
