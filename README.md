# MethodMan

[![Validate](https://github.com/N3xu666/MethodMan/actions/workflows/validate.yml/badge.svg?style=flat-square)](https://github.com/N3xu666/MethodMan/actions/workflows/validate.yml)
[![Last commit](https://img.shields.io/github/last-commit/N3xu666/MethodMan?style=flat-square&label=last&v=4)](https://github.com/N3xu666/MethodMan/commits/main)
[![Repo size](https://img.shields.io/github/repo-size/N3xu666/MethodMan?style=flat-square&label=repo&v=5)](https://github.com/N3xu666/MethodMan)
[![Docs: CC BY-NC 4.0](https://img.shields.io/badge/Docs-CC%20BY--NC%204.0-lightgrey.svg?style=flat-square)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Code: MIT](https://img.shields.io/badge/Code-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)

![MethodMan - trilingual HTB writeups, web application security reference, methodology and tools](./social-preview.png)

New HTB machines are added as they are completed (retired only - see the stub scheme below for active machines). Reference material grows in parallel: the Application Security Reference (`APPLICATIONS/`), the Infrastructure Security Reference (`INFRASTRUCTURE/`), methodology notes, cheatsheets, and custom tooling (`tools/`).

Writeups available in Az/En/Ru. Currently: **17 published (retired) + 3 active stubs** = **20 completed machines**.

> The `(Now: M machines)` counter counts **only published walkthroughs** (machines retired on Hack The Box). Writeups for active machines are withheld per HTB ToS and stored as stubs (`Status: Completed`) until retirement.

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Structure

```
MethodMan/
+-- WRITEUPS/                # HTB walkthroughs, trilingual
|   +-- 01 Hack The Box/
|       +-- 01 All Machines/
|       |   +-- 01 Season 12 (Aero, Sep - Nov 2026)/
|       |       +-- 01 Az/   # Azerbaijani writeups
|       |       +-- 02 En/   # English writeups
|       |       +-- 03 Ru/   # Russian writeups
|       +-- 02 OSCP/
|           +-- 01 Linux/
|           |   +-- 01 Az/
|           |   +-- 02 En/
|           |   +-- 03 Ru/
|           +-- 02 Windows/
|           |   +-- 01 Az/
|           |   +-- 02 En/
|           |   +-- 03 Ru/
|           +-- 03 Active Directory and Networks/
|               +-- 01 Az/
|               +-- 02 En/
|               +-- 03 Ru/
+-- APPLICATIONS/            # application security reference
|   +-- 01 Web/
|   |   +-- 01 Recon/
|   |   +-- 02 Frameworks/
|   |   +-- 03 Languages/
|   |   +-- 04 Servers/
|   |   +-- 05 CMS/
|   |   +-- 06 Technologies/
|   |   +-- 07 Databases/
|   |   +-- 08 Vulnerabilities/
|   |   +-- 09 OWASP Top 10/
|   +-- 05 API/
|       +-- OWASP API Top 10, REST, GraphQL, gRPC, WebSocket, SOAP,
|           Authentication, Rate-Limiting, API Gateway (9 files)
+-- INFRASTRUCTURE/          # infrastructure security reference
|   +-- 01 Active Directory/
|   +-- 02 Windows Infrastructure/
|   +-- 03 Linux Infrastructure/
|   +-- 04 Network Services/
|   +-- 05 Network Attacks/
|   +-- 06 Wireless/
|   +-- 07 Mail-and-VPN/
+-- methodology/             # OSCP reporting rules and notes
+-- tools/                   # custom pentest tools (Python, Go, Bash)
+-- tests/                   # test runner + fixtures for mask.ps1 / check.ps1
```

---

## Contents

| Section | Description | Az | En | Ru |
|---------|-------------|-----|-----|-----|
| [HTB / Season 12 Aero](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/) | Special HTB season, Sep - Nov 2026 | [Az](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/03%20Ru/) |
| [HTB / OSCP / Linux](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/) | Linux machines for OSCP prep | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/03%20Ru/) |
| [HTB / OSCP / Windows](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/) | Windows machines for OSCP prep | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/03%20Ru/) |
| [HTB / OSCP / Active Directory and Networks](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/) | AD and networks | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/03%20Ru/) |
| [Web Application Security Reference](./APPLICATIONS/01%20Web/) | Stack-organized web testing reference (recon, frameworks, languages, servers, CMS, technologies, databases, vulnerabilities, OWASP Top 10) | - | [En](./APPLICATIONS/01%20Web/) | - |

### Other Resources

Reference material and tooling, independent of any single HTB machine:

| Resource | Description |
|----------|-------------|
| [Application Security Reference](./APPLICATIONS/01%20Web/) | Web and API testing reference: recon, frameworks, languages, servers, CMS, technologies, databases, vulnerabilities, OWASP Top 10 (61 files); plus API Top 10, REST, GraphQL, gRPC, WebSocket, SOAP, auth, rate-limiting, API gateway (9 files). |
| [Infrastructure Security Reference](./INFRASTRUCTURE/) | Active Directory, Windows, Linux, network services and attacks, wireless, mail and VPN. Two-track format (offensive + defensive) across 7 subcategories (46 files). |
| [METHODOLOGY.md](./METHODOLOGY.md) | Engagement phases, intensity profiles, checklists. |
| [CHEATSHEET.md](./CHEATSHEET.md) | Quick command reference for common tools and techniques. |
| [methodology/OSCP-Reporting.md](./methodology/OSCP-Reporting.md) | OSCP exam reporting rules (evidence, screenshots, structure). |
| [tools/](./tools/) | Custom pentest tools (Python, Go, Bash). First tool: `Session_Report.py` - terminal session recorder. |

**Note:** files marked with `Status: Completed` are **stubs** for machines still active on HTB. Full writeups are published after retirement.

---

## Quality & Automation

Validation is split across three independent layers:

- **Pre-commit hook (`check.ps1`)** - LOCAL only, opt-in. Lives in `.git/hooks/pre-commit`, which is not tracked by git (git does not clone hooks). To install, add a one-line invocation of `check.ps1` to `.git/hooks/pre-commit` and make it executable. Fast (14 checks, ~2 seconds).

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
- **CI (`.github/workflows/validate.yml`)** - runs 4 jobs on every push to any branch and on PRs to `main` (pinned actions, read-only permissions):
  - `check` (windows-latest) - `check.ps1` with a placeholder `masking-dict.ps1` (the real dict is not in git).
  - `test` (windows-latest) - `tests/run-tests.ps1` (masking + check.ps1 leak tests).
  - `tools-syntax` (ubuntu-latest) - `python -m py_compile` on every `.py` under `tools/`.
  - `tools-tests` (ubuntu-latest) - pytest suite in `tools/python/tests/` plus a pip-install smoke test of the `methodman-session-report` package.
  Does NOT run `audit.ps1` (local-only).

The masking pipeline (`mask.ps1` + a local-only `masking-dict.ps1` with known sensitive values) detects and masks flags (32-hex pattern), values listed in the dictionary, and heuristic password shapes. Detection is dictionary- and pattern-based, not exhaustive - manual review remains part of the workflow.

---

## Conventions

- **`01 Az/`** - Azerbaijani writeups.
- **`02 En/`** - English writeups.
- **`03 Ru/`** - Russian writeups.
- Each writeup follows a unified structure: Attack Chain (tree) -> Machine Briefing -> Reconnaissance -> Foothold -> [Authenticated Enumeration (AD only)] -> [Exploitation] -> Lateral Movement -> Privilege Escalation -> Flags -> Key Takeaways. Exploitation sections carry a CVE reference (NVD/MITRE link or "No CVE"); key commands show expected output; OSCP machines include screenshot reminders (`> [!IMPORTANT]`).
- All sensitive data (flags, passwords, hashes) is masked.
- Machines still active on HTB are represented by **stubs** (`Status: Completed`, neutral filename). Full writeups are published after retirement.

---

## License

This repository uses a **dual-license model**:

- **Documentation** (walkthroughs, `APPLICATIONS/`, `INFRASTRUCTURE/`, `METHODOLOGY.md`, `CHEATSHEET.md`, `README.md`, `SECURITY.md`, and other prose/Markdown content) - [Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](./LICENSE).
- **Source code** (`.py`, `.go`, `.sh`, `.ps1`, `.yml`) - MIT License, applies to `tools/` and to the root scripts (`check.ps1`, `mask.ps1`, `audit.ps1`, `tests/run-tests.ps1`). Full text: [tools/LICENSE](./tools/LICENSE).

See [LICENSE](./LICENSE) for the full text and the file-type rules.

---

*Personal project. For educational purposes only.*
