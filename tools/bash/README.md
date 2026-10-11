\# Bash Tools



Shell wrappers and recon scripts for authorized penetration testing,

CTF environments (Hack The Box, OSCP labs), and educational purposes.



Part of the \[tools](../README.md) collection. Scope and legal boundaries:

see \[SECURITY.md](../../SECURITY.md).



\## Purpose



Bash is used here for:



\- Thin wrappers around system utilities (`nmap`, `gobuster`, `ffuf`,

&#x20; `curl`, `jq`) that chain them into a single recon step.

\- Quick enumeration helpers for HTB / OSCP lab workflow.

\- Post-exploitation triage on Linux targets.



Bash tools are \*\*glue\*\*, not reimplementations. If a mature tool exists

(`linpeas`, `nmap`, `feroxbuster`), wrap it, do not rewrite it.



\## Tools



\*No tools published yet.\*



| Tool | Purpose | Status |

|------|---------|--------|

|      |         |        |



\## Conventions



\- One tool per file. File name in `kebab-case` (e.g. `recon-wrapper.sh`).

\- Shebang: `#!/usr/bin/env bash` and `set -euo pipefail` at the top.

\- Top-of-file comment block: purpose, authorized-use warning, link to

&#x20; `../../SECURITY.md`, usage line.

\- No external dependencies beyond coreutils + the wrapped tools. If a

&#x20; dependency is required, check for it and fail with a clear message.

\- POSIX-compatible where possible. Avoid Bash-isms unless they add real

&#x20; value.

\- Output files go to a path outside the repo (or to a `tmp/` that is

&#x20; gitignored). Never commit scan results.



\## See Also



\- \[tools/README.md](../README.md) - collection overview.

\- \[SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.

\- \[METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where

&#x20; these tools apply.

\- \[CHEATSHEET.md](../../CHEATSHEET.md) - underlying commands these

&#x20; wrappers call.

