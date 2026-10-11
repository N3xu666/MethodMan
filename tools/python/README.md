\# Python Tools



Python scripts and small utilities for authorized penetration testing,

CTF environments (Hack The Box, OSCP labs), and educational purposes.



Part of the \[tools](../README.md) collection. Scope and legal boundaries:

see \[SECURITY.md](../../SECURITY.md).



\## Purpose



Python is used here for:



\- Parsers for tool output (`nmap`, `ffuf`, `gobuster`, `nuclei`) that

&#x20; turn raw logs into structured data.

\- PoC templates for CVE reproduction in lab environments.

\- Automation glue for repetitive lab workflow (session recording,

&#x20; evidence collection, report scaffolding).

\- Small REST / HTTP helpers for web application testing.



Python tools are \*\*bounded and auditable\*\*. No obfuscation. No

network beacons. No persistence mechanisms. Every tool must be readable

end-to-end in one sitting.



\## Tools



| Tool | Purpose | Status |

|------|---------|--------|

| \[Session\_Report.py](./Session\_Report.md) | Terminal session recorder that produces a walkthrough draft (Linux-only, uses `script(1)`). | planned |



\*More tools added as they are implemented.\*



\## Conventions



\- One tool per file. File name in `PascalCase` or `snake\_case`, no spaces

&#x20; (e.g. `Session\_Report.py`, `nmap\_parser.py`).

\- Python 3.8+ only. No Python 2 compatibility.

\- Standard library first. Third-party dependencies allowed only when they

&#x20; add real value; document them at the top of the file and in a per-tool

&#x20; section here.

\- Top-of-file docstring: purpose, authorized-use warning, link to

&#x20; `../../SECURITY.md`, usage line, exit codes.

\- `argparse` for CLI. `--help` must explain every flag in one sentence.

\- No hardcoded credentials, no hardcoded IPs, no hardcoded paths outside

&#x20; the tool's own working directory.

\- Output files go to a path outside the repo (or to a `tmp/` that is

&#x20; gitignored). Never commit scan results or session logs.

\- Every tool ships with a short `.md` doc next to it (e.g.

&#x20; `Session\_Report.md`), describing purpose, install, usage, examples,

&#x20; and platform requirements.



\## Tool docs



\- \[Session\_Report.md](./Session\_Report.md) - design and usage of the

&#x20; terminal session recorder (status: planned).



\## See Also



\- \[tools/README.md](../README.md) - collection overview.

\- \[SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.

\- \[METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where

&#x20; these tools apply.

\- \[methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md) -

&#x20; evidence collection, which `Session\_Report.py` is intended to support.

