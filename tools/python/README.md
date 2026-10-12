# Python Tools

> **Status:** active. `Session_Report.py` is available; more tools will be added as they are built.

Part of the [tools](../README.md) collection. Scope and legal boundaries:
see [SECURITY.md](../../SECURITY.md).

---

## Purpose

Python tools in this directory automate repetitive parts of authorized
penetration testing and OSCP/HTB lab work:

- parsing tool output into structured reports;
- generating walkthrough drafts from raw session logs;
- small PoC harnesses for lab-only exploitation.

Everything here is built for **authorized use only** (own lab, HTB, OSCP
exam, client engagement with written permission).

## Tools

| Tool | Purpose | Status |
|------|---------|--------|
| [`Session_Report.py`](./Session_Report.md) | Terminal session recorder that produces a walkthrough draft (Linux-only, uses `script(1)`). | active |

## Conventions

- Python 3.9+.
- One tool = one `.py` file + one `.md` doc.
- Header comment in each `.py`: purpose, target platforms, authorized-use disclaimer.
- No third-party dependencies unless justified in the tool doc.
- No hardcoded targets, credentials, or IPs.

## License

MIT. Applies to every file in this directory (`.py`, `.md`, `pyproject.toml`), including the pip-installable `methodman-session-report` package.

Documentation elsewhere in the repository (walkthroughs, `02 Web/`, `METHODOLOGY.md`, `CHEATSHEET.md`) is licensed under CC BY-NC 4.0 - see [../../LICENSE](../../LICENSE).

## See Also

- [tools/README.md](../README.md) - collection overview.
- [SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.
- [METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where these tools apply.
- [methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md) - reporting rules for OSCP.