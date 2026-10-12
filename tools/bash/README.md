# Bash Tools

> **Status:** scaffolding only. No runnable tools yet.

Part of the [tools](../README.md) collection. Scope and legal boundaries:
see [SECURITY.md](../../SECURITY.md).

---

## Purpose

Bash tools in this directory are thin wrappers around standard Linux
utilities for authorized penetration testing and lab work:

- recon pipelines (subdomain, port, service enumeration);
- post-exploitation checklists that call existing tools safely;
- small glue scripts that pipe output of one tool into another.

Everything here is built for **authorized use only** (own lab, HTB, OSCP
exam, client engagement with written permission).

## Tools

| Tool | Purpose | Status |
|------|---------|--------|
| _(none yet)_ | | |

## Conventions

- POSIX `sh` where possible; `bash` when arrays or `[[ ]]` are needed.
- `#!/usr/bin/env bash` + `set -euo pipefail` at the top.
- Header comment in each script: purpose, target platforms, authorized-use disclaimer.
- No hardcoded targets, credentials, or IPs.
- Prefer existing tools over reimplementation; this directory is glue, not a framework.

## See Also

- [tools/README.md](../README.md) - collection overview.
- [SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.
- [METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where these tools apply.
- [CHEATSHEET.md](../../CHEATSHEET.md) - underlying commands these scripts wrap.