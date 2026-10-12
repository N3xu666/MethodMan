# Go Tools

> **Status:** scaffolding only. No runnable tools yet.

Part of the [tools](../README.md) collection. Scope and legal boundaries:
see [SECURITY.md](../../SECURITY.md).

---

## Purpose

Go tools in this directory provide small, statically-compiled utilities for
authorized penetration testing and lab work:

- network probes (TCP, HTTP, TLS);
- fast port and service scanners with structured output;
- single-binary helpers that run without runtime dependencies.

Everything here is built for **authorized use only** (own lab, HTB, OSCP
exam, client engagement with written permission).

## Tools

| Tool | Purpose | Status |
|------|---------|--------|
| _(none yet)_ | | |

## Conventions

- Go 1.21+.
- One tool = one `.go` file or one subdirectory + one `.md` doc.
- Header comment in each `.go`: purpose, target platforms, authorized-use disclaimer.
- No third-party modules unless justified in the tool doc.
- Cross-compile with `GOOS`/`GOARCH`; commit source, not binaries.

## See Also

- [tools/README.md](../README.md) - collection overview.
- [SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.
- [METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where these tools apply.