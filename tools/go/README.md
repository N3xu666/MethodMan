\# Go Tools



Network utilities and compiled binaries for authorized penetration testing,

CTF environments (Hack The Box, OSCP labs), and educational purposes.



Part of the \[tools](../README.md) collection. Scope and legal boundaries:

see \[SECURITY.md](../../SECURITY.md).



\## Purpose



Go is used here for:



\- Standalone network utilities (port scanners, HTTP probers).

\- Fast, single-binary tools that run without a runtime.

\- Cross-compiled tools for Linux targets (`GOOS=linux GOARCH=amd64`).



\## Tools



\*No tools published yet.\*



| Tool | Purpose | Status |

|------|---------|--------|

|      |         |        |



\## Conventions



\- One tool per file. File name in `snake\_case` (e.g. `port\_scanner.go`).

\- Top-of-file comment block: purpose, authorized-use warning, link to

&#x20; `../../SECURITY.md`, usage line.

\- No external dependencies unless justified (keep `go.mod` minimal).

\- Build target documented in a comment: `GOOS=linux GOARCH=amd64 go build`.

\- Output files go to a path outside the repo (or to a `tmp/` that is

&#x20; gitignored). Never commit scan results.



\## See Also



\- \[tools/README.md](../README.md) - collection overview.

\- \[SECURITY.md](../../SECURITY.md) - scope, reporting, abuse contact.

\- \[METHODOLOGY.md](../../METHODOLOGY.md) - engagement phases where

&#x20; these tools apply.

