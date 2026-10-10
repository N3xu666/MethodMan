# Tools

Custom penetration testing tools used across the MethodMan walkthroughs,
methodologies, and OSCP preparation. Written in **Python**, **Go**, and **Bash**.

These are **not** replacements for established tools (nmap, feroxbuster,
linpeas, etc.). They are small wrappers, parsers, and automation scripts
built for specific phases of the workflow.

---

## Authorized Use Only

**All tools in this directory are intended exclusively for:**

- Authorized penetration testing engagements (with written permission)
- CTF environments (Hack The Box, OSCP labs, TryHackMe, etc.)
- Personal lab environments you own or are authorized to test
- Educational study and research

**Do NOT use these tools against systems you do not own or have explicit
written authorization to test.** Unauthorized access to computer systems is
illegal in most jurisdictions and is not condoned by the author.

See [`../SECURITY.md`](../SECURITY.md) for the full security policy,
including how to report abuse or unauthorized use.

---

## Contents

| Language | Directory | Purpose |
|----------|-----------|---------|
| Python | [`python/`](./python/) | PoC scripts, output parsers, automation |
| Go | [`go/`](./go/) | Network utilities, compiled binaries |
| Bash | [`bash/`](./bash/) | System wrappers, recon helpers |

**Status:** _no tools yet - first additions planned (see `_WORKFLOW.md` section 20)._

---

## Related Documentation

- [`../METHODOLOGY.md`](../METHODOLOGY.md) - penetration testing methodology (phases, profiles, checklists).
- [`../CHEATSHEET.md`](../CHEATSHEET.md) - quick command reference for common tools and techniques.
- [`../methodology/OSCP-Reporting.md`](../methodology/OSCP-Reporting.md) - OSCP exam reporting rules (evidence, screenshots, structure).
- [`../SECURITY.md`](../SECURITY.md) - security policy, scope, responsible disclosure, abuse reports.

---

## Conventions

Every tool in this directory follows these rules:

**1. Header comment.** Each script starts with a comment block:

```
# <name> - <one-line purpose>
#
# Authorized use only. See ../../SECURITY.md for scope and disclosure.
#
# Usage: <command> [options]
```

**2. No real secrets.** Never commit real flags, passwords, hashes, tokens,
or keys. If a tool needs a secret at runtime, read it from an environment
variable or a local file that is not tracked in git.

**3. No active-machine exploits.** Do not add exploit code specific to
HTB machines that are still active (per HTB ToS). Retired machines only.

**4. Documented dependencies.** List required packages/tools in a comment
at the top of the file (e.g. `Requires: python3, requests`).

**5. Self-contained where possible.** Prefer standard library. If a
dependency is unavoidable, document why in the header comment.

---

## Adding a New Tool

1. Choose the language directory (`python/`, `go/`, `bash/`).
2. Create the file with a clear name (`nmap-parser.py`, `port-scan.go`, `recon-wrapper.sh`).
3. Add the header comment (see Conventions).
4. Update the **Contents** table above with a one-line description.
5. Update `_WORKFLOW.md` section 20.10 progress table (local-only file).
6. Run `.\check.ps1` and `.\audit.ps1` before committing.

---

## See Also

- [`../README.md`](../README.md) - main repository README.
- [`../LICENSE`](../LICENSE) - CC BY-NC 4.0 (tools inherit this license).
- [GitHub Linguist](https://github.com/github/linguist) - `.gitattributes` marks `tools/**` as `linguist-detectable=true` so the language bar chart reflects these tools.

---

*Authorized use only. For educational purposes and authorized engagements.*