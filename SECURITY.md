# Security Policy

## About This Repository

MethodMan is a personal collection of penetration testing walkthroughs, tools,
methodologies, and cheatsheets, published as a portfolio and community resource.

All published walkthroughs are **fully masked**: flags, passwords, hashes, tokens,
and session identifiers are replaced with placeholders before publication.
Real values are never committed to this repository.

---

## Sensitive Data

This repository does **not** contain:

- Real HTB flags (user, root, system)
- Real passwords, hashes, or API keys
- Real session tokens or serial numbers
- Writeups for machines that are **currently active** on Hack The Box (per HTB ToS)

Active-machine writeups are withheld and replaced with stub files
(see the `## Completed (Writeups Pending)` sections in category READMEs).

---

## Reporting a Vulnerability

If you find a security issue in this repository, please report it **privately**:

1. **Preferred:** GitHub Private Vulnerability Reporting
   - Go to the **Security** tab -> **Report a vulnerability**
   - https://github.com/N3xu666/MethodMan/security/advisories/new
2. **Email:** huseynovirshad@gmail.com
   - Subject: `[MethodMan Security] <short description>`

**Do NOT open a public GitHub issue for security problems.**

---

## Abuse Reports

If you believe any tool in this repository has been used against a system
without authorization, or you have received unsolicited traffic originating
from this code, contact: huseynovirshad@gmail.com

We do not condone unauthorized use. All tools are intended for authorized
penetration testing, CTF environments (Hack The Box, OSCP labs), and
educational purposes only.

---

## What Qualifies

- Unmasked real secrets (flag, password, hash, token) in any file
- Unmasked real secrets in git **history** (even if removed from HEAD)
- Published writeup for an HTB machine that is **still active**
- Leaked local file paths, usernames, or other PII
- CI/CD workflow weaknesses (script injection, unpinned actions, excessive permissions)
- Broken masking that reveals a real value through placeholders

---

## What Does NOT Qualify

- Placeholders themselves (`<PASSWORD>`, `<USER_FLAG>`, etc.) - these are intentional
- Walkthroughs for **retired** HTB machines
- Theoretical issues without a concrete reproduction
- Style, formatting, or localization complaints (use a normal issue instead)

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix + disclosure coordination | depends on severity |

This is a personal project maintained on a best-effort basis.
No bug bounty is offered. Credit will be given in the advisory if desired.

---

## Scope

**In scope:**

- This repository and its entire git history
- Published walkthroughs, cheatsheets, methodology docs
- GitHub Actions workflows in `.github/workflows/`
- README files and inline links

**Out of scope:**

- Hack The Box platform itself (report to HTB support)
- Third-party tools mentioned in walkthroughs (report to their maintainers)
- The author's personal machine or local environment

---

*Last updated: 2026-10-09*
