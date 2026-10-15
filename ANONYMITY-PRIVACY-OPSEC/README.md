# Anonymity, Privacy and OpSec

A practical reference for privacy engineering, anonymous communication,
anti-surveillance operations and operational security. Written for
authorized red team engagements, privacy research, and personal threat
modeling.

> [!CAUTION]
> **Authorized Use Only.**
>
> The material in this category describes anonymization networks, secure
> communication tools, and operational security techniques. Some of these
> techniques are dual-use: they are legitimate for journalists, activists,
> researchers and authorized red teams, but may be illegal in certain
> jurisdictions or when applied to systems you do not own.
>
> **You are solely responsible for complying with all applicable laws.**
> Do not use any technique here to:
> - evade lawful investigation,
> - conduct unauthorized access to any system,
> - traffic illegal material,
> - harm any person or organization.
>
> Read `SECURITY.md` at the repository root before using anything in this
> category. All examples assume an authorized engagement or a personal
> threat model on systems you own or have explicit permission to test.

---

## Scope

This category covers:

- **Anonymous networks** - Tor, I2P, Lokinet, VPN chains.
- **Secure communications** - Session, SimpleX, XMPP/OMEMO, PGP, anonymous email.
- **Operating systems and hygiene** - Tails, Qubes/Whonix, data destruction, metadata.
- **Dark web** - hidden services, OnionShare, SecureDrop, dead drops.
- **Anonymous hosting** - bulletproof hosting, off-shore VPS, CDN fronting.
- **Anonymous crypto operations and AML** - Monero, Bitcoin, mixers, chain analysis.
- **OpSec and threat models** - compartmentalization, attribution, case studies.
- **Attacks and detection** - de-anonymization, hidden service attacks, LE takedowns.

This category does **NOT** cover:

- hacking tools or exploits (see `APPLICATIONS/` and `INFRASTRUCTURE/`),
- OSINT techniques against individuals (out of scope, ethically fraught),
- "how to disappear" lifestyle advice (not a technical topic).

---

## Format

Every file in this category uses one of two formats (see `_WORKFLOW.md`
section 6.7 for the full templates):

- **Format 4 - Hands-on** (subcategories 01-06). Installation, hardening,
  operational usage, common mistakes, attacks, detection, case studies,
  legal and ethical notes.
- **Format 5 - Conceptual** (subcategories 07-08). Threat modeling,
  practical frameworks, real-world examples, risk context - no install steps.

Both formats replace the usual `## OSCP Notes` section with
`## Legal and Ethical Notes`. OSCP does not cover anonymity or privacy
topics; the legal section covers jurisdiction, authorization and the
boundaries that apply to the technique.

---

## Structure

```text
ANONYMITY-PRIVACY-OPSEC/
+-- README.md                                  (this file)
+-- 01 Anonymous Networks/                      Format 4
+-- 02 Secure Communications/                   Format 4
+-- 03 Operating Systems and Hygiene/           Format 4
+-- 04 Dark Web/                                Format 4
+-- 05 Anonymous Hosting/                       Format 4
+-- 06 Anonymous Crypto Operations and AML/     Format 4
+-- 07 OpSec and Threat Models/                 Format 5
+-- 08 Attacks and Detection/                   Format 5
```

---

## Subcategory Status

| # | Subcategory | Format | Status |
|---|-------------|--------|--------|
| 01 | Anonymous Networks | Hands-on | done |
| 02 | Secure Communications | Hands-on | planned |
| 03 | Operating Systems and Hygiene | Hands-on | planned |
| 04 | Dark Web | Hands-on | planned |
| 05 | Anonymous Hosting | Hands-on | planned |
| 06 | Anonymous Crypto Operations and AML | Hands-on | planned |
| 07 | OpSec and Threat Models | Conceptual | planned |
| 08 | Attacks and Detection | Conceptual | planned |

Status legend:

- **in progress** - at least one file written, subcategory not complete.
- **planned** - index README exists, no content files yet.
- **done** - all files written and reviewed.

---

## Related Material

- `SECURITY.md` (repository root) - authorized use policy.
- `METHODOLOGY.md` - engagement methodology (where anonymity fits in a red team op).
- `_WORKFLOW.md` section 6.7 - document format templates (Format 4, Format 5).
- `APPLICATIONS/` - web application attacks (out of scope here).
- `INFRASTRUCTURE/` - infrastructure attacks (out of scope here).

---

## References

The material in this category draws on publicly available sources:

- Tor Project documentation and specifications.
- I2P documentation.
- EFF Surveillance Self-Defense guides.
- Citizen Lab research publications.
- Academic papers on traffic analysis and de-anonymization.
- Public court records and incident reports (case studies).

Full per-file references are listed in each file's `## References` section.
