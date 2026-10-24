# Verification and Documentation

Verification turns a collection of claims into a finding. Documentation
makes that finding reproducible, auditable, and defensible. Without both,
OSINT is opinion.

This file covers the verification workflow, the documentation standard,
and the evidence handling rules that apply before, during, and after
collection.

## 1. Overview

A verified finding has four properties:

- **Sourced** - every claim traces to a logged source.
- **Corroborated** - critical claims have at least two independent sources.
- **Dated** - every fact carries the date it was collected or last verified.
- **Reproducible** - another analyst can rerun the collection and reach
  the same conclusion.

Documentation is the artifact that proves these properties. It is not
optional, and it is not written after the fact.

## 2. Reconnaissance / Collection

### Verification workflow

```text
1. Collect raw data and log the source
2. Normalize (dates, names, addresses)
3. Cross-check each claim against an independent source
4. Resolve contradictions (re-check both sources)
5. Assign confidence (high / medium / low, with reasons)
6. Document the finding with sources and confidence
7. Archive raw data with a retention period
```

### Documentation artifacts

- **Collection log** - one line per collection action, with timestamp,
  source, query, and operator.
- **Evidence file** - raw output (HTML, screenshots, API responses),
  stored with a hash so it can be verified later.
- **Finding record** - the verified conclusion, with sources and
  confidence level.
- **Chain of custody** - who collected, who analyzed, who reviewed.

## 3. Common Attack Vectors

Weak verification and documentation are exploited in several ways:

- **Fabricated evidence** - a screenshot or quote is edited to support a
  false claim. Without a hash and a chain of custody, the fabrication is
  hard to disprove.
- **Cherry-picking** - only sources that support the hypothesis are
  documented; contradictory sources are omitted.
- **Retroactive documentation** - the report is written from memory after
  the collection, and the sources no longer match the claims.
- **Silent revision** - a finding is edited without a change log, so the
  client cannot tell which version was delivered.
- **Broken provenance** - a secondary source is cited instead of the
  primary, and the primary turns out to say something different.

Each risk has a control: hashes, change logs, mandatory corroboration,
and a reviewer who checks the documentation against the raw evidence.

## 4. Exploitation Recipes

### Recipe 1 - Evidence hash and timestamp

```text
$ curl -s "https://target.example/about" -o evidence-001.html
$ sha256sum evidence-001.html
  a3f5...  evidence-001.html
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
  2026-10-24T12:34:56Z
```

Store the hash, timestamp, and URL in the collection log. Any later claim
about the page can be verified against the archived copy.

### Recipe 2 - Contradiction resolution

```text
Claim A: "Company X is headquartered in Berlin" (source: news article, 2024)
Claim B: "Company X is headquartered in Munich" (source: company registry, 2026)

Resolution:
- Registry (B) is the primary source and is more recent -> higher weight
- News article (A) may be outdated (company moved) or wrong
- Document the contradiction and the resolution in the finding record
```

### Recipe 3 - Change log entry

```text
finding: F-014
version: 2
date: 2026-10-24T13:00Z
change: corrected headquarters city from Berlin to Munich
reason: company registry updated 2026-09-01
reviewer: analyst-2
```

## 5. Post-Exploitation

After delivery, verification and documentation continue:

- **Client review** - the client may challenge a finding. The evidence
  file answers the challenge directly.
- **Retraction** - if a finding is later shown false, issue a correction
  with the same documentation standard as the original.
- **Retention** - raw evidence is kept for the agreed retention period,
  then destroyed. The finding record is kept indefinitely.
- **Lessons** - document which verification steps worked and which did
  not, so the next engagement is stronger.

## 6. Preventive Controls

On the defensive side, organizations can make verification easier for
legitimate analysts and harder for attackers:

- **Publish authoritative records** - registries, official pages, and
  documented changes make primary-source verification cheap.
- **Use signed communications** - PGP or DKIM-signed emails allow a
  recipient to verify the sender.
- **Maintain a change log** - public-facing pages should note when they
  were last updated.
- **Provide a verification channel** - a documented way for outsiders to
  confirm a claim, e.g. a security.txt file or a press contact.

## 7. Detection Controls

Detection of verification failures and evidence manipulation:

- **Honeytokens with unique canaries** - a document that says "Berlin"
  in one place and "Munich" in another reveals which version an attacker
  is using.
- **Access logs on evidence stores** - unusual reads or downloads of
  archived evidence indicate tampering or leakage.
- **Hash mismatch alerts** - if a stored evidence file's hash no longer
  matches the log, it has been modified.
- **Change log monitoring** - findings that are edited without a change
  log entry are a red flag.

## 8. Verification

Verification of the verification process itself:

- Every finding has a documented source, a date, and a confidence level.
- Every critical claim has two independent sources.
- Every evidence file has a hash and a timestamp.
- Every change to a finding has a change log entry.
- A reviewer has compared the documentation against the raw evidence.
- Negative results are documented, not omitted.

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Evidence is the report** - a pentest finding without evidence is
  an opinion. Verification and documentation make it defensible.
- **OSINT findings feed other phases** - a verified OSINT finding becomes
  input to phishing, infrastructure recon, or physical assessment.
- **Client trust** - a documented methodology, with sources and
  confidence levels, is the difference between a professional report
  and a guess.
- **Post-engagement** - evidence handling rules apply until the
  retention period ends, not just until delivery.

Rules:

- Never edit raw evidence. Copy it, then work on the copy.
- Never cite a source you have not opened.
- Never publish a finding with a lower confidence level than its weakest
  critical source.

## 10. Legal and Ethical Notes

- **Evidence handling** - in some jurisdictions, collected evidence may
  become discoverable in litigation. Follow the same rules a forensic
  examiner would.
- **Personal data** - evidence files often contain personal data. Apply
  data minimization and retention limits.
- **Retraction** - a public retraction is often legally required when a
  finding is shown false. Do not hide a retraction.
- **Copyright** - screenshots and quotes of third-party content may
  require attribution or permission. Document the license.

## 11. Production Notes

- **Templates** - collection log, evidence hash log, finding record,
  change log. All four should be standard.
- **Tooling** - Hunchly or a manual equivalent for web capture, Git for
  change tracking, GPG for evidence signing if needed.
- **Storage** - evidence stored with read-only permissions, access logged,
  encrypted at rest.
- **Retention** - retention defined before collection, enforced
  automatically where possible, documented when a record is destroyed.

## 12. References

- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- First Draft's Verification Handbook - https://firstdraftnews.org/long-form-article/verification-handbook/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- NIST SP 800-86 (Guide to Integrating Forensic Techniques) - https://csrc.nist.gov/pubs/sp/800/86/final
- OSINT Framework - https://osintframework.com/
