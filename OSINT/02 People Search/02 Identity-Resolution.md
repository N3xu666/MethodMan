# Identity Resolution

Identity resolution is the process of deciding whether two pieces of
information refer to the same person. It is the hardest part of people
search: names are not unique, usernames are reused, photos are stolen,
and public records are incomplete or wrong.

This file covers the resolution workflow: how to build an identity graph,
how to test hypotheses, how to handle ambiguity, and how to document a
conclusion that another analyst can review.

## 1. Overview

An identity is not a fact. It is a hypothesis supported by evidence.

The analyst maintains a graph of nodes (identifiers) and edges
(connections). Every edge is a hypothesis:

- "This email belongs to this person" (edge: email-person)
- "This username is used by the same person on two platforms"
  (edge: username-username)
- "This photo appears on both profiles" (edge: photo-photo)

Each edge has a confidence level. A finding is the subgraph where all
critical edges are corroborated.

## 2. Reconnaissance / Collection

### Identifier strength

```text
Strong (near-unique):
  - email address
  - phone number
  - unique username (e.g. jdoe92, not "john")
  - government ID (not usually public)

Medium:
  - full legal name + employer
  - full legal name + city
  - photo (if unique)

Weak (ambiguous):
  - first name + last name alone
  - common username (e.g. "admin", "john")
  - generic job title
```

### Resolution workflow

```text
1. Pick the strongest identifier available
2. Search it and record every result (candidate identities)
3. For each candidate, find one corroborating identifier
4. Reject candidates with contradictions (wrong city, wrong employer)
5. For the surviving candidate, find a second corroborating identifier
6. If two candidates survive, keep searching until one is eliminated
7. Document the graph, the confidence of each edge, and the elimination log
```

## 3. Common Attack Vectors

In an offensive engagement, identity resolution is used to:

- **Target the right person** - phishing the wrong employee wastes effort
  and may tip off the organization.
- **Bypass MFA** - identifying the right person lets the operator target
  their specific phone or email.
- **Physical approach** - knowing which person works at which office,
  on which schedule, enables tailgating.
- **Pretext building** - the more identifiers are resolved, the more
  believable the pretext.

The attacker's advantage is time; identity resolution is slow but
methodical. The defender's counter is to keep identifiers unlinkable
(separate work/personal accounts, no shared photos).

## 4. Exploitation Recipes

### Recipe 1 - Username-to-identity resolution

```text
username: jdoe92
  Step 1: namechk.com -> registered on 12 platforms
  Step 2: GitHub -> 3 repos, one with real name in commits
  Step 3: X/Twitter -> profile photo matches LinkedIn photo (visual check)
  Step 4: Reddit -> posts mention employer (company name in a comment)
  Step 5: LinkedIn -> search real name -> matches employer and role
  Conclusion: jdoe92, GitHub, X, Reddit, LinkedIn all belong to one person
  Confidence: high (4 independent edges, 2 with visual confirmation)
```

### Recipe 2 - Photo-to-identity resolution

```text
photo: profile.jpg
  Step 1: Google Images reverse search -> 3 matches
  Step 2: Yandex reverse search -> 1 match on a blog (older photo)
  Step 3: TinEye -> 0 new matches
  Step 4: Blog post mentions the person's name and employer
  Step 5: Name + employer search -> LinkedIn profile with same photo
  Conclusion: photo, blog, LinkedIn belong to one person
  Confidence: medium (photo match + name match, no independent technical edge)
```

### Recipe 3 - Email-to-identity resolution

```text
email: jane.doe@example.com
  Step 1: Hunter.io -> pattern = first.last@example.com, 4 other emails listed
  Step 2: Have I Been Pwned -> email in 2 breaches (email only)
  Step 3: GitHub search -> commits with this email -> username jdoe92
  Step 4: Username resolution (Recipe 1) -> full identity
  Conclusion: email, GitHub, and LinkedIn belong to one person
  Confidence: high (email-username edge is strong)
```

## 5. Post-Exploitation

After resolution, the operator has a resolved identity. Post-exploitation
uses it:

- **Pretext** - the resolved identity becomes the target of a
  personalized engagement.
- **MFA bypass** - the resolved phone is the target of a SIM-swap or
  push-notification fatigue attack.
- **Physical** - the resolved address and routine become the target
  of a physical approach.
- **Credential attack** - the resolved email is the username in a
  password spraying attack.

**Warning:** every step past "resolution" is active engagement and
requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce the resolvability of their employees by:

- **Account separation** - work and personal accounts should not share
  photos, usernames, or contact information.
- **Photo hygiene** - do not reuse profile photos across work and
  personal accounts.
- **Username hygiene** - do not reuse a unique username across platforms.
- **Email hygiene** - do not use the same email for work and public
  services.
- **Privacy settings** - lock social profiles to connections.

## 7. Detection Controls

Detection of identity resolution is difficult. The strongest signals
are:

- **Profile view anomalies** - spikes in views from new accounts are a
  signal of active collection.
- **Honeytokens** - fake identifiers (a unique email, a fake username)
  used only in specific places. Any appearance of the honeytoken
  reveals the leak channel.
- **Reverse image search alerts** - monitor when a company profile
  photo appears in reverse searches.
- **Password reset anomalies** - an identity under resolution is
  sometimes tested via password reset flows.

## 8. Verification

Verification of an identity resolution finding:

- **Two independent edges** - each critical edge needs two independent
  sources.
- **No contradictions** - a single contradiction (wrong city, wrong
  employer, wrong photo) invalidates the hypothesis until explained.
- **Elimination log** - document why each alternative candidate was
  rejected.
- **Second analyst review** - a reviewer checks the graph and the
  elimination log before the finding is used.

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Resolution is the entry point** - every later phase (phishing,
  vishing, physical) depends on the right identity.
- **Documented elimination** - a report that says "we resolved John Doe"
  must show how the other John Does were eliminated.
- **Minimization** - resolve only the identities the engagement
  requires. Do not build a graph of the whole company.
- **Pretext safety** - a resolved identity with a wrong edge destroys
  the operation. Re-verify before use.

Rules:

- Do not interact with the target during resolution.
- Do not use leaked data.
- Do not publish individual dossiers unless the SOW requires them.

## 10. Legal and Ethical Notes

- **Attribution errors** - the most common harm from people search is
  misidentifying an innocent person. Disambiguation is not optional.
- **GDPR / CCPA** - resolution is processing personal data. Lawful basis
  is required.
- **Data minimization** - resolve only what the requirement needs.
- **Retention** - delete the identity graph when the engagement ends.
- **Consent** - professional identity resolution (recruiting, due
  diligence) usually requires consent under company policy.

## 11. Production Notes

- **Templates** - identity graph template, elimination log template,
  confidence rubric.
- **Tooling** - Maltego for graph work, namechk for username pivots,
  Hunter.io for email patterns, reverse image search engines.
- **Automation limits** - automated resolution produces false positives;
  every match needs manual verification.
- **Review** - a second analyst reviews every high-stakes resolution.
- **Retention** - graphs are deleted on the agreed schedule, not kept
  indefinitely.

## 12. References

- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- OSINT Framework - https://osintframework.com/
- GDPR official text - https://gdpr-info.eu/
- First Draft's Verification Handbook - https://firstdraftnews.org/long-form-article/verification-handbook/
