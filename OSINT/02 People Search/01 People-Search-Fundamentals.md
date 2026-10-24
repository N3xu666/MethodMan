# People Search Fundamentals

People search is the OSINT discipline of resolving an identity from
partial information and connecting it to public records. It is the most
privacy-sensitive subcategory: a wrong attribution can harm an innocent
person, and an over-broad search can violate data-protection law.

This file covers the fundamentals: what people search is, the identity
graph, the main source types, and the ethical boundaries that apply
before any query is run.

## 1. Overview

People search answers questions like:

- Who is this email address registered to?
- Which social accounts belong to this username?
- What is this person's professional history?
- Is this person connected to this organization?

The core object is the **identity graph**: a set of nodes (names, emails,
usernames, phones, photos, addresses) and edges (connections between
them). The analyst's job is to add edges only when they are corroborated.

## 2. Reconnaissance / Collection

### Identity node types

- **Name** - full name, variants, transliterations, maiden names.
- **Email** - personal, professional, aliases.
- **Username** - platform-specific handles, reused across platforms.
- **Phone** - mobile, landline, VoIP.
- **Photo** - profile photos, avatars, reverse-searchable images.
- **Address** - residential, professional, historical.
- **Employer** - current and past, with dates.

### Source categories

- **Social platforms** - LinkedIn, X/Twitter, Instagram, Facebook,
  Telegram, Mastodon, GitHub.
- **Public records** - corporate registries, court filings, property
  records, voter records (where public).
- **Data brokers** - aggregators that sell compiled profiles (legal in
  some jurisdictions, not in others).
- **Professional** - conference talks, published papers, patents.
- **Leaked data** - NOT OSINT. Excluded from this methodology.

### Search order

```text
1. Start with the strongest identifier (email, phone, unique username)
2. Pivot to weaker identifiers (name, employer)
3. Corroborate each pivot with an independent source
4. Record every pivot in the collection log
```

## 3. Common Attack Vectors

In an offensive engagement, people search supports:

- **Pretexting** - building a believable cover story from public facts.
- **Phishing targeting** - identifying which employees are most likely
  to click, based on role and public activity.
- **Credential discovery** - emails and usernames are the first step to
  password spraying.
- **Physical access** - home address, commute pattern, gym membership.
- **Social engineering** - knowing a target's interests makes a vishing
  call far more convincing.

The attacker's advantage is that people search is passive: the target
cannot tell they are being researched. The defender's counter is to
minimize the public footprint and to monitor for signs of collection.

## 4. Exploitation Recipes

### Recipe 1 - Email to identity pivot

```text
email: jane.doe@example.com
  -> Hunter.io: pattern = first.last@example.com (confirmed)
  -> Have I Been Pwned: 2 breaches (email only, no passwords)
  -> GitHub search: commits with this email in author field
  -> Gravatar: profile photo + linked accounts
```

### Recipe 2 - Username pivot

```text
username: jdoe92
  -> namechk.com: registered on 14 platforms
  -> GitHub: 3 repos, 1 with real name in commits
  -> X/Twitter: profile photo matches LinkedIn photo
  -> Reddit: posts in /r/netsec, mentions employer
```

### Recipe 3 - Reverse image search

```text
photo: profile.jpg
  -> Google Images: 3 matches, one on a personal blog
  -> Yandex: 1 match on a cached LinkedIn profile (older photo)
  -> TinEye: no additional matches
  -> Metadata: EXIF stripped (likely re-encoded)
```

## 5. Post-Exploitation

After a profile is built, the operator has a target package. Post-
exploitation in people search means using it:

- **Phishing** - a personalized email referencing real facts is far more
  effective than a generic one.
- **Vishing** - a phone call with the right context (employer, role,
  recent conference) bypasses suspicion.
- **Physical** - home address and routine enable tailgating or direct
  approach.
- **Credential attacks** - usernames feed password spraying.

**Warning:** every step past "profile building" is active engagement
and requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce people-search exposure by:

- **Data minimization** - employees should not post home address, phone,
  or live location.
- **Privacy settings** - social profiles should be locked to connections.
- **Professional separation** - work and personal accounts should be
  distinct, with no cross-linking.
- **Opt-out from data brokers** - many jurisdictions allow removal
  requests; a documented process helps.
- **Awareness training** - employees should know what makes them a
  high-value target.

## 7. Detection Controls

Detection of people search is difficult. The strongest signals are:

- **Profile view analytics** - LinkedIn and similar platforms show who
  viewed a profile. Sudden spikes from unknown accounts are a signal.
- **Honeytokens** - fake profiles with unique details; any interaction
  indicates collection.
- **Email canaries** - unique email addresses used only in specific
  places; any unsolicited contact reveals the leak.
- **Search trend analysis** - spikes in searches for specific employees.

## 8. Verification

Verification of a people-search finding:

- **Disambiguation** - two people with the same name must be separated
  by at least two independent identifiers (email, employer, location).
- **Corroboration** - each edge in the identity graph needs two
  independent sources.
- **Recency** - a 2018 employer is not proof of 2026 employment.
- **Documentation** - every node and edge is logged with source and date.

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Scope** - the SOW must define which employees may be researched and
  for what purpose.
- **Minimization** - collect only what the engagement requires. Do not
  build a full profile if a partial one answers the question.
- **Pretext material** - use only verified facts; a wrong fact in a
  pretext destroys the operation.
- **Reporting** - present findings in aggregate (e.g. "12 employees are
  discoverable via LinkedIn") rather than individual dossiers, unless
  the SOW explicitly requires individual detail.

Rules:

- Do not contact the target during passive collection.
- Do not use leaked data, ever.
- Do not store personal data longer than the engagement requires.

## 10. Legal and Ethical Notes

- **GDPR / CCPA** - people search about EU or California residents is
  regulated. Lawful basis is required even for public data.
- **Consent** - professional people search (e.g. for recruiting) usually
  requires consent under company policy.
- **Data minimization** - collect only what answers the requirement.
  Delete raw data when the engagement ends.
- **No doxxing** - publishing information that exposes a person to harm
  is unethical and often illegal.
- **No leaked data** - using breached data is a crime in most
  jurisdictions.
- **Attribution risk** - a wrong attribution can harm an innocent person.
  Disambiguate before publishing.

## 11. Production Notes

- **Templates** - identity graph template, source log template, consent
  checklist.
- **Tooling** - Maltego for graph work, namechk for username enumeration,
  Hunter.io for email patterns, reverse image search engines.
- **Tool limits** - automated tools produce false positives; every
  automated match must be manually verified.
- **Retention** - personal data retention is defined before collection
  and enforced automatically.
- **Review** - a second analyst reviews the identity graph before it is
  used in a pretext or report.

## 12. References

- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- OSINT Framework - https://osintframework.com/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- GDPR official text - https://gdpr-info.eu/
- NIST SP 800-53 (Privacy controls) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
