# OSINT Fundamentals

OSINT is the discipline of collecting and analyzing information from
publicly available sources to answer a specific question. It is not
"googling someone" - it is a repeatable process with defined scope,
documented sources, and verifiable conclusions.

This file covers the core concepts: what counts as OSINT, how the
collection cycle works, and where the legal boundaries are.

## 1. Overview

Open-source intelligence (OSINT) is intelligence produced from publicly
available information that is collected, exploited, and disseminated in
a timely manner to an appropriate audience for the purpose of addressing
a specific intelligence requirement.

Key properties:

- **Public** - the source is accessible without breaking access controls.
  Paywalled, private, or breached data is NOT OSINT.
- **Legal** - collection does not violate law or terms of service in the
  operator's jurisdiction.
- **Purposeful** - it answers a defined question, not "collect everything".
- **Verifiable** - every claim can be traced back to a source.

## 2. Reconnaissance / Collection

The OSINT collection cycle has six stages:

```text
1. Requirements  -> what question are we answering?
2. Planning      -> which sources can answer it? legal review?
3. Collection    -> gather raw data from those sources
4. Processing    -> normalize, deduplicate, translate
5. Analysis      -> corroborate, link, draw conclusions
6. Dissemination -> report with sources and confidence levels
```

Common source categories:

- **Search engines** - Google, Bing, Yandex, specialized (Shodan, Censys).
- **Social media** - LinkedIn, X/Twitter, Instagram, Telegram, Mastodon.
- **Public records** - corporate registries, court filings, property records.
- **Technical** - WHOIS, DNS, certificate transparency, BGP, GitHub.
- **Media** - news archives, image/video platforms, podcasts.

Operators worth knowing (Google dorks):

```text
site:example.com           restrict to a domain
filetype:pdf               restrict to a file type
intitle:"index of"         find directory listings
inurl:admin                find admin panels
"exact phrase"             exact match
-exclude                   exclude a term
```

## 3. Common Attack Vectors

OSINT is used offensively in several ways:

- **Target profiling** - identify employees, technologies, physical locations.
- **Credential discovery** - leaked credentials in public repos, paste sites.
- **Infrastructure mapping** - subdomains, cloud assets, exposed services.
- **Social engineering pretexting** - build believable cover stories.
- **Phishing infrastructure selection** - find domains the target trusts.
- **Physical security** - badge photos, office layouts, guard schedules.

The attacker's advantage is asymmetry: the target cannot see who is
collecting, how much, or why. The defender's counter is to minimize the
public footprint and monitor for collection patterns.

## 4. Exploitation Recipes

### Recipe 1 - Google dork for exposed documents

```text
site:target.com filetype:pdf (confidential OR internal OR "do not distribute")
site:target.com filetype:xlsx (password OR credentials OR "api key")
```

### Recipe 2 - Subdomain enumeration via certificate transparency

```text
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Recipe 3 - GitHub secret search

```text
"target.com" password
"target.com" api_key
org:target-org "BEGIN RSA PRIVATE KEY"
```

### Recipe 4 - Employee enumeration via LinkedIn (manual)

Search: `site:linkedin.com/in "Target Corp" ("engineer" OR "admin" OR "security")`
Record: name, role, tenure, technologies mentioned, public email pattern.

## 5. Post-Exploitation

After OSINT collection, the operator has a profile. Post-exploitation
in OSINT terms means turning the profile into action:

- **Credential stuffing** - try leaked creds against exposed login pages.
- **Password spraying** - pattern-derived passwords against known accounts.
- **Pretexted outreach** - phishing or vishing using collected context.
- **Physical intrusion** - badge cloning, tailgating, social engineering.
- **Supply chain mapping** - identify third parties to pivot through.

**Warning:** every step past "collection" crosses from OSINT into active
testing. It requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce OSINT exposure by:

- **Minimizing public footprint** - remove unnecessary metadata from
  documents, photos, and code.
- **Employee awareness** - train staff on what not to post (badges,
  screens, org charts).
- **Domain hygiene** - monitor certificate transparency, take down
  dangling DNS records.
- **Code hygiene** - pre-commit secret scanning, no `.env` in public repos.
- **Social media policy** - clear rules on posting about work.
- **Privacy reviews** - audit what a search for the company reveals.

## 7. Detection Controls

Detecting OSINT collection is hard because it looks like normal browsing.
Signals that help:

- **Honeytokens** - fake documents/accounts that only an OSINT collector
  would find. Access triggers an alert.
- **Search analytics** - monitor for unusual searches of the company name,
  executive names, or internal document titles.
- **Certificate transparency monitoring** - alert on new subdomains that
  should not exist.
- **GitHub monitoring** - alert on new public repos mentioning the org.
- **Paste site monitoring** - watch for leaked credentials.
- **LinkedIn scraping detection** - rate-limit and anomaly detection.

## 8. Verification

Verification is the difference between intelligence and gossip.

- **Corroborate** - at least two independent sources for every claim.
- **Date everything** - a 2019 fact may be false in 2026.
- **Trace to primary** - cite the original source, not a summary.
- **Record confidence** - high / medium / low, with reasons.
- **Document negative results** - "we found nothing" is a finding.

Every claim in the final report must be reproducible by another analyst
using the same sources.

## 9. Pentest and Red Team Application

In an authorized engagement, OSINT feeds the recon phase:

- **Scope validation** - confirm the client's asset inventory.
- **Attack surface discovery** - find assets the client forgot (shadow IT).
- **Pretexting** - build believable phishing and vishing scenarios.
- **Credential discovery** - leaked creds in public sources.
- **Physical** - office locations, guard schedules, badge designs.

Rules for engagements:

- OSINT collection is passive and legal; active testing requires the SOW.
- Document every source - the client will ask "how did you find this?".
- Do not collect more than the engagement requires (data minimization).
- Report sensitive findings privately, not in the final deck.

## 10. Legal and Ethical Notes

- **Jurisdiction matters** - GDPR (EU), CCPA (California), and similar
  laws restrict collection about individuals. Know your local law.
- **Terms of service** - scraping may violate platform ToS even if data
  is public. This is a contract issue, not a criminal one, but it matters.
- **Consent** - for people search, the subject's consent is often required
  in professional contexts.
- **No breached data** - data from leaks is NOT OSINT. Using it may be
  a crime in your jurisdiction.
- **No doxxing** - publishing information that exposes an individual to
  harm is unethical and often illegal.
- **Reporting** - if you find a vulnerability during OSINT, report it
  responsibly (see SECURITY.md).

## 11. Production Notes

- **Tooling** - Maltego for link analysis, Shodan/Censys for infrastructure,
  SpiderFoot for automation, theHarvester for email/domain recon.
- **Automation boundaries** - automate collection, not judgment. Analysis
  is human work.
- **Storage** - encrypt collected data at rest; delete when the engagement
  ends.
- **Reproducibility** - save the exact queries and timestamps, not just
  the results.

## 12. References

- OSINT Framework - https://osintframework.com/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- NIST SP 800-53 (Privacy controls) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Google Search Operators - https://support.google.com/websearch/answer/2466433
