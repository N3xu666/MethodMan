# Collection Planning

Collection planning is the bridge between "we have a question" and "we
have data". A plan defines what to collect, from where, for how long,
and under which legal constraints. Without a plan, OSINT turns into
unfocused browsing.

This file covers the planning process: intelligence requirements,
scope, source selection, legal review, and documentation before
collection starts.

## 1. Overview

A collection plan answers five questions before any data is gathered:

- **What** - the intelligence requirement, stated as a question.
- **Why** - the decision the answer will support.
- **Where** - the sources that can answer it.
- **How** - the tools and techniques allowed.
- **When** - the collection window and the delivery deadline.

A plan that cannot answer all five is not a plan - it is a wish.

## 2. Reconnaissance / Collection

### Step 1 - Requirements

Write the requirement as a question, not a topic:

- Bad: "research the target company".
- Good: "which cloud provider hosts target.com, and is the storage bucket public?"

Each requirement gets a priority (critical / important / nice-to-have)
and an owner.

### Step 2 - Scope

Define what is in scope and what is out:

- Domains, IP ranges, subsidiaries, employee groups.
- Time window (last 12 months vs all history).
- Geographic and jurisdictional limits.

### Step 3 - Source selection

For each requirement, list candidate sources and rank them by:

- **Relevance** - can this source answer the question?
- **Reliability** - has it been accurate before?
- **Access** - public, paywalled, requires registration?
- **Cost** - time, money, legal risk.

### Step 4 - Legal review

Before collection:

- Confirm the jurisdiction of the target and of the operator.
- Confirm that each source's terms of service allow the planned use.
- Confirm that no personal data beyond the requirement will be collected.

## 3. Common Attack Vectors

In an offensive engagement, a weak collection plan creates these risks:

- **Scope creep** - collecting everything "just in case", increasing
  legal exposure and storage cost.
- **Source bias** - relying on one source (e.g. only LinkedIn) and
  missing the real picture.
- **Stale data** - using 2019 records to describe a 2026 organization.
- **Attribution errors** - confusing two people with the same name.
- **Operational security failure** - the target notices the collection
  (e.g. profile views, honeypot documents).

Each risk has a planning control: scope limits, source diversity,
recency checks, identity verification, and OPSEC review.

## 4. Exploitation Recipes

### Recipe 1 - Requirement-to-source matrix

Build a table before collecting:

```text
Requirement                  | Primary source        | Secondary source
-----------------------------|-----------------------|------------------
Cloud provider of target.com | DNS + CNAME history   | Shodan
Employee emails              | LinkedIn + Hunter.io  | GitHub commits
Public S3 buckets            | crt.sh + GrayhatWarfare | Google dorks
```

### Recipe 2 - Collection log entry

Every collection action is logged before it runs:

```text
timestamp: 2026-10-24T12:00Z
requirement: R-03 (public S3 buckets)
source: crt.sh
query: %.target.com
legal: public source, ToS allow automated query at <=1 req/s
operator: analyst-1
```

### Recipe 3 - Stop conditions

Write explicit stop conditions:

- Collected 100 results and still no signal -> escalate, do not expand scope.
- Source returns personal data outside the requirement -> discard immediately.
- Target responds with a legal notice -> stop, escalate to legal.

## 5. Post-Exploitation

After collection, the plan is reviewed against what was actually gathered:

- **Coverage** - which requirements are fully, partially, or not answered?
- **Gaps** - what could not be collected, and why?
- **Quality** - were sources as reliable as expected?
- **Lessons** - what would the next plan do differently?

The review is written down, not remembered. It becomes the input to the
next collection cycle.

## 6. Preventive Controls

Defenders cannot see an OSINT plan, but they can reduce its effectiveness:

- **Minimize public footprint** - remove stale records, old subdomains,
  public documents with metadata.
- **Monitor collection signals** - honeytokens, profile-view analytics,
  unusual search patterns.
- **Employee training** - what not to post (badges, screens, org charts).
- **Legal readiness** - a documented process for responding to OSINT
  collection about the organization.

## 7. Detection Controls

Detection of planned collection is difficult; the strongest signals are:

- **Honeytokens** - fake documents or accounts that only a collector
  would find. Any access is a high-confidence signal.
- **Search analytics** - spikes in searches for executive names, internal
  project names, or document titles.
- **Certificate transparency monitoring** - new subdomains that should
  not exist indicate someone is mapping the estate.
- **GitHub monitoring** - new public repos mentioning the organization.
- **Paste and leak monitoring** - early warning of credential exposure.

## 8. Verification

Before a plan is executed, verify:

- Each requirement maps to at least two independent sources.
- The legal review is signed off by the responsible person.
- Stop conditions are written and understood by the operator.
- The collection log template exists and is ready.

After collection, verify:

- Every finding traces to a logged source.
- Every claim has a confidence level.
- Negative results are documented.

## 9. Pentest and Red Team Application

In an authorized engagement, the collection plan is a deliverable:

- **Scope agreement** - the plan defines what OSINT will and will not
  collect, protecting both the client and the tester.
- **Pretext material** - the plan identifies which public facts can be
  used in phishing or vishing scenarios.
- **Attack surface input** - the plan feeds the infrastructure recon
  phase (subdomains, cloud assets, exposed services).
- **Reporting** - the plan and its results become an appendix to the
  final report, showing what was found and how.

Rules for engagements:

- Do not collect employee personal data beyond what the SOW allows.
- Do not interact with targets during passive collection.
- Report sensitive findings privately, never in the final deck.

## 10. Legal and Ethical Notes

- **Jurisdiction** - collection about EU residents is governed by GDPR;
  California residents by CCPA. Know both the target's and the operator's
  jurisdiction.
- **Terms of service** - automated scraping may violate a platform's ToS
  even when the data is public. This is a contract risk, not a criminal one,
  but it matters for professional engagements.
- **Consent** - for people search in a professional context, consent is
  often required by company policy even when not by law.
- **Data minimization** - collect only what the requirement needs. Delete
  raw data when the engagement ends.
- **No breached data** - leaked credentials are not OSINT. Using them may
  be a crime in the operator's jurisdiction.

## 11. Production Notes

- **Templates** - keep a requirement template, a source matrix template,
  and a collection log template in the team's knowledge base.
- **Tooling** - the plan is tool-agnostic; tools (Maltego, SpiderFoot,
  theHarvester) implement the plan, they do not replace it.
- **Review cadence** - review the plan at 25%, 50%, and 100% of the
  collection window. Adjust scope only with documented justification.
- **Retention** - define retention before collection: how long raw data
  is kept, who can access it, when it is destroyed.

## 12. References

- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- OSINT Framework - https://osintframework.com/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- NIST SP 800-53 (Privacy controls) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- GDPR official text - https://gdpr-info.eu/
