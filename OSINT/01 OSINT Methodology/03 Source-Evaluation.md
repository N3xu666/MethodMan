# Source Evaluation

Every OSINT finding rests on a source. A weak source produces a weak
finding, no matter how confident the analyst feels. Source evaluation is
the discipline of deciding how much to trust a source before using it.

This file covers source types, evaluation criteria, bias detection, and
the scoring method used to rank sources in a collection plan.

## 1. Overview

A source is evaluated on four axes:

- **Reliability** - has this source been accurate in the past?
- **Relevance** - does it actually answer the requirement?
- **Freshness** - when was it last updated or verified?
- **Accessibility** - can the finding be reproduced by another analyst?

No source is perfect. The goal is not "trust everything" or "trust
nothing" - it is to assign each finding a confidence level that reflects
the strength of its sources.

## 2. Reconnaissance / Collection

### Source categories

- **Primary** - the original record (court filing, corporate registry,
  the target's own website).
- **Secondary** - a report or summary of a primary source (news article,
  blog post, aggregator).
- **Tertiary** - a compilation of secondary sources (Wikipedia, directories).

Prefer primary sources. Secondary and tertiary sources are useful for
discovery, but findings should trace back to a primary record where one
exists.

### Evaluation workflow

```text
1. Identify the source type (primary / secondary / tertiary)
2. Check the author or publisher (who made this claim?)
3. Check the date (when was it published or updated?)
4. Check the evidence (does the source cite its own sources?)
5. Cross-check (at least one independent source for the same claim)
6. Score (A-F, see section 3)
7. Record the score in the collection log
```

## 3. Common Attack Vectors

Source evaluation fails in predictable ways. In an offensive context,
these failures are exploited by adversaries who plant or manipulate
sources:

- **Source poisoning** - an adversary publishes a false record on a site
  the analyst trusts (a fake LinkedIn profile, a fake company registry
  entry, a fake GitHub repo).
- **Citation laundering** - a false claim is repeated across secondary
  sources until it looks well-established, though every path leads back
  to one primary fabrication.
- **Stale authority** - an authoritative source from 2018 is used to
  describe 2026 without checking for updates.
- **Recency bias** - the newest source is trusted over more reliable but
  older sources.
- **Confirmation bias** - sources that agree with the analyst's hypothesis
  are ranked higher than sources that disagree, without justification.

Each failure has a control: source provenance checks, independent
corroboration, date verification, and a written evaluation that another
analyst can review.

## 4. Exploitation Recipes

### Recipe 1 - Admiralty Code (NATO source reliability)

The Admiralty Code ranks sources A-F and information 1-6:

```text
Source reliability:
  A - Completely reliable
  B - Usually reliable
  C - Fairly reliable
  D - Not usually reliable
  E - Unreliable
  F - Cannot be judged

Information credibility:
  1 - Confirmed by other sources
  2 - Probably true
  3 - Possibly true
  4 - Doubtful
  5 - Improbable
  6 - Cannot be judged
```

A finding is written as `B2` (usually reliable source, probably true) or
`A1` (completely reliable, confirmed). This forces the analyst to separate
source quality from information quality.

### Recipe 2 - Provenance check for a social media profile

```text
1. Account creation date (older = usually more genuine)
2. Posting history (consistent topic and style?)
3. Connections (real people who vouch for the account?)
4. Cross-platform (does the same identity exist on other platforms?)
5. Reverse image search (profile photo reused from elsewhere?)
6. Metadata (EXIF if a photo, if available)
```

### Recipe 3 - Independent corroboration

```text
Claim: "Company X uses AWS us-east-1"

Source 1: DNS CNAME pointing to amazonaws.com (primary technical)
Source 2: Job posting mentioning "AWS us-east-1" (secondary, weak)
Source 3: Shodan banner showing AWS IP range (primary technical)

Confidence: high (2 independent primary sources agree)
```

## 5. Post-Exploitation

After a finding is published, the source evaluation is reviewed:

- **Was the score accurate?** - did the source live up to its rating?
- **Was corroboration sufficient?** - would a different analyst reach
  the same conclusion?
- **Were any sources manipulated?** - did an adversary plant data?

Failures become case studies. The team's source evaluation improves with
each documented miss.

## 6. Preventive Controls

Defenders cannot see how they are being evaluated, but they can shape the
sources an analyst will find:

- **Publish accurate, up-to-date information** - the target's own website
  is usually the strongest primary source. Make it easy to verify facts.
- **Monitor impersonation** - fake social media profiles and cloned
  websites harm the target's reputation and mislead analysts.
- **Maintain authoritative registries** - company registries, official
  documentation, and public records that are easy to cite.
- **Respond to false information** - a documented correction is itself
  a primary source for future analysts.

## 7. Detection Controls

Detection focuses on signs that sources about the organization are being
manipulated or that analysts are actively collecting:

- **Impersonation monitoring** - new accounts claiming to be the org or
  its employees.
- **Domain typosquatting** - fake domains mimicking the org's.
- **Search trend analysis** - spikes in searches for executives, product
  names, or internal projects.
- **Honeytoken documents** - fake documents that appear in searches only
  if the attacker is actively collecting.

## 8. Verification

Before a finding is published, verify:

- Every claim has a source with an Admiralty Code score.
- At least one independent source corroborates each critical claim.
- The source's date is checked and, if old, that recency is noted.
- The evaluation can be reproduced by another analyst using the same
  sources.
- Negative results are recorded (what was searched, what was not found).

## 9. Pentest and Red Team Application

In an engagement:

- **Source scoring protects the report** - a client is more likely to
  accept findings backed by `A1` sources than `C3` sources.
- **Poisoning awareness** - in a red team context, assume the adversary
  may plant sources to mislead you. Cross-check everything.
- **Pretext material** - source evaluation determines which public facts
  are safe to use in a pretext (verified, stable, non-controversial).
- **Reporting** - source scores go in the appendix, so the client can
  audit the intelligence themselves.

Rules:

- Do not cite a secondary source when the primary is available.
- Do not publish a finding with a lower score than its weakest source.
- Do not hide negative results to make a finding look stronger.

## 10. Legal and Ethical Notes

- **Attribution** - naming a person or organization as a source can have
  legal consequences. Evaluate whether the source would want to be cited.
- **Privacy** - evaluating a source's reliability may involve collecting
  information about them. Data minimization applies.
- **Manipulation** - publishing an evaluation of a source can itself
  influence that source. Be aware of the feedback loop.
- **Retraction** - if a finding is later shown false, retract it publicly
  and document the evaluation failure.

## 11. Production Notes

- **Templates** - keep an Admiralty Code template and a provenance checklist
  in the team's knowledge base.
- **Tooling** - source scoring is manual; tools can assist with dates and
  cross-checking but not with judgment.
- **Review cadence** - re-evaluate sources on a schedule (quarterly for
  active engagements, annually for standing sources).
- **Retention** - source evaluations are part of the finding and are
  retained under the same rules as the finding itself.

## 12. References

- Admiralty Code (NATO AJP-2.1) - https://www.nato.int/cps/en/natohq/topics_111830.htm
- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- OSINT Framework - https://osintframework.com/
- First Draft's Verification Handbook - https://firstdraftnews.org/long-form-article/verification-handbook/
