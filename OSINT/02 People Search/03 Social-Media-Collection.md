# Social Media Collection

Social media is where people volunteer the most information about
themselves. For OSINT it is both the richest source and the most
sensitive: posts, photos, check-ins, and connections form a detailed
picture of a person's life, often without their awareness.

This file covers platform-specific collection: which platforms matter,
what each exposes, how to collect without alerting the target, and how
to document what was found.

## 1. Overview

Social media collection is not "scrape everything". It is a targeted
process:

- **Platform selection** - which platforms does the target actually use?
- **Surface mapping** - what does each platform expose publicly vs to
  connections?
- **Collection method** - manual browsing, API, or archived data?
- **Documentation** - what was collected, when, and from where?

The goal is a defensible finding, not a comprehensive dossier.

## 2. Reconnaissance / Collection

### Platform quick reference

```text
Platform    | Public surface                          | Notes
------------|-----------------------------------------|----------------------------
LinkedIn    | Name, role, employer, education, skills | Profile views visible to owner
X/Twitter   | Posts, followers, likes, DMs (closed)   | Search is public; rate limited
Instagram   | Posts, stories (24h), profile photo     | Private accounts require follow
Facebook    | Posts, friends (if public), photos      | Most profiles are friends-only
GitHub      | Repos, commits, email in git log        | Email exposure is common
Reddit      | Posts, comments, subreddit history      | Pseudonymous; linkage via writing style
Telegram    | Channels public; groups semi-public     | Search via tgstat, telemetr
Mastodon    | Federated; instance-specific visibility | Search across instances
```

### Collection workflow

```text
1. Enumerate platforms the target is likely on (from prior identifiers)
2. For each platform, check what is public without logging in
3. Log in only if the engagement authorizes it and the platform ToS allows
4. Record each collected item with URL, timestamp, and screenshot hash
5. Do not interact (no likes, follows, or DMs) unless authorized
```

## 3. Common Attack Vectors

In an offensive engagement, social media collection enables:

- **Pretext building** - a believable cover story uses real interests,
  recent events, and professional context.
- **Phishing personalization** - a message referencing a recent post is
  far more likely to be clicked.
- **Credential discovery** - posts sometimes leak API keys, tokens, or
  internal URLs (especially on GitHub).
- **Physical targeting** - check-ins and geotagged photos reveal routine.
- **Organizational mapping** - who works with whom, who reports to whom,
  who is likely to have privileged access.

The attacker's advantage is that social media is designed for sharing.
The defender's counter is awareness: what not to post, and how to limit
audience.

## 4. Exploitation Recipes

### Recipe 1 - GitHub email harvesting

```text
$ git log --format='%ae %an' --all | sort -u
  jane.doe@example.com Jane Doe
  jdoe@personal.example  jdoe
$ curl -s "https://api.github.com/users/jdoe92/events/public" | jq -r '.[].actor.login'
```

The email in git log is often the corporate email; the personal email
sometimes appears in commits from a personal machine.

### Recipe 2 - X/Twitter advanced search

```text
from:jdoe92 since:2026-01-01 until:2026-10-01
from:jdoe92 "conference" OR "speaking"
from:jdoe92 filter:links
geocode:40.7128,-74.0060,5km
```

### Recipe 3 - Instagram geolocation

```text
1. Public profile -> posts with location tags
2. Google reverse image search on each photo -> other posts, blogs
3. Check the background of photos: signage, landmarks, license plates
4. Cross-reference with check-ins on other platforms
5. Build a routine map: home area, workplace, gym, regular cafes
```

### Recipe 4 - Preserving evidence

```text
$ curl -s "https://twitter.com/jdoe92/status/123" -o evidence-042.html
$ sha256sum evidence-042.html
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
```

Store the URL, hash, and timestamp. Social media posts disappear; the
evidence must survive.

## 5. Post-Exploitation

After collection, the operator has a social profile. Post-exploitation
uses it:

- **Phishing** - personalized emails referencing real posts.
- **Vishing** - phone calls with correct context (recent conference,
  recent job change).
- **Physical** - routine map from geotagged posts.
- **Credential attacks** - leaked API keys, tokens, internal URLs from
  GitHub posts.
- **Social engineering of connections** - approaching the target's
  network first.

**Warning:** every step past "collection" is active engagement and
requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce social media exposure by:

- **Audience management** - posts visible only to known connections.
- **Location hygiene** - disable geotagging; do not check in to home
  or workplace.
- **Photo hygiene** - no badges, screens, whiteboards, or documents in
  the background.
- **Account separation** - work and personal accounts distinct.
- **Employee training** - what not to post (ongoing travel, org charts,
  internal tools).
- **Regular review** - quarterly check of what a stranger can find.

## 7. Detection Controls

Detection of social media collection:

- **Profile view analytics** - LinkedIn and similar platforms show who
  viewed a profile. Sudden spikes are a signal.
- **Honeytokens** - fake posts with unique details; any interaction
  reveals the collector.
- **Email canaries** - unique emails used only on specific platforms;
  any unsolicited contact reveals the leak.
- **Follower anomalies** - sudden follows from unknown accounts before
  a phishing campaign.

## 8. Verification

Verification of a social media finding:

- **Screenshot + hash** - every item is captured and hashed.
- **Timestamp** - the collection time is recorded; posts change.
- **Cross-platform check** - the same fact should appear on at least
  two platforms if it is critical.
- **No interaction** - collection must be passive; any interaction
  (like, follow, DM) invalidates the "passive" claim.

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Collection is passive** - no likes, follows, or DMs during passive
  phase. Active engagement requires a separate authorization.
- **Minimization** - collect only what the engagement requires.
- **Documentation** - every item has URL, timestamp, and hash, so the
  finding can be defended.
- **Reporting** - aggregate findings (e.g. "40% of employees have public
  LinkedIn profiles listing internal tools") rather than individual
  dossiers, unless the SOW requires detail.

Rules:

- Do not create fake accounts to view private content unless the SOW
  explicitly authorizes it (and the platform ToS allows it - usually not).
- Do not use leaked data.
- Do not store personal data beyond the engagement.

## 10. Legal and Ethical Notes

- **Platform ToS** - automated scraping usually violates ToS even when
  the data is public. Manual browsing is generally allowed.
- **GDPR / CCPA** - collecting personal data is processing. Lawful basis
  is required.
- **Data minimization** - collect only what answers the requirement.
- **No doxxing** - publishing information that exposes a person to harm
  is unethical and often illegal.
- **No fake accounts** - creating fake accounts to bypass privacy
  settings is a common line that most engagements should not cross.
- **Consent** - professional people search usually requires consent
  under company policy.

## 11. Production Notes

- **Templates** - collection log, evidence log, platform checklist.
- **Tooling** - manual browsing, Hunchly for capture, Twitter advanced
  search, GitHub API, tgstat/telemetr for Telegram.
- **Automation limits** - automated scraping is fragile and often
  violates ToS. Manual collection with good documentation is more
  defensible.
- **Retention** - personal data retention is defined before collection
  and enforced automatically.
- **Review** - a second analyst reviews the collection before it is
  used in a pretext or report.

## 12. References

- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- OSINT Framework - https://osintframework.com/
- GDPR official text - https://gdpr-info.eu/
- X/Twitter advanced search - https://help.x.com/en/using-x/x-advanced-search
