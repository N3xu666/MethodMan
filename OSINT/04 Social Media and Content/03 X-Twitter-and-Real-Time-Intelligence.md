# X (Twitter) and Real-Time Intelligence

## 1. Overview

X (formerly Twitter) is the platform of record for real-time public discourse. For OSINT, it provides immediate access to events as they unfold: breaking news, live incidents, public reactions, and official statements. For red teams, it is a source of operational details (travel, technical discussions, professional grievances). For blue teams, it is a monitoring surface for brand impersonation and threats.

This file covers X-specific collection: searching, filtering, network analysis, and the unique challenges of real-time data (velocity, noise, deletion).

Relevance: X data is the fastest-moving source in OSINT. A fact that is true one minute can be false the next; a post that exists today can be deleted tomorrow. Collection must be fast, timestamped, and archived.

## 2. Reconnaissance and Collection

X collection can be passive (reading public posts) or semi-active (using the API or third-party tools). The platform's search interface and advanced operators are the primary manual tools.

Key search operators:

- `from:username` - posts by a specific user.
- `to:username` - replies to a specific user.
- `@username` - mentions of a user.
- `since:YYYY-MM-DD` and `until:YYYY-MM-DD` - date range.
- `geocode:lat,lon,radius` - posts near a location.
- `filter:links`, `filter:images`, `filter:media` - filter by media type.
- `min_faves:N`, `min_retweets:N` - filter by engagement.
- `lang:xx` - filter by language.
- `#hashtag` - hashtag search.
- `"exact phrase"` - exact phrase.

```bash
# Manual search via X search interface (paste into x.com/search)
"Example Corp" filter:links since:2025-01-01
from:example_ceo until:2025-06-01
geocode:40.7128,-74.0060,10km "Example Corp"
```

Expected output (conceptual):

```text
# Search results are a mix of posts, replies, and retweets.
# Use "Latest" tab to see chronological order; "Top" tab shows engagement-ranked.
```

## 3. Common Attack Vectors

- **Real-time event exploitation.** Breaking news, outages, and incidents are moments of confusion; pretexts based on current events are highly effective.
- **Network mapping.** Retweets, replies, and mentions reveal who follows whom and who interacts with whom. This is a social graph.
- **Deleted content recovery.** Posts can be deleted; caching services, screenshots, and third-party archives can recover them.
- **Geolocation.** Posts with images or check-ins can be geolocated; even without geotags, the content may include landmarks.
- **Account takeover signals.** A compromised account often posts unusual content; the pattern is detectable.

## 4. Exploitation Recipes

**Recipe 1 - Track a breaking event.** Search for the event name; filter by `since:` and `filter:media`. The result is a stream of images, videos, and eyewitness accounts. Cross-reference with official sources.

**Recipe 2 - Map the network around a person.** Use `@username` and `from:username` to identify interactions. A reply graph over time reveals close contacts and conversation clusters.

**Recipe 3 - Recover deleted posts.** Use archive.today, Wayback Machine, or third-party Twitter archive services. Also search for quotes or screenshots of the deleted post.

**Recipe 4 - Geolocate a post.** Look for landmarks, signs, license plates. Use Google Street View and Mapillary to confirm the location.

**Recipe 5 - Detect a compromised account.** Unusual language, sudden topic changes, or unexpected links. Compare with past posts.

## 5. Post-Exploitation

- **Build a timeline.** Each post has a timestamp. Merge posts from multiple accounts into a single chronological timeline.
- **Graph the network.** Nodes are accounts; edges are retweets, replies, and mentions. Use graph tools (Gephi, Neo4j) for analysis.
- **Tag by topic and location.** A post can be tagged with topic (politics, technology, incident) and location (city, landmark).
- **Archive critical content.** X is volatile; posts can be deleted, accounts can be suspended. Archive with timestamps.

## 6. Preventive Controls

- **Employee training.** Basic awareness that public posts are visible and persistent (even after deletion).
- **Screenshot hygiene.** Do not post screenshots of internal tools, customer data, or credentials.
- **Privacy settings.** Review public profile settings; consider limiting who can see posts.
- **Incident response.** Pre-plan for account compromise; MFA and recovery codes.

## 7. Detection Controls

- **Monitoring for brand mentions.** Track mentions of the organization; alert on negative or sensitive mentions.
- **Impersonation detection.** Look for accounts that copy the organization's name, logo, or style.
- **Threat monitoring.** Track keywords related to attacks, leaks, or disclosures about the organization.
- **Account compromise detection.** Alert on unusual posting patterns from corporate accounts.

## 8. Verification

- **Verify the account is official.** Check for a verified badge (blue check); check the account's bio and links. Verified accounts can still be compromised; do not rely solely on verification.
- **Verify the post is authentic.** Check the account's post history; check for consistency with other sources.
- **Verify the image is not manipulated.** Reverse image search; check for editing artifacts.
- **Verify the timestamp.** X shows timestamps in local time; convert to UTC.

## 9. Pentest and Red Team Application

- **Phase 1 - Target profiling.** Identify the target's account(s) and typical activity.
- **Phase 2 - Network mapping.** Map the target's social network (retweets, replies, mentions).
- **Phase 3 - Pretext development.** Use current events, shared interests, or professional context to build a pretext.
- **Phase 4 - Engagement.** Contact the target via DM, reply, or mention. Respect the engagement scope.
- **Phase 5 - Reporting.** Document the exposure and the interaction.

Red team note: X is a public platform; a DM or reply is visible to anyone who looks. Do not contact targets without written authorization.

## 10. Legal and Ethical Notes

- **X terms of service prohibit scraping.** Use manual collection and official APIs where possible. Do not use unauthorised bots or scrapers.
- **Do not create fake accounts.** Fake accounts violate terms and may violate law.
- **Respect privacy.** Public does not mean fair game for unlimited collection; GDPR applies to personal data.
- **Do not interact with the target** unless authorized.

## 11. Production Notes

- **Archive early.** Use archive.today, Wayback Machine, or a local scraper. X content disappears.
- **Timestamp everything.** Use UTC. The local timestamp is not enough.
- **Store as structured data.** JSON with fields: account, timestamp, content, media URLs, engagement counts, URL.
- **Use a dedicated OSINT workstation.** Do not use personal accounts.

## 12. References

- X (Twitter) - https://x.com/
- X Advanced Search - https://x.com/search-advanced
- Archive.today - https://archive.ph/
- Wayback Machine - https://web.archive.org/
- OSINT Framework (Twitter section) - https://osintframework.com/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit