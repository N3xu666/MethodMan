# Social Media Fundamentals

## 1. Overview

Social media is the largest source of open-source information about individuals, organizations, and their relationships. For OSINT, it provides direct access to what people say, where they are, who they know, and what they do. For red teams, social media is a primary vector for pretexting, phishing, and physical access planning. For blue teams, it is a source of exposure (employees posting credentials, internal screenshots, or location data).

This file covers the fundamentals of social media collection: the major platforms and their data models, the types of information they expose, and the general approach to systematic collection. Platform-specific techniques are covered in the follow-up files.

Relevance: social media data is high-volume, high-noise, and highly perishable. A structured approach is necessary to avoid drowning in irrelevant posts while missing critical details.

## 2. Reconnaissance and Collection

Social media collection is fully passive when done through public views, search engines, and cached copies. It becomes semi-active when using platform APIs or automated scrapers.

The core data model across platforms is similar:

- **Profile data.** Name, handle, bio, profile picture, cover image, join date, location (if provided), website links.
- **Content.** Posts, comments, reactions, media (images, video), live streams.
- **Network.** Followers, following, groups, pages, friends (where applicable).
- **Metadata.** Timestamps, geolocation tags (EXIF in images, check-ins), device type, edit history (rarely exposed).

General collection approach:

- **Define the target.** An individual, an organization, or a topic.
- **Map the platforms.** People use multiple platforms; each platform reveals a different facet.
- **Collect in layers.** Start with the profile, then the content, then the network.
- **Preserve evidence.** Screenshots, timestamps, and URLs for each fact.

```bash
# Example: Search across public social media via search engines
# (Fully passive; search engine indexes the public profile pages)
"site:linkedin.com/in \"Example Corp\""
"site:twitter.com \"Example Corp\""
"site:instagram.com \"Example Corp\""
```

Expected output (conceptual):

```text
# A search engine query returns public profile pages where "Example Corp" appears.
# Each result is a candidate profile to inspect.
```

## 3. Common Attack Vectors

In social media OSINT, "attack vectors" are the ways information from social platforms can be used.

- **Pretexting.** Details from posts (job title, projects, travel plans) allow a convincing social engineering pretext.
- **Credential exposure.** Employees occasionally post screenshots that include API keys, internal URLs, or email addresses.
- **Organizational mapping.** LinkedIn reveals the org chart; employee posts reveal team structure and internal tool names.
- **Physical security.** Location check-ins, photos with visible landmarks, and travel posts reveal physical security gaps.
- **Supply chain.** Employees of vendors and partners post about the target organization, revealing integrations and dependencies.

## 4. Exploitation Recipes

For OSINT, exploitation means extracting and confirming a fact from social media data.

**Recipe 1 - Reconstruct the org chart from LinkedIn.** Search for the organization name; filter by current employees; sort by seniority or start date. This reveals the reporting structure and recent hires.

**Recipe 2 - Discover internal tooling from posts.** Engineers post about "our new CI pipeline" or "our Kubernetes migration". Each post is a hint about the internal stack.

**Recipe 3 - Timeline of an individual.** Combine posts from multiple platforms to build a timeline of the target's activity. Travel dates, project milestones, and personal events are all timeline entries.

**Recipe 4 - Image geolocation.** Photos posted publicly can be geolocated by landmarks, storefronts, signs, or by EXIF data if present.

**Recipe 5 - Relationship mapping.** Followers and following lists reveal who a person interacts with. This is a strong signal for trust relationships.

## 5. Post-Exploitation

After collection, the data must be organized for analysis and reporting.

- **Structured storage.** For each entity (person, org, platform), store a record with the profile URL, timestamps, and extracted facts.
- **Graph building.** Nodes are people, organizations, and events; edges are "works for", "knows", "attended". This graph is the core of the analysis.
- **Verification.** Cross-reference facts from multiple platforms. A fact stated on one platform and confirmed on another is much stronger than a fact from one source.
- **Archiving.** Social media content can be deleted. Save local copies of critical posts and images with timestamps.

## 6. Preventive Controls

Defenders can reduce the exposure their people create on social media.

- **Acceptable use policies.** Clear guidance on what employees can post about their work, tools, and travel.
- **Screenshot hygiene.** Train employees to blur or remove sensitive information from screenshots before posting.
- **Privacy settings.** Employees should review the privacy settings of their personal profiles.
- **Corporate social media monitoring.** Track what is being said about the organization, and respond to accidental disclosures.

## 7. Detection Controls

- **Monitoring for employee disclosures.** Tools that alert on public posts from employees that mention internal systems or credentials.
- **Brand and impersonation monitoring.** Detect fake profiles that impersonate the organization or key employees.
- **Data loss prevention (DLP).** Prevent posting of sensitive documents to social platforms.

## 8. Verification

- **Profile verification.** Confirm that a profile belongs to the target by checking the organization's website, email format, and mutual connections.
- **Post verification.** A single post can be misleading. Look for consistency across posts and platforms.
- **Image verification.** Reverse image search for reused photos, checking that the photo is not from a stock site or another person.
- **Timeline verification.** Cross-reference dates and events.

## 9. Pentest and Red Team Application

- **Phase 1 - Target profile.** Define the target individuals and organizations.
- **Phase 2 - Profile mapping.** Collect profiles across platforms.
- **Phase 3 - Content analysis.** Extract facts, usernames, technologies, and relationships.
- **Phase 4 - Pretexting preparation.** Use collected information to prepare a pretext for social engineering.
- **Phase 5 - Reporting.** Document the exposure, with actionable recommendations.

Red team note: social media data is often the highest-signal source for pretexting. The most effective pretexts use details from multiple platforms, not just one.

## 10. Legal and Ethical Notes

- **Public data is generally lawful to collect.** But terms of service of each platform still apply.
- **Do not create fake profiles to access private content.** Fake profiles violate platform terms and may violate law in some jurisdictions.
- **Do not collect personal data beyond scope.** GDPR and similar laws restrict processing of personal data. Only collect what is necessary for the engagement.
- **Do not engage with the target on social media** unless authorized. Any interaction (like, comment, message) is a signal that an investigation is underway.

## 11. Production Notes

- **Use a dedicated OSINT workstation.** Do not use personal accounts to browse target profiles; this leaves a trace.
- **Document sources.** For every fact, record the URL and the timestamp.
- **Store evidence in a structured format.** JSON or CSV with consistent fields.
- **Use archiving services.** Archive.org and similar can preserve deleted content.

## 12. References

- LinkedIn - https://www.linkedin.com/
- X (Twitter) - https://x.com/
- Instagram - https://www.instagram.com/
- Facebook - https://www.facebook.com/
- Reddit - https://www.reddit.com/
- GDPR Overview - https://gdpr.eu/
- Archive.org - https://archive.org/