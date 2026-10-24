# LinkedIn and Corporate Intelligence

## 1. Overview

LinkedIn is the most valuable public source for organizational intelligence. Unlike other social platforms, its data model is explicitly professional: job titles, employment history, education, skills, and connections. For OSINT and red teaming, LinkedIn provides the org chart, the technology stack (from job postings and employee skills), and the human network needed for pretexting.

This file covers LinkedIn-specific collection: profile enumeration, organizational mapping, job posting analysis, and the ethical boundaries of professional network intelligence.

Relevance: a red team that understands the target's org chart and technology stack can plan a much more targeted phishing campaign, a more effective pretext, or a more realistic physical intrusion. Blue teams use the same data to understand what their employees are exposing publicly.

## 2. Reconnaissance and Collection

LinkedIn collection is mostly passive when using public profile views and search engines, but becomes semi-active when automating with tools or APIs. Note that LinkedIn's terms of service prohibit scraping; use public search engines and manual collection where possible.

Key data dimensions:

- **Profile.** Name, headline, current role, location, profile photo.
- **Employment history.** Past roles, dates, companies, durations.
- **Education.** Schools, degrees, graduation years.
- **Skills and endorsements.** Technical stack, soft skills, languages.
- **Connections.** Number of connections (visible), mutual connections (visible to logged-in users), and occasionally the public list of followers.
- **Activity.** Posts, comments, reactions (visible when public).
- **Job postings.** The organization's open roles, which reveal technology stack and team structure.

```bash
# Google dork for LinkedIn profiles at a target organization
site:linkedin.com/in "Example Corp"

# Google dork for LinkedIn company page
site:linkedin.com/company "Example Corp"

# Google dork for job postings
site:linkedin.com/jobs "Example Corp"
```

Expected output (conceptual):

```text
# Each result is a public LinkedIn page. Open in a private window,
# do not log in with a personal account.
```

## 3. Common Attack Vectors

- **Org chart reconstruction.** Employment history and current roles reveal reporting structure. Seniority can be inferred from titles.
- **Technology stack inference.** Job postings mention specific tools (Kubernetes, Terraform, specific CI/CD). Skills endorsements confirm the stack.
- **Pretexting.** Job titles and recent hires are excellent pretext material ("I'm a new hire in your team, I need access to...").
- **Vendor and partner mapping.** Mutual connections reveal partnerships and vendor relationships.
- **Hiring signals.** Recent hires in security, cloud, or specific teams indicate organizational priorities.

## 4. Exploitation Recipes

**Recipe 1 - Reconstruct the org chart.** Search for the company; filter employees by current role; sort by seniority. Group by department (engineering, sales, finance). This produces a structural map.

**Recipe 2 - Identify the technology stack from job postings.** Search for job postings at the target; extract keywords: cloud provider, CI/CD tool, database, monitoring stack. Each posting is a hint.

**Recipe 3 - Identify recent hires.** Sort employees by start date (LinkedIn shows "Started this month" or "Started 3 months ago"). Recent hires are more likely to be targeted by pretexts.

**Recipe 4 - Locate key individuals.** The CISO, the IT manager, the HR director. These roles are high-value for social engineering.

**Recipe 5 - Map the supply chain.** Mutual connections with employees of known vendors reveal the relationships.

## 5. Post-Exploitation

- **Store the org chart in a graph.** Nodes are people and roles; edges are "reports to", "works with", "previously worked at".
- **Tag each person with risk.** Executives, IT staff, HR, and recent hires are highest risk for social engineering.
- **Cross-reference with other platforms.** A LinkedIn profile that also appears on X (Twitter) or GitHub enriches the picture.
- **Track job postings over time.** New postings reveal growth areas and new technologies.

## 6. Preventive Controls

- **Limit what employees publish.** Job titles and employment history are necessary; detailed project descriptions and internal tool names are not.
- **Screenshot hygiene.** Train employees not to post screenshots of internal tools, Slack channels, or credentials.
- **Review public job postings.** Job postings can leak internal architecture. Consider whether specific tool names are necessary.
- **Employee training.** Basic awareness of what LinkedIn data is public and what it reveals.

## 7. Detection Controls

- **Monitoring for sensitive disclosures.** Alert on public posts from employees that mention internal systems, projects, or credentials.
- **Brand impersonation monitoring.** Detect fake LinkedIn profiles that impersonate the organization or its employees.
- **Phishing simulation.** Use LinkedIn-derived pretexts in authorized phishing simulations to test employee awareness.

## 8. Verification

- **Verify the profile is real.** Cross-check against the organization's website (team page), email format, and mutual connections.
- **Verify employment claims.** Past roles can be confirmed via other public sources (company website, press releases).
- **Verify the profile is current.** People change jobs; a profile may show a role that ended months ago.
- **Do not assume the person is who the profile says.** Impersonation is possible; use multiple sources.

## 9. Pentest and Red Team Application

- **Phase 1 - Target selection.** From the org chart, identify the highest-value individuals (IT, HR, executives, recent hires).
- **Phase 2 - Pretext development.** Use collected details (job title, recent project, recent hire status) to build a pretext.
- **Phase 3 - Social engineering.** Contact the target via email, phone, or other channels. Respect the engagement scope.
- **Phase 4 - Reporting.** Document the exposure, the pretext, and the outcome.

Red team note: LinkedIn pretexts are highly effective but also highly visible. A single message can trigger a security alert. Use sparingly and only with written authorization.

## 10. Legal and Ethical Notes

- **LinkedIn terms of service prohibit automated scraping.** Use public search engines and manual collection where possible. Do not use bots or scrapers against LinkedIn.
- **Do not create fake profiles.** Fake profiles violate LinkedIn terms and may violate law.
- **Do not use personal accounts to browse.** This leaves a trace and may be logged.
- **Collect only what is necessary.** GDPR applies to personal data.
- **Respect the target's boundaries.** Do not contact individuals unless authorized.

## 11. Production Notes

- **Use a dedicated OSINT workstation.** Do not use personal accounts. Log out of LinkedIn before collecting.
- **Screenshot and archive.** LinkedIn profiles change; archive critical evidence with a timestamp.
- **Store data in a structured format.** CSV or JSON with columns: name, role, company, start date, URL, notes.
- **Combine with other sources.** LinkedIn alone is one layer; combine with DNS, certificates, and public documents for a complete picture.

## 12. References

- LinkedIn - https://www.linkedin.com/
- LinkedIn Terms of Service - https://www.linkedin.com/legal/user-agreement
- LinkedIn Privacy Policy - https://www.linkedin.com/legal/privacy-policy
- GDPR Overview - https://gdpr.eu/
- OSINT Framework (LinkedIn section) - https://osintframework.com/