# Patents Trademarks and IP

## 1. Overview

Intellectual property (IP) is a rich source of corporate intelligence. Patents reveal the technology a company is developing, the engineers behind it, and the filing strategy. Trademarks reveal product names and brand expansion plans. Copyrights reveal content assets. For OSINT, IP data provides a forward-looking view of the organization: what it is building, where it is investing, and who is doing the work.

For red teams, patents can reveal internal technology names and architectures. For blue teams, IP monitoring detects trademark infringement and brand impersonation. For OSINT analysts, IP data is a reliable and structured source of corporate strategy.

This file covers the main IP databases, how to search them, and how to use IP data for organizational profiling.

## 2. Reconnaissance and Collection

IP data is public by design. Patents and trademarks are published by national and international offices; the data is searchable via free and commercial tools.

Key databases:

- **Patents:** USPTO (US), EPO (Europe), WIPO (international), Google Patents, Lens.org.
- **Trademarks:** USPTO TESS, EUIPO, WIPO Global Brand Database.
- **Copyrights:** mostly not registered; copyright exists automatically, registration is optional.

Key fields in patent data:

- **Title and abstract:** what the invention does.
- **Inventors:** the engineers behind it.
- **Assignee:** the company that owns the patent.
- **Filing date and priority date:** when the invention was filed.
- **Citations:** patents cited by this patent and patents citing it. This reveals the technology lineage.

```bash
# Search Google Patents via the unofficial API
curl -s "https://patents.google.com/xhr/query?url=q%3DExample%2BCorp" | jq '.results'

# Search USPTO Patent Public Search (requires web interface; the API is at patft.uspto.gov)
curl -s "https://developer.uspto.gov/ibd-api/v1/application/publications?patentAssignee=Example+Corp" | jq '.results'
```

Expected output (trimmed):

```text
$ curl -s "https://developer.uspto.gov/ibd-api/v1/application/publications?patentAssignee=Example+Corp" | jq '.results'
{
  "count": 42,
  "publications": [
    {
      "title": "Method for Secure Data Transmission",
      "inventors": ["John Doe", "Jane Smith"],
      "filingDate": "2023-05-15",
      "assignee": "Example Corp"
    }
  ]
}
```

## 3. Common Attack Vectors

- **Technology stack inference.** Patent titles and abstracts reveal internal technologies, algorithms, and architectures.
- **Engineer identification.** Inventors are named in patents. They are also employees of the assignee. This is a pivot to LinkedIn and other sources.
- **Brand expansion inference.** Trademark filings reveal new product names and planned expansions.
- **IP litigation.** Patent lawsuits reveal disputes and competitors.
- **Trademark infringement.** Fake products and fake websites use similar trademarks; monitoring detects them.

## 4. Exploitation Recipes

**Recipe 1 - Map the technology portfolio.** Search for all patents assigned to the target. Group by technology area (e.g. AI, security, networking). This is the R&D map.

**Recipe 2 - Identify key engineers.** Extract inventors from patents. Cross-reference with LinkedIn. Senior inventors are usually senior engineers or architects.

**Recipe 3 - Track filing activity over time.** Patents filed per year reveal R&D investment trends. A spike indicates a new program.

**Recipe 4 - Detect trademark expansion.** New trademarks filed by the target reveal new products and services before they are announced.

**Recipe 5 - Analyze citations.** Patents citing the target's patents indicate competitors building on the same technology. Patents cited by the target indicate prior art.

## 5. Post-Exploitation

- **Build a technology graph.** Nodes are patents, inventors, and technologies. Edges are "invented by", "cites", "assigned to".
- **Tag by technology area.** Group patents by CPC (Cooperative Patent Classification) code.
- **Cross-reference with LinkedIn.** Inventors and assignees are people and companies; both are pivots.
- **Track over time.** New filings and new trademarks are forward-looking signals.

## 6. Preventive Controls

- **IP strategy review.** Ensure that patent filings do not reveal more than necessary about internal technologies.
- **Trademark monitoring.** Monitor for infringement and brand impersonation.
- **Employee training.** Engineers should be aware that patents are public.
- **Competitive intelligence.** Track competitors' patents as part of the strategy function.

## 7. Detection Controls

- **Trademark monitoring services.** Commercial services scan marketplaces and websites for trademark infringement.
- **Patent landscape monitoring.** Track new patents in relevant CPC classes; alert on competitor activity.
- **Domain monitoring.** Detect domains that use the company's trademarks.
- **Social media monitoring.** Detect accounts that impersonate the brand.

## 8. Verification

- **Check the primary source.** USPTO, EPO, and WIPO are authoritative. Google Patents and Lens.org are aggregators.
- **Check the status.** A patent application may be pending, granted, or abandoned. The status matters.
- **Check the assignee.** Large companies have many subsidiaries; check which entity owns the patent.
- **Check the inventors.** Inventors may have moved to other companies; cross-reference with LinkedIn.

## 9. Pentest and Red Team Application

- **Phase 1 - IP portfolio.** Collect all patents and trademarks for the target.
- **Phase 2 - Technology mapping.** Group by technology and identify key engineers.
- **Phase 3 - Pretext development.** Use technology names and engineer names in pretexts.
- **Phase 4 - Reporting.** Document the IP exposure and the technology map.

Red team note: patent data is highly structured and reliable. It reveals what a company is building years before product announcements.

## 10. Legal and Ethical Notes

- **Patent and trademark data is public by design.** Using it for security research is lawful.
- **Respect inventors' privacy.** Inventors are individuals; GDPR applies.
- **Do not infringe trademarks.** Using a trademark without permission in a commercial context is illegal.
- **Respect terms of service of data providers.** Google Patents and USPTO have usage limits.

## 11. Production Notes

- **Automate collection.** Use the Google Patents and USPTO APIs for bulk collection.
- **Store in a structured format.** CSV or JSON with fields: patent number, title, inventors, assignee, filing date, CPC code, status.
- **Cross-reference with other sources.** Patents alone are one layer; combine with LinkedIn, corporate filings, and press releases.
- **Track changes.** New patents and trademarks are forward-looking signals; monitor continuously.

## 12. References

- Google Patents - https://patents.google.com/
- USPTO Patent Public Search - https://ppubs.uspto.gov/
- EPO Espacenet - https://worldwide.espacenet.com/
- WIPO PATENTSCOPE - https://patentscope.wipo.int/
- Lens.org - https://www.lens.org/
- USPTO TESS (Trademarks) - https://tmsearch.uspto.gov/
- EUIPO - https://euipo.europa.eu/
- WIPO Global Brand Database - https://www3.wipo.int/branddb/en/