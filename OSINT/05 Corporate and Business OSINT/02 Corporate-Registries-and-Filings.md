# Corporate Registries and Filings

## 1. Overview

Corporate registries are the official records of legal entities. They are maintained by government agencies in each jurisdiction and contain the core legal facts about a company: registration number, incorporation date, registered address, directors, and shareholders. Regulatory filings add financial data, ownership disclosures, and material events.

For OSINT, registries are the most authoritative source for corporate facts. Press releases and websites can be outdated or inaccurate; the registry is the legal record. For red teams, registries reveal the corporate structure behind a target, including subsidiaries and holding companies. For blue teams, they are the basis for vendor due diligence and sanctions screening.

This file covers how to use corporate registries and filings systematically: which registries matter, how to search them, and how to interpret the results.

## 2. Reconnaissance and Collection

Corporate registry data is public by design, though some jurisdictions charge for access or require registration.

Key registries by region:

- **United States:** State Secretary of State databases for incorporation; SEC EDGAR for public company filings (10-K, 10-Q, 8-K, proxy statements).
- **United Kingdom:** Companies House (free, comprehensive: incorporation, filings, directors, persons with significant control).
- **European Union:** national registries (e.g. Handelsregister in Germany, Registro Mercantil in Spain); the EU Business Register links them.
- **Global:** OpenCorporates aggregates many national registries into one search interface.

Key filing types in the US (SEC EDGAR):

- **10-K:** annual report (financial statements, risk factors, business description).
- **10-Q:** quarterly report (financial statements).
- **8-K:** current report (material events: executive changes, M&A, bankruptcies).
- **DEF 14A:** proxy statement (executive compensation, board composition).
- **S-1:** registration statement for IPOs.

```bash
# Search SEC EDGAR full-text search for a company name
curl -s "https://efts.sec.gov/LATEST/search-index?q=%22Example%20Corp%22" | jq '.hits.hits[]._source'

# Search OpenCorporates for a company name
curl -s "https://api.opencorporates.com/v0.4/companies/search?q=Example+Corp" | jq '.results.companies[] | {name, company_number, jurisdiction_code}'
```

Expected output (trimmed):

```text
$ curl -s "https://api.opencorporates.com/v0.4/companies/search?q=Example+Corp" | jq '.results.companies[] | {name, company_number, jurisdiction_code}'
{
  "name": "Example Corp",
  "company_number": "12345678",
  "jurisdiction_code": "us_de"
}
{
  "name": "Example Corp Ltd",
  "company_number": "09876543",
  "jurisdiction_code": "gb_eng"
}
```

## 3. Common Attack Vectors

- **Corporate structure mapping.** Parent companies, subsidiaries, and holding companies reveal the full scope of an organization.
- **Director and shareholder pivots.** A director in one company may be a director in many. This reveals networks of related entities.
- **Financial distress signals.** Filings reveal declining revenue, layoffs, and going-concern warnings. Distressed companies are often more vulnerable to fraud.
- **M&A activity.** 8-K filings and proxy statements reveal acquisitions and mergers. These are prime pretexts for BEC.
- **Sanctions and PEP connections.** Ownership disclosures may reveal sanctioned individuals or politically exposed persons behind the company.

## 4. Exploitation Recipes

**Recipe 1 - Build the corporate tree.** Start with the target company. Search for its parent company and subsidiaries in the registry. Follow ownership links as far as they go. The result is a corporate graph.

**Recipe 2 - Identify key directors.** Extract all directors from the registry. Search each director's name in the registry to find other companies they control. This reveals the director's full portfolio.

**Recipe 3 - Detect financial distress.** Read the 10-K risk factors and MD&A. Look for language about liquidity, going concern, and restructuring.

**Recipe 4 - Identify recent M&A.** Search 8-K filings for the last 12 months. Each acquisition or merger is a pretext opportunity.

**Recipe 5 - Sanctions screening.** Cross-reference directors and shareholders with OpenSanctions and OFAC SDN list.

## 5. Post-Exploitation

- **Build a corporate graph.** Nodes are companies and people; edges are "director of", "shareholder of", "subsidiary of".
- **Tag risk.** Financial distress, recent M&A, sanctions connections, and unusual ownership structures are risk flags.
- **Verify with primary sources.** OpenCorporates aggregates; the primary registry is authoritative. When a fact matters, check the primary source.

## 6. Preventive Controls

- **Audit your own registry data.** Ensure the organization's filings are accurate and current.
- **Monitor for impersonation.** A fake company registered with a name similar to yours can be used for fraud.
- **Vendor due diligence.** Check each vendor against the registry and sanctions lists before onboarding.
- **Training.** Teach finance and procurement staff to check corporate registries.

## 7. Detection Controls

- **Registry monitoring.** Subscribe to alerts for new companies registered in your jurisdiction with names similar to yours.
- **Filing monitoring.** Track 8-K filings of vendors and partners for material events.
- **Sanctions list monitoring.** Continuous screening of vendors and partners against sanctions lists.

## 8. Verification

- **Check the primary source.** OpenCorporates aggregates; the primary registry is authoritative.
- **Check the date.** Registry data changes; use current filings.
- **Check the jurisdiction.** The same company name may exist in multiple jurisdictions. The legal entity depends on the jurisdiction.
- **Check the directors.** Cross-reference with LinkedIn and other sources to confirm the people.

## 9. Pentest and Red Team Application

- **Phase 1 - Legal structure.** Map the target's corporate tree from the registry.
- **Phase 2 - Financial picture.** Read the 10-K and recent 8-K filings.
- **Phase 3 - Key people.** Identify directors and executives from filings.
- **Phase 4 - Pretext development.** Use M&A activity, financial distress, and executive changes to build pretexts.
- **Phase 5 - Reporting.** Document the corporate structure and the exposure.

Red team note: corporate registry data is the authoritative foundation for all corporate OSINT. Without it, the picture is incomplete.

## 10. Legal and Ethical Notes

- **Corporate registries are public by design.** Using them for security research is lawful.
- **Personal data in registries is subject to privacy laws.** Directors' home addresses may be protected by GDPR. Do not collect more than necessary.
- **Do not register a fake company.** Creating a company to impersonate another is fraud.
- **Respect API terms of service.** OpenCorporates and SEC EDGAR have rate limits.

## 11. Production Notes

- **Automate collection.** Use the SEC EDGAR API and OpenCorporates API for bulk collection; manual search is fine for targeted queries.
- **Store data in a structured format.** JSON with fields: entity name, jurisdiction, company number, directors, shareholders, source URL.
- **Timestamp everything.** Registry data changes slowly but changes.
- **Verify with primary sources.** Do not rely on a single aggregator.

## 12. References

- SEC EDGAR Full-Text Search - https://efts.sec.gov/LATEST/search-index
- SEC EDGAR Company Search - https://www.sec.gov/edgar/searchedgar/companysearch
- Companies House (UK) - https://find-and-update.company-information.service.gov.uk/
- OpenCorporates - https://opencorporates.com/
- OpenSanctions - https://www.opensanctions.org/
- OFAC Sanctions List - https://sanctionssearch.ofac.treas.gov/
- EU Business Register - https://eubusinessregister.com/