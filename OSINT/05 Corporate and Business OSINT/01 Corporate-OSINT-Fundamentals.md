# Corporate OSINT Fundamentals

## 1. Overview

Corporate OSINT is the collection and analysis of public information about businesses: their legal structure, ownership, finances, operations, and relationships. For red teams, it reveals the organization's assets, vendors, and potential weak points in the supply chain. For blue teams, it is a monitoring surface for impersonation and fraud. For OSINT analysts, it is the foundation for understanding any organization.

This file covers the fundamentals: what data sources exist, how to structure collection, and how to verify corporate facts.

Relevance: every organization has a legal footprint (registrations, filings) and a public footprint (press releases, job postings, patents). Together they reveal more than either alone.

## 2. Reconnaissance and Collection

Corporate collection spans several data layers:

- **Legal registries.** Company registration number, incorporation date, registered address, directors, shareholders.
- **Regulatory filings.** Annual reports, financial statements, ownership disclosures, sanctions.
- **Press and media.** Announcements, interviews, partnership news.
- **Procurement and contracts.** Public tenders, awarded contracts, vendor lists.
- **Intellectual property.** Patents, trademarks, copyrights.
- **People.** Directors, executives, board members, and their other affiliations.

Key sources by region:

- **US:** SEC EDGAR (filings), OpenCorporates (registries), state Secretary of State sites.
- **UK:** Companies House (registrations, filings, directors).
- **EU:** national business registries (e.g. Handelsregister in Germany), EU Transparency Register (lobbying).
- **Global:** OpenCorporates, Aleph (OpenSanctions), OCCRP Aleph.

```bash
# Search for company filings via SEC EDGAR full-text search
curl -s "https://efts.sec.gov/LATEST/search-index?q=%22Example%20Corp%22&dateRange=custom" | jq '.'

# Search OpenCorporates for a company name
curl -s "https://api.opencorporates.com/v0.4/companies/search?q=Example+Corp" | jq '.results.companies[0]'
```

Expected output (trimmed):

```text
$ curl -s "https://api.opencorporates.com/v0.4/companies/search?q=Example+Corp" | jq '.results.companies[0]'
{
  "name": "Example Corp",
  "company_number": "12345678",
  "jurisdiction_code": "us_de",
  "incorporation_date": "2010-01-15",
  "company_type": "Corporation",
  "current_status": "Active",
  "registered_address": "123 Main St, Wilmington, DE"
}
```

## 3. Common Attack Vectors

- **Impersonation.** Fake invoices, fake suppliers, fake executives - all require corporate knowledge.
- **Supply chain attack.** A public contract or partnership announcement reveals a vendor. The vendor may be a weaker target.
- **Business email compromise (BEC).** Corporate structure and recent M&A activity are prime pretexts.
- **Insider identification.** Directors, executives, and their public affiliations are potential social engineering targets.
- **Sanctions evasion.** Corporate filings may reveal hidden ownership or connections to sanctioned entities.

## 4. Exploitation Recipes

**Recipe 1 - Build a corporate profile.** Start with the legal registry (company number, address, directors). Cross-reference with press releases and filings.

**Recipe 2 - Map ownership.** Shareholders and directors reveal the corporate tree. Follow parent companies and subsidiaries.

**Recipe 3 - Identify recent changes.** Annual filings and press releases reveal new executives, new products, and new markets. Changes are opportunities for pretexts.

**Recipe 4 - Map the supply chain.** Public procurement databases and partner announcements reveal vendors. Each vendor is a potential point of access.

**Recipe 5 - Check sanctions and PEPs.** Search for individuals and companies in sanctions lists and politically exposed persons (PEP) databases.

## 5. Post-Exploitation

- **Build a corporate graph.** Nodes are companies, people, contracts, and events. Edges are ownership, employment, contracts, and partnerships.
- **Tag by risk.** Recent M&A, financial distress, and executive turnover are risk signals.
- **Verify each fact.** Corporate data can be outdated (filings are annual) or inaccurate (self-reported). Cross-reference with multiple sources.

## 6. Preventive Controls

- **Audit public disclosures.** Review what is published about the organization; correct inaccuracies.
- **Monitor for impersonation.** Watch for fake websites, fake invoices, and fake social media profiles using the organization's name.
- **Vendor due diligence.** Check new vendors against corporate registries and sanctions lists.
- **Employee training.** Recognize BEC patterns and verify supplier changes.

## 7. Detection Controls

- **Domain and brand monitoring.** Detect fake domains that look like the organization's.
- **Financial anomaly detection.** Unusual invoices, new bank accounts, changes in payment instructions.
- **Supply chain monitoring.** Track public announcements about the organization's vendors.

## 8. Verification

- **Check the primary source.** SEC EDGAR, Companies House, and OpenCorporates are primary; press releases are secondary.
- **Check the date.** Corporate data changes; use current filings.
- **Check the jurisdiction.** A company registered in Delaware may have operations elsewhere; the legal entity is not the same as the operating company.
- **Cross-reference directors.** A director in one company may be a director in many; this is a key pivot.

## 9. Pentest and Red Team Application

- **Phase 1 - Legal structure.** Identify the legal entities, their registrations, and their directors.
- **Phase 2 - Financial picture.** Use annual reports and filings to understand size, growth, and financial health.
- **Phase 3 - Supply chain.** Map vendors and partners from public procurement and press releases.
- **Phase 4 - People.** Identify executives, directors, and key employees for social engineering.
- **Phase 5 - Reporting.** Document the corporate structure and the exposure.

Red team note: corporate OSINT is a foundation, not a weapon. It makes pretexts more realistic and supply chain attacks more targeted.

## 10. Legal and Ethical Notes

- **Corporate registries are public by design.** Using them for security research is lawful.
- **Personal data in registries (e.g. directors' home addresses) may be protected by GDPR.** Do not collect more than necessary.
- **Do not impersonate the organization.** Creating fake invoices or fake emails is fraud.
- **Respect terms of service of data providers.** OpenCorporates and similar have usage limits.

## 11. Production Notes

- **Store data in a structured format.** CSV or JSON with fields: entity name, jurisdiction, company number, incorporation date, directors, source URL, collection date.
- **Timestamp everything.** Corporate data changes slowly but changes.
- **Verify with primary sources.** Do not rely on Wikipedia or a single aggregator.
- **Use a dedicated OSINT workstation.** Do not use personal accounts for sensitive queries.

## 12. References

- SEC EDGAR - https://www.sec.gov/edgar/
- OpenCorporates - https://opencorporates.com/
- Companies House (UK) - https://find-and-update.company-information.service.gov.uk/
- OCCRP Aleph - https://aleph.occrp.org/
- OpenSanctions - https://www.opensanctions.org/
- EU Transparency Register - https://transparency-register.europa.eu/