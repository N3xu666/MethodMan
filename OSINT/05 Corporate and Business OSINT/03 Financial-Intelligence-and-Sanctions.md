# Financial Intelligence and Sanctions

## 1. Overview

Financial intelligence is the collection and analysis of public financial data about organizations and individuals. For OSINT, it encompasses annual reports, SEC filings, sanctions lists, politically exposed persons (PEP) databases, and financial news. The goal is to understand the financial position, ownership, and risk profile of an entity.

For red teams, financial distress and recent M&A activity are prime pretexts. For blue teams, sanctions screening and continuous monitoring of vendors and partners are compliance and security requirements. For OSINT analysts, financial data reveals the motive and capability behind an organization's actions.

This file covers the key sources of financial intelligence, how to use them for sanctions screening, and how to build a financial profile of a target.

## 2. Reconnaissance and Collection

Financial intelligence comes from several types of sources:

- **Regulatory filings.** SEC EDGAR (US), Companies House (UK), SEDAR (Canada), and national equivalents. Annual reports (10-K), quarterly reports (10-Q), and material event filings (8-K).
- **Sanctions lists.** OFAC (US), EU Consolidated List, UN Security Council, UK OFSI. These are authoritative and updated frequently.
- **PEP databases.** OpenSanctions, Dow Jones, WorldCheck. These identify politically exposed persons and their associates.
- **Financial news.** Reuters, Bloomberg, financial times, and specialized outlets. Useful for context and recent events.
- **Credit ratings.** S&P, Moody's, Fitch. Ratings indicate financial health and risk.

```bash
# Query OFAC SDN list (download and search locally)
curl -s "https://www.treasury.gov/ofac/downloads/sdn.csv" | grep -i "Example Corp"

# Query OpenSanctions API
curl -s "https://api.opensanctions.org/search/default?q=Example+Corp" -H "Authorization: ApiKey YOUR_API_KEY" | jq '.results'
```

Expected output (trimmed):

```text
$ curl -s "https://api.opensanctions.org/search/default?q=Example+Corp" -H "Authorization: ApiKey YOUR_API_KEY" | jq '.results'
[
  {
    "id": "NK-abc123",
    "caption": "Example Corp",
    "schema": "Company",
    "datasets": ["us_ofac_sdn", "eu_fsf"]
  }
]
```

## 3. Common Attack Vectors

- **Financial distress pretexts.** A company in financial trouble is more likely to accept a fake invoice, a phishing email, or a fraudulent payment request.
- **M&A pretexts.** During an acquisition, employees expect changes, new systems, and new contacts. This is a window for BEC.
- **Sanctions evasion.** Entities under sanctions may attempt to hide ownership or use front companies. Financial intelligence reveals these structures.
- **Executive fraud.** Executive changes (CEO, CFO) are prime pretexts for wire transfer fraud.
- **Vendor fraud.** A vendor in financial distress may be replaced by a fake vendor with the same name.

## 4. Exploitation Recipes

**Recipe 1 - Build a financial profile.** Use SEC filings (10-K, 10-Q) to get revenue, profitability, debt, and cash flow. Combine with credit ratings and financial news.

**Recipe 2 - Screen for sanctions.** Check the company and its directors against OFAC, EU, UN, and UK sanctions lists. Cross-reference with OpenSanctions.

**Recipe 3 - Identify PEP connections.** Use OpenSanctions to identify if any director is a PEP or related to one.

**Recipe 4 - Detect financial distress.** Look for language in 10-K filings about going concern, restructuring, and liquidity. Cross-reference with financial news.

**Recipe 5 - Map recent M&A.** Search 8-K filings for the last 12 months. Each acquisition is a pretext opportunity.

## 5. Post-Exploitation

- **Build a financial risk score.** Combine indicators: sanctions hits, financial distress, recent M&A, executive turnover. A high score means higher risk for fraud.
- **Tag entities.** For each entity (company, person), tag with sanctions status, PEP status, and financial health.
- **Verify with primary sources.** Sanctions lists are authoritative; OpenSanctions aggregates but is not the legal source.
- **Monitor continuously.** Sanctions lists change; financial conditions change. Collection is not one-time.

## 6. Preventive Controls

- **Sanctions screening.** Screen all vendors, partners, and new hires against sanctions lists before onboarding and periodically thereafter.
- **Vendor financial health monitoring.** Use credit ratings and news to detect financial distress in key vendors.
- **Executive change verification.** Verify executive changes via official filings, not just press releases.
- **Wire transfer controls.** Require multi-person approval and out-of-band verification for wire transfers.

## 7. Detection Controls

- **Sanctions list monitoring.** Continuous screening of the vendor database against updated sanctions lists.
- **Financial anomaly detection.** Unusual invoices, new bank accounts, changes in payment instructions.
- **M&A monitoring.** Track 8-K filings of key vendors for acquisitions and mergers.
- **Executive change monitoring.** Alert on new executive appointments in vendors and partners.

## 8. Verification

- **Check the primary source.** OFAC, EU, UN, and UK sanctions lists are authoritative. OpenSanctions is an aggregator.
- **Check the date.** Sanctions lists are updated frequently; use the most recent version.
- **Check the name.** Sanctions lists include aliases; a match on one name may be a false positive if the entity is different.
- **Check the jurisdiction.** Sanctions apply in specific jurisdictions; the same entity may be sanctioned in one but not another.

## 9. Pentest and Red Team Application

- **Phase 1 - Financial profile.** Build from SEC filings and financial news.
- **Phase 2 - Sanctions screening.** Check the target against sanctions lists.
- **Phase 3 - Pretext development.** Use financial distress, M&A, and executive changes to build pretexts.
- **Phase 4 - Reporting.** Document the financial exposure and the pretexts.

Red team note: financial intelligence is powerful for social engineering but also sensitive. Use only within the engagement scope and with written authorization.

## 10. Legal and Ethical Notes

- **Sanctions lists are public by design.** Using them for compliance and security research is lawful.
- **Financial data of public companies is public.** Private company financials are not.
- **Do not use financial intelligence for insider trading.** This is a crime.
- **Respect privacy.** Financial data of individuals is subject to GDPR and similar laws.

## 11. Production Notes

- **Automate sanctions screening.** Use the OpenSanctions API or a commercial provider. Manual screening is error-prone.
- **Store results with timestamps.** Sanctions status changes; a past screening is not proof of current status.
- **Combine multiple sources.** A single source may miss entities; use at least two.
- **Verify with primary sources.** The legal obligation is to check the authoritative list.

## 12. References

- SEC EDGAR - https://www.sec.gov/edgar/
- OFAC Sanctions List - https://sanctionssearch.ofac.treas.gov/
- EU Consolidated List - https://www.eeas.europa.eu/topics/sanctions-policy/consolidated-list_en
- UN Security Council Sanctions - https://www.un.org/securitycouncil/sanctions/information
- UK OFSI Consolidated List - https://www.gov.uk/government/publications/the-uk-sanctions-list
- OpenSanctions - https://www.opensanctions.org/
- OpenCorporates - https://opencorporates.com/