# Supply Chain and Vendor Mapping

## 1. Overview

A supply chain is the network of organizations, people, and processes involved in creating and delivering a product or service. For OSINT, supply chain mapping is the process of identifying a target's vendors, partners, and dependencies from public sources. For red teams, the supply chain is often the weakest link: a small vendor with poor security can provide access to a large customer. For blue teams, supply chain visibility is a core risk management requirement.

This file covers how to identify and map a target's supply chain from public data: procurement records, press releases, partner directories, job postings, and technical fingerprints.

Relevance: modern organizations depend on hundreds of vendors. Most of them are not visible from the outside. OSINT reveals the critical ones: the ones with public contracts, public partnerships, and public technical integrations.

## 2. Reconnaissance and Collection

Supply chain data comes from several public sources:

- **Procurement and tenders.** Government procurement portals (e.g. SAM.gov in the US, TED in the EU) publish awarded contracts. These reveal vendors and contract values.
- **Press releases and announcements.** Partnerships, integrations, and reseller agreements are usually announced publicly.
- **Partner directories.** Many vendors publish a list of partners, resellers, and integrators.
- **Job postings.** Job postings mention specific tools and vendors (e.g. "experience with Salesforce and Workday").
- **Technical fingerprints.** DNS, certificates, and HTTP headers reveal SaaS providers, CDNs, and payment processors.
- **Social media.** Employees mention vendors and tools in posts.

```bash
# Search SAM.gov for contracts awarded to a company
curl -s "https://api.sam.gov/opportunities/v2/search?q=Example+Corp" | jq '.opportunitiesData[] | {title, awardee, amount}'

# Search TED (EU procurement) for a company
curl -s "https://ted.europa.eu/api/v3.0/notices/search?q=Example+Corp" | jq '.notices[] | {title, buyer, value}'
```

Expected output (trimmed):

```text
$ curl -s "https://api.sam.gov/opportunities/v2/search?q=Example+Corp" | jq '.opportunitiesData[] | {title, awardee, amount}'
{
  "title": "IT Support Services",
  "awardee": "Example Corp",
  "amount": 1500000
}
```

## 3. Common Attack Vectors

- **Vendor compromise.** A small vendor with weak security is compromised; the attacker uses the vendor's access to reach the target.
- **Impersonation of a vendor.** A fake vendor sends invoices or emails to the target, using details from public sources.
- **Supply chain injection.** A malicious update or component is inserted into the vendor's product, which is then delivered to the target.
- **Third-party data breach.** A vendor's data breach exposes the target's data.
- **Subdomain takeover via vendor.** A CNAME pointing to a vendor's service that has been deprovisioned can be claimed by an attacker.

## 4. Exploitation Recipes

**Recipe 1 - Map public contracts.** Use SAM.gov, TED, and national procurement portals to find awarded contracts. Extract vendor names, contract values, and dates.

**Recipe 2 - Map press release partnerships.** Search for press releases mentioning the target and "partner", "integration", "reseller". Each announcement is a vendor link.

**Recipe 3 - Map technical integrations.** Use DNS, certificates, and HTTP headers to identify SaaS providers. A CNAME to `target.salesforce.com` reveals Salesforce as a vendor.

**Recipe 4 - Map job postings.** Job postings mention specific tools and vendors. Aggregate across postings to build a technology stack.

**Recipe 5 - Identify the weakest vendor.** Rank vendors by size, security posture, and access to the target. Small vendors with high access are the highest risk.

## 5. Post-Exploitation

- **Build a supply chain graph.** Nodes are organizations; edges are "supplies to", "partners with", "integrates with".
- **Rank by risk.** Small vendors, vendors with poor security, vendors with privileged access.
- **Track changes.** New vendors appear in press releases and job postings; lost vendors disappear.
- **Verify with multiple sources.** A single press release is not enough; cross-reference with job postings, technical fingerprints, and procurement records.

## 6. Preventive Controls

- **Vendor risk assessment.** Assess each vendor's security posture before onboarding and periodically thereafter.
- **Contractual controls.** Require security clauses, breach notification, and right to audit.
- **Least privilege.** Vendors should have only the access they need.
- **Continuous monitoring.** Track vendor security incidents and news.
- **Supply chain visibility.** Maintain an inventory of all vendors and their access.

## 7. Detection Controls

- **Vendor access monitoring.** Track vendor access to internal systems; alert on unusual behavior.
- **Supply chain incident monitoring.** Track security incidents at vendors; alert on breaches that may affect the target.
- **New vendor detection.** Alert on new vendors appearing in job postings or press releases.
- **CNAME monitoring.** Detect CNAMEs pointing to vendor services that no longer exist.

## 8. Verification

- **Check the primary source.** Procurement records are authoritative for contracts. Press releases are secondary.
- **Check the date.** Vendors change; a partnership announced in 2020 may no longer exist.
- **Check the nature of the relationship.** A vendor may be a reseller, an integrator, or a direct supplier. The risk profile differs.
- **Check the technical integration.** A press release may announce a partnership that is not yet implemented.

## 9. Pentest and Red Team Application

- **Phase 1 - Identify public vendors.** Procurement, press releases, partner directories.
- **Phase 2 - Map technical integrations.** DNS, certificates, job postings.
- **Phase 3 - Rank by risk.** Small vendors with high access are top targets.
- **Phase 4 - Test the weakest vendor.** With written authorization, test the vendor's security as a path to the target.
- **Phase 5 - Report.** Document the supply chain and the exposure.

Red team note: supply chain attacks are increasingly common. Identifying the weakest vendor is often the most effective path to the target.

## 10. Legal and Ethical Notes

- **Public procurement data is public by design.** Using it for security research is lawful.
- **Do not test a vendor without authorization.** The vendor is a separate organization; testing it requires its own scope.
- **Respect privacy.** The vendor's employees are individuals; GDPR applies.
- **Do not impersonate a vendor.** Creating fake invoices or emails is fraud.

## 11. Production Notes

- **Maintain a structured vendor inventory.** CSV or JSON with fields: vendor name, relationship, contract value, access, source URL.
- **Automate procurement monitoring.** Use the SAM.gov and TED APIs for continuous collection.
- **Map technical integrations from DNS.** Regular DNS collection reveals changes in SaaS providers.
- **Combine OSINT with internal data.** The OSINT view is external; internal procurement and vendor management data is internal. Combine for full visibility.

## 12. References

- SAM.gov (US procurement) - https://sam.gov/
- TED (EU procurement) - https://ted.europa.eu/
- OpenCorporates - https://opencorporates.com/
- NIST SP 800-161 (Supply Chain Risk Management) - https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final
- CISA ICT Supply Chain Risk Management - https://www.cisa.gov/topics/supply-chain-security