# Public Records

Public records are official documents that governments and regulators
make available to the public: corporate registries, court filings,
property records, licensing databases. They are the strongest primary
sources in people search because they are authoritative and (usually)
verifiable.

This file covers the main record types, how to search them per
jurisdiction, and how to handle the legal and ethical constraints that
apply.

## 1. Overview

Public records fall into five broad categories:

- **Corporate** - company registries, filings, directors, shareholders.
- **Judicial** - court cases, judgments, bankruptcy, liens.
- **Property** - ownership, mortgages, deeds, tax assessments.
- **Licensing** - professional licenses, permits, regulatory actions.
- **Vital** - birth, marriage, death (often restricted).

Each category has its own access rules. Some are free and online, some
require a fee, some require a physical visit, some are restricted to
the person themselves.

## 2. Reconnaissance / Collection

### Corporate registries by jurisdiction

```text
US        | SEC EDGAR (public companies) | https://www.sec.gov/edgar
US states | Secretary of State portals    | varies by state
UK        | Companies House              | https://find-and-update.company-information.service.gov.uk
EU        | national registries          | e.g. Handelsregister (DE), RCS (FR)
Azerbaijan| e-taxes.gov.az (tax registry)| https://www.e-taxes.gov.az
Offshore  | ICIJ Offshore Leaks DB       | https://offshoreleaks.icij.org
```

### Court records

```text
US federal | PACER (paid)                 | https://pacer.uscourts.gov
US state   | state court portals          | varies
UK         | Find a Court Judgment        | https://www.gov.uk/find-court-judgment
EU         | e-Justice portal             | https://e-justice.europa.eu
International | ICC, ICJ, arbitration      | direct sites
```

### Property records

```text
US        | county assessor / recorder  | varies by county
UK        | HM Land Registry            | https://www.gov.uk/search-property-information-land-registry
EU        | national cadastre           | varies
```

### Collection workflow

```text
1. Identify the jurisdiction(s) relevant to the target
2. Identify the record type(s) that answer the requirement
3. Check access rules (free / paid / restricted)
4. Query, capture, and log each record with URL, timestamp, hash
5. Cross-reference with other sources for corroboration
```

## 3. Common Attack Vectors

Public records enable several offensive techniques:

- **Corporate structure mapping** - who owns what, who are the directors,
  which shell companies share the same address.
- **Employee verification** - confirming that a person works where they
  claim to work, via filings and licenses.
- **Financial context** - liens, bankruptcies, judgments indicate
  financial pressure, a useful pretext angle.
- **Property targeting** - home ownership records give addresses and
  purchase history.
- **Regulatory history** - fines, enforcement actions, license
  revocations reveal organizational risk.

The attacker's advantage is that these records are official; the target
cannot claim they are fake. The defender's counter is minimization and
corporate hygiene (e.g. using registered agents, not home addresses).

## 4. Exploitation Recipes

### Recipe 1 - Corporate officer search

```text
US: https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany
UK: https://find-and-update.company-information.service.gov.uk/officers
Query: "John Smith" + company name
Result: list of companies where the person is an officer
Pivot: for each company, check filings for address, co-directors
```

### Recipe 2 - Court record search

```text
US: PACER (federal, paid) + state portal (free/paid)
UK: https://www.gov.uk/find-court-judgment
Query: full name + jurisdiction
Result: list of cases with case number, parties, judgment
Pivot: check co-parties, attorneys, and referenced companies
```

### Recipe 3 - Property record search

```text
US: county assessor + recorder (varies)
UK: https://www.gov.uk/search-property-information-land-registry
Query: full name or address
Result: ownership, purchase date, mortgage history
Pivot: cross-check with voter records (where public)
```

### Recipe 4 - Offshore leak cross-reference

```text
ICIJ Offshore Leaks DB: https://offshoreleaks.icj.org
Query: full name or company name
Result: offshore entity, jurisdiction, linked persons
Note: database is a curated leak; use only as a lead, verify each
finding against primary records.
```

## 5. Post-Exploitation

After a public record is found, post-exploitation uses it:

- **Pretext** - corporate roles, litigation history, and property
  ownership make a pretext far more convincing.
- **Phishing** - knowing which executive is under financial or legal
  pressure shapes the message.
- **Physical** - property records give home addresses (subject to
  privacy law in some jurisdictions).
- **Supply chain** - corporate filings reveal subsidiaries and partners
  to pivot through.

**Warning:** every step past "record retrieval" is active engagement
and requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce public-record exposure by:

- **Registered agents** - use a registered agent instead of a home
  address for corporate filings.
- **Corporate structure hygiene** - minimize the number of legal
  entities and directors whose names appear in public registries.
- **Privacy requests** - where law allows, request redaction of personal
  data from public records.
- **Property privacy** - in some jurisdictions, property can be held
  through a trust or LLC (subject to disclosure rules).
- **Awareness** - executives should know what their name reveals in
  public records.

## 7. Detection Controls

Detection of public-record collection is limited because the records
are designed to be queried. Possible signals:

- **Bulk query patterns** - unusually high query volume against a
  specific registry (if the registry logs and reports).
- **Honeytoken records** - fake corporate officers or fake properties
  inserted where only a collector would query them.
- **Cross-reference anomalies** - a sudden appearance of a company or
  person in multiple unrelated queries.

## 8. Verification

Verification of a public-record finding:

- **Primary source** - the record itself, not a summary or news article.
- **Timestamp** - the record date and the query date.
- **Jurisdiction** - the record is only authoritative in its own
  jurisdiction.
- **Hash** - the captured record (PDF or HTML) is hashed and stored.
- **Corroboration** - a critical claim needs two independent records
  (e.g. corporate registry + court filing).

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Records are primary sources** - a corporate filing is a stronger
  finding than a LinkedIn profile.
- **Minimization** - retrieve only the records the engagement requires.
- **Documentation** - every record has URL, timestamp, and hash.
- **Legal review** - some records (e.g. PACER, certain state portals)
  require payment or registration; the engagement budget covers this.
- **Reporting** - findings are presented in aggregate where possible.

Rules:

- Do not contact the target during passive collection.
- Do not use leaked data (ICIJ leak is a curated public dataset, not
  a raw breach; still, verify each finding).
- Do not publish personal addresses or financial details in the final
  deck unless the SOW explicitly requires it.

## 10. Legal and Ethical Notes

- **Public does not mean unrestricted** - many records are public but
  their use is limited by data-protection law (GDPR, CCPA).
- **Paid access** - PACER and some registries charge fees; using them
  without paying or via unofficial scrapers may violate ToS.
- **Access restrictions** - some records (e.g. certain court filings)
  are sealed; do not attempt to bypass seals.
- **Sensitive categories** - records about minors, victims, and certain
  protected classes are usually restricted.
- **Retention** - delete records when the engagement ends.
- **No doxxing** - publishing addresses or financial details can harm
  an individual. Report only what the engagement requires.

## 11. Production Notes

- **Templates** - record log (type, jurisdiction, URL, timestamp, hash),
  corporate structure diagram template.
- **Tooling** - OpenCorporates (aggregator), ICIJ Offshore Leaks DB,
  SEC EDGAR, Companies House, national registries.
- **Automation limits** - registry scraping is often rate-limited or
  prohibited; manual queries are slower but safer.
- **Cost** - budget for PACER, paid registries, and any official copies.
- **Retention** - records deleted on schedule; findings retained.

## 12. References

- SEC EDGAR - https://www.sec.gov/edgar
- UK Companies House - https://find-and-update.company-information.service.gov.uk
- ICIJ Offshore Leaks Database - https://offshoreleaks.icij.org
- OpenCorporates - https://opencorporates.com
- Berkeley Protocol on Digital Open Source Investigations - https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source-investigations
