# Regulatory Landscape

The regulatory landscape is the set of laws, regulations, standards
and contractual obligations that apply to an organization. It is not
static: new regulations appear, existing ones are amended, enforcement
priorities shift and interpretations evolve. A compliance program that
does not track the landscape is managing yesterday's obligations.

## 1. Overview

### Layers of Obligation

- **International** - treaties, cross-border frameworks (GDPR for EU
  residents, Basel III for banking, UN sanctions).
- **National** - country-level laws (HIPAA in the US, DPA 2018 in the
  UK, Federal Data Protection Act in Germany).
- **Regional / state** - sub-national laws (CCPA/CPRA in California,
  state breach notification laws in the US, provincial privacy laws
  in Canada).
- **Sectoral** - industry-specific regulations (PCI DSS for card
  data, FFIEC for US banking, NERC CIP for power grid).
- **Contractual** - obligations imposed by customer, partner or
  insurance contracts (security addenda, DPAs, right-to-audit
  clauses).
- **Standards** - voluntary frameworks adopted as obligations via
  contract or certification (ISO 27001, SOC 2, NIST).

### The Same Obligation, Many Names

The same control can appear under different names in different
regulations. The compliance program must map the underlying
objective, not the label:

- "Access control" (ISO 27001) = "Access Control (AC)" (NIST 800-53)
  = "Logical access controls" (PCI DSS) = "Information access
  restriction" (HIPAA Security Rule).
- "Encryption in transit" appears in PCI DSS 4.1, GDPR Art. 32,
  HIPAA 164.312(e)(1), ISO 27001 A.8.24, NIST 800-53 SC-8.

The mapping layer (see 03 Control Mapping and Frameworks) makes this
manageable. Without it, the organization duplicates work for every
framework.

### Jurisdictional Complexity

An organization operating across jurisdictions faces:

- **Conflicting requirements** - GDPR restricts transfers outside
  the EU; some US laws require disclosure that GDPR prohibits.
- **Different definitions** - "personal data" (GDPR) vs "personally
  identifiable information" (US state laws) vs "protected health
  information" (HIPAA).
- **Different breach notification timelines** - GDPR 72 hours; US
  state laws vary from 30 to 90 days; HIPAA 60 days.
- **Extraterritorial reach** - GDPR applies to non-EU organizations
  that process EU residents' data; CCPA applies to businesses
  serving California residents.

The landscape must be mapped per jurisdiction, not aggregated
globally.

## 2. Where in the Organization

Regulatory tracking is a joint function:

- **Legal / regulatory affairs** - primary owner of interpretation
  and regulator relationships.
- **Compliance officer** - translates obligations into control
  requirements, maintains the obligation inventory.
- **CISO** - assesses technical impact, maps to controls.
- **Privacy officer / DPO** - GDPR, CCPA and similar privacy laws.
- **Business unit leaders** - identify which obligations apply to
  their processes.
- **Internal audit** - verifies that the mapping is accurate and
  up-to-date.

### Regulator Relationships

For regulated sectors (finance, healthcare, energy, telecom), the
regulator relationship is a strategic asset:

- **Examinations** - regulators perform periodic examinations; the
  organization must be prepared.
- **Notifications** - certain events require proactive notification
  (breach, change of control, new product).
- **Guidance** - regulators publish guidance that shapes
  interpretation; track it.
- **Enforcement actions** - peer enforcement actions are lessons and
  early warnings.

An adversarial relationship with the regulator is a failure mode.
Early engagement, transparent reporting and cooperative remediation
produce better outcomes than avoidance.

## 3. Threats and Failure Modes

### Failure Modes of Landscape Tracking

- **Static obligation list** - the inventory was built once and never
  updated. New regulations are missed; amendments are ignored.
- **Regulatory blind spot** - no one tracks regulatory change; the
  organization learns of new obligations only when notified by a
  regulator or auditor.
- **Jurisdiction mismatch** - the organization applies one
  jurisdiction's requirements globally, or misses a jurisdiction it
  operates in.
- **Contract drift** - customer contracts contain security and
  privacy clauses that are not tracked in the compliance program.
- **Sectoral ignorance** - the organization assumes a sector
  regulation does not apply, but the regulation's scope is broader
  than assumed.
- **Version confusion** - the standard has been updated (e.g.
  ISO 27001:2013 to 2022, PCI DSS 3.2.1 to 4.0); the program
  still references the old version.
- **Enforcement blindness** - the organization does not track
  enforcement actions against peers; it learns the regulator's
  priorities only when it is the target.

### Failure Modes of Interpretation

- **Literal-only reading** - the regulation says "shall implement
  access control"; the organization implements a firewall and calls
  it done. Intent matters.
- **Over-interpretation** - the organization reads every guidance
  note as a hard requirement, creating unnecessary work and
  obscuring the real obligations.
- **Regulator shopping** - the organization seeks the interpretation
  it prefers from the most permissive source.
- **Frozen interpretation** - the interpretation is fixed at
  implementation and never revisited as guidance evolves.
- **No legal review** - technical teams interpret the law without
  legal input; the interpretation is plausible but wrong.

### Failure Modes of Response to Change

- **Slow response** - the regulation changes, but the control
  mapping is updated months or years later.
- **No impact assessment** - the change is noted but not analyzed;
  the organization does not know what controls need to change.
- **No stakeholder communication** - the change is known to the
  compliance team but not to the control owners who must act.
- **No evidence of response** - the organization responds but does
  not document the response; the next audit cannot verify it.

## 4. Controls and Implementation

### Building the Obligation Inventory

For each obligation, record:

- **Identifier** - internal ID for cross-referencing.
- **Source** - the law, regulation, standard or contract.
- **Authority** - who enforces it.
- **Jurisdiction** - which countries, regions, sectors it applies to.
- **Scope** - which systems, data, processes, geographies.
- **Requirement summary** - plain-language summary of obligations.
- **Applicability rationale** - why this obligation applies (or
  does not).
- **Penalty** - fines, sanctions, contract termination, personal
  liability.
- **Owner** - named person accountable.
- **Mapped controls** - link to the control framework.
- **Evidence** - how compliance is demonstrated.
- **Review date** - next scheduled review.
- **Change log** - amendments and their dates.

### Regulatory Change Management

A defensible change process:

1. **Monitor** - regulatory tracking services, regulator
   newsletters, industry associations, legal counsel updates.
2. **Triage** - does the change apply to the organization? To which
   jurisdiction, sector, process?
3. **Impact assessment** - which controls, processes, contracts,
   systems are affected?
4. **Plan** - what changes are needed, by when, at what cost?
5. **Implement** - execute the changes, update documentation.
6. **Verify** - confirm the changes work, update evidence.
7. **Document** - record the change, the response and the evidence.

Steps 2-3 must be time-bound (e.g. 10 business days from detection).
Without a time bound, triage becomes backlog.

### Contractual Obligations

Customer and partner contracts often impose obligations stricter
than any law:

- **Security addenda** - specific controls, audit rights,
  notification timelines.
- **DPAs (Data Processing Agreements)** - GDPR Art. 28 obligations,
  sub-processor approval, data location.
- **Right to audit** - the customer can audit the organization;
  evidence must be ready.
- **Insurance requirements** - cyber insurance policies require
  certain controls.

Contractual obligations must be in the inventory with the same
rigor as laws. They are enforceable in contract, not by a
regulator, but the consequence (loss of customer, litigation) can
be larger than a fine.

### Jurisdictional Mapping

For each jurisdiction the organization operates in:

- **List applicable obligations** - laws, regulators, standards.
- **Identify local requirements** - data residency, breach
  notification, language, retention.
- **Identify conflicting obligations** - where local law conflicts
  with another jurisdiction, document the resolution (usually
  local law prevails).
- **Identify the local owner** - a named person accountable for
  local compliance.
- **Review annually** - local law changes; the mapping must be
  updated.

## 5. Tooling

- **Regulatory intelligence** - Thomson Reuters Regulatory
  Intelligence, LexisNexis, Compliance.ai, Ascent, Corlytics.
  Track changes across jurisdictions and sectors.
- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate.
  Obligation inventory, change workflow, impact assessment.
- **Legal research** - Westlaw, LexisNexis, EUR-Lex, national
  regulator websites. Primary source of the actual text.
- **Contract management** - Ironclad, DocuSign CLM, Coupa CLM.
  Contract repository, clause extraction, obligation tracking.
- **Privacy management** - OneTrust Privacy, TrustArc, BigID.
  GDPR, CCPA and similar compliance.
- **Industry associations** - sector-specific compliance
  associations (financial services, healthcare, energy) publish
  guidance and peer practices.
- **Regulator portals** - direct subscriptions to regulator
  publications (SEC, FCA, BaFin, HHS OCR, ICO).

## 6. Verification and Metrics

### Verification of Landscape Tracking

- **Inventory coverage** - percentage of applicable obligations in
  the inventory. Target: 100% of known obligations.
- **Inventory currency** - percentage of obligations reviewed in
  the last 12 months.
- **Change response time** - median time from regulatory change to
  updated inventory and impact assessment. Target: <30 days.
- **Jurisdictional coverage** - percentage of operating
  jurisdictions with a named local owner.
- **Contract coverage** - percentage of contracts with security or
  privacy clauses mapped to the inventory.

### Metrics

- **Obligations by jurisdiction** - distribution across the
  operating footprint.
- **Obligations by severity** - high (criminal, license-loss),
  medium (fine), low (administrative).
- **Open impact assessments** - regulatory changes awaiting
  assessment.
- **Overdue reviews** - obligations past their review date.
- **Contract clause coverage** - percentage of contracts with
  mapped obligations.
- **Peer enforcement actions tracked** - count of relevant
  enforcement actions in the last 12 months.

### Common Verification Steps

1. Sample 10 obligations; verify source, jurisdiction, scope,
   owner, mapped controls, review date.
2. Review the last 3 regulatory changes; verify triage, impact
   assessment, plan, evidence of response.
3. Sample 5 contracts with security or privacy clauses; verify
   mapped to inventory.
4. Verify a named local owner for each operating jurisdiction.

## 7. Anti-Patterns

- **One-time inventory.** The obligation list is built once and
  never updated. This is the single most common compliance failure.
- **Global interpretation.** Applying one jurisdiction's rules
  globally misses local obligations and can conflict with local
  law.
- **Lawyer-only interpretation.** Legal reads the law but does not
  understand the technical impact; security implements but does
  not understand the legal requirement. The two must collaborate.
- **Over-interpretation.** Reading every guidance note as a hard
  requirement creates unnecessary work and hides real obligations.
- **Ignoring enforcement.** Peer enforcement actions are the
  cheapest form of regulatory intelligence; ignoring them means
  learning the regulator's priorities the hard way.
- **Contractual blind spot.** Contracts contain obligations that
  no one has mapped. When the customer audits, the gap is
  discovered.
- **Version drift.** The standard has been updated; the program
  still cites the old version. Auditors notice.
- **Compliance team as sole owner.** The compliance team cannot
  own obligations that require operational execution. Every
  obligation must have an accountable business owner.
- **No regulator relationship.** Treating the regulator as an
  adversary guarantees a worse outcome than early engagement.
- **Change without communication.** A regulatory change is noted
  but not communicated to control owners; nothing changes on the
  ground.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): legal and
  regulatory issues, compliance, investigation types.
- **CISM** - Domain 1 (Information Security Governance): external
  requirements, regulator relationships.
- **CISA** - Domain 1 (Information System Auditing Process):
  regulatory frameworks, audit standards.
- **CRISC** - Domain 1 (Governance): compliance alignment with IT
  risk.
- **ISO 27001 LI/LA** - Clause 4.2 (Understanding the needs and
  expectations of interested parties), Annex A.5.31 (Legal,
  statutory, regulatory and contractual requirements).
- **CIPP/E, CIPT, CIPM** - GDPR, ePrivacy, and privacy regulation.
- **CGEIT** - Regulatory alignment with enterprise IT governance.

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- EU GDPR - Regulation (EU) 2016/679 - https://eur-lex.europa.eu/eli/reg/2016/679/oj
- California Consumer Privacy Act (CCPA) / CPRA - https://oag.ca.gov/privacy/ccpa
- HIPAA - Health Insurance Portability and Accountability Act - https://www.hhs.gov/hipaa/index.html
- PCI Security Standards Council - PCI DSS v4.0 - https://www.pcisecuritystandards.org/
- Sarbanes-Oxley Act (SOX) - https://www.sec.gov/spotlight/sarbanes-oxley.htm
- NIS2 Directive (EU) - https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- DORA (Digital Operational Resilience Act, EU) - https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- SEC Cybersecurity Disclosure Rules - https://www.sec.gov/rules/final/2023/33-11216.pdf
- FFIEC Cybersecurity Assessment Tool - https://www.ffiec.gov/cyberassessmenttool.htm
- NERC CIP Standards - https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx
