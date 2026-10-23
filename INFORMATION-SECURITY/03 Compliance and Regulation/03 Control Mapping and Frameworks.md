# Control Mapping and Frameworks

Control mapping is the discipline of connecting obligations to
controls to evidence. Without mapping, every new regulation forces a
fresh implementation; with mapping, a new regulation is usually a
mapping exercise, not an engineering project. This file covers the
mapping methodology, the major frameworks and the common pitfalls.

## 1. Overview

### What Control Mapping Is

Control mapping is the process of establishing traceable relationships
between three layers:

- **Obligations** - external requirements (laws, regulations,
  standards, contracts).
- **Controls** - internal mechanisms that satisfy the obligations.
- **Evidence** - artifacts that demonstrate the controls are
  operating.

A complete mapping answers, for any obligation: *which controls
satisfy it, who owns them, and how is that demonstrated?* And, for
any control: *which obligations does it satisfy, and is there any
obligation it does not cover?*

### Why Frameworks Exist

Frameworks provide a structured set of controls that have been
vetted by an industry body and accepted by auditors. Using a
framework is efficient because:

- **Coverage** - the framework's controls are designed to cover the
  obligations of its domain.
- **Auditor familiarity** - auditors know the framework; the mapping
  is easier to accept.
- **Common language** - the framework gives a shared vocabulary
  across teams, vendors and regulators.
- **Benchmarking** - the organization can compare itself to peers.

Frameworks are not obligations themselves. Adopting ISO 27001 does
not make the organization compliant with GDPR; it makes the
organization *eligible* to demonstrate GDPR compliance through its
controls.

### The Three Common Mapping Strategies

- **One framework per obligation** - the simplest but most
  redundant. Each obligation is satisfied by a dedicated framework.
  Expensive and prone to duplication.
- **One framework covers all** - adopt one comprehensive framework
  (e.g. NIST 800-53) and map every obligation to it. Elegant but
  requires the framework to genuinely cover all obligations, which
  it rarely does for niche obligations.
- **Common control framework (recommended)** - build an internal
  framework of controls that reflect the organization's actual
  risks, and map both obligations and external frameworks to it.
  One set of controls, many mappings.

## 2. Where in the Organization

Control mapping is a joint responsibility:

- **Compliance / GRC team** - owns the mapping repository, runs the
  mapping process, maintains the crosswalk.
- **Control owners** - the operational roles that execute the
  controls; they confirm the mapping is accurate.
- **Security architecture** - confirms that controls are
  technically sound and appropriate for the risk.
- **Internal audit** - validates the mapping and tests the
  controls.
- **Framework owners** - the people responsible for the
  organization's relationship with each framework (ISO 27001
  manager, SOC 2 manager, PCI DSS compliance lead).
- **Legal** - confirms the mapping correctly interprets the
  obligation.

### The Control Owner

Every control must have a named owner. The owner is accountable
for:

- **Operating the control** - executing it as designed.
- **Producing evidence** - collecting and retaining the artifacts
  that demonstrate operation.
- **Reporting** - reporting control status, gaps and failures.
- **Reviewing the mapping** - confirming the control still
  satisfies the obligation.
- **Responding to failures** - when the control fails, the owner
  leads the response.

An ownerless control is not a control. It is a documentation
artifact.

## 3. Threats and Failure Modes

### Failure Modes of Control Mapping

- **Mapping as spreadsheet** - the mapping exists in a
  spreadsheet that no one updates. The mapping is fiction.
- **One-to-one mapping** - every obligation is mapped to a unique
  control. The organization duplicates work and loses sight of
  shared controls.
- **Framework silos** - each framework (ISO, SOC 2, PCI, NIST) is
  mapped separately, with no crosswalk. Work is done three times.
- **Mapping without owner** - the mapping is done by the compliance
  team without control owner confirmation. The mapping is
  plausible but wrong.
- **Untested mapping** - the control is mapped to the obligation,
  but no one has tested that the control actually satisfies it.
- **Static crosswalk** - the framework is updated (ISO 27001:2013
  to 2022, NIST 800-53 Rev. 4 to Rev. 5), but the crosswalk is
  not.
- **Evidence gap** - the control exists and is mapped, but the
  evidence is not defined; when the auditor asks, no one can
  produce it.
- **Over-mapping** - every control is mapped to every framework
  "just in case". The mapping loses meaning.

### Framework-Specific Failure Modes

- **ISO 27001** - the ISMS exists on paper; the risk assessment is
  not refreshed; the Statement of Applicability (SoA) is not
  updated when controls change.
- **SOC 2** - the trust services criteria are mapped to controls
  that have not been tested; the audit is a documentation
  exercise.
- **PCI DSS** - the CDE (Cardholder Data Environment) scope is
  underestimated; compensating controls are accepted without
  justification.
- **NIST CSF** - the framework is used for maturity assessment but
  not tied to actual controls; the tier rating is self-assessed.
- **HIPAA** - the Security Rule is treated as a checklist; the
  risk analysis is not performed.
- **NIS2 / DORA** - the regulation is new and the mapping has not
  yet been done; the organization assumes existing controls
  satisfy the new obligations.

### Failure Modes of Crosswalk Maintenance

- **No single source of truth** - each framework owner maintains
  their own crosswalk; they disagree.
- **No change log** - when a control changes, no one records the
  impact on the mapping.
- **No version control** - the mapping has no history; when an
  audit finding appears, the mapping cannot be traced to the
  version in effect.
- **No annual review** - the mapping is reviewed when an audit is
  due, not on a regular cycle.

## 4. Controls and Implementation

### Building the Common Control Framework

Step 1. **Define the control library.** A set of controls that
reflect the organization's actual risks. Typically 50-200 controls.
Each control has: ID, description, objective, owner, evidence,
test method.

Step 2. **Map obligations to controls.** For each obligation, list
the controls that satisfy it. Document any obligation that cannot
be satisfied by existing controls; these are gaps requiring new
controls.

Step 3. **Map external frameworks to controls.** For each
framework the organization adopts (ISO 27001, SOC 2, PCI DSS,
NIST CSF, CIS Controls), map the framework's requirements to the
internal controls. Most frameworks will map to 70-90% of the
internal controls; the rest are framework-specific.

Step 4. **Publish the crosswalk.** One document (or GRC
repository) that shows:

- Each obligation and its mapped controls.
- Each control and the obligations/frameworks it satisfies.
- Each framework requirement and its mapped controls.
- Gaps and their planned treatments.

Step 5. **Maintain the crosswalk.** Assign an owner. Review on a
schedule (at least annually). Update when obligations or controls
change. Version the crosswalk.

### The Statement of Applicability (SoA)

The SoA is an ISO 27001 artifact that documents, for each Annex A
control: whether it is applicable, why, and how it is
implemented. The SoA is the ISO-specific instance of the crosswalk.

A well-maintained SoA:

- Lists every Annex A control (93 controls in ISO 27001:2022).
- States applicability or exclusion with justification.
- Maps each applicable control to the internal control that
  implements it.
- References the evidence.
- Is signed by management.
- Is reviewed annually and on change.

### Major Frameworks

**ISO/IEC 27001:2022**

- International standard for Information Security Management
  Systems (ISMS).
- 4 control themes, 93 controls in Annex A.
- Certifiable by an accredited body.
- Requires: risk assessment, SoA, management review, continual
  improvement.
- Best for: organizations seeking an internationally recognized
  certificate, or a comprehensive ISMS framework.

**ISO/IEC 27002:2022**

- Implementation guidance for the ISO 27001 Annex A controls.
- Not certifiable; used with ISO 27001.

**NIST Cybersecurity Framework (CSF) 2.0**

- Voluntary framework, US-origin, globally used.
- 6 functions: Govern, Identify, Protect, Detect, Respond,
  Recover.
- Not certifiable; used for maturity assessment and program
  structure.
- Best for: structuring a security program, communicating with
  the board.

**NIST SP 800-53 Rev. 5**

- Comprehensive control catalog (1000+ controls across 20
  families).
- US federal standard; widely used by other sectors.
- Heavy; usually tailored via a baseline.
- Best for: organizations subject to US federal requirements, or
  needing a very comprehensive control catalog.

**NIST SP 800-171**

- Subset of 800-53 for protecting Controlled Unclassified
  Information (CUI).
- Required for US defense contractors.
- 110 requirements.

**CIS Controls v8**

- 18 prioritized controls, 153 safeguards.
- Implementation groups (IG1, IG2, IG3) by organizational
  maturity.
- Best for: prioritization, especially for mid-size
  organizations.

**SOC 2 (AICPA Trust Services Criteria)**

- Attestation report, not a certification.
- Five trust services criteria: Security (required),
  Availability, Processing Integrity, Confidentiality, Privacy.
- Type I (point-in-time) or Type II (period of time).
- Best for: SaaS vendors, service providers; customer-driven.

**PCI DSS v4.0**

- Payment Card Industry Data Security Standard.
- 12 requirements, ~300 sub-requirements.
- Enforced by contracts with acquirers, not by a regulator.
- Best for: any organization that stores, processes or transmits
  cardholder data.

**HIPAA Security Rule**

- US healthcare regulation.
- Three safeguard categories: Administrative, Physical,
  Technical.
- Risk analysis is a required element.
- Best for: US healthcare covered entities and business
  associates.

**GDPR**

- EU regulation on data protection.
- 99 articles, principles-based.
- Applies to any organization processing EU residents' personal
  data.
- Best for: any organization with EU data subjects.

**NIS2 (EU)**

- Network and Information Security Directive 2.
- Applies to essential and important entities in the EU.
- Expands scope and raises requirements compared to NIS1.
- Best for: EU operators of critical infrastructure and digital
  services.

**DORA (EU)**

- Digital Operational Resilience Act.
- Applies to EU financial entities and their critical ICT
  providers.
- Focus on operational resilience, incident reporting, third-party
  risk.
- Best for: EU financial sector.

### Framework Selection

A practical approach for a mid-size organization:

- **ISO 27001** - for an internationally recognized ISMS and
  comprehensive framework.
- **SOC 2** - if the organization sells to enterprise customers
  who require it.
- **PCI DSS** - if the organization handles card data.
- **NIST CSF** - for program structure and board communication.
- **CIS Controls** - for prioritization and implementation
  sequencing.

The choice of framework is less important than the discipline of
mapping. An organization with a good crosswalk and a mediocre
framework is better off than an organization with a top-tier
framework and no crosswalk.

## 5. Tooling

- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate,
  Vanta, Drata, Secureframe. Obligation inventory, control library,
  crosswalk, evidence.
- **Framework-specific tools** - ISMS.online (ISO 27001), Vanta
  (SOC 2 / ISO), Tugboat Logic (multi-framework), Apptega
  (multi-framework).
- **Control catalogs** - NIST 800-53, CIS Controls, ISO 27001
  Annex A, PCI DSS. Available from the issuing body.
- **Crosswalk repositories** - NIST OLIR (Online Informative
  References), CIS Crosswalk, AICPA mapping documents. Provide
  pre-built mappings between frameworks; use as a starting point,
  not a final answer.
- **Version control** - Git or similar for the mapping document.
  Every change is traceable.
- **Evidence management** - shared drive, Confluence, GRC tool.
  Named evidence per control, retained for the audit period.

## 6. Verification and Metrics

### Verification of the Crosswalk

- **Mapping completeness** - percentage of obligations with at
  least one mapped control. Target: 100%.
- **Control completeness** - percentage of controls with a named
  owner and defined evidence. Target: 100%.
- **Framework coverage** - percentage of framework requirements
  mapped to internal controls. Target: 100% of applicable.
- **Crosswalk currency** - date of last review. Target: within the
  last 12 months.
- **Change log completeness** - percentage of control or framework
  changes reflected in the crosswalk.

### Metrics

- **Controls per obligation** - average number of controls per
  obligation. Low = gaps; very high = duplication.
- **Obligations per control** - average number of obligations per
  control. High = efficient common control framework.
- **Framework reuse** - percentage of internal controls used by
  more than one framework. Target: >50%.
- **Mapping time** - hours from new obligation to mapped controls.
- **Audit findings per framework** - distribution across
  frameworks; concentrated findings indicate a specific mapping
  gap.

### Common Verification Steps

1. Sample 10 obligations; trace each to mapped controls, owner,
   evidence.
2. Sample 10 controls; verify each is mapped to at least one
   obligation and has current evidence.
3. Sample 3 frameworks; verify the framework requirement list is
   covered by the crosswalk.
4. Verify the crosswalk has a version history and a named owner.

## 7. Anti-Patterns

- **Spreadsheet mapping.** The crosswalk lives in a spreadsheet
  that one person maintains. When the person leaves, the mapping
  dies.
- **Framework as goal.** The organization pursues the certificate,
  not the control. The certificate is obtained; the control
  degrades.
- **One framework per obligation.** Duplicated work, inconsistent
  controls, higher cost, no benefit.
- **No crosswalk.** Each framework owner maps independently;
  redundant controls satisfy the same obligation.
- **Mapping without owners.** The compliance team maps controls
  that no one owns; the mapping is a hypothesis, not a fact.
- **Mapping without evidence.** The control is mapped to the
  obligation, but the evidence is undefined; the auditor finds
  the gap.
- **Static crosswalk.** The framework is updated (ISO 27001:2013
  to 2022, NIST CSF 1.1 to 2.0), but the crosswalk is not.
- **Over-mapping.** Every control mapped to every framework "for
  completeness"; the mapping loses meaning and becomes noise.
- **Framework sprawl.** Adopting every framework the organization
  encounters; the team spends more time mapping than improving
  security.
- **No annual review.** The crosswalk is reviewed when an audit is
  scheduled, not on a cycle. Drift is invisible until it is a
  finding.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): compliance
  frameworks, control mapping.
- **CISM** - Domain 1 (Information Security Governance):
  frameworks and standards, control integration.
- **CISA** - Domain 1 (Information System Auditing Process):
  frameworks, control assessment.
- **CRISC** - Domain 1 (Governance): control frameworks
  alignment with IT risk.
- **ISO 27001 LI/LA** - Clauses 4-10, Annex A controls, Statement
  of Applicability.
- **CIPP/E, CIPT, CIPM** - GDPR, privacy frameworks.
- **CGEIT** - Framework alignment with enterprise IT governance.

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 - Information security controls - https://www.iso.org/standard/75652.html
- NIST Cybersecurity Framework 2.0 - https://www.nist.gov/cyberframework
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-171 Rev. 3 - Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/171/r3/final
- NIST OLIR - Online Informative References - https://csrc.nist.gov/projects/olir
- CIS Critical Security Controls v8 - https://www.cisecurity.org/controls
- CIS Controls Crosswalk - https://www.cisecurity.org/controls/cis-controls-list
- AICPA - SOC 2 Trust Services Criteria - https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
- PCI Security Standards Council - PCI DSS v4.0 - https://www.pcisecuritystandards.org/
- HHS - HIPAA Security Rule - https://www.hhs.gov/hipaa/for-professionals/security/index.html
