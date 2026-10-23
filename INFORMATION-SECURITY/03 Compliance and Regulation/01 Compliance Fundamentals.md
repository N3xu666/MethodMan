# Compliance Fundamentals

Compliance is the state of meeting obligations imposed by external
authorities: laws, regulations, industry standards and contracts. It
is distinct from security (which protects the organization) and from
governance (which directs the organization). An organization can be
compliant and insecure, or secure and non-compliant. The goal is
both, and the discipline is keeping them aligned without confusing
one for the other.

## 1. Overview

### Compliance vs Security vs Governance

- **Governance** - the system by which the organization is directed
  and controlled. Sets objectives, defines authority, assigns
  accountability.
- **Compliance** - the state of meeting external obligations. Answers
  "are we allowed to do this, and can we prove it?"
- **Security** - the state of being protected against threats.
  Answers "are we safe?"

A control can exist for compliance reasons without improving
security (e.g. annual password rotation). A control can improve
security without being required by any regulation (e.g. threat
hunting). The two must be tracked separately, even when they
overlap.

### Why Compliance Exists

- **Legal obligation** - laws require certain controls (GDPR,
  HIPAA, SOX, PCI DSS via contracts).
- **Contractual obligation** - customers, partners and insurers
  require attestations.
- **Market access** - some markets require certification to sell.
- **Trust signal** - certification is a shorthand for "audited by
  someone credible".
- **Liability management** - documented compliance reduces personal
  and corporate liability in the event of an incident.

### The Compliance Paradox

Compliance is necessary but not sufficient for security. A common
failure mode is treating the audit as the goal: controls are
implemented to pass the audit, not to reduce risk. The result is
**compliance theatre** - the appearance of control without the
substance. The discipline is to use compliance as a **floor**, not
a ceiling, and to keep risk-based decisions separate from
audit-driven decisions.

## 2. Where in the Organization

Compliance is a cross-functional function with clear ownership:

- **Compliance officer / CCO** - owns the compliance program,
  interprets obligations, reports to the board.
- **CISO** - owns the security controls that satisfy compliance
  obligations, reports on security risk.
- **Legal** - interprets laws, reviews contracts, manages regulator
  relationships.
- **Internal audit** - provides independent assurance that controls
  work.
- **Control owners** - the operational roles that execute each
  control.
- **Business units** - own the processes that must comply.
- **Board / audit committee** - oversees the compliance program,
  receives reports, approves remediation budgets.

### The Three Lines Model (revisited)

- **First line** - operational management. Owns and executes
  controls.
- **Second line** - compliance and risk functions. Set policy,
  monitor, advise.
- **Third line** - internal audit. Independent assurance.

Compliance sits in the **second line**. It must not also be the
third line (self-audit is not assurance), and it must not be only
the first line (operations cannot interpret the law).

## 3. Threats and Failure Modes

### Failure Modes of Compliance Programs

- **Compliance theatre** - controls exist to pass an audit, not to
  reduce risk. The audit passes, the risk remains.
- **Framework sprawl** - the organization adopts every framework it
  encounters (ISO, NIST, CIS, SOC 2, PCI, HIPAA), maps each
  separately, and burns out the team on redundant work.
- **Control duplication** - the same objective is tracked as three
  different controls under three different frameworks, with no
  single source of truth.
- **Scope creep** - the compliance scope grows to cover systems
  that are not actually subject to the obligation, diluting
  effort.
- **Evidence decay** - evidence is collected for the audit and then
  discarded; the next audit rebuilds from scratch.
- **Audit-driven engineering** - technical teams optimize for the
  audit checklist instead of the threat model.
- **Regulator blind spot** - the organization does not track
  regulatory change and discovers a new obligation only when
  notified.
- **Certification as endpoint** - the certificate is framed as
  the goal, not the baseline; post-certification drift goes
  unnoticed.

### Failure Modes of Compliance Operations

- **Manual evidence collection** - screenshots and spreadsheets
  rebuilt every cycle; high cost, high error rate.
- **Stale control descriptions** - the control document describes
  a process that no longer matches reality.
- **Unclear ownership** - a control has no named owner; when it
  fails, no one is accountable.
- **Audit without follow-up** - findings are logged, not
  remediated; the next audit repeats the same findings.
- **Regulator relationship as adversarial** - the organization
  hides from the regulator, then is surprised by enforcement.
- **Contract drift** - customer contracts include security clauses
  that are not tracked in the compliance program.

## 4. Controls and Implementation

### Building a Compliance Program

A defensible compliance program has seven components:

1. **Obligation inventory** - what laws, regulations, standards
   and contracts apply? Who is the owner of each?
2. **Scope definition** - which systems, processes and geographies
   are in scope for each obligation?
3. **Control mapping** - which controls satisfy which obligations?
   One control can satisfy multiple obligations; that is the point.
4. **Ownership** - every control has a named owner and a defined
   evidence requirement.
5. **Evidence management** - how is compliance demonstrated?
   Automated where possible.
6. **Monitoring** - continuous control monitoring, not just
   annual audit prep.
7. **Reporting** - who receives what, at what cadence, with what
   decisions required.

### Obligation Inventory

For each obligation, record:

- **Source** - the law, regulation, standard or contract.
- **Authority** - who enforces it (regulator, auditor, customer).
- **Scope** - what it applies to (systems, data, geographies,
  processes).
- **Requirement summary** - the actual obligations in plain
  language.
- **Penalty** - fines, sanctions, contract termination, personal
  liability.
- **Owner** - the named person accountable for compliance.
- **Review date** - when the obligation is next reviewed.

The inventory is the foundation; without it, compliance is
guesswork.

### Control Mapping

Control mapping is the discipline of connecting obligations to
controls to evidence:

```
Obligation -> Control -> Evidence -> Owner -> Review
```

Key principles:

- **One control, many obligations** - map once, satisfy many.
- **One obligation, many controls** - defense in depth.
- **Evidence is defined at mapping time** - if you cannot define
  the evidence, the control is not operational.
- **Owner is a person** - not a team, not a department.
- **Review is scheduled** - at least annually.

### The Common Control Framework

The efficient approach is to build an internal control framework
that maps to all external obligations:

- Define a set of controls that address the organization's actual
  risks.
- Map each external obligation to the internal controls.
- Maintain one set of evidence per control.
- When a new obligation appears, map it to existing controls first;
  add new controls only if the gap is real.

This avoids duplicating controls across frameworks and gives the
organization a single source of truth.

## 5. Tooling

- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate,
  Vanta, Drata, Secureframe. Obligation inventory, control mapping,
  evidence collection, audit workflow.
- **Compliance automation** - continuous control monitoring via API
  integrations (cloud, identity, endpoint). Reduces manual evidence.
- **Policy management** - PolicyTech, Confluence, Git-backed policy
  repos. Version control, review cycle, acknowledgment tracking.
- **Evidence repositories** - SharePoint, Confluence, S3 with
  immutability. Named evidence per control, retained per obligation.
- **Regulatory tracking** - Thomson Reuters, LexisNexis, Compliance.ai,
  regulator newsletters. Change monitoring for the obligation
  inventory.
- **Audit management** - AuditBoard, TeamMate, Workiva. Audit plan,
  findings, remediation tracking.
- **Control testing** - Drata, Vanta, Tugboat Logic. Automated
  control tests with evidence artifacts.

## 6. Verification and Metrics

### Verification of the Compliance Program

- **Obligation coverage** - percentage of obligations in the
  inventory with a named owner and mapped controls. Target: 100%.
- **Control coverage** - percentage of controls with current
  evidence and a named owner. Target: 100% for in-scope controls.
- **Evidence freshness** - percentage of evidence collected within
  the required period.
- **Audit findings** - open findings by severity, age, owner.
- **Remediation timeliness** - percentage of findings closed by
  target date.
- **Certification currency** - certifications are valid and in
  scope.
- **Regulatory change response** - time from regulatory change to
  updated inventory and control mapping.

### Metrics of the Compliance Program

- **Compliance cost** - total cost of compliance as percentage of
  revenue or IT budget.
- **Controls per obligation** - average number of controls per
  obligation. Too many = complexity; too few = gaps.
- **Evidence automation rate** - percentage of evidence collected
  automatically vs manually.
- **Audit cycle time** - days from audit start to report.
- **Repeat findings** - percentage of findings that repeat from
  the previous cycle. Target: <10%.
- **Training completion** - percentage of in-scope staff with
  current compliance training.

### Common Verification Steps

1. Sample 10 obligations; verify inventory entry, owner, mapped
   controls, evidence.
2. Sample 10 controls; verify owner, evidence freshness, test
   result.
3. Trace 3 audit findings to remediation evidence and closure.
4. Review the last regulatory change; verify inventory and control
   mapping were updated.

## 7. Anti-Patterns

- **Audit as goal.** Passing the audit is not the point; managing
  the obligation is. An audit is a check, not an outcome.
- **Framework sprawl.** Adopting every framework produces
  redundant work and no additional assurance. Choose the minimum
  set that covers the obligations.
- **Compliance as security.** Being compliant is not the same as
  being secure. Both must be measured separately.
- **Evidence theatre.** Collecting evidence that no one reviews
  is the same as no evidence.
- **Control duplication.** The same objective tracked as three
  controls under three frameworks multiplies cost without
  improving assurance.
- **Static inventory.** Obligations change; an inventory that is
  not reviewed annually is fiction.
- **Ownerless controls.** A control without a named owner is no
  one's responsibility.
- **Regulator avoidance.** Hiding from the regulator guarantees a
  worse outcome than engaging early.
- **Certification as endpoint.** The certificate marks the
  baseline, not the finish line.
- **Compliance team as scapegoat.** When the breach happens, the
  compliance team is blamed for the controls that operations did
  not execute. Ownership must be clear at every level.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): legal and
  regulatory issues, compliance requirements.
- **CISM** - Domain 1 (Information Security Governance): compliance
  with external requirements; Domain 5 (Incident Management):
  reporting obligations.
- **CISA** - Domain 1 (Information System Auditing Process): audit
  standards, compliance; Domain 5 (Protection of Information
  Assets): control implementation.
- **CRISC** - Domain 1 (Governance): compliance integration into IT
  risk.
- **ISO 27001 LI/LA** - Clauses 4-10 (ISMS requirements), Annex
  A.5.31 (Legal, statutory, regulatory and contractual
  requirements).
- **CIPP/E, CIPT, CIPM** - GDPR-specific privacy compliance.
- **CGEIT** - IT governance and compliance alignment.

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- NIST Cybersecurity Framework 2.0 - https://www.nist.gov/cyberframework
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-66 Rev. 2 - Implementing the HIPAA Security Rule - https://csrc.nist.gov/pubs/sp/800/66/r2/final
- PCI Security Standards Council - PCI DSS v4.0 - https://www.pcisecuritystandards.org/
- ISACA - COBIT 2019 Framework - https://www.isaca.org/resources/cobit
- ISACA - CISA Review Manual (current edition) - no URL (printed reference)
- AICPA - SOC 2 Trust Services Criteria - https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
- EU GDPR - Regulation (EU) 2016/679 - https://eur-lex.europa.eu/eli/reg/2016/679/oj
- HIPAA - Health Insurance Portability and Accountability Act - https://www.hhs.gov/hipaa/index.html
