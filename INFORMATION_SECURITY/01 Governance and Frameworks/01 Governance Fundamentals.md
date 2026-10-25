# Governance Fundamentals

Governance is how an organization decides what security it needs, who owns each decision, and how it proves the decisions are followed. Without governance, security is a set of disconnected technical controls with no owner, no budget and no accountability.

## 1. Overview

Security governance answers four questions:

- **What** does the organization need to protect? (assets, data, services)
- **Why** does it matter? (business impact, legal obligation, contractual requirement)
- **Who** decides and who is accountable? (board, CISO, risk committee, asset owner)
- **How** is compliance verified? (audit, metrics, reporting)

A governance program produces artifacts that outlive any single person: a charter, a policy set, a risk register, a control framework, a reporting cadence. These artifacts are what auditors review and what regulators demand.

This file is the foundation for the rest of the subcategory. It does not cover specific frameworks (see files 02 and 03) or specific roles (file 04). It covers the reasoning and the vocabulary.

## 2. Where in the Organization

Governance is not an IT function. It sits at the board and executive level, delegated to a CISO or equivalent, executed by security teams, and evidenced by audit.

```
Board / Audit Committee
    |
    v
CISO / Security Executive
    |
    +--> Security Governance Committee (policy approval, risk acceptance)
    |
    +--> Security Operations (execution)
    |
    +--> Internal Audit (independent verification)
    |
    +--> Business Units (asset owners, risk owners)
```

A recurring failure mode is "governance by the security team alone": the team writes policy, the business ignores it, and no one has authority to enforce exceptions or fund remediation. Effective governance requires business participation at the decision table, not just at the receiving end of a policy email.

## 3. Threats and Failure Modes

Governance failures are rarely caused by a single malicious actor. They are systemic.

- **Orphaned controls.** A control exists because it always has, nobody knows who owns it, and nobody checks whether it still works.
- **Policy without enforcement.** A document says "passwords must be 16 characters", the identity provider enforces 8, and no one notices because there is no verification step.
- **Risk acceptance without an owner.** A known risk is accepted in a meeting and never written down; when it materializes, no one remembers the decision.
- **Shadow IT.** Business units bypass governance because the official process is too slow; the security team discovers systems in the next audit.
- **Compliance theater.** Controls are implemented to pass an audit, not to reduce risk; after the auditor leaves, the control decays.
- **Unfunded mandates.** A regulator or board requires a control, but no budget is allocated to implement or maintain it.

Each failure mode has a governance countermeasure: ownership, verification, documented risk acceptance, exception handling, honest metrics. These are the topics of sections 4 and 6.

## 4. Controls and Implementation

A governance program has five core components. Each is a control in its own right.

### 4.1 Charter

A one-page document, approved by the board, that states: the security program exists, who leads it (CISO), what authority the CISO has, what the reporting line is, and what the program is accountable for. Without a charter, the security team has no formal authority to set policy or demand remediation.

### 4.2 Policy Set

A hierarchy of documents, from high-level to low-level (see file 04 in this subcategory for the full hierarchy):

- **Policy**: what the organization requires (mandatory, board-approved).
- **Standard**: how the requirement is met (mandatory, CISO-approved).
- **Procedure**: step-by-step instructions (mandatory, team-level).
- **Guideline**: recommended practice (advisory).

The policy set must be small enough to be read and specific enough to be enforced. A 400-page policy manual is a signal that no one has read it.

### 4.3 Control Framework

A structured catalog of controls, mapped to a recognized framework (ISO 27001 Annex A, NIST CSF, CIS Controls, or a combination). The framework provides:

- **Coverage**: a checklist so nothing obvious is missed.
- **Common language**: auditors, regulators and customers recognize the framework.
- **Maturity path**: each framework has levels that support incremental improvement.

Choosing a framework is a governance decision, not a technical one. Many organizations use ISO 27001 as the certifiable base and NIST CSF as the operational overlay.

### 4.4 Risk Register

A living document listing each identified risk with: description, likelihood, impact, inherent risk score, mitigating controls, residual risk score, risk owner, treatment decision (mitigate / transfer / avoid / accept), review date. See file 02 (Risk Management) for the process.

### 4.5 Reporting Cadence

A scheduled report to the board or executive committee that covers: current risk posture, open incidents, audit findings, control gaps, budget status, regulatory changes. A governance program without reporting is invisible until it fails.

## 5. Tooling

Governance is mostly document-driven, but a few categories of tooling help.

- **GRC platforms** (Governance, Risk, Compliance): ServiceNow GRC, Archer, OneTrust, LogicGate. Centralize policy management, risk registers, control testing and audit findings. Worth the cost above roughly 500 employees; below that, spreadsheets plus a document management system are workable.
- **Policy management**: a wiki or document management system with version control (Confluence, SharePoint, Git for technical policies). The key feature is versioning, not formatting.
- **Control testing automation**: scripts and CI checks that verify technical controls continuously (see the check scripts in this repository as a small example). Manual control testing once a year is a snapshot; continuous verification is a control.
- **Security metrics dashboards**: a BI tool (Power BI, Grafana, Looker) fed by data from the SIEM, the vulnerability scanner, the ticketing system. The dashboard is only useful if the metrics were chosen for a decision, not for a slide.

Tooling does not fix a broken governance program. It amplifies whatever the program already is.

## 6. Verification and Metrics

Verification answers "is the governance program working?", not "are the technical controls working?". Four verification mechanisms:

- **Internal audit**: an independent team (reporting to the audit committee, not to the CISO) samples controls and reports findings. Independence is the point.
- **External audit**: a certification body (for ISO 27001) or a regulator. The external audit is a point-in-time check, not a continuous guarantee.
- **Control self-assessment**: asset owners attest that their controls are in place. Useful for coverage, weak as evidence.
- **Continuous monitoring**: automated checks (see section 5) that flag drift between policy and reality.

Useful governance metrics (chosen for decisions, not for looking good):

- **Policy coverage**: percentage of systems covered by an approved policy.
- **Control test pass rate**: percentage of sampled controls that passed the last test.
- **Mean time to remediate (MTTR)**: by severity, trending over time.
- **Open audit findings**: count and age, by severity.
- **Risk register currency**: percentage of risks reviewed within their review window.
- **Exception count**: number of approved policy exceptions, trending. A growing exception count is a signal that the policy is unrealistic.

Anti-metrics: number of policies published, number of training sessions delivered, number of security team members. These measure activity, not outcome.

## 7. Anti-Patterns

- **Security as a police force.** Governance is advisory and enabling; if the security team is seen as the department that says no, business units will route around it.
- **Compliance as the goal.** Passing the audit becomes the objective, and risk reduction becomes secondary. The next audit may pass; the next incident may not.
- **Policy bloat.** Every incident produces a new policy; the policy set grows, nobody reads it, and enforcement becomes impossible.
- **Governance without authority.** The CISO is accountable for security but has no budget authority, no hire/fire authority over security staff, and no escalation path to the board. Accountability without authority is a setup for failure.
- **Risk acceptance as a silent default.** Risks that are not explicitly accepted are implicitly accepted. If the register is empty, the organization has accepted every risk without deciding to.
- **Annual audit as the only verification.** A year is long enough for a control to decay completely. Continuous monitoring is not optional for high-impact controls.

## 8. Certification Alignment

This file supports the following certification domains:

- **CompTIA Security+**: governance, risk and compliance domain.
- **ISC2 CISSP**: Domain 1 (Security and Risk Management) - security governance principles, compliance, policy, roles.
- **ISACA CISM**: Domain 1 (Information Security Governance) - governance framework, strategy, roles, reporting.
- **ISO 27001 Lead Implementer / Lead Auditor**: the ISMS foundation, policy set, management review.

## 9. References

- NIST Cybersecurity Framework - https://www.nist.gov/cyberframework
- ISO/IEC 27001 - https://www.iso.org/standard/27001
- CIS Controls - https://www.cisecurity.org/controls
- ISACA COBIT - https://www.isaca.org/resources/cobit
- ISACA CISM Review Manual - https://www.isaca.org/credentialing/cism
- ISC2 CISSP CBK - https://www.isc2.org/certifications/cissp