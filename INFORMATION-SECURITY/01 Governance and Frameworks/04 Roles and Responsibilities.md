# Roles and Responsibilities

Every security control needs an owner. A control with no owner is not a control; it is a hope. This file defines the roles that make a governance program function, what each role is accountable for, and how the roles fit together.

## 1. Overview

Security governance assigns three things to every person and every control:

- **Accountability**: who answers for the outcome.
- **Responsibility**: who does the work.
- **Authority**: who can approve, deny, or fund.

A common governance failure is to confuse these. The board is accountable for security but not responsible for configuring firewalls. The CISO is responsible for the program but needs delegated authority to enforce policy. The asset owner is accountable for their asset but relies on the security team for expertise.

Key role families in a mature program:

- **Executive / board level**: accountable for the program.
- **Program leadership**: the CISO and their direct reports; responsible for strategy and delivery.
- **Control owners**: engineering and operational teams; responsible for specific controls.
- **Risk owners**: business unit leaders; accountable for the risk on their systems.
- **Independent assurance**: internal audit; accountable to the board, not to the CISO.

A mid-size organization does not need every role named in this file; one person often wears several hats. The point is that each role is *assigned*, not assumed.

## 2. Where in the Organization

```
Board of Directors / Audit Committee
    |  (accountable for the program, approves risk appetite)
    v
CEO / Executive Team
    |  (resources the program, resolves escalations)
    v
CISO / Security Executive
    |  (responsible for strategy, program, reporting)
    +--> Security Architecture / Engineering
    +--> Security Operations (SOC)
    +--> GRC / Risk / Compliance
    +--> Identity and Access Management
    |
    v
Control Owners (IT, DevOps, HR, Facilities)
    |  (responsible for implementing and operating specific controls)
    v
Risk Owners (Business Unit Leaders)
    |  (accountable for the risk on their systems)
    v
Internal Audit (independent, reports to Audit Committee)
       (provides assurance to the board)
```

The line between "security team" and "control owners" is the most commonly broken boundary. The security team writes policy, defines controls, and measures compliance; the control owners (IT, DevOps, HR) actually implement and operate the controls. If the security team attempts to be the control owner for everything, it becomes a bottleneck and a scapegoat.

## 3. Threats and Failure Modes

- **Role confusion.** The CISO is accountable for security incidents but has no authority to enforce patching on the engineering team; the engineering team owns patching but is not measured on it. Nobody fixes the gap.
- **Orphaned accountability.** No one is assigned as the owner of a given control; the control drifts. Detected at the next audit.
- **Shadow decisions.** A business unit decides to skip a control (e.g. skip MFA on a legacy system) without documenting the exception. When the incident happens, no one remembers who decided.
- **Authority without accountability.** The security team can block a deployment but is not measured on delivery velocity; the team is incentivized to block, not to enable.
- **Accountability without authority.** The security team is responsible for security outcomes but has no budget, no hire/fire authority, and no escalation path. A setup for burnout.
- **Conflict of interest in audit.** The internal audit reports to the CISO, so findings are filtered. The audit committee never sees the real picture.
- **Role inflation.** The organization creates "Security Champion" roles without allocating time; the champions burn out in six months.
- **Role ossification.** The org chart is written once; the organization changes; the roles do not.

## 4. Controls and Implementation

### 4.1 Board and Audit Committee

- **Accountability**: oversight of the security program, approval of the risk appetite, review of the top risks and incidents.
- **Authority**: approves budget, hires/removes the CISO, sets risk tolerance.
- **Responsibility**: meets at planned intervals (quarterly at minimum), requires management reporting, escalates to regulators when necessary.

Effective boards do not approve individual controls; they set the risk appetite and ask whether the organization is operating within it.

### 4.2 CISO / Security Executive

- **Accountability**: for the security program as a whole.
- **Authority**: sets policy, approves standards, escalates through the executive team, owns the security budget.
- **Responsibility**: strategy, program, reporting to the board, external representation, hiring.

The CISO's reporting line is a governance decision. Direct reporting to the CEO or CTO gives the CISO authority; reporting to a mid-level IT manager cripples the role. Best practice is CEO or a direct report to the CEO (COO, CRO, occasionally CTO with a dotted line to the CEO).

### 4.3 Security Architecture / Engineering

- **Accountability**: for the technical design of security controls.
- **Authority**: approves designs, defines standards, vetoes non-compliant architectures.
- **Responsibility**: threat modeling, secure design, control specifications, security tooling.

### 4.4 Security Operations (SOC)

- **Accountability**: for detection and response.
- **Authority**: to isolate systems, disable accounts, escalate incidents.
- **Responsibility**: monitoring, triage, incident handling, threat hunting, forensic preservation.

### 4.5 GRC / Risk / Compliance

- **Accountability**: for the risk register, the policy set, and compliance evidence.
- **Authority**: to demand evidence from control owners, to escalate noncompliance.
- **Responsibility**: risk assessment, control testing, audit coordination, policy lifecycle.

### 4.6 Identity and Access Management

- **Accountability**: for authentication, authorization, and identity lifecycle.
- **Authority**: to grant, revoke, and modify access; to enforce MFA and conditional access.
- **Responsibility**: SSO, MFA, PAM, joiner/mover/leaver processes, access reviews.

### 4.7 Control Owners (IT, DevOps, HR, Facilities)

- **Accountability**: for implementing and operating specific controls in their domain.
- **Authority**: within their systems; escalates to the CISO for cross-domain decisions.
- **Responsibility**: implement the control, keep it running, provide evidence on request.

Examples: IT owns endpoint management; DevOps owns CI/CD controls; HR owns onboarding and termination controls; Facilities owns physical access controls.

### 4.8 Risk Owners (Business Unit Leaders)

- **Accountability**: for the risk on the systems and processes their unit operates.
- **Authority**: to accept residual risk (with CISO concurrence), to fund mitigation.
- **Responsibility**: sign off on risk assessments, participate in management reviews, own the remediation plan.

Risk ownership is often the missing link: the security team identifies a risk, the IT team owns the technical fix, but no business leader signs off on the residual risk. When the risk materializes, no one is accountable.

### 4.9 Internal Audit

- **Accountability**: to the audit committee, not to the CISO.
- **Authority**: unrestricted access to records, systems, and personnel relevant to the audit.
- **Responsibility**: independent verification of controls, reporting findings, following up on remediation.

The independence requirement is the core of the role. An auditor who reports to the auditee cannot provide assurance.

### 4.10 Security Champions (optional)

- **Accountability**: for security practices within their team.
- **Authority**: to raise security issues, to block non-compliant merges (if delegated).
- **Responsibility**: advocate for security, triage findings, coordinate with the security team.

Champions fail when the role is volunteer-only with no allocated time. Budget 10-20% of their time explicitly.

## 5. Tooling

- **RACI matrix**: Responsible, Accountable, Consulted, Informed. A one-page matrix per major control or process. Effective when kept current, useless when stale. Maintain in the GRC tool or a wiki, not in a Word document that no one can find.
- **GRC platform**: role assignment, risk ownership, control ownership, workflow for approvals and exceptions.
- **HRIS integration**: joiner/mover/leaver automation; role changes trigger access reviews.
- **IAM**: role-based access control; the technical counterpart of the governance role model.
- **Organizational chart tools**: Visio, Lucidchart, or a wiki page; the chart is a snapshot, the RACI matrix is the operational document.

## 6. Verification and Metrics

Governance of roles is verified by checking whether the roles actually function, not by whether the org chart exists.

- **Ownership coverage**: percentage of controls with a named accountable owner.
- **RACI freshness**: percentage of RACI matrices reviewed within the last 12 months.
- **Risk owner coverage**: percentage of register entries with a named business-unit owner.
- **Exception processing time**: how long it takes from exception request to decision.
- **Escalation frequency**: how often the CISO escalates to the executive team or board; rising trend may indicate authority gaps.
- **Audit independence**: does the internal audit report to the CISO? If yes, that is a finding, not a metric.
- **Champion activity**: percentage of champions who attended the last sync, contributed to a finding, or blocked a merge in the last quarter.

Anti-metrics: number of roles defined in the org chart, number of RACI cells filled, number of champions appointed.

## 7. Anti-Patterns

- **The CISO as the scapegoat.** The CISO is accountable for the program and blamed for every incident, but has no budget authority and no direct line to the board. The role is set up for failure.
- **The security team as control owner.** The security team implements and operates controls that should be owned by IT, HR, DevOps. The security team is a permanent bottleneck.
- **RACI as decoration.** The matrix exists, no one consults it, decisions are made by whoever shouts loudest.
- **Audit reporting to the CISO.** The audit is not independent; findings are filtered; the board sees a rosy picture until the incident.
- **Security champion as volunteer.** Champions have no allocated time, no mandate, no recognition; the program decays within two quarters.
- **Risk owner as a signature.** The business leader signs the risk register without reading it; the sign-off provides legal cover but not accountability.
- **Role inflation.** Every framework adds a new role (DPO, AI Officer, Cloud Security Lead); the org chart grows, the accountability map does not.

## 8. Certification Alignment

This file supports the following certification domains:

- **CompTIA Security+**: governance, roles and responsibilities.
- **ISC2 CISSP**: Domain 1 (Security and Risk Management) - roles, responsibilities, organizational structure.
- **ISACA CISM**: Domain 1 (Information Security Governance) - roles and responsibilities, reporting lines.
- **ISO 27001 Lead Implementer / Lead Auditor**: Clause 5.3 (organizational roles, responsibilities and authorities).
- **ISACA CISA**: audit independence, role of internal audit.

## 9. References

- NIST Cybersecurity Framework 2.0 (Govern function) - https://www.nist.gov/cyberframework
- ISO/IEC 27001:2022 (Clause 5.3) - https://www.iso.org/standard/27001
- ISACA CISM Review Manual - https://www.isaca.org/credentialing/cism
- ISC2 CISSP CBK - https://www.isc2.org/certifications/cissp
- IIA International Standards for the Professional Practice of Internal Auditing - https://www.theiia.org/en/standards/
- NIST SP 800-39 (Managing Information Security Risk) - https://csrc.nist.gov/publications/detail/sp/800-39/final