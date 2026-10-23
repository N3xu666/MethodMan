# ISO 27001 and ISMS

ISO/IEC 27001 is the international standard for information security management systems (ISMS). It is the most widely recognized certifiable security standard; "ISO 27001 certified" is a procurement requirement in many industries. This file explains what an ISMS is, what the standard actually requires, and how certification works in practice.

## 1. Overview

An ISMS is a management system, not a technical control set. It is the organizational structure that decides what security the organization needs, implements it, measures it, and improves it over time. ISO 27001 specifies the requirements for that management system. It does not prescribe which technical controls to use; it prescribes how the organization decides which controls it needs.

Key facts:

- **Certifiable**: an accredited certification body audits the organization and issues the certificate. Valid for three years, with surveillance audits annually.
- **Risk-driven**: the standard requires a risk assessment and a risk treatment plan. Controls are selected based on risk, not taken from a fixed checklist.
- **Annex A**: a catalog of 93 controls across 4 themes (organizational, people, physical, technological). Annex A is the reference menu, not a mandatory set; the organization justifies its selection.
- **Compatibility**: aligned with ISO 27002 (implementation guidance for Annex A controls), ISO 27005 (risk management), ISO 27701 (privacy), ISO 27017/27018 (cloud).

The 2022 revision of the standard merged the previous 114 controls of the 2013 version into 93 controls of the 2022 version, and added 11 new controls (threat intelligence, cloud services security, data leakage prevention, monitoring activities, web filtering, secure coding, configuration management, information deletion, data masking, data leakage prevention, physical security monitoring, and others). It also reorganized Annex A into 4 themes instead of 14 domains.

## 2. Where in the Organization

An ISMS touches every part of the organization; it is not owned by IT alone.

```
Top Management (accountable, must demonstrate leadership)
    |
    v
ISMS Manager / CISO (operational owner)
    |
    +--> ISMS Steering Committee (management review, resourcing)
    |
    +--> Risk Owners (business unit leaders)
    |
    +--> Control Owners (technical and operational teams)
    |
    +--> Internal Audit (independent; ISO 19011-based)
    |
    +--> Certification Body (external; three-year cycle)
```

The standard requires "top management" to demonstrate leadership (Clause 5.1). In practice, this means the CISO has a direct reporting line to the executive team, the ISMS has a budget, and management reviews the ISMS at planned intervals. An ISMS that exists only on paper, maintained by one person in the security team, will fail the certification audit.

## 3. Threats and Failure Modes

ISO 27001 certification failures and ISMS program failures share predictable causes.

- **Documentation without operation.** The ISMS manual, policies and risk register exist in a SharePoint folder; nobody uses them. Auditors detect this by asking operational staff "what is the policy?" and "show me the last management review minutes".
- **Risk assessment performed once.** ISO 27001 requires the risk assessment to be repeated at planned intervals and when significant changes occur. Many organizations do it once before certification and never again.
- **Annex A as a checklist.** The organization implements every Annex A control because "it's in the standard", which wastes budget and dilutes focus. The standard requires risk-based selection with a Statement of Applicability that explains exclusions.
- **Statement of Applicability (SoA) as a copy-paste.** The SoA lists each Annex A control with "applicable: yes" and a rationale that restates the control. Auditors require a justification grounded in risk.
- **Internal audit not independent.** The internal audit is performed by the ISMS team itself, which defeats the purpose. The standard requires objectivity; an auditor cannot audit their own work.
- **Scope creep.** The ISMS scope expands to cover everything, including systems the organization does not control (SaaS providers, customer environments), making certification impossible to maintain. A defined, defensible scope is a strength, not a weakness.

## 4. Controls and Implementation

The 2022 standard is organized into 10 clauses (4-10 are the certifiable requirements) plus Annex A.

### 4.1 The 10 Clauses

- **Clause 4**: Context of the organization. Understand internal and external issues, interested parties, and define the ISMS scope.
- **Clause 5**: Leadership. Top management commitment, information security policy, roles and responsibilities.
- **Clause 6**: Planning. Risk assessment, risk treatment, Statement of Applicability, information security objectives.
- **Clause 7**: Support. Resources, competence, awareness, communication, documented information.
- **Clause 8**: Operation. Implement the risk treatment plan; operate the controls.
- **Clause 9**: Performance evaluation. Monitoring, measurement, internal audit, management review.
- **Clause 10**: Improvement. Nonconformity, corrective action, continual improvement.
- **Clauses 1-3**: Scope, normative references, terms and definitions (not certifiable).

### 4.2 Annex A (2022)

93 controls in 4 themes:

- **A.5 Organizational controls** (37 controls): policies, roles, threat intelligence, asset management, supplier relationships, incident management, business continuity, compliance.
- **A.6 People controls** (8 controls): screening, terms of employment, awareness, disciplinary process, remote working.
- **A.7 Physical controls** (14 controls): physical perimeter, entry, offices, equipment, clear desk, secure disposal.
- **A.8 Technological controls** (34 controls): endpoint, privileged access, authentication, logging, network security, secure development, data masking, data leakage prevention.

### 4.3 The Certification Path (PDCA)

```
1. Gap analysis (against ISO 27001:2022)
2. Scope definition
3. Risk assessment and risk treatment plan
4. Statement of Applicability
5. Policy set and control implementation
6. Internal audit (Clause 9.2)
7. Management review (Clause 9.3)
8. Stage 1 audit (documentation review) - external
9. Stage 2 audit (implementation evidence) - external
10. Certification issued; surveillance audits at 12 and 24 months; recertification at 36 months
```

Steps 1-7 are typically 6-18 months for a mid-size organization. Steps 8-9 are the external audit; a Stage 2 audit that finds major nonconformities delays certification until remediation is verified.

### 4.4 Statement of Applicability

The SoA is the central artifact of ISO 27001. For each of the 93 Annex A controls, it states:

- Whether the control is applicable (yes / no).
- Justification for the decision (for exclusions: why the control does not apply).
- Implementation status (implemented / partially / planned).
- Reference to the control's implementation (policy section, technical control, procedure).

The SoA is what the auditor reviews first. A copy-pasted SoA is the fastest way to fail Stage 1.

## 5. Tooling

- **GRC platforms** with ISO 27001 templates: OneTrust, Archer, ServiceNow GRC, Vanta, Drata, Secureframe. The last three are "compliance automation" platforms aimed at startups and mid-market; they automate evidence collection but do not replace the risk assessment or the SoA.
- **Risk register**: a spreadsheet is sufficient below roughly 200 employees. Above that, a GRC platform pays for itself in audit preparation time.
- **Document management**: a versioned document repository (Confluence, SharePoint, Git for technical policies). Version control is the key feature.
- **Evidence collection**: automated tools that pull evidence from cloud providers (AWS Config, Azure Policy, GCP Security Command Center), identity providers, endpoint tools. Evidence on demand is much cheaper than evidence gathered in a panic before the audit.
- **Internal audit management**: a tracker for findings, owners, remediation dates. Jira or a dedicated audit tool.

Tooling accelerates a working ISMS; it does not create one. The most common compliance-automation failure mode is buying a platform before the risk assessment exists; the platform then documents the absence of a program.

## 6. Verification and Metrics

ISO 27001 verification is built into the standard.

- **Internal audit (Clause 9.2)**: at planned intervals, by objective auditors, covering the full ISMS scope. Findings are nonconformities (major / minor) or observations.
- **Management review (Clause 9.3)**: top management reviews ISMS performance, audit results, risk status, and makes resourcing decisions. Minutes are required evidence.
- **Surveillance audits**: annually for years 1 and 2; the certification body samples controls and checks that the ISMS is still operating.
- **Recertification audit**: year 3; full re-audit, not a sample.

Useful ISMS metrics:

- **Nonconformities open / closed**: by severity, trending.
- **Risk treatment progress**: percentage of planned treatments implemented on schedule.
- **Control effectiveness**: sampled controls that passed the last test.
- **Incident metrics**: count, MTTR, by severity, trending.
- **Management review actions**: percentage completed by due date.
- **Audit findings age**: how long findings stay open.

Anti-metrics: number of policies, number of Annex A controls implemented (without risk justification), number of training hours delivered.

## 7. Anti-Patterns

- **Certification as the goal.** The certificate is a byproduct of a working ISMS, not a substitute for one. Auditors increasingly detect "paper ISMS" and issue major nonconformities.
- **Scope inflation.** Trying to certify everything, including systems the organization does not control. A narrow, well-justified scope is more defensible.
- **Risk assessment performed once.** The standard requires periodic reassessment; a stale risk register is a finding.
- **Internal audit performed by the ISMS team.** Clause 9.2 requires objectivity; auditors cannot audit their own work.
- **SoA as a copy-paste.** The SoA must reflect the organization's actual risk decisions, not a template.
- **Compliance automation as a substitute for the program.** Vanta/Drata/Secureframe automate evidence; they do not perform risk assessment, define scope, or write the SoA.
- **Certification without operational buy-in.** The certificate is issued to the organization; if business units do not participate, the ISMS decays within one surveillance cycle.

## 8. Certification Alignment

This file supports the following certification domains:

- **ISO 27001 Lead Implementer (LI)**: the full standard, risk assessment, SoA, control implementation.
- **ISO 27001 Lead Auditor (LA)**: the audit process, Clause 9, ISO 19011, nonconformity classification.
- **ISC2 CISSP**: Domain 1 (Security and Risk Management) - compliance, security program.
- **ISACA CISM**: Domain 3 (Information Security Program) - program development and management.
- **CompTIA Security+**: governance and compliance domain.

## 9. References

- ISO/IEC 27001:2022 - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 (implementation guidance) - https://www.iso.org/standard/75652.html
- ISO/IEC 27005:2022 (risk management) - https://www.iso.org/standard/80585.html
- ISO 19011:2018 (auditing management systems) - https://www.iso.org/standard/70017.html
- ISO 27701 (privacy) - https://www.iso.org/standard/71670.html
- ISACA CISM Review Manual - https://www.isaca.org/credentialing/cism