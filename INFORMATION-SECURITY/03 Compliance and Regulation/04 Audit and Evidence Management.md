# Audit and Evidence Management

An audit is an independent examination of controls against a defined
standard or set of obligations. Evidence is the artifact that
demonstrates a control operated as designed during the audit period.
Without evidence, the control is a claim. Without audit, the claim is
unverified. The two together produce assurance - for the regulator,
the customer, the board and the organization itself.

## 1. Overview

### Types of Audit

- **Internal audit** - performed by the organization's own audit
  function, independent of operations. Reports to the audit
  committee. Provides management assurance.
- **External audit** - performed by an independent third party.
  Reports to the board, the regulator or the customer. Provides
  external assurance.
- **Certification audit** - performed by an accredited certification
  body against a standard (ISO 27001, ISO 9001). Results in a
  certificate valid for a defined period.
- **Attestation** - a report (not a certificate) by a CPA firm on
  controls (SOC 1, SOC 2, SOC 3). Results in an opinion, not a
  certificate.
- **Regulatory examination** - performed by a regulator (SEC, FCA,
  HHS OCR, DORA authorities) against statutory requirements.
  Results in a report, and possibly enforcement action.
- **Customer audit** - performed by or on behalf of a customer
  under contractual right-to-audit. Results in a finding report.
- **Self-assessment** - performed by the control owners against a
  framework. Not independent; used as preparation.

### Audit Phases

A typical audit has five phases:

1. **Planning** - scope, criteria, schedule, team, logistics.
2. **Fieldwork** - interviews, evidence collection, testing.
3. **Reporting** - findings, observations, draft report,
   management responses.
4. **Remediation** - corrective actions for findings.
5. **Follow-up** - verification that remediation worked.

The organization's preparation spans all five phases, not just
fieldwork. The most common failure is treating the audit as a
fieldwork event; the work that determines the outcome happens in
planning and evidence management.

### Audit Criteria vs Audit Standards

- **Audit criteria** - what the audit measures against (ISO 27001,
  PCI DSS, GDPR, internal policy).
- **Audit standards** - how the audit is performed (ISAE 3000,
  ISA 700, ISO 19011, IIA Standards).

Both must be defined before the audit begins. An audit without
defined criteria is an inspection; an audit without defined
standards is an opinion.

## 2. Where in the Organization

Audit and evidence management involve multiple roles:

- **Audit committee** - oversees the audit program, receives audit
  reports, approves remediation budgets.
- **Chief Audit Executive (CAE)** - leads internal audit, reports
  functionally to the audit committee (not to management).
- **Internal audit team** - performs audits, tests controls,
  reports findings.
- **External auditor** - independent assurance provider; reports
  to the board or regulator.
- **Compliance / GRC team** - maintains the crosswalk, coordinates
  audit preparation, tracks findings.
- **Control owners** - produce evidence, respond to findings,
  implement remediation.
- **CISO** - accountable for the security controls being audited;
  responds to findings at the executive level.
- **Legal** - manages regulator examinations, privilege, and
  disclosure obligations.

### Independence

Audit independence is the foundation of audit value:

- **Internal audit** reports functionally to the audit committee,
  not to the CISO or the CIO. Otherwise the audit lacks authority.
- **External audit** has no commercial relationship with the
  organization beyond the audit engagement; independence is
  attested annually.
- **Control owners** do not audit their own controls. The auditor
  is a separate role from the control owner.
- **Self-assessment** is preparation, not audit. It does not
  substitute for independent assurance.

An audit that is not independent is a review, not an audit. It
provides limited assurance and should be labeled accordingly.
## 3. Threats and Failure Modes

### Failure Modes of Audit Preparation

- **Audit as fire drill** - the organization scrambles at audit
  time to produce evidence that should have been collected
  continuously. High stress, low quality.
- **Scope creep** - the audit scope grows to include systems that
  are not in scope, or the scope is defined too broadly to be
  manageable.
- **Evidence theatre** - evidence is collected for the audit but
  not from actual operation. Screenshots of settings, not logs of
  actions.
- **Auditor unprepared** - the auditor is not briefed; interviews
  go badly; the auditor draws wrong conclusions from partial
  information.
- **Hidden findings** - the organization knows about a control gap
  and hopes the auditor misses it. The auditor usually does not.
- **Over-rehearsal** - the team is coached to give the "right"
  answers; the auditor detects the coaching and distrusts the
  whole audit.

### Failure Modes of Evidence Management

- **Evidence decay** - evidence is collected, used for the audit,
  and then deleted. The next audit rebuilds from scratch.
- **Evidence without context** - the artifact exists but is not
  linked to the control it supports; the auditor cannot verify
  the mapping.
- **Evidence without date** - the artifact does not show when it
  was produced; the auditor cannot verify it was within the audit
  period.
- **Evidence without integrity** - the artifact can be edited
  without detection; the auditor cannot trust it.
- **Manual collection** - evidence is collected by hand from many
  systems; slow, error-prone, often stale by the time it is
  delivered.
- **Ownerless evidence** - no one is accountable for producing the
  evidence; it is produced late and incomplete.
- **Evidence hoarding** - too much evidence, no index, the
  auditor cannot find the relevant artifact.
- **Evidence retention** - the evidence is deleted before the
  retention period ends; the next audit cannot verify the
  previous period.

### Failure Modes of Findings Management

- **Findings without owners** - the finding is logged but no one
  is accountable for remediation.
- **Findings without dates** - the finding has no target date;
  remediation drifts.
- **Findings without severity** - every finding is "high"; the
  organization cannot prioritize.
- **Repeat findings** - the same finding appears in consecutive
  audits; remediation was not effective.
- **Management response as narrative** - the response describes
  what will be done but not by whom and by when.
- **No follow-up** - the finding is closed when the response is
  written, not when the remediation is verified.

## 4. Controls and Implementation

### Audit Preparation

A defensible preparation program:

1. **Maintain the crosswalk** (see 03 Control Mapping and
   Frameworks). The crosswalk is the map the auditor will use to
   find evidence.
2. **Collect evidence continuously** - not at audit time. Every
   control produces evidence as part of its operation.
3. **Define the evidence standard** per control - what artifact
   counts, what period, what format.
4. **Assign evidence owners** - the control owner is the evidence
   owner.
5. **Review evidence quarterly** - spot-check that the evidence
   exists and is current.
6. **Brief the auditor** - scope, systems, contacts, known issues.
   An auditor who is not briefed will draw their own conclusions.
7. **Rehearse the interviews** - the control owner must be able to
   explain the control without notes. If they cannot, the control
   is not understood.
8. **Prepare the evidence index** - a single document linking each
   criterion to the evidence artifact.

### Evidence Standard

For each control, define:

- **What artifact** proves the control operated (log, ticket,
  screenshot, configuration, certificate).
- **What period** the artifact covers (daily, weekly, monthly,
  per event).
- **What format** the auditor will accept (PDF, CSV, screenshot
  with timestamp).
- **Where it is stored** - the evidence repository location.
- **Who produces it** - the control owner.
- **How long it is retained** - the retention period, aligned
  with the audit cycle and legal requirements.
- **How it is protected** - integrity, access control, audit
  trail.

### Evidence Collection Methods

- **Automated** - the control logs its own operation to a
  centralized system (SIEM, GRC, ticketing). Preferred; scalable,
  accurate, low effort.
- **Semi-automated** - the control produces a periodic report
  (weekly backup report, monthly access review). Automated where
  possible, manual where not.
- **Manual** - the control owner collects evidence manually
  (screenshot of configuration). Acceptable for infrequent
  controls, not for continuous ones.
- **Attestation** - the control owner signs a statement that the
  control operated. Weakest form; acceptable only when no artifact
  is possible.

The evidence standard should push toward automated collection.
Manual collection is a tax on the team and a source of audit
findings.

### Evidence Repository

A well-designed evidence repository:

- **Centralized** - one location, not five drives.
- **Indexed** - searchable, tagged by control and audit period.
- **Immutable** - write-once, cannot be edited after collection.
- **Access-controlled** - only authorized people can read; only
  the control owner can write.
- **Versioned** - the history of evidence is preserved.
- **Retained** - kept for the required retention period.

Common tools: SharePoint with retention labels, GRC platform
evidence modules, S3 with object lock, dedicated evidence
platforms (AuditBoard, Vanta, Drata).

### Findings Management

For each finding, record:

- **Finding ID** - unique identifier.
- **Criteria** - the audit criterion the finding relates to.
- **Condition** - what the auditor observed.
- **Cause** - why the condition exists (root cause, not just
  symptom).
- **Effect** - the risk or impact.
- **Severity** - critical, high, medium, low, observation.
- **Owner** - named person accountable for remediation.
- **Remediation plan** - what will be done, by whom, by when.
- **Management response** - the owner's formal response.
- **Target date** - the remediation deadline.
- **Actual closure date** - when remediation was verified.
- **Verification evidence** - the artifact that proves
  remediation worked.

A finding is not closed when the plan is written. It is closed
when the remediation is verified with evidence.

### Audit Follow-Up

The follow-up phase:

1. **Verify the remediation** - the control owner produces
   evidence that the finding is fixed.
2. **Re-test the control** - the auditor or internal audit
   re-tests; the control must operate, not just exist.
3. **Update the crosswalk** - if the remediation changed the
   control, update the mapping.
4. **Close the finding** - with evidence and date.
5. **Log the lesson** - if the finding revealed a systemic
   weakness, add it to the lessons learned.

## 5. Tooling

- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate,
  AuditBoard, TeamMate, Workiva. Audit management, evidence
  collection, findings tracking.
- **Compliance automation** - Vanta, Drata, Secureframe, Tugboat
  Logic. Continuous control monitoring, automated evidence.
- **Evidence repositories** - SharePoint, Confluence, S3 with
  object lock, dedicated evidence platforms. Centralized,
  immutable, indexed.
- **Ticketing** - Jira, ServiceNow ITSM, Azure DevOps. Findings
  tracked as tickets, linked to the register.
- **Log management** - Splunk, Elastic, Sumo Logic. Log retention
  for controls that produce log evidence.
- **Backup and archive** - Veeam, Commvault, cloud-native backup.
  Retention, immutability, verifiability.
- **Audit-specific tools** - AuditBoard, TeamMate, Diligent.
  Audit plans, workpapers, findings, remediation.

## 6. Verification and Metrics

### Verification of Audit Preparation

- **Evidence coverage** - percentage of controls with current
  evidence. Target: 100% for in-scope controls.
- **Evidence automation** - percentage of controls with automated
  evidence collection. Target: >50%.
- **Evidence freshness** - percentage of evidence within the
  required period.
- **Crosswalk currency** - last review date; target: within 12
  months.
- **Pre-audit self-assessment** - percentage of controls
  self-assessed before the external audit.

### Verification of Evidence Management

- **Evidence integrity** - sample 10 artifacts; verify they are
  immutable, timestamped, linked to the control.
- **Evidence retention** - percentage of evidence retained for the
  required period.
- **Evidence accessibility** - time to locate a specific evidence
  artifact for the auditor. Target: <5 minutes.
- **Evidence owner** - percentage of controls with a named
  evidence owner. Target: 100%.

### Verification of Findings Management

- **Findings closure rate** - percentage of findings closed by
  target date. Target: >80%.
- **Repeat findings** - percentage of findings repeated from the
  previous audit. Target: <10%.
- **Findings with owner** - percentage with a named owner.
  Target: 100%.
- **Findings with target date** - percentage with a remediation
  date. Target: 100%.
- **Findings verification** - percentage closed with
  verification evidence. Target: 100%.
- **Audit cycle time** - days from audit start to final report.
- **Cost per audit** - total cost / audits performed.

### Common Verification Steps

1. Sample 10 controls; verify evidence exists, is current,
   timestamped and linked to the control.
2. Sample 5 audit findings; verify owner, remediation plan,
   target date, verification evidence, closure date.
3. Verify the evidence repository is immutable and indexed.
4. Verify the auditor was briefed; verify the interview notes
   match the controls.

## 7. Anti-Patterns

- **Audit as theatre.** Preparing for the audit as a performance,
  not as an exercise in confirming the controls work.
- **Evidence as screenshot.** Screenshots of settings do not prove
  the control operated. Use operational evidence (logs,
  tickets, reports).
- **Evidence at audit time.** Evidence collected only when the
  auditor asks is stale, incomplete and often missing.
- **Evidence without integrity.** Editable evidence has no value;
  the auditor cannot trust it.
- **Evidence without date.** An undated artifact cannot be
  attributed to the audit period.
- **Findings as narrative.** A finding without a named owner, a
  target date and verification evidence is not a finding; it is a
  wish.
- **Closure without verification.** Closing a finding when the
  response is written is a promise, not a fact.
- **Repeat findings.** A repeated finding is evidence the
  remediation process does not work. Investigate the process, not
  just the symptom.
- **Audit as endpoint.** The audit is a check, not the goal. The
  goal is the control, operating continuously.
- **Auditor as adversary.** An adversarial relationship with the
  auditor guarantees a worse outcome than a collaborative one.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): audit and
  assurance; Domain 7 (Security Operations): investigations.
- **CISM** - Domain 1 (Information Security Governance): audit
  oversight.
- **CISA** - Domain 1 (Information System Auditing Process): audit
  planning, fieldwork, reporting, follow-up.
- **CRISC** - Domain 1 (Governance): audit and assurance of risk
  management.
- **ISO 27001 LI/LA** - Clause 9.2 (Internal audit), Clause 9.3
  (Management review), Annex A.5.35 (Independent review of
  information security).
- **IIA Standards** - International Standards for the Professional
  Practice of Internal Auditing.
- **ISACA IS Audit Standards** - ITAF (IT Assurance Framework).

## 9. References

- ISO 19011:2018 - Guidelines for auditing management systems - https://www.iso.org/standard/70017.html
- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISAE 3000 (Revised) - Assurance Engagements Other than Audits or Reviews of Historical Financial Information - https://www.iaasb.org/publications/international-standard-assurance-engagements-3000-revised-assurance-engagements-other-audits-or
- AICPA - SOC 2 Trust Services Criteria - https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
- IIA - International Standards for the Professional Practice of Internal Auditing - https://www.theiia.org/en/standards/
- ISACA - ITAF (IT Assurance Framework) - https://www.isaca.org/resources/itaf
- NIST SP 800-53A Rev. 5 - Assessing Security and Privacy Controls in Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/a/r5/final
