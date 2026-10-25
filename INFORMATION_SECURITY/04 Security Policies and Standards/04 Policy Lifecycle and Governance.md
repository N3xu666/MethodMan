# Policy Lifecycle and Governance

A policy is not a document that is written once and filed. It is a
living artifact with a lifecycle: it is drafted, reviewed, approved,
published, communicated, acknowledged, enforced, measured, reviewed,
updated and eventually retired. Governance is the discipline that
ensures each stage happens, on time, by the right role, with the
right evidence. Without governance, policies drift out of date and
the organization loses the authority they were meant to provide.

## 1. Overview

### The Policy Lifecycle

A defensible policy lifecycle has eight stages:

1. **Trigger** - what causes a new policy or a review? (new
   regulation, new risk, incident, scheduled review, change in
   business.)
2. **Draft** - the author drafts the policy with input from
   legal, security, business owners.
3. **Review** - the reviewer checks accuracy, consistency, legal
   compliance, feasibility.
4. **Approval** - the approver signs the policy; it becomes
   mandatory.
5. **Publication** - the policy is published in an accessible
   location; version controlled.
6. **Communication and acknowledgment** - the policy is
   communicated to those who must comply; acknowledgment is
   collected.
7. **Enforcement and measurement** - the policy is enforced;
   compliance is measured; exceptions are managed.
8. **Review and retirement** - the policy is reviewed on cycle;
   updated or retired.

Each stage has a role, an artifact and a timestamp. Missing any
stage breaks the lifecycle.

### Triggers for a Review

A policy is reviewed when:

- **Scheduled** - on the defined review cycle (annual, semiannual,
  quarterly for high-change topics).
- **Regulatory change** - a new or changed regulation affects the
  policy.
- **Incident** - an incident reveals a gap or a problem with the
  policy.
- **Risk change** - the risk assessment changes; the policy may
  need to change.
- **Business change** - a merger, acquisition, new product, new
  market affects the policy.
- **Organizational change** - the policy owner changes; the policy
  is reviewed by the new owner.
- **Technology change** - a new technology makes the policy
  obsolete or incomplete.
- **Audit finding** - an audit finding reveals a gap.
- **Stakeholder request** - a stakeholder requests a review.

### The Version Model

A policy has a version:

- **Major version (X.0)** - a substantive change that alters
  requirements, scope or consequences. Requires full review and
  approval.
- **Minor version (X.Y)** - a clarifying or editorial change.
  Requires review; approval may be delegated.
- **Patch (X.Y.Z)** - a typo or formatting fix. May not require
  review.

Versioning is a discipline: readers must be able to tell whether
the policy they read is current.

## 2. Where in the Organization

The policy lifecycle involves multiple roles:

- **Trigger owner** - the role that identifies the need for a
  new policy or review (compliance, risk, audit, business).
- **Author** - drafts the policy; often the policy owner or their
  delegate.
- **Reviewer** - checks the draft; legal, security, business.
- **Approver** - signs the policy; board, executive or delegate.
- **Publisher** - publishes the policy; policy administrator.
- **Communicator** - distributes the policy; usually HR or
  compliance.
- **Enforcer** - acts on violations; manager, HR, legal.
- **Auditor** - verifies compliance; internal audit or external.

### Governance Bodies

- **Policy committee** - cross-functional body that reviews and
  recommends policies before approval. Typically includes legal,
  security, IT, HR, business.
- **Board / audit committee** - approves top-level policy; receives
  policy compliance reports.
- **Executive management** - approves policies above a defined
  threshold; funds enforcement.

### Decision Rights

The governance must define who decides:

- **New policy** - who proposes, who reviews, who approves.
- **Substantive change** - same as new policy.
- **Minor change** - who reviews, who approves (often the owner).
- **Exception** - who requests, who approves, who reviews
  periodically.
- **Retirement** - who proposes, who approves.

Without defined decision rights, the lifecycle stalls.

## 3. Threats and Failure Modes

### Failure Modes of the Lifecycle

- **No trigger** - the policy is not reviewed when the trigger
  occurs (regulation, incident, business change). The policy is
  stale.
- **Draft without review** - the policy is drafted by one person
  and published without review. Errors, legal risks,
  inconsistencies.
- **Review without authority** - the reviewer has no authority to
  reject the policy. The review is a formality.
- **Approval without accountability** - the approver signs without
  reading. The policy is approved; no one is accountable.
- **Publication without communication** - the policy is published;
  no one reads it.
- **Communication without acknowledgment** - the policy is
  communicated; no one acknowledges.
- **Enforcement without measurement** - the policy is enforced;
  no one knows whether it works.
- **Measurement without action** - the metrics show a problem; no
  one acts.
- **Review without retirement** - the policy is reviewed; it is
  never retired, even when obsolete.
- **Retirement without archive** - the policy is retired; the
  archive is lost. Historical analysis is impossible.

### Failure Modes of Governance

- **No governance body** - no cross-functional body to review
  policies; each function publishes its own.
- **Governance without decision rights** - the governance body
  meets; no one knows who decides.
- **Governance without quorum** - the body meets; the wrong
  people attend; decisions lack legitimacy.
- **Governance without records** - decisions are made; no
  minutes; no audit trail.
- **Governance without cadence** - the body meets irregularly;
  policies backlog.
- **Governance without escalation** - contested decisions have
  no path to resolution; the policy stalls.

### Failure Modes of Versioning

- **No version control** - the policy is edited in place; no
  history; no audit trail.
- **Version without change log** - the version changes; no one
  knows what changed.
- **Major vs minor ambiguity** - the reviewer cannot tell whether
  a change is substantive. Version numbers become meaningless.
- **Old versions accessible** - the intranet has multiple
  versions; employees read the wrong one.
- **Version without approver** - a version exists; no one signed
  it.

## 4. Controls and Implementation

### The Lifecycle Process

Step 1. **Trigger** - a trigger event is logged; the policy owner
is notified; the policy enters the review queue.

Step 2. **Draft** - the author drafts the policy using the
organization's template; includes purpose, scope, requirements,
roles, exceptions, consequences, review cycle.

Step 3. **Review** - reviewers (legal, security, business) check
the draft; comments are collected and resolved; the draft is
revised.

Step 4. **Approval** - the approver signs the policy; the
signature is retained as evidence; the policy becomes mandatory.

Step 5. **Publication** - the policy is published to the
authoritative location; the version is recorded; old versions are
archived.

Step 6. **Communication** - the policy is communicated to
in-scope audiences; acknowledgment is collected; the deadline is
tracked.

Step 7. **Enforcement** - the policy is enforced; violations are
detected and acted on; exceptions are managed; compliance is
measured.

Step 8. **Review** - the policy is reviewed on cycle; changes are
made or the policy is retired; the cycle repeats.

### The Change Log

Every policy maintains a change log:

```
Version | Date       | Author   | Approver | Summary
--------|------------|----------|----------|-----------------------------
1.0     | 2026-01-15 | J. Smith | Board    | Initial policy
1.1     | 2026-04-10 | J. Smith | CISO     | Add cloud scope
2.0     | 2026-09-01 | J. Smith | Board    | Align with GDPR amendments
```

The change log is the policy's history. Without it, the policy's
state is unknown; with it, any version is traceable.

### Communication and Acknowledgment

Communication is not a single email. It is:

- **Publish** - the policy is on the intranet, accessible, search.
- **Announce** - a formal announcement to in-scope audiences.
- **Train** - a short training or briefing on key changes.
- **Acknowledge** - employees must confirm they read and
  understand.
- **Record** - the acknowledgment is recorded, timestamped, per
  employee.
- **Remind** - non-acknowledgers receive reminders.
- **Escalate** - non-acknowledgers after the deadline are
  escalated to their manager.

Acknowledgment is evidence. Without it, a violation of the policy
can be defended on the grounds of "I didn't know".

### Review Cycle

The review cycle is defined per policy:

- **Annual** - standard for most policies.
- **Semiannual** - for policies in high-change areas (cloud,
  third-party, data).
- **Quarterly** - for critical policies in rapidly changing
  environments (crypto, incident response).
- **Event-driven** - in addition to the cycle, a review is
  triggered by defined events (regulatory change, incident).

The cycle is recorded in the policy; the review is scheduled; the
results are retained.

### Retirement

A policy is retired when:

- It is superseded by a new policy.
- Its topic is no longer relevant.
- The organization has ceased the activity it governed.
- The regulatory basis is gone.

Retirement process:

1. Draft a retirement note explaining the rationale.
2. Review by the policy committee.
3. Approve by the approver of the original policy.
4. Publish the retirement note alongside the archived policy.
5. Archive the policy; do not delete it.
6. Update the policy map.
7. Notify in-scope audiences.

Retired policies are archived, not deleted. Historical analysis
requires them; legal proceedings may require them.

## 5. Tooling

- **Policy management platforms** - PolicyTech (NAVEX),
  ConvergePoint, MetaCompliance, PowerDMS, Onspring. Workflow,
  version control, approval, publication, acknowledgment tracking.
- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate.
  Policy module integrated with risk, controls, compliance.
- **Document management** - SharePoint, Confluence with version
  history. Adequate for small organizations; lacks policy-specific
  workflow.
- **Learning management** - Cornerstone, Docebo, KnowBe4. Training
  and acknowledgment.
- **Electronic signature** - DocuSign, Adobe Sign, HelloSign. For
  formal approval of high-stakes policies.
- **Git-backed lifecycle** - for technical policies, version
  control in Git with pull-request workflow, review, approval.
  Excellent for policies that change frequently.
- **Workflow automation** - Power Automate, Zapier, Camunda. To
  automate trigger-to-review and review-to-approval steps.

## 6. Verification and Metrics

### Verification of the Lifecycle

- **Lifecycle completeness** - percentage of policies with all
  eight stages documented. Target: 100%.
- **Approval evidence** - percentage of policies with a recorded
  approval. Target: 100%.
- **Publication** - percentage of policies in the authoritative
  location. Target: 100%.
- **Acknowledgment** - percentage of in-scope employees who have
  acknowledged the current version. Target: >95%.
- **Change log** - percentage of policies with a complete change
  log. Target: 100%.
- **Review currency** - percentage of policies reviewed within the
  defined cycle. Target: 100%.
- **Retirement** - percentage of retired policies with a
  retirement note. Target: 100%.

### Metrics

- **Average policy age** - by policy. Older policies are more
  likely to be stale.
- **Time to approve** - median days from draft to approval.
- **Time to publish** - median days from approval to publication.
- **Acknowledgment rate** - percentage acknowledged within the
  deadline.
- **Exception rate** - exceptions per policy; high = policy does
  not fit reality.
- **Review backlog** - policies overdue for review.
- **Retirement rate** - policies retired per year. Zero
  retirements indicates the portfolio is not maintained.

### Common Verification Steps

1. Sample 5 policies; verify lifecycle stages, approval, change
   log, acknowledgment records, review date.
2. Sample 5 recent changes; verify review, approval, publication,
   communication.
3. Verify acknowledgment rate for the last cycle; verify reminders
   and escalation for non-acknowledgers.
4. Verify the review schedule; verify any overdue reviews have a
   documented plan.
5. Verify a recent retirement; verify the retirement note, the
   archive, the policy map update.

## 7. Anti-Patterns

- **Policy written once.** The policy is written and filed; it is
  never reviewed, never updated.
- **Approval as formality.** The approver signs without reading;
  no one is accountable.
- **Publication without communication.** The policy is published;
  no one reads it.
- **Communication without acknowledgment.** The policy is
  communicated; no one acknowledges.
- **Acknowledgment without training.** Employees click "I agree";
  they do not understand.
- **Review without retirement.** The policy is reviewed; obsolete
  policies are kept alive.
- **Retirement without archive.** The policy is retired; the
  history is lost.
- **Version without change log.** The version changes; no one
  knows why.
- **Governance without records.** Decisions are made; no audit
  trail.
- **Governance without cadence.** The body meets irregularly;
  decisions backlog.
- **Policy owner as bottleneck.** One person must review every
  policy; the queue grows.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): policy
  lifecycle, governance; Domain 7 (Security Operations): policy
  enforcement.
- **CISM** - Domain 1 (Information Security Governance): policy
  lifecycle and governance.
- **CISA** - Domain 5 (Protection of Information Assets): policy
  lifecycle.
- **ISO 27001 LI/LA** - Clause 5.2 (Information security policy),
  Clause 7.5 (Documented information), Annex A.5.1 (Policies for
  information security), Annex A.5.37 (Documented operating
  procedures).
- **COBIT 2019** - APO01 (Managed I&T Management Framework),
  MEA01 (Performance and Conformance Monitoring).

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 - Information security controls - https://www.iso.org/standard/75652.html
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-12 Rev. 1 - An Introduction to Information Security - https://csrc.nist.gov/pubs/sp/800/12/r1/final
- NIST SP 800-100 - Information Security Handbook: A Guide for Managers - https://csrc.nist.gov/pubs/sp/800/100/final
- ISACA - COBIT 2019 Framework - https://www.isaca.org/resources/cobit
- SANS Institute - Information Security Policy Templates - https://www.sans.org/INFORMATION_SECURITY-policy/
