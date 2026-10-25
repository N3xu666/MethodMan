# Policy Fundamentals

A security policy is a formal statement of management intent. It
defines what the organization requires, who it applies to, and what
the consequences of non-compliance are. A policy is not a procedure
and not a standard: it is the mandate that both derive from. Without
a policy, standards and procedures have no authority. Without
standards and procedures, the policy has no execution.

## 1. Overview

### Policy, Standard, Procedure, Guideline

The four documents are often confused. They have distinct purposes:

- **Policy** - management's intent. What the organization requires
  and why. States mandatory compliance. Short (1-10 pages). Owned
  by executive management. Reviewed annually.
- **Standard** - mandatory requirements that satisfy the policy.
  How the organization meets the requirement. Specific,
  measurable, technical or administrative. Owned by the function
  responsible for the topic.
- **Procedure** - step-by-step instructions for executing a
  standard. Who does what, when, how. Operational. Owned by the
  team executing it.
- **Guideline** - recommended practices. Advisory, not mandatory.
  Used to guide decisions where the policy and standard do not
  prescribe.

A useful test:

- If it says "must" - it is a policy or standard.
- If it says "should" - it is a guideline.
- If it says "click here, then here" - it is a procedure.

### Why Policies Exist

- **Management mandate** - gives security requirements authority.
  Without a policy, a control owner cannot enforce a control on a
  peer.
- **Consistency** - the same requirement applies across the
  organization. Without a policy, every team invents its own
  rules.
- **Defensibility** - in an incident or legal proceeding, the
  policy shows the organization's intent and standard of care.
- **Communication** - the policy is the authoritative statement
  employees read and acknowledge.
- **Regulatory evidence** - many regulations require documented
  policies; the policy itself is the evidence.

### The Policy Paradox

A policy that is not enforced is worse than no policy: it shows
the organization knew what it required but did not act. A policy
that is enforced but not understood is not effective: employees
comply without comprehension, and the policy drifts. A good policy
is:

- **Specific enough** to be enforceable.
- **General enough** to remain relevant as technology changes.
- **Understood** by the people who must comply.
- **Enforced** with consequences for non-compliance.
- **Reviewed** on a cycle so it does not become stale.

## 2. Where in the Organization

Policy ownership is layered:

- **Board** - approves the highest-level policy (information
  security policy, acceptable use, risk appetite).
- **Executive management** - approves policy direction, funds
  enforcement.
- **CISO** - owns the security policy set, maintains the policy
  framework, reviews annually.
- **Policy owner** - the executive accountable for a specific
  policy (e.g. HR owns acceptable use, IT owns access control).
- **Policy administrator** - the role that maintains the document
  (version control, review cycle, communication).
- **Control owner** - the operational role that executes the
  standard derived from the policy.
- **Employees** - must read, acknowledge and comply.

### Policy Roles

- **Approver** - signs the policy; accountable for its content.
  Typically the board or an executive.
- **Owner** - ensures the policy stays accurate and relevant;
  initiates reviews.
- **Author** - drafts the document, often with legal and security
  input.
- **Reviewer** - checks accuracy, consistency and legal
  compliance before approval.
- **Communicator** - distributes the policy and collects
  acknowledgments.
- **Enforcer** - acts on violations; usually the manager of the
  employee, with HR and legal support.

A single person often holds more than one of these roles. What
matters is that each role has a named responsible person.

## 3. Threats and Failure Modes

### Failure Modes of Policy Content

- **Policy as wish** - the policy says "must" but there is no
  enforcement, no consequence and no evidence the organization
  cares. The policy is ignored.
- **Policy as legal boilerplate** - the policy is copied from a
  template or a peer organization; it does not reflect the
  organization's actual obligations or risks.
- **Policy as overreach** - the policy prohibits things the
  organization cannot enforce (e.g. personal use of social media
  on personal devices), making every employee a violator.
- **Policy as underreach** - the policy omits controls that
  actually matter (e.g. no policy on cloud use, no policy on
  third-party risk).
- **Policy without standard** - the policy says "encrypt data"
  but no standard defines which data, which algorithms, which
  keys. The policy is aspirational.
- **Policy without procedure** - the standard says "rotate keys
  every 90 days" but no procedure tells anyone how. The standard
  is not executed.
- **Policy without exception path** - the policy has no defined
  process for exceptions; the first exception becomes a
  precedent.
- **Policy without owner** - the policy has no named owner; it
  is not reviewed, not updated, not enforced.

### Failure Modes of Policy Management

- **Policy shelfware** - the policy exists, is published, and is
  never used. It is checked by the auditor and ignored by
  operations.
- **Policy sprawl** - the organization has hundreds of policies,
  many overlapping, some contradicting. No one knows which
  applies.
- **Policy drift** - the policy is not reviewed; it describes an
  organization that no longer exists.
- **Policy without acknowledgment** - employees are not required
  to read the policy; when a violation happens, the employee
  claims they did not know.
- **Policy without consequence** - the policy states
  consequences but they are never applied. The policy loses
  credibility.
- **Policy without training** - the policy is published but
  employees are not trained to understand it. The policy is
  compliance theater.
- **Policy behind a login** - the policy is on the intranet
  behind a login, inaccessible to the people who need it.
- **Policy in a language no one reads** - the policy is
  translated poorly or not at all; the people who must comply
  cannot read it.

### Failure Modes of Policy Enforcement

- **Selective enforcement** - senior leaders are not subject to
  the policy; everyone sees the double standard.
- **Punitive enforcement** - the policy is used to punish, not to
  guide; employees hide incidents instead of reporting them.
- **Inconsistent enforcement** - one team is held to the policy,
  another is not; the policy is not credible.
- **Enforcement without investigation** - the policy is enforced
  based on a technical alert without verifying the context; the
  wrong person is punished.
- **No enforcement at all** - the policy is a suggestion; the
  organization has no way to detect violations and no mechanism
  to respond.

## 4. Controls and Implementation

### Building the Policy Set

A minimal, defensible policy set:

1. **Information Security Policy** - the top-level statement of
   management intent. Approved by the board. Sets objectives,
   scope, principles, roles and consequences.
2. **Acceptable Use Policy** - how employees may use
   organizational systems and data. Covers personal use,
   monitoring, privacy, social media.
3. **Access Control Policy** - who gets access to what, under
   what conditions. Covers onboarding, role-based access, review,
   termination.
4. **Data Classification and Handling Policy** - how data is
   classified (public, internal, confidential, restricted) and
   how each class is handled (storage, transmission, retention,
   destruction).
5. **Incident Response Policy** - what constitutes an incident,
   who responds, what is reported to whom, within what timeframe.
6. **Business Continuity and Disaster Recovery Policy** - how
   the organization maintains essential operations and recovers
   from disruption.
7. **Third-Party Risk Policy** - how vendors are selected,
   assessed, monitored and exited.
8. **Risk Management Policy** - how risk is identified,
   assessed, treated and reported.
9. **Cryptography Policy** - what cryptography is required,
   which algorithms are approved, how keys are managed.
10. **Physical Security Policy** - how facilities are protected,
    who has access, how visitors are managed.

Most organizations need 8-15 policies. More than 20 policies
indicates sprawl. Fewer than 5 indicates gaps.

### Policy Content Structure

A defensible policy has:

- **Purpose** - what the policy achieves.
- **Scope** - who and what it applies to.
- **Definitions** - terms that need clarification.
- **Policy statements** - the actual requirements. Use "must",
  "shall" for mandatory. Use "should" for recommended.
- **Roles and responsibilities** - who does what.
- **Compliance and exceptions** - how compliance is verified,
  how exceptions are requested and approved.
- **Consequences** - what happens on violation.
- **Related documents** - standards, procedures, guidelines.
- **Review cycle** - how often the policy is reviewed.
- **Approval** - who approved it, when, version.

### Writing Principles

- **Short** - 1-10 pages per policy. If longer, split.
- **Plain language** - avoid legal jargon; write for the
  employee, not the lawyer.
- **Specific** - "must" not "should", "encrypted at rest using
  AES-256" not "strong encryption".
- **Enforceable** - if the organization cannot enforce it, do
  not write it.
- **Technology-neutral** - describe the requirement, not the
  current tool. The policy should survive technology changes.
- **Consistent** - the same term means the same thing across
  policies.
- **Translucent** - state exceptions clearly. Every policy needs
  an exception path.

### The Policy Hierarchy

The organization's policies form a hierarchy:

```
Board-approved policy (Information Security Policy)
    |
    +-- Standards (mandatory requirements)
    |       |
    |       +-- Procedures (step-by-step execution)
    |       +-- Baselines (specific configurations)
    |
    +-- Guidelines (advisory recommendations)
```

A standard must trace to a policy. A procedure must trace to a
standard. A guideline may stand alone.

## 5. Tooling

- **Policy management platforms** - PolicyTech (NAVEX), ConvergePoint,
  MetaCompliance, PowerDMS, Onspring. Version control, review
  workflow, acknowledgment tracking, publication.
- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate.
  Policy module integrated with risk and controls.
- **Document management** - SharePoint, Confluence, Google Drive.
  Version control, access control, search. Adequate for small
  organizations; not sufficient at scale.
- **Learning management** - LMS platforms (Cornerstone, Docebo,
  KnowBe4) for policy training and acknowledgment.
- **Git-backed policy** - for technical policies that change
  frequently, version control in Git with pull-request review.
  Good for infrastructure, cloud, security engineering.
- **Electronic signature** - DocuSign, Adobe Sign, HelloSign. For
  formal acceptance of high-stakes policies.

## 6. Verification and Metrics

### Verification of Policies

- **Policy currency** - percentage of policies reviewed within
  the last 12 months. Target: 100%.
- **Policy ownership** - percentage of policies with a named
  owner and approver. Target: 100%.
- **Policy accessibility** - percentage of in-scope employees who
  can access the policy on the intranet or mobile.
- **Policy acknowledgment** - percentage of in-scope employees
  who have acknowledged the policy in the last cycle. Target:
  >95%.
- **Policy comprehension** - percentage of employees who pass a
  comprehension quiz after training. Target: >80%.
- **Policy coverage** - percentage of critical topics with a
  policy (information security, acceptable use, access control,
  data classification, incident response, business continuity,
  third-party risk, risk management).
- **Policy consistency** - no contradictions between policies;
  no orphan standards without a parent policy.

### Metrics

- **Policies per employee** - if high, likely sprawl.
- **Average age of policies** - older policies are more likely
  to be stale.
- **Acknowledgment rate** - percentage of employees who have
  acknowledged the current version.
- **Exception rate** - percentage of employees or systems with
  active policy exceptions. High rate indicates the policy does
  not fit reality.
- **Enforcement actions** - number and type of enforcement
  actions per period; zero may indicate the policy is not
  enforced.
- **Policy-related incidents** - incidents traced to policy
  non-compliance; a rising trend indicates the policy or the
  training is not effective.

### Common Verification Steps

1. Sample 5 policies; verify owner, approver, last review date,
   version.
2. Verify the policy is accessible to in-scope employees; verify
   acknowledgment records.
3. Sample 3 standards; verify each traces to a policy.
4. Sample 3 procedures; verify each traces to a standard.
5. Review the exception register; verify approvals, review
   dates, remediation plans.

## 7. Anti-Patterns

- **Policy as legal shield.** The policy exists only to protect
  the organization in court. It does not reflect actual practice.
- **Policy without enforcement.** A policy no one enforces is a
  suggestion, not a policy.
- **Policy without training.** A policy no one understands is
  not effective.
- **Policy sprawl.** Hundreds of policies, overlapping,
  contradicting. No one knows which applies.
- **Policy shelfware.** The policy is published and never used.
  The auditor sees it; operations does not.
- **Selective enforcement.** Senior leaders are exempt; everyone
  sees the double standard.
- **Policy without exception path.** The first exception becomes
  a precedent, not a decision.
- **Policy drift.** The policy describes an organization that no
  longer exists.
- **Policy in the wrong language.** The policy is in a language
  the workforce cannot read.
- **Policy behind a login.** The policy is inaccessible to the
  people who need it.
- **Policy without consequence.** Non-compliance has no defined
  outcome; employees ignore the policy.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): policies,
  standards, procedures, guidelines; Domain 2 (Asset Security):
  data classification and handling.
- **CISM** - Domain 1 (Information Security Governance): policy
  framework.
- **CISA** - Domain 5 (Protection of Information Assets): policy
  design and implementation.
- **ISO 27001 LI/LA** - Clause 5.2 (Information security policy),
  Clause 7.5 (Documented information), Annex A.5.1 (Policies for
  information security), Annex A.5.10 (Acceptable use of
  information and other associated assets).
- **COBIT 2019** - APO01 (Managed I&T Management Framework),
  APO13 (Managed Security).

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 - Information security controls - https://www.iso.org/standard/75652.html
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-12 Rev. 1 - An Introduction to Information Security - https://csrc.nist.gov/pubs/sp/800/12/r1/final
- NIST SP 800-100 - Information Security Handbook: A Guide for Managers - https://csrc.nist.gov/pubs/sp/800/100/final
- NIST Cybersecurity Framework 2.0 - https://www.nist.gov/cyberframework
- ISACA - COBIT 2019 Framework - https://www.isaca.org/resources/cobit
- SANS Institute - Information Security Policy Templates - https://www.sans.org/INFORMATION_SECURITY-policy/
