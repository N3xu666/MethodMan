# Policy Hierarchy and Architecture

A policy architecture is the deliberate structure of the organization's
documented requirements: which documents exist, how they relate, who
owns each, and how they trace from board intent down to operational
procedure. An architecture that is not deliberate becomes policy
sprawl - hundreds of documents, overlapping, contradicting, owned by
no one. An architecture that is deliberate is small, traceable and
maintained.

## 1. Overview

### The Five Layers

A defensible policy architecture has five layers:

- **Charter** - the board's mandate for the security program. Rarely
  a standalone document; often part of the governance framework.
- **Policy** - management's intent. What is required and why. 1-10
  pages. Board or executive approval.
- **Standard** - mandatory requirements that satisfy the policy.
  Specific, measurable, technical or administrative.
- **Procedure** - step-by-step instructions for executing a
  standard. Operational.
- **Guideline** - advisory recommendations. Not mandatory.

Each layer traces upward: a procedure exists because a standard
requires it, a standard exists because a policy requires it, a
policy exists because the charter mandates it. A document that
cannot trace to the layer above is orphan; a document that cannot
be traced to from the layer below is unimplemented.

### Traceability

Traceability is the property that makes a policy architecture
defensible:

- **Upward trace** - every document names the parent document.
- **Downward trace** - every requirement in the parent is
  addressed by at least one child document.
- **Cross trace** - related documents reference each other.
- **Version trace** - every document records its version history
  and approval.

Without traceability, the architecture is a folder of documents,
not a system.

### Scope Boundaries

Each policy must define its scope:

- **Organizational** - applies to all employees, contractors,
  vendors.
- **Geographic** - applies to specific jurisdictions.
- **System** - applies to specific classes of systems.
- **Data** - applies to specific data classes.

A policy without a scope is either too broad (unmanageable) or
too narrow (gaps). The scope must be explicit and match the
organization's structure.

## 2. Where in the Organization

The policy architecture is maintained by a policy owner:

- **Board** - approves the top-level policy and the architecture
  itself.
- **CISO** - owns the architecture; ensures the layers are
  coherent, traceable and maintained.
- **Policy owner** - an executive accountable for a specific
  policy and its children (standards, procedures, guidelines).
- **Policy administrator** - the role that maintains version
  control, review cycles, publication, acknowledgment.
- **Control owner** - the operational role that implements the
  standard and follows the procedure.
- **Internal audit** - validates the architecture; identifies
  orphans and gaps.

### Architecture Review

The architecture itself is reviewed annually:

- **Coherence** - do the layers trace to each other?
- **Coverage** - is every critical topic covered by at least one
  policy?
- **Consistency** - do overlapping policies contradict each
  other?
- **Currency** - are the documents current?
- **Complexity** - has the architecture grown beyond what the
  organization can maintain?

The review is an architecture exercise, not a document edit. It
looks at the system, not the individual documents.

## 3. Threats and Failure Modes

### Failure Modes of Architecture

- **No architecture** - documents exist in a folder with no
  structure. No one knows which policy applies to which topic.
- **Flat architecture** - every document is called a "policy".
  There are no standards, no procedures, no guidelines. The
  policies are either vague (no execution) or overly detailed
  (no authority).
- **Orphan documents** - a standard exists without a parent
  policy; a procedure exists without a parent standard. The
  document has no authority.
- **Unimplemented policies** - a policy exists; no standard or
  procedure implements it. The policy is aspirational.
- **Duplicate coverage** - the same topic is covered by two or
  three policies with different requirements. The control owner
  cannot know which applies.
- **Contradiction** - two policies require opposite things. The
  control owner chooses one and violates the other.
- **Policy sprawl** - hundreds of documents, many outdated, many
  overlapping. The architecture has grown beyond what the
  organization can maintain.
- **Architecture without owner** - no one is accountable for the
  architecture; documents accumulate; no one prunes.

### Failure Modes of Traceability

- **No upward references** - the document does not name its
  parent. The reader cannot verify authority.
- **No downward references** - the parent does not reference the
  children. The reader cannot find the execution.
- **Broken references** - the parent references a child that no
  longer exists, or a child references a parent that has been
  superseded.
- **Version mismatch** - the parent is at version 3; the child is
  built against version 1. The child may not satisfy the current
  parent.
- **Cross-reference drift** - related documents reference each
  other; when one changes, the other is not updated.

### Failure Modes of Scope

- **Scope creep** - the scope of a policy grows to cover
  everything, making it unmanageable.
- **Scope gap** - the policy omits something important (e.g.
  cloud, contractors, third parties).
- **Scope mismatch** - the policy claims to apply globally but
  only reflects one jurisdiction's requirements.
- **Scope ambiguity** - the policy says "the organization" but
  does not specify whether that includes subsidiaries, joint
  ventures, contractors.

## 4. Controls and Implementation

### Designing the Architecture

Step 1. **Identify the mandatory topics.** From the risk
assessment and the obligation inventory, list every topic that
requires a policy (information security, acceptable use, access
control, data classification, incident response, business
continuity, third-party risk, risk management, cryptography,
physical security).

Step 2. **Define the top-level policy.** The Information Security
Policy, board-approved, sets the mandate for all the topic
policies.

Step 3. **Define the topic policies.** One policy per topic.
Each names its scope, its requirements, its exceptions path, its
consequences.

Step 4. **Define the standards.** For each policy, define the
mandatory requirements that satisfy it. Standards are specific,
measurable, technical or administrative.

Step 5. **Define the procedures.** For each standard, define the
procedures that execute it.

Step 6. **Identify guidelines.** For topics where judgment is
required, define guidelines. Guidelines are advisory.

Step 7. **Document the traceability.** Every document names its
parent; every parent references its children. Cross-references
between related documents are recorded.

Step 8. **Define ownership.** Each document has a named owner, a
named approver, a review cycle.

Step 9. **Publish.** One authoritative location for all
documents, with version control and search.

### The Policy Map

A useful artifact is a policy map:

```
Information Security Policy (board)
    |
    +-- Acceptable Use Policy
    |       +-- Standard: Email and Messaging
    |       +-- Standard: Social Media
    |       +-- Guideline: Personal Devices
    |
    +-- Access Control Policy
    |       +-- Standard: Authentication
    |       +-- Standard: Authorization
    |       +-- Procedure: Onboarding / Offboarding
    |
    +-- Data Classification Policy
    |       +-- Standard: Classification Labels
    |       +-- Standard: Encryption
    |       +-- Procedure: Data Handling
    |
    +-- Incident Response Policy
    |       +-- Standard: Incident Severity
    |       +-- Procedure: Incident Response Plan
    |
    +-- Business Continuity Policy
            +-- Standard: RTO/RPO
            +-- Procedure: Disaster Recovery Plan
```

The map is the architecture's single-page summary. It shows what
exists, how it traces, and where the gaps are.

### Architecting for Change

The architecture must survive:

- **Technology change** - describe requirements, not tools. A
  policy that requires "encryption using AES-256" will outlast a
  policy that requires "use KMS".
- **Regulatory change** - the topic policies are stable; the
  standards change when the regulation does.
- **Organizational change** - the owners change; the architecture
  maps roles, not names.
- **Business change** - the policies reflect the current
  business; when the business changes, the architecture is
  reviewed.

### Retiring Documents

A document is retired when:

- It is no longer applicable to the organization's operations.
- Its topic is covered by a successor document.
- Its implementation is no longer possible or desirable.

Retirement is deliberate: the document is marked superseded,
its references are updated, and its content is archived. A
retired document that is not marked is a source of confusion.

## 5. Tooling

- **Policy management platforms** - PolicyTech (NAVEX), ConvergePoint,
  MetaCompliance, PowerDMS, Onspring. Support the hierarchy, trace
  links, version control, approval workflow, publication.
- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate.
  Policy module integrated with risk, controls, compliance.
- **Document management** - SharePoint with metadata, Confluence
  with page hierarchy, Google Drive with folders. Adequate for
  smaller organizations.
- **Diagram tools** - Lucidchart, Draw.io, Visio. For the policy
  map and architecture diagrams.
- **Git-backed architecture** - for technical policies (cloud,
  infrastructure, security engineering), version control in Git
  with pull-request review. The policy map is a markdown file
  alongside the documents.
- **Search and discovery** - enterprise search (Coveo, Lucidworks)
  that indexes policies and their metadata.

## 6. Verification and Metrics

### Verification of the Architecture

- **Traceability completeness** - percentage of documents with a
  named parent and named children. Target: 100%.
- **Coverage** - percentage of mandatory topics with a policy.
  Target: 100%.
- **Orphan count** - documents without a parent or without
  children. Target: 0.
- **Contradiction count** - overlapping policies with contradictory
  requirements. Target: 0.
- **Version match** - percentage of child documents built against
  the current parent version. Target: 100%.
- **Ownership completeness** - percentage of documents with a
  named owner and approver. Target: 100%.
- **Currency** - percentage of documents reviewed within the last
  12 months. Target: 100%.
- **Architecture review** - has the architecture been reviewed in
  the last 12 months?

### Metrics

- **Documents per layer** - policies, standards, procedures,
  guidelines. Ratio indicates maturity.
- **Documents per topic** - a topic with 10 procedures and no
  policy indicates a gap in the parent.
- **Average age** - by layer; older documents are more likely to
  be stale.
- **Change frequency** - by layer; high change frequency in
  standards is normal; high in policies indicates instability.
- **Exception volume** - exceptions per policy; a high count
  indicates the policy does not fit reality.

### Common Verification Steps

1. Sample 5 policies; verify each has a named owner, approver,
   version and last review date.
2. Sample 5 standards; verify each names its parent policy;
   verify the parent references the standard.
3. Sample 3 procedures; verify each names its parent standard.
4. Verify the policy map is current; verify it matches the
   documents in the repository.
5. Verify no orphan documents exist; verify no contradictions
   exist in overlapping policies.

## 7. Anti-Patterns

- **Flat policy set.** Every document is a "policy". No
  standards, no procedures. The policies are either vague or
  overly detailed.
- **Policy without standard.** The policy states a requirement
  that no standard implements. The policy is aspirational.
- **Standard without policy.** The standard is a technical
  document without authority. When the standard is challenged,
  there is no mandate to back it.
- **Procedure without standard.** The procedure exists; no one
  knows why. When the procedure changes, no one knows what
  requirement it satisfies.
- **Orphan document.** A document that traces to nothing. It
  is either obsolete or missing its parent; either way, it is
  confusing.
- **Duplicate coverage.** Two policies on the same topic with
  different requirements. The control owner cannot comply with
  both.
- **Policy sprawl.** Hundreds of documents, many outdated, many
  overlapping. The architecture has grown beyond what the
  organization can maintain.
- **No architecture owner.** No one is accountable for the
  architecture; documents accumulate; no one prunes.
- **Architecture as diagram only.** The map exists; the documents
  are not maintained to match it. The map becomes fiction.
- **Frozen architecture.** The architecture is defined once and
  never reviewed. The business changes; the architecture does
  not.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): policies,
  standards, procedures, guidelines; the hierarchical relationship.
- **CISM** - Domain 1 (Information Security Governance): policy
  architecture, governance alignment.
- **CISA** - Domain 5 (Protection of Information Assets): policy
  design and implementation.
- **ISO 27001 LI/LA** - Clause 5.2 (Information security policy),
  Clause 7.5 (Documented information), Annex A.5.1 (Policies for
  information security), Annex A.5.37 (Documented operating
  procedures).
- **COBIT 2019** - APO01 (Managed I&T Management Framework),
  APO13 (Managed Security).

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 - Information security controls - https://www.iso.org/standard/75652.html
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-12 Rev. 1 - An Introduction to Information Security - https://csrc.nist.gov/pubs/sp/800/12/r1/final
- NIST SP 800-100 - Information Security Handbook: A Guide for Managers - https://csrc.nist.gov/pubs/sp/800/100/final
- ISACA - COBIT 2019 Framework - https://www.isaca.org/resources/cobit
- SANS Institute - Information Security Policy Templates - https://www.sans.org/information-security-policy/
