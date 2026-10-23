# Standards and Baselines

A standard is a mandatory requirement that satisfies a policy. A
baseline is the specific configuration state that satisfies a
standard for a given system class. Together they are the bridge
between management intent (policy) and operational execution
(procedure). A policy without a standard is aspirational. A standard
without a baseline is unmeasurable. A baseline without a standard is
arbitrary.

## 1. Overview

### Standard vs Baseline vs Procedure

- **Standard** - a mandatory requirement. "All data at rest must be
  encrypted with AES-256." Specific, measurable, technology-aware.
- **Baseline** - a specific configuration that satisfies the
  standard for a class of systems. "RHEL 9 workstations must have
  LUKS2 with AES-256-XTS on all non-boot partitions." The baseline
  is the standard applied to a concrete system.
- **Procedure** - the steps to bring a system into baseline
  compliance. "Run Ansible playbook hardening-rhel9.yml."

A standard has one or more baselines. A baseline has one or more
procedures. Every layer is traceable upward.

### Types of Standards

- **Technical standards** - specific technical requirements
  (cryptography, authentication, network segmentation). Usually
  measurable, often enforceable by configuration management.
- **Administrative standards** - process requirements (access
  reviews, background checks, training). Measurable via evidence.
- **Physical standards** - facility requirements (access control,
  environmental controls, visitor management). Measurable via
  inspection.
- **Data standards** - classification, labeling, retention,
  destruction. Measurable via inventory and audit.

Each type needs its own evidence model. A technical standard is
verified by scanning; an administrative standard by record review;
a physical standard by inspection; a data standard by data
inventory audit.

### What Makes a Standard Defensible

- **Traceable** - names the policy it implements.
- **Specific** - measurable, unambiguous. "Strong passwords" is not
  a standard; "minimum 12 characters, 4 character classes" is.
- **Testable** - can be verified. If you cannot test it, it is a
  wish.
- **Achievable** - the organization can comply with the resources
  available. An unachievable standard is a compliance trap.
- **Current** - reviewed on a cycle, updated when the environment
  changes.
- **Owned** - a named person is accountable.

## 2. Where in the Organization

Standards and baselines are owned by the function responsible for
the topic:

- **CISO** - owns the overall standard framework; ensures
  consistency across topics.
- **Security architecture** - owns technical standards (crypto,
  network, identity).
- **IT operations** - owns operational standards (patching,
  backup, monitoring).
- **HR** - owns administrative standards for employees (background
  checks, acceptable use).
- **Facilities** - owns physical standards (access control,
  environmental).
- **Data governance** - owns data standards (classification,
  retention).
- **Control owners** - implement the standard; produce evidence.
- **Internal audit** - verifies the standard is achieved.

### The Standard Owner

The standard owner is accountable for:

- **Content** - the standard accurately reflects the policy.
- **Currency** - the standard is reviewed on cycle and updated
  when needed.
- **Achievability** - the standard can be met with available
  resources.
- **Evidence** - the standard has a defined evidence model.
- **Exceptions** - exceptions are reviewed and decided.
- **Communication** - the standard is communicated to those who
  must comply.

An ownerless standard is a document, not a requirement.

## 3. Threats and Failure Modes

### Failure Modes of Standards

- **Vague standard** - "strong encryption", "secure configuration",
  "appropriate access". Not measurable, not testable, not
  enforceable.
- **Unachievable standard** - requires technology the organization
  does not have, or budget it cannot spend. Creates a permanent
  exception state.
- **Standard without baseline** - the standard says "encrypt at
  rest"; no baseline defines what that means on Windows vs Linux
  vs cloud. Implementation is inconsistent.
- **Baseline without standard** - the baseline exists but no one
  knows why. When the baseline is challenged, no policy or
  standard defends it.
- **Standard without evidence** - the standard exists; no one
  defined how compliance is demonstrated. The auditor asks; no
  one can produce.
- **Standard without owner** - no one reviews the standard; it
  drifts out of date.
- **Standard without exception path** - the first exception
  becomes a precedent; the standard is effectively dead.
- **Standard copied from another organization** - reflects that
  organization's risks, not ours. Either overkill or gap.
- **Standard as wish** - the standard is stated but no one is
  required to comply, no consequence for non-compliance.

### Failure Modes of Baselines

- **Baseline too strict** - all systems must be hardened to the
  maximum, including systems that do not need it. Breakage,
  exceptions, complaints.
- **Baseline too loose** - the baseline is minimal, provides
  little protection, and passes audit by technicality.
- **Baseline without exception handling** - a legitimate
  business need requires a deviation; there is no process. The
  system is either broken or non-compliant.
- **Baseline not automated** - the baseline is documented but not
  enforced by configuration management. Drift is invisible.
- **Baseline without drift detection** - the baseline is applied
  once; changes to the system are not detected. Drift accumulates.
- **Baseline without testing** - the baseline is applied but not
  tested; the system does not actually work as intended.
- **Baseline per system** - every system has its own baseline;
  the organization cannot scale.
- **Baseline out of date** - the baseline reflects an OS version
  two years old. New vulnerabilities are not addressed.

### Failure Modes of the Standard-Baseline Relationship

- **Orphan baseline** - the baseline does not trace to a
  standard. It is either a technical preference or an obsolete
  artifact.
- **Orphan standard** - the standard does not trace to a policy.
  It has no authority.
- **Version mismatch** - the standard is at version 3; the
  baseline reflects version 1. The baseline may not satisfy the
  standard.
- **Over-specific standard** - the standard names a specific
  vendor or product. When the vendor changes, the standard must
  change.
- **Under-specific standard** - the standard is so general it
  can be met by any baseline. It provides no real assurance.

## 4. Controls and Implementation

### Writing a Standard

Step 1. **Name the policy.** The standard exists to satisfy a
specific policy. State the policy explicitly.

Step 2. **Define scope.** Which systems, data, people, facilities
are in scope. Which are explicitly out of scope.

Step 3. **Define requirements.** Each requirement is specific,
measurable, testable. Use "must" for mandatory, "should" for
recommended.

Step 4. **Define evidence.** For each requirement, what artifact
proves compliance. Log, scan report, configuration export.

Step 5. **Define baselines.** For each system class in scope,
define the specific configuration that satisfies the standard.

Step 6. **Define exceptions.** How to request, who approves, how
often reviewed.

Step 7. **Define review cycle.** At least annually; more often if
the environment changes rapidly.

Step 8. **Publish and communicate.** The standard and its
baselines are accessible to those who must comply.

### The Standard Structure

```
Standard: <Name>
Version: <X.Y>
Owner: <Role>
Parent policy: <Policy name>
Scope: <in scope / out of scope>
Requirements:
  R1: <specific requirement>
      Evidence: <artifact>
      Baseline: <baseline name>
      Exceptions: <process link>
  R2: ...
Review cycle: <annually / semiannually>
References: <related standards, frameworks>
```

### The Baseline Structure

```
Baseline: <system class + version>
Version: <X.Y>
Owner: <Role>
Parent standard: <Standard name, requirement IDs>
Configuration:
  - <setting> = <value>
  - <setting> = <value>
Enforcement:
  - Tool: <Ansible / GPO / Intune / Terraform>
  - Schedule: <continuous / daily / on deploy>
Drift detection:
  - Tool: <scanner>
  - Schedule: <continuous>
Exceptions:
  - <system> = <deviation, approved by, review date>
Testing:
  - <test> = <expected result>
```

### Baseline Implementation

- **Automated enforcement** - configuration management
  (Ansible, Puppet, Chef), group policy, MDM (Intune, JAMF),
  cloud-native policy (AWS Config, Azure Policy, GCP
  Organization Policy).
- **Drift detection** - regular scanning against the baseline
  (OpenSCAP, Lynis, cloud-native scanners, CSPM).
- **Exception management** - deviations are documented,
  approved, time-bound, and reported.
- **Testing** - each baseline is tested in a lab before
  production deployment; the test result is retained as evidence.
- **Versioning** - the baseline has a version; changes are
  reviewed and documented.

### Common Baselines

Organizations rarely write baselines from scratch. Common
sources:

- **CIS Benchmarks** - per OS, database, cloud service. Widely
  used; well maintained.
- **DISA STIGs** - US Department of Defense. Very strict;
  often used in regulated sectors.
- **Microsoft Security Baselines** - for Windows and Microsoft
  products.
- **AWS Foundational Security Best Practices** - for AWS
  environments.
- **Azure Security Benchmark** - for Azure.
- **GCP Security Command Center** - for GCP.

The organization adopts a public baseline as the starting point,
adapts it to the environment, and documents the deviations.
Writing from scratch is a waste of effort.

## 5. Tooling

- **Configuration management** - Ansible, Puppet, Chef, SaltStack.
  Automated baseline enforcement.
- **Group policy and MDM** - Active Directory GPO, Microsoft
  Intune, JAMF Pro, Kandji. Baseline enforcement for endpoints.
- **Cloud-native policy** - AWS Config, Azure Policy, GCP
  Organization Policy, AWS Organizations SCPs. Baseline
  enforcement for cloud.
- **Container security** - OPA Gatekeeper, Kyverno, Trivy, Anchore.
  Baseline enforcement for container images.
- **Compliance scanners** - OpenSCAP, Lynis, CIS-CAT Pro,
  Qualys Policy Compliance. Drift detection.
- **CSPM** - Prisma Cloud, Wiz, Orca, Lacework. Cloud security
  posture management.
- **Benchmark sources** - CIS Benchmarks, DISA STIGs, vendor
  baselines. Content for the organization's baselines.
- **Documentation and versioning** - Git for technical
  standards, policy management platforms for administrative
  standards.

## 6. Verification and Metrics

### Verification of Standards

- **Traceability** - percentage of standards with a named parent
  policy. Target: 100%.
- **Ownership** - percentage of standards with a named owner.
  Target: 100%.
- **Measurability** - percentage of requirements that are
  specific and testable. Target: 100%.
- **Evidence defined** - percentage of requirements with a
  defined evidence artifact. Target: 100%.
- **Currency** - percentage of standards reviewed within the
  last 12 months. Target: 100%.
- **Achievability** - percentage of requirements met by at
  least 90% of in-scope systems.

### Verification of Baselines

- **Coverage** - percentage of in-scope system classes with a
  defined baseline. Target: 100%.
- **Enforcement automation** - percentage of baselines enforced
  by automated tooling. Target: >80%.
- **Compliance rate** - percentage of in-scope systems meeting
  their baseline. Target: >95%.
- **Drift detection** - percentage of systems scanned for
  drift within the defined cadence. Target: 100%.
- **Exception volume** - number of active exceptions per
  baseline; high count indicates the baseline does not fit the
  environment.
- **Exception review** - percentage of exceptions reviewed
  within the last 12 months. Target: 100%.
- **Baseline test** - percentage of baselines tested before
  deployment. Target: 100%.

### Metrics

- **Compliance trend** - baseline compliance rate over 4
  quarters.
- **Mean time to remediate drift** - days from drift detection
  to remediation.
- **Repeat drift** - percentage of systems with repeated drift.
  High = enforcement is not working.
- **Standards per policy** - average number of standards per
  policy. High = complexity; low = gaps.
- **Baselines per standard** - average number of baselines per
  standard. High = the standard is not technology-neutral; low =
  incomplete coverage.

### Common Verification Steps

1. Sample 5 standards; verify parent policy, owner, evidence,
   review date.
2. Sample 3 baselines; verify parent standard, enforcement
   mechanism, test result.
3. Sample 10 systems; verify baseline compliance; verify drift
   detection result.
4. Review the exception register; verify approvals, review
   dates, remediation plans.
5. Verify a recent standard or baseline change; verify it was
   reviewed, approved, communicated, and deployed.

## 7. Anti-Patterns

- **Vague standard.** "Strong encryption" is not a standard. It
  is a wish.
- **Unachievable standard.** The standard requires something the
  organization cannot do. It creates a permanent exception state.
- **Standard without baseline.** The standard says "harden
  systems"; no baseline defines what that means.
- **Baseline without standard.** The baseline exists without a
  mandate. When challenged, no one can defend it.
- **Standard without owner.** No one reviews, updates, or
  enforces the standard.
- **Standard without evidence.** The standard exists; no one
  defined how to verify compliance.
- **Standard without exception path.** The first exception
  becomes a precedent.
- **Baseline not automated.** The baseline is documented but not
  enforced. Drift is invisible.
- **Baseline without drift detection.** The baseline is applied
  once; changes are not detected.
- **Baseline too strict.** Breakage, exceptions, complaints.
- **Baseline out of date.** The baseline reflects an OS version
  two years old. New vulnerabilities are not addressed.
- **Standard copied from another organization.** Overkill or
  gap; not aligned to our risk.
- **Standard as wish.** The standard is stated but no one is
  required to comply.

## 8. Certification Alignment

- **CISSP** - Domain 3 (Security Architecture and Engineering):
  security models, control selection; Domain 6 (Security
  Assessment and Testing): verification.
- **CISM** - Domain 1 (Information Security Governance): standards
  framework.
- **CISA** - Domain 5 (Protection of Information Assets):
  standards and baselines.
- **ISO 27001 LI/LA** - Annex A.5.1 (Policies for information
  security), Annex A.8.9 (Configuration management), Annex A.8.7
  (Protection against malware), Annex A.8.20 (Networks security).
- **CISSP, CCSP** - Cloud baselines, configuration management.
- **CIS Benchmarks** - publicly available baseline content.
- **DISA STIGs** - baseline content for regulated sectors.

## 9. References

- ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements - https://www.iso.org/standard/27001
- ISO/IEC 27002:2022 - Information security controls - https://www.iso.org/standard/75652.html
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-70 Rev. 4 - National Checklist Program for IT Products - Guidelines for Checklist Users and Developers - https://csrc.nist.gov/pubs/sp/800/70/r4/final
- CIS Benchmarks - https://www.cisecurity.org/cis-benchmarks
- DISA Security Technical Implementation Guides (STIGs) - https://public.cyber.mil/stigs/
- Microsoft Security Baselines - https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- AWS Foundational Security Best Practices - https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html
- Azure Security Benchmark - https://learn.microsoft.com/en-us/security/benchmark/azure/
