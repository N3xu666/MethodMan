# Third-Party and Supply Chain Risk

Third-party risk is the risk that a supplier, vendor or partner fails
to meet obligations, introduces vulnerabilities, or becomes a vector
for attack. Supply chain risk extends this to the full chain of
components, services and dependencies - including software, hardware
and data. In modern organizations, third-party risk is often the
largest single category in the risk register.

## 1. Overview

### Third Party vs Supply Chain

- **Third-party risk** - a direct relationship with a vendor, partner
  or service provider. The organization has a contract, a contact and
  some leverage.
- **Supply chain risk** - the chain of dependencies behind that
  vendor, and behind their vendors. The organization may have no
  direct relationship, no contract and no visibility.

A vendor can be secure and still have an insecure supply chain. A
supply chain can be secure and still be compromised through a single
weak vendor. Both must be assessed.

### Categories of Third-Party Risk

- **Strategic** - the vendor fails as a business (bankruptcy,
  acquisition, exit from market).
- **Operational** - the vendor fails to deliver service (outage, SLA
  breach, quality).
- **Security** - the vendor is breached and exposes the
  organization's data or systems.
- **Compliance** - the vendor fails to meet regulatory obligations
  (GDPR, HIPAA, PCI DSS).
- **Reputational** - the vendor's actions damage the organization's
  brand.
- **Concentration** - too much dependence on one vendor (single point
  of failure).

### The Shared Responsibility Model

In cloud and SaaS, security responsibilities are split between the
customer and the provider. The split depends on the service model:

- **IaaS** - provider secures the infrastructure; customer secures
  the OS, runtime, applications and data.
- **PaaS** - provider secures up to the runtime; customer secures
  applications and data.
- **SaaS** - provider secures everything up to the application;
  customer secures data, identity and configuration.

A common failure is assuming the provider covers more than they do.

## 2. Where in the Organization

Third-party risk is a cross-functional function:

- **Procurement** - owns the vendor relationship, negotiates
  contracts, runs the vendor lifecycle.
- **Legal** - owns contractual terms, liability, data protection
  clauses, indemnity.
- **Security** - assesses vendor security posture, reviews
  attestations, runs questionnaires.
- **Risk management** - integrates vendor risk into the enterprise
  risk register.
- **Business owner** - the internal person who uses the vendor
  service and accepts the residual risk.
- **Compliance** - maps vendor obligations to regulatory
  requirements.

### Vendor Lifecycle

1. **Selection** - business need, market scan, initial screening.
2. **Due diligence** - security, financial, legal, compliance
   assessment.
3. **Contracting** - negotiate security and data protection terms.
4. **Onboarding** - integration, access provisioning, data transfer.
5. **Monitoring** - ongoing assessment, incident notification,
   attestation review.
6. **Renewal / offboarding** - re-assessment before renewal, data
   return or destruction at exit.

Each stage has its own risk controls. Skipping any stage leaves a gap.

## 3. Threats and Failure Modes

### Third-Party Failure Modes

- **Concentration risk** - critical operations depend on one vendor
  with no alternative. An outage becomes a business outage.
- **Vendor breach as own breach** - the vendor is compromised;
  organizational data is exposed. The organization's incident
  response must cover the vendor.
- **Sub-processor blindness** - the vendor uses sub-processors that
  the organization has not assessed or approved.
- **Contract gap** - the contract lacks security obligations,
  incident notification timelines, data protection clauses or audit
  rights.
- **Attestation drift** - the vendor was certified at onboarding,
  but the certificate is now expired or the scope has changed.
- **Access creep** - the vendor has more access than needed, or
  access that was not removed after the project ended.
- **Fourth-party risk** - the vendor's vendor fails, and the
  organization inherits the impact with no visibility.

### Supply Chain Failure Modes

- **Dependency confusion** - a malicious package with the same name
  as an internal package is published to a public registry.
- **Typosquatting** - a malicious package with a name similar to a
  popular package is published.
- **Compromised maintainer** - an attacker gains control of a
  legitimate package's maintainer account and publishes a malicious
  version.
- **Abandoned dependency** - a critical dependency is no longer
  maintained; vulnerabilities accumulate.
- **Build system compromise** - the build pipeline is compromised,
  and artifacts are backdoored before distribution (SolarWinds).
- **Hardware implant** - a hardware component is tampered with
  before delivery.
- **Logistics interception** - a shipment is intercepted and
  modified in transit.

### Real-World Cases

- **SolarWinds (2020)** - build system compromise; backdoored update
  distributed to 18,000 customers, including US government agencies.
- **Log4Shell (2021)** - vulnerability in a ubiquitous Java logging
  library; exposed millions of systems worldwide.
- **Codecov (2021)** - bash uploader script compromised; CI secrets
  exfiltrated from customers.
- **xz-utils (2024)** - backdoor inserted by a long-term contributor
  in the build scripts; nearly shipped in major Linux distributions.
- **3CX (2023)** - desktop client backdoored via a compromised
  build environment, distributed to customers.

These cases illustrate the two dimensions: a single vulnerable
dependency (Log4Shell) and a compromised build/distribution chain
(SolarWinds, 3CX, xz-utils).

## 4. Controls and Implementation

### Vendor Due Diligence

Minimum due diligence for any vendor that handles organizational
data or has network access:

- **Security questionnaire** - CAIQ, SIG, or custom, depending on
  vendor criticality.
- **Attestation review** - SOC 2 Type II, ISO 27001 certificate,
  PCI DSS AOC. Verify scope, period and auditor.
- **Financial health** - credit check, public filings, news.
- **Legal review** - data protection clauses, liability, indemnity,
  audit rights, sub-processor list, breach notification.
- **Reference checks** - for critical vendors, ask other customers.
- **Penetration test report** - for high-criticality vendors, request
  a recent third-party test summary.

### Contractual Controls

Contracts must include:

- **Security obligations** - baseline controls the vendor must
  maintain.
- **Breach notification** - timeframe (e.g. 24 or 72 hours), content,
  contact.
- **Audit rights** - right to audit or to receive audit reports.
- **Data protection** - data location, encryption, retention,
  deletion, sub-processor approval.
- **Sub-processor list** - named, with change notification.
- **Liability and indemnity** - for breach-related losses.
- **Termination and exit** - data return, destruction, transition
  assistance.

Absence of any of these is a finding to record against the vendor.

### Supply Chain Controls

- **SBOM (Software Bill of Materials)** - machine-readable list of
  components and versions in a product. Required by US Executive
  Order 14028 for federal suppliers.
- **Dependency pinning** - exact versions, no floating ranges.
- **Lockfiles** - committed to version control, reviewed on change.
- **Private registries** - internal packages hosted privately, with
  upstream proxy and allowlist.
- **Signed artifacts** - Sigstore, cosign, GPG-signed releases.
- **Provenance attestation** - SLSA framework, in-toto attestations.
- **Build isolation** - hermetic builds, reproducible builds.
- **Vulnerability scanning** - SCA tools (Dependabot, Snyk, Trivy,
  Grype) on every build.
- **Vendor access controls** - least privilege, time-bound access,
  just-in-time provisioning, access review.

### Monitoring

- **Continuous attestation monitoring** - vendors' certifications
  expire; track them.
- **Security rating services** - BitSight, SecurityScorecard,
  RiskRecon provide external posture signals.
- **Breach notification feeds** - Have I Been Pwned, vendor
  disclosures, threat intelligence.
- **Access reviews** - quarterly for critical vendors, annual for
  others.
- **Concentration analysis** - at least annually, review the
  portfolio for single points of failure.

## 5. Tooling

- **TPRM platforms** - OneTrust, Prevalent, ProcessUnity, Whistic,
  Vanta, Drata. Manage questionnaires, attestations, monitoring.
- **Security rating services** - BitSight, SecurityScorecard,
  RiskRecon, UpGuard. External posture scoring without questionnaires.
- **SBOM generation** - Syft, CycloneDX, SPDX, Trivy. Generate
  SBOMs for software products.
- **SBOM consumption** - Dependency-Track, OWASP Dependency-Check.
  Continuously monitor SBOMs for new vulnerabilities.
- **SCA (Software Composition Analysis)** - Snyk, Mend (WhiteSource),
  Sonatype, Black Duck. Detect vulnerable dependencies.
- **Artifact signing** - Sigstore, cosign, GPG, Notary.
- **Provenance attestation** - SLSA framework, in-toto.
- **Vendor access management** - CyberArk, BeyondTrust, Okta
  Privileged Access. Time-bound, audited vendor access.

## 6. Verification and Metrics

### Verification of Vendor Risk

- **Attestation validity** - sample 10 vendors; check the
  certificate/attestation is current and in scope.
- **Contract coverage** - sample 5 contracts; verify security,
  breach notification, audit rights, sub-processor clauses.
- **Access review completion** - verify the last review happened and
  was documented.
- **Questionnaire currency** - sample 10 vendors; the assessment is
  less than 12 months old for critical vendors.
- **Incident notification test** - for critical vendors, verify the
  breach notification path works.

### Verification of Supply Chain

- **SBOM coverage** - percentage of critical software with a current
  SBOM.
- **Dependency review** - percentage of dependency changes that went
  through review.
- **Signed artifact coverage** - percentage of distributed artifacts
  that are signed.
- **Known vulnerabilities in dependencies** - open vulnerabilities
  by severity, with age.
- **Provenance coverage** - percentage of builds with SLSA level 2
  or above.

### Metrics

- **Vendor inventory coverage** - percentage of vendors in the
  register with an assigned owner and assessment.
- **Critical vendor assessment cadence** - percentage assessed in
  the last 12 months.
- **Open findings by severity** - vendor findings not yet remediated.
- **Time to remediate vendor findings** - days from identification
  to closure.
- **Concentration index** - for each critical business process, the
  number of viable vendors. Target: >1 for critical processes.
- **Fourth-party visibility** - percentage of critical vendors with
  a published sub-processor list.

### Common Verification Steps

1. Pick 10 vendors; verify owner, assessment date, attestation,
   contract clauses.
2. Trace 3 vendor access grants; verify they are time-bound and
   documented.
3. Review the last concentration analysis; verify alternatives exist
   for critical processes.
4. Sample 5 SBOMs; verify they cover the deployed versions.

## 7. Anti-Patterns

- **Onboarding-only assessment.** Vendors are assessed once, then
  never again. Attestations expire, vendors change, risk drifts.
- **Questionnaire theatre.** Long questionnaires are sent, filled
  in by the vendor's sales team, and filed without review.
- **Trust the brand.** Big-name vendors can be breached (SolarWinds,
  3CX). Brand is not a control.
- **Trust the certificate.** The certificate covers a scope; the
  organization's data may be outside that scope.
- **Skip the contract.** A perfect security questionnaire is
  worthless if the contract has no security obligations.
- **Ignore sub-processors.** The vendor's vendor is the organization's
  risk. Require a sub-processor list and change notification.
- **Access without expiration.** Vendor accounts that never expire
  become permanent backdoors.
- **Dependency pinning without monitoring.** Pinned versions still
  develop vulnerabilities. Monitor, do not just freeze.
- **SBOM as a checkbox.** An SBOM that is generated but not
  consumed provides no security value.
- **No exit plan.** When the vendor fails or the contract ends, data
  return and transition assistance must be pre-agreed.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): supply chain
  risk management, third-party risk.
- **CISM** - Domain 2 (Information Risk Management): third-party
  risk, vendor management.
- **CRISC** - Domain 2 (IT Risk Assessment): third-party risk,
  supply chain risk.
- **CISA** - Domain 5 (Protection of Information Assets):
  vendor management, third-party assurance.
- **CySA+** - Domain 1 (Security Operations): supply chain threats,
  dependency management.
- **ISO 27001 LI/LA** - Annex A.5.19 (Information security in
  supplier relationships), A.5.20 (Addressing information security
  within supplier agreements), A.5.21 (Managing information security
  in the ICT supply chain), A.5.22 (Monitoring, review and change
  management of supplier services), A.5.23 (Information security
  for use of cloud services).
- **CIPP/E, CIPT** - GDPR data processing agreements, cross-border
  transfers.

## 9. References

- NIST SP 800-161 Rev. 1 - Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations - https://csrc.nist.gov/pubs/sp/800/161/r1/final
- NIST SP 800-218 - Secure Software Development Framework (SSDF) - https://csrc.nist.gov/pubs/sp/800/218/final
- ISO/IEC 27036-1:2021 - Information security for supplier relationships - Overview and concepts - https://www.iso.org/standard/82648.html
- ISO/IEC 27036-2:2022 - Information security for supplier relationships - Requirements - https://www.iso.org/standard/82648.html
- ISO/IEC 27036-3:2023 - Information security for supplier relationships - Guidelines for ICT supply chain security - https://www.iso.org/standard/82648.html
- US Executive Order 14028 - Improving the Nation's Cybersecurity - https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
- CISA - Cyber Supply Chain Risk Management - https://www.cisa.gov/topics/cyber-threats-and-advisories/supply-chain
- SLSA (Supply-chain Levels for Software Artifacts) - https://slsa.dev/
- Sigstore - Software signing and transparency - https://www.sigstore.dev/
- Cloud Security Alliance - Consensus Assessments Initiative Questionnaire (CAIQ) - https://cloudsecurityalliance.org/artifacts/caiq
