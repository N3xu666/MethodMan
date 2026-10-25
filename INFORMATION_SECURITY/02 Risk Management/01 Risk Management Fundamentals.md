# Risk Management Fundamentals

Risk management is the systematic process of identifying, assessing,
treating and monitoring uncertainties that could affect organizational
objectives. In information security, the objective is the confidentiality,
integrity and availability of information assets.

## 1. Overview

Risk is the combination of the probability of an event and its
consequences. In information security, risk is typically expressed as:

```
Risk = Likelihood x Impact
```

Three components must be distinguished:

- **Asset** - anything of value to the organization (data, systems,
  people, reputation).
- **Threat** - a potential cause of an unwanted incident (actor,
  natural event, failure).
- **Vulnerability** - a weakness that a threat can exploit.

A **risk** exists only when a threat can exploit a vulnerability on an
asset with a measurable impact.

### Risk vs Issue vs Finding

- **Risk** - future, uncertain. "A SQL injection could lead to data loss."
- **Issue** - present, confirmed. "A SQL injection exists in production."
- **Finding** - the observation from an assessment. "A SQLi was found in
  the login form; CVSS 9.8."

Risk management is about the future. Issues are managed by operations.

## 2. Where in the Organization

Risk management is not owned by security alone. It is a **business
function** that security supports.

- **Board / executive** - owns risk appetite, approves treatment.
- **CISO** - owns the security risk register, reports to the board.
- **Risk owners** - business units accept risk for their assets.
- **Security team** - identifies, assesses, recommends treatment.
- **Internal audit** - verifies that risk management works.

The **three lines of defense** model:

1. **First line** - operational management (owns risk).
2. **Second line** - risk and compliance functions (oversee risk).
3. **Third line** - internal audit (independent assurance).

Security sits across the first and second lines depending on the
organization. It is never the third line.

## 3. Threats and Failure Modes

Risk identification must consider threats from every category:

### Threat Categories

- **Adversarial** - nation-state, organized crime, insider, hacktivist,
  script kiddie, competitor.
- **Accidental** - misconfiguration, human error, lost device,
  failed patch.
- **Environmental** - fire, flood, power failure, earthquake.
- **Structural** - hardware failure, software defect, dependency
  collapse, cloud provider outage.

### Failure Modes in Risk Management

The process itself fails in predictable ways:

- **Risk register rot** - entries never updated, owners leave, scores
  become fiction.
- **Checkbox compliance** - the register exists, nobody reads it,
  treatment plans are copy-paste.
- **Risk theater** - risks are re-labelled as "accepted" to avoid
  work, with no documented justification.
- **Siloed scoring** - different teams use different scales, so
  aggregate risk is meaningless.
- **Unquantified "High"** - a risk rated "High" with no defined impact
  or likelihood numbers cannot be compared or treated.
- **Never-closed risks** - risks stay "in progress" for years because
  closing them requires admitting failure.

## 4. Controls and Implementation

Risk treatment has four canonical options (ISO 31000):

1. **Mitigate** - reduce likelihood or impact (controls, hardening,
   redundancy).
2. **Transfer** - shift financial impact (insurance, contractual
   clauses, outsourced SLA).
3. **Avoid** - eliminate the activity that creates the risk.
4. **Accept** - acknowledge the risk and document the decision.

### Risk Register Structure

A useful register contains at minimum:

- Risk ID, title, description.
- Asset affected, business process.
- Threat source and vulnerability.
- Likelihood (scale + justification).
- Impact (scale + justification, in business terms).
- Inherent risk score.
- Existing controls.
- Residual risk score.
- Treatment option and plan.
- Risk owner (named person, not team).
- Target date and review date.
- Status (open, mitigated, accepted, closed).

### Control Categories

- **Preventive** - stop the event (firewall, access control, training).
- **Detective** - notice the event (SIEM, IDS, audit logs).
- **Corrective** - reduce impact after the event (backups, IR plan).
- **Deterrent** - discourage the actor (banners, legal action).
- **Compensating** - substitute when primary control is not feasible.

### Risk Appetite and Tolerance

- **Risk appetite** - how much risk the organization is willing to
  take in pursuit of objectives (strategic, board-approved).
- **Risk tolerance** - the acceptable variation from appetite for a
  specific category or asset.
- **Risk capacity** - the maximum risk the organization can absorb
  before failure.

These must be defined before scoring, otherwise prioritization is
arbitrary.

## 5. Tooling

Common tooling for risk management:

- **GRC platforms** - Archer, ServiceNow GRC, OneTrust, LogicGate.
  Enterprise-grade, expensive, integrate with controls frameworks.
- **Open source registers** - Eramba, SimpleRisk, RiskWatch.
  Sufficient for mid-size organizations.
- **Spreadsheets** - still the most common tool in practice. Use with
  a defined template; do not improvise per team.
- **Quantitative tools** - FAIR (Factor Analysis of Information Risk)
  via RiskLens, OpenFAIR, or custom Monte Carlo in Python/R.
- **Attack path tools** - XM Cyber, Pentera, BloodHound Enterprise
  (maps technical risk to business assets).

For a small team, start with a spreadsheet and a documented taxonomy.
Do not buy a GRC platform before the process exists.

## 6. Verification and Metrics

Risk management is verified by both process metrics and outcome
metrics. Neither alone is sufficient.

### Process Metrics

- **Register currency** - percentage of risks reviewed in the last
  quarter. Target: 100%.
- **Treatment timeliness** - percentage of treatment plans completed
  by target date. Target: >80%.
- **Owner coverage** - percentage of risks with a named owner.
  Target: 100%.
- **Assessment coverage** - percentage of critical assets with a
  current risk assessment. Target: 100%.

### Outcome Metrics

- **Residual risk trend** - aggregate residual risk over time.
  Should decrease or stay flat, not grow silently.
- **Incident-to-risk mapping** - percentage of incidents traceable
  to a known risk. Low percentage means the register is incomplete.
- **Control effectiveness** - percentage of controls verified as
  operating effectively in the last audit cycle.
- **Loss events** - realized losses vs predicted impact. Large gaps
  mean the scoring model is wrong.

### Verification Steps

1. Sample 10 risks; check owner, score justification, treatment
   status, last review date.
2. Trace 3 treatment plans to evidence of completion.
3. Compare 3 recent incidents against the register; every incident
   should map to a known risk or trigger a new entry.
4. Re-score 3 risks independently; compare with the recorded score.
   Divergence >1 level indicates inconsistent taxonomy.

## 7. Anti-Patterns

- **Scoring without a scale.** "High/Medium/Low" with no defined
  criteria means every analyst scores differently.
- **Risk owner = "the security team".** A team cannot accept risk;
  a named business person must.
- **Accepting risk without signature.** Acceptance without documented
  approval is not acceptance; it is neglect.
- **One-time assessment.** A risk register that is not reviewed is a
  historical document, not a management tool.
- **Conflating risk with vulnerability.** A vulnerability is a fact;
  a risk is a forecast. Ten low-risk vulnerabilities do not equal one
  high-risk vulnerability.
- **Ignoring aggregation.** Ten medium risks on the same asset can
  combine into one critical risk. Aggregate, do not just list.
- **Compliance as a proxy for risk.** Passing an audit does not mean
  the risk is managed; it means the audit passed.
- **Risk theater.** Reporting that "all risks are under control"
  without evidence destroys the credibility of the entire function.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): risk
  terminology, risk assessment, risk treatment, risk appetite,
  supply chain risk.
- **CISM** - Domain 2 (Information Risk Management): risk
  identification, assessment, treatment, monitoring, reporting.
- **CRISC** - Domain 1 (Governance), Domain 2 (IT Risk Assessment),
  Domain 3 (Risk Response and Reporting): the entire CRISC body of
  knowledge aligns with this file.
- **CISA** - Domain 5 (Protection of Information Assets): risk-based
  control selection.
- **ISO 27001 LI/LA** - Clause 6 (Planning), Clause 8 (Operation),
  Clause 9 (Performance evaluation).

## 9. References

- NIST SP 800-30 Rev. 1 - Guide for Conducting Risk Assessments - https://csrc.nist.gov/pubs/sp/800/30/r1/final
- NIST SP 800-39 - Managing Information Security Risk - https://csrc.nist.gov/pubs/sp/800/39/final
- ISO 31000:2018 - Risk Management Guidelines - https://www.iso.org/standard/65694.html
- ISO/IEC 27005:2022 - Information Security Risk Management - https://www.iso.org/standard/80585.html
- FAIR Institute - Factor Analysis of Information Risk - https://www.fairinstitute.org/
- Open Group - Risk Taxonomy (O-RT) Standard - https://www.opengroup.org/openfair
- CRISC Review Manual (ISACA) - no URL (printed reference)
