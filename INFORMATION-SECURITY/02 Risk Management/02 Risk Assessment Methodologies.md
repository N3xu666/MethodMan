# Risk Assessment Methodologies

A risk assessment methodology is a structured process for identifying,
analyzing and evaluating risk. The methodology defines what data is
collected, how it is scored, and how the output feeds into treatment
decisions. Choosing the wrong methodology is a common cause of
risk-management failure.

## 1. Overview

Risk assessment answers three questions:

1. What can go wrong? (identification)
2. How likely is it, and how bad would it be? (analysis)
3. What should we do about it? (evaluation)

### Qualitative vs Quantitative vs Semi-Quantitative

- **Qualitative** - uses ordinal scales ("Low/Medium/High"). Fast,
  intuitive, useful for triage and communication. Weak for aggregation
  and cost-benefit analysis.
- **Quantitative** - uses monetary values and probabilities (e.g.
  Annualized Loss Expectancy). Rigorous, comparable, requires data.
  Expensive to produce.
- **Semi-quantitative** - assigns numeric values to ordinal bands
  (e.g. Low=1, Medium=2, High=3). Combines speed with some
  comparability. Most common in practice.

### Risk Analysis vs Risk Evaluation

- **Risk analysis** - determine the level of risk (score).
- **Risk evaluation** - compare the level against risk criteria to
  decide whether treatment is required.

The methodology must cover both, or the score has no consequence.

## 2. Where in the Organization

Risk assessment is performed at three levels:

- **Strategic** - annual, board-level, focuses on business objectives
  and top risks. Uses aggregated data from operational assessments.
- **Tactical** - quarterly, business-unit level, focuses on processes
  and projects. Uses threat intelligence and control assessments.
- **Operational** - continuous, system level, focuses on technical
  vulnerabilities, incidents and changes. Uses scanners, SIEM, IR.

The methodology must specify which level it applies to. A methodology
designed for strategic assessments is too coarse for operational use,
and vice versa.

## 3. Threats and Failure Modes

### Common Methodologies

- **NIST SP 800-30** - US government standard. Nine-step process:
  prepare, conduct (identify, analyze, evaluate), communicate, and
  maintain. Strong on threat sources and likelihood.
- **ISO/IEC 27005** - international standard aligned with ISO 27001.
  Risk-centric, flexible on method. Pairs well with ISO 27001 ISMS.
- **FAIR (Factor Analysis of Information Risk)** - quantitative.
  Models risk as the probability and magnitude of loss events.
  Requires asset valuation and loss data.
- **OCTAVE (Operationally Critical Threat, Asset, and Vulnerability
  Evaluation)** - Carnegie Mellon. Three variants (OCTAVE-S,
  OCTAVE-Allegro, OCTAVE). Asset-driven, workshop-based.
- **CRAMM** - UK-origin, asset/impact-based. Used in government.
- **CORAS** - model-based, uses UML diagrams. Academic origin,
  practical for complex systems.
- **COBIT** - IT governance framework with risk components. Not a
  pure risk methodology; used for IT risk alignment.

### Failure Modes of Assessment

- **Methodology shopping** - choosing a methodology based on the
  desired answer, not on fit.
- **Scale inflation** - everything becomes "Critical" because no
  calibration exists between assessors.
- **Missing threat data** - likelihood is guessed without threat
  intelligence or historical incidents.
- **Missing asset context** - technical findings scored without
  knowing what the asset supports.
- **No re-assessment trigger** - assessments happen once, then the
  asset changes and the score is stale.
- **Assessor bias** - the team that built the system assesses it and
  finds it low-risk.

## 4. Controls and Implementation

### Selecting a Methodology

Criteria for selection:

- **Regulatory fit** - does a regulator mandate a specific method?
- **Data availability** - can the organization supply the inputs?
- **Scale** - is the method usable across the whole estate?
- **Comparability** - can outputs be aggregated and compared?
- **Cost** - does the rigor justify the effort?
- **Skill** - does the team have the expertise to apply it?

A common pattern: **FAIR for top risks**, **NIST SP 800-30 or
ISO 27005 for the broader portfolio**, **qualitative scoring for
triage**.

### Assessment Process Steps

1. **Scope** - define the assets, processes and boundaries.
2. **Asset identification and valuation** - what is at stake, in
   business terms.
3. **Threat identification** - sources, actors, events.
4. **Vulnerability identification** - weaknesses that threats can
   exploit.
5. **Control assessment** - what mitigations exist, how effective.
6. **Likelihood determination** - probability of a loss event.
7. **Impact determination** - consequence if the event occurs.
8. **Risk calculation** - combine likelihood and impact.
9. **Risk evaluation** - compare with criteria.
10. **Documentation and communication** - record and report.
11. **Re-assessment trigger** - define when to revisit.

### Scoring Scales

A defensible scale must have:

- **Defined criteria per level** - not just labels.
- **Calibration examples** - what a "Medium" looks like.
- **Independence between levels** - no overlap.
- **Consistent application** - same scale across teams.

Example 5x5 matrix:

```
Likelihood / Impact   1 Negligible  2 Minor   3 Moderate  4 Major   5 Severe
1 Rare                Low            Low        Low         Medium    Medium
2 Unlikely            Low            Low        Medium      Medium    High
3 Possible            Low            Medium     Medium      High      High
4 Likely              Medium         Medium     High        High      Critical
5 Almost Certain      Medium         High       High        Critical  Critical
```

Without defined criteria for each cell, the matrix is decoration.

## 5. Tooling

- **Spreadsheet templates** - NIST, ISO and FAIR all publish
  spreadsheet templates. Sufficient for most mid-size assessments.
- **FAIR tools** - RiskLens, OpenFAIR, FAIR-U (free). Quantitative
  modeling with Monte Carlo simulation.
- **GRC platforms** - ServiceNow GRC, Archer, OneTrust. Integrate
  assessment workflow with register and controls.
- **Threat intelligence** - MITRE ATT&CK, CISA KEV, commercial feeds.
  Supply likelihood data for threat-driven assessments.
- **Vulnerability scanners** - Qualys, Tenable, Rapid7. Supply
  vulnerability data, not risk data; must be combined with asset
  context.
- **Attack path modeling** - XM Cyber, Pentera, BloodHound Enterprise.
  Map technical paths to business assets.
- **Custom scripts** - Python with pandas for portfolio aggregation
  and Monte Carlo simulation of loss distributions.

## 6. Verification and Metrics

### Verification of the Methodology

- **Inter-rater reliability** - two assessors score the same asset
  independently; divergence >1 level indicates a methodology problem.
- **Back-testing** - compare predicted likelihood with observed
  incidents over 12 months.
- **Sensitivity analysis** - vary inputs; the output should change
  proportionally, not chaotically.
- **Traceability** - every score must trace to a documented input
  (threat source, asset value, control status).

### Metrics of the Assessment Process

- **Coverage** - percentage of in-scope assets assessed.
- **Currency** - percentage of assessments reviewed in the last cycle.
- **Cycle time** - average time from scope to signed-off output.
- **Reuse** - percentage of assessments that reference prior work
  instead of starting from scratch.
- **Downstream use** - percentage of treatment decisions traceable
  to an assessment.

### Common Verification Steps

1. Pick 5 assessments; verify each score has documented inputs.
2. Re-score 2 assessments independently; compare.
3. Trace 3 treatment plans back to the assessment that justified them.
4. Compare 3 incidents in the last year with the register; missing
   entries mean the methodology missed a threat.

## 7. Anti-Patterns

- **CVSS as risk.** CVSS is a severity score, not a risk score. It
  lacks asset value, threat context and business impact.
- **One-size-fits-all.** Using the same method for a payment system
  and an internal wiki is waste or negligence, depending on direction.
- **Assessor as judge.** The team that runs the assessment should not
  also accept the residual risk.
- **Pre-filled spreadsheets.** Templates populated by guesswork to
  satisfy an auditor are worse than no assessment: they create false
  confidence.
- **No calibration.** Without calibration examples, "High" means
  different things to different people.
- **Ignoring aggregation.** Individual risks scored correctly can
  combine into a portfolio risk the methodology does not see.
- **Assessment without action.** An assessment that does not change
  a decision is documentation, not management.
- **Static methodology.** Threats, assets and controls change; a
  methodology that is not revisited annually becomes fiction.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): risk
  assessment concepts, methodologies, quantitative and qualitative
  analysis.
- **CISM** - Domain 2 (Information Risk Management): risk
  identification, analysis, evaluation.
- **CRISC** - Domain 2 (IT Risk Assessment): risk assessment
  process, analysis techniques, data collection.
- **CISA** - Domain 5 (Protection of Information Assets): risk-based
  control evaluation.
- **ISO 27001 LI/LA** - Clause 6.1.2 (Information security risk
  assessment), Annex A.5.7 (Threat intelligence).
- **FAIR certification** - Open Group Open FAIR certification
  (Foundation and Practitioner).

## 9. References

- NIST SP 800-30 Rev. 1 - Guide for Conducting Risk Assessments - https://csrc.nist.gov/pubs/sp/800/30/r1/final
- ISO/IEC 27005:2022 - Information Security Risk Management - https://www.iso.org/standard/80585.html
- ISO 31000:2018 - Risk Management Guidelines - https://www.iso.org/standard/65694.html
- Open Group - Risk Analysis (O-RA) Standard - https://www.opengroup.org/openfair
- Open Group - Risk Taxonomy (O-RT) Standard - https://www.opengroup.org/openfair
- MITRE ATT&CK - Adversarial Tactics, Techniques and Common Knowledge - https://attack.mitre.org/
- CISA - Known Exploited Vulnerabilities Catalog - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OCTAVE - Operationally Critical Threat, Asset, and Vulnerability Evaluation - https://www.sei.cmu.edu/our-work/cybersecurity-assurance/octave/
- CRAMM - CCTA Risk Analysis and Management Method - no URL (commercial)
- NIST SP 800-39 - Managing Information Security Risk - https://csrc.nist.gov/pubs/sp/800/39/final
