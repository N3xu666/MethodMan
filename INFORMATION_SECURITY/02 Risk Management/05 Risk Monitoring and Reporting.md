# Risk Monitoring and Reporting

Risk monitoring is the continuous process of tracking the risk
landscape, treatment progress and the effectiveness of controls.
Risk reporting is the structured communication of that state to the
audiences who need it. Without monitoring, the risk register becomes a
historical document. Without reporting, monitoring has no consequence.

## 1. Overview

Risk monitoring answers three questions on an ongoing basis:

1. Has the risk changed? (likelihood, impact, context)
2. Has the treatment progressed? (plan vs actual)
3. Has the control worked? (effectiveness, drift)

Risk reporting answers two questions for each audience:

1. What is the current risk posture?
2. What decisions are needed?

### Monitoring vs Reporting vs Review

- **Monitoring** - continuous data collection and tracking.
- **Reporting** - periodic structured communication.
- **Review** - periodic re-assessment of the risk and its treatment.

Monitoring feeds reporting. Reporting triggers review. Review updates
monitoring criteria. All three are required.

### What Must Be Monitored

- **Risk profile** - aggregate risk level over time.
- **Individual risks** - likelihood, impact, score, owner, status.
- **Treatment plans** - progress against milestones, budget, scope.
- **Control effectiveness** - are controls operating as designed?
- **External context** - threat landscape, regulatory changes, vendor
  changes.
- **Incidents** - realized risks, and their mapping to the register.

## 2. Where in the Organization

Monitoring and reporting involve multiple audiences with different
needs:

- **Board** - quarterly, strategic, aggregated, focuses on top risks
  and appetite. Decisions: accept, fund treatment, change strategy.
- **Executive / C-suite** - monthly, tactical, focuses on business
  impact and treatment progress. Decisions: prioritize, fund,
  escalate.
- **Risk committee** - monthly, cross-functional, reviews the
  register and treatment portfolio. Decisions: approve, adjust,
  escalate.
- **Security leadership** - weekly, operational, reviews incidents,
  control health, emerging threats. Decisions: respond, adjust.
- **Risk owners** - continuous, individual risk tracking. Decisions:
  treat, accept, escalate.

### Reporting Cadence

- **Continuous** - dashboards, alerting.
- **Weekly** - operational security review.
- **Monthly** - risk committee, executive summary.
- **Quarterly** - board report, risk appetite review.
- **Annual** - full register review, methodology review, framework
  alignment.

The cadence must match the decision cycle of each audience. A board
that meets quarterly does not need weekly reports; an operational
team that meets weekly cannot wait for a quarterly review.

## 3. Threats and Failure Modes

### Failure Modes of Monitoring

- **Stale register** - entries are not updated; scores reflect a
  past state. The register becomes fiction.
- **No owner updates** - owners are assigned but never review their
  risks. Ownership is nominal.
- **Monitoring without triggers** - nothing tells the organization
  when to re-assess. Re-assessment happens by chance.
- **Alert fatigue** - too many low-value signals; the real signal is
  lost.
- **Vanity metrics** - metrics that look good but do not correlate
  with risk reduction (e.g. number of assessments completed).
- **Gaming** - owners reclassify risks to avoid scrutiny (e.g.
  "reduce" likelihood without evidence).
- **Tool sprawl** - multiple registers, inconsistent data, no single
  source of truth.

### Failure Modes of Reporting

- **Data dump** - reports contain everything; the audience reads
  nothing.
- **No decision** - reports do not state what decisions are needed.
- **Wrong level** - technical detail for the board, strategic summary
  for the SOC.
- **No trend** - reports show the current state, not the direction.
  Without trend, the audience cannot judge progress.
- **Optimistic framing** - bad news is buried; risk is understated.
  Trust is destroyed when the next incident contradicts the report.
- **No follow-up** - previous report actions are not tracked; the
  same issues recur.

### Failure Modes of Review

- **Review without criteria** - "we reviewed the risk" with no defined
  trigger or output.
- **Review as meeting** - the review is a calendar event, not an
  analytical exercise.
- **Review without data** - the review uses opinion, not monitoring
  data.
- **Review without authority** - the reviewer cannot change the
  treatment or escalate.

## 4. Controls and Implementation

### Monitoring Framework

A complete monitoring framework defines:

- **What is monitored** - the data elements (score, status, owner,
  treatment progress, control tests).
- **How often** - the cadence per element.
- **By whom** - the responsible role.
- **Triggers** - events that force re-assessment regardless of
  cadence.
- **Thresholds** - levels that force escalation.
- **Data sources** - where the data comes from.

### Re-Assessment Triggers

Re-assessment must be triggered by:

- **Material change** - significant change to the asset, system,
  process or business context.
- **New threat intelligence** - a new threat actor, technique or
  vulnerability affecting the risk.
- **Incident** - a related incident occurred (including at a peer
  organization).
- **Control failure** - a control failed or was bypassed.
- **Regulatory change** - a new or changed regulation affects the
  risk.
- **Scheduled review** - the defined review date.
- **Owner change** - the risk owner changed.
- **Treatment completion** - to verify residual risk.

### Reporting Structure

A defensible report contains:

1. **Executive summary** - one paragraph, current state and key
   decisions.
2. **Risk posture** - aggregate risk vs appetite, with trend.
3. **Top risks** - the top N risks (by score, by business impact, or
   by velocity).
4. **Changes since last report** - new, closed, escalated, re-scored.
5. **Treatment portfolio** - progress, budget, blockers.
6. **Incidents and near-misses** - mapped to risks.
7. **External context** - threat landscape, regulatory changes.
8. **Decisions required** - what the audience must decide.
9. **Actions from previous report** - status of prior commitments.

### Dashboard Design

A risk dashboard must:

- Show the aggregate score and trend, not just today's number.
- Split by risk category and business unit, not just total.
- Highlight the top risks and their trajectory.
- Show treatment progress and overdue items.
- Show incident rate and mapping to known risks.
- Use consistent scales and definitions across time.

Avoid: 3D charts, gauges without context, metrics without
thresholds, screens that require clicking to find the key message.

## 5. Tooling

- **GRC platforms** - ServiceNow GRC, Archer, OneTrust, LogicGate.
  Integrated register, treatment, monitoring and reporting.
- **BI and dashboarding** - Power BI, Tableau, Looker, Grafana.
  Visualization and scheduled distribution.
- **Ticketing** - Jira, ServiceNow ITSM, Azure DevOps. Treatment
  plan tracking, linked to the register.
- **Threat intelligence** - Recorded Future, Mandiant Advantage,
  MISP, CISA feeds. External context for monitoring.
- **Security rating services** - BitSight, SecurityScorecard,
  RiskRecon. External posture of vendors and the organization.
- **Incident management** - ServiceNow SecOps, PagerDuty, Splunk
  SOAR. Incident data feeding the risk register.
- **Compliance automation** - Vanta, Drata, Secureframe. Continuous
  control monitoring against frameworks.

## 6. Verification and Metrics

### Verification of Monitoring

- **Register currency** - percentage of risks reviewed in the last
  quarter. Target: 100% of critical, >80% overall.
- **Owner activity** - percentage of owners who updated their risks
  in the last quarter.
- **Trigger responsiveness** - time from trigger event to
  re-assessment completion.
- **Data consistency** - sample 10 risks; verify the score matches
  the documented inputs.
- **Threshold operation** - verify escalation thresholds were
  triggered and acted upon in the last cycle.

### Verification of Reporting

- **Decision traceability** - percentage of reports with a
  "decisions required" section and follow-up.
- **Audience fit** - sample reports against audience; check that
  the level matches.
- **Timeliness** - percentage of reports delivered by the scheduled
  date.
- **Trend presence** - every report shows trend, not just current
  state.
- **Action follow-up** - percentage of prior actions with a status
  update.

### Metrics

- **Risk profile trend** - aggregate risk score over 4 quarters.
- **Top-risk velocity** - how fast top risks are increasing or
  decreasing.
- **Treatment on-time completion** - percentage of plans completed
  by target date.
- **Overdue risks** - risks past their review date.
- **Incident-to-risk ratio** - incidents traceable to a known risk
  vs total incidents. Low ratio = register gap.
- **Control effectiveness rate** - percentage of tested controls
  operating effectively.
- **Report decision rate** - percentage of reports that led to a
  documented decision.

### Common Verification Steps

1. Sample 10 risks; verify the last review date, owner, score and
   justification.
2. Sample 3 reports; verify trend, decisions required, action
   follow-up.
3. Compare 3 incidents from the last quarter against the register;
   every incident must map to a known risk or a new entry.
4. Verify escalation worked: at least one risk was escalated and
   acted upon in the last cycle.

## 7. Anti-Patterns

- **Monitoring as reporting.** Counting reports is not measuring
  risk. Report delivery is an output; risk reduction is the outcome.
- **Register as archive.** A register that is not reviewed is a
  historical document, not a monitoring tool.
- **Metrics theater.** Metrics that cannot change a decision are
  decoration. Delete them.
- **Optimism bias.** Understating risk destroys credibility. The
  next incident will be the audit.
- **One-size-fits-all reporting.** The board and the SOC need
  different reports. A single report serves neither.
- **No trend.** A snapshot without direction cannot support
  judgment. Show where the risk is heading.
- **Review without owner.** A review without the risk owner present
  is a staff exercise, not a risk review.
- **Static thresholds.** Thresholds that never change either become
  noise or miss emerging risks. Re-calibrate annually.
- **Ignoring near-misses.** Near-misses are free lessons; ignoring
  them makes the next incident the lesson.
- **Silent acceptance.** Acceptance without documented rationale
  and review date is abandonment.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): risk
  monitoring, reporting to management, risk appetite.
- **CISM** - Domain 2 (Information Risk Management): risk
  monitoring, risk reporting.
- **CRISC** - Domain 3 (Risk Response and Reporting): risk
  monitoring, risk reporting, key risk indicators.
- **CISA** - Domain 5 (Protection of Information Assets): monitoring
  and reporting.
- **CySA+** - Domain 2 (Vulnerability Management): continuous
  monitoring; Domain 3 (Software and Systems Security): monitoring.
- **ISO 27001 LI/LA** - Clause 9.1 (Monitoring, measurement,
  analysis and evaluation), Clause 9.3 (Management review), Annex
  A.5.7 (Threat intelligence).
- **CRISC, CGEIT, CISA** - Key Risk Indicators (KRIs) and Key
  Performance Indicators (KPIs).

## 9. References

- ISO 31000:2018 - Risk Management Guidelines - https://www.iso.org/standard/65694.html
- ISO/IEC 27005:2022 - Information Security Risk Management - https://www.iso.org/standard/80585.html
- NIST SP 800-39 - Managing Information Security Risk - https://csrc.nist.gov/pubs/sp/800/39/final
- COSO - Enterprise Risk Management - Integrating with Strategy and Performance - https://www.coso.org/guidance-erm
- ISACA - Risk IT Framework - https://www.isaca.org/resources/isaca-focus/newsletters/2021/vol-2/risk-it-framework
- FAIR Institute - Factor Analysis of Information Risk - https://www.fairinstitute.org/
- Open Group - Risk Taxonomy (O-RT) Standard - https://www.opengroup.org/openfair
- MITRE ATT&CK - Adversarial Tactics, Techniques and Common Knowledge - https://attack.mitre.org/
