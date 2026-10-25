# Risk Treatment and Response

Risk treatment is the process of selecting and implementing measures to
modify risk. Risk response is the broader organizational reaction to a
risk event or a change in the risk profile. Treatment is planned;
response is executed. A treatment plan without a response capability is
a document, not a control.

## 1. Overview

ISO 31000 defines seven treatment options. In practice, security teams
use four primary categories (mitigate, transfer, avoid, accept) and
three secondary options (share, retain, exploit).

### The Four Primary Options

- **Mitigate (reduce)** - implement controls to lower likelihood or
  impact. The most common option.
- **Transfer (share)** - shift financial impact to a third party
  (insurance, contractual indemnity, outsourced SLA).
- **Avoid** - eliminate the activity that creates the risk. Rarely
  viable, but sometimes correct (retire a legacy system).
- **Accept (retain)** - acknowledge the risk and document the
  decision. Valid only with named owner, rationale and review date.

### The Three Secondary Options

- **Exploit** - actively pursue the upside of a risk (e.g. adopt a
  new technology early). Used in positive-risk contexts.
- **Share** - split risk with a partner (joint venture, consortium).
- **Retain** - keep residual risk after treatment. Same as accept,
  but applied to the residual portion.

### Treatment vs Acceptance

Acceptance is not the absence of treatment. Acceptance is a documented
decision that treatment is not cost-effective, not feasible, or not
aligned with risk appetite. Acceptance without documentation is neglect.

## 2. Where in the Organization

Treatment decisions involve four roles:

- **Risk owner** - the business person who owns the asset and accepts
  the residual risk. Named individual, not a team.
- **Security team** - recommends treatment options, provides cost and
  effectiveness estimates.
- **Finance** - provides cost data, approves budget.
- **Executive / board** - approves treatments above a defined
  threshold, reviews acceptance decisions.

### Governance Structure

- **Low risk** - security team decides, risk owner informed.
- **Medium risk** - risk owner decides, security advises.
- **High risk** - risk owner and CISO decide, executive informed.
- **Critical risk** - board or risk committee decides.

The threshold for each level must be defined, documented and applied
consistently. Otherwise governance is theatre.

## 3. Threats and Failure Modes

### Failure Modes of Treatment

- **Treatment theatre** - a plan exists, no budget, no owner, no
  deadline. Equivalent to no treatment.
- **Control without verification** - a control is deployed and assumed
  effective without testing. Untested controls fail silently.
- **Transfer without due diligence** - insurance does not cover the
  actual loss scenario; the vendor does not meet the SLA.
- **Acceptance without signature** - the risk is "accepted" in a
  meeting but no one signed. When the loss occurs, no one remembers.
- **Mitigation drift** - the control is deployed, then weakened by
  configuration changes. No re-verification means drift is invisible.
- **Treatment for the wrong risk** - the treatment addresses a
  symptom, not the root cause.
- **Cost myopia** - choosing the cheapest treatment, ignoring lifecycle
  cost (maintenance, training, false positives).
- **Risk displacement** - the treatment moves risk elsewhere (e.g.
  outsourcing moves operational risk to vendor risk). Must be
  documented.

### Failure Modes of Response

- **No playbook** - the incident happens, no one knows what to do.
- **Untested playbook** - the playbook exists, but no one has run it.
- **Wrong escalation** - the incident is escalated to the wrong role
  or too late.
- **Communication collapse** - the technical team fixes the issue;
  legal, comms and executives are not informed.
- **Evidence loss** - response destroys forensic evidence.
- **Response without root cause** - the incident is closed, the root
  cause remains.

## 4. Controls and Implementation

### Treatment Plan Structure

A complete treatment plan contains:

- Risk ID and title.
- Risk owner (named).
- Selected treatment option (mitigate / transfer / avoid / accept /
  share / retain).
- Specific controls to implement.
- Cost estimate (capex and opex).
- Expected risk reduction (before -> after, in the same scale).
- Implementation timeline (milestones, dates).
- Verification method (how we know the control works).
- Residual risk acceptance (owner signature).
- Review date.

A plan missing any of these is incomplete.

### Response Plan Structure

A response plan (or playbook) contains:

- Trigger conditions (what activates the plan).
- Roles and responsibilities (who does what).
- Communication lines (internal, external, regulatory).
- Technical steps (containment, eradication, recovery).
- Evidence preservation steps.
- Escalation thresholds.
- Post-incident review process.

### Treatment Cost-Benefit

Treatment should be justified against the cost of the risk:

```
Annualized Loss Expectancy (ALE) = Single Loss Expectancy (SLE) x Annualized Rate of Occurrence (ARO)
Treatment justified if: Annual Treatment Cost < ALE reduction
```

For qualitative risks, use a documented rationale instead of a number.
"Treatment cost is 2x the annual insurance premium and reduces the
risk from High to Medium" is a defensible rationale.

### Response Lifecycle

1. **Preparation** - playbooks, training, tooling, communication plans.
2. **Detection** - monitoring, alerting, reporting channels.
3. **Containment** - limit the scope, isolate affected assets.
4. **Eradication** - remove the cause, patch, rebuild.
5. **Recovery** - restore operations, verify integrity.
6. **Lessons learned** - post-incident review, root cause, control
   updates.

## 5. Tooling

- **Treatment tracking** - GRC platforms, Jira, ServiceNow. Must link
  to the risk register, not exist as a separate spreadsheet.
- **Response orchestration** - SOAR platforms (Splunk SOAR, Palo Alto
  Cortex XSOAR, Tines, Shuffle). Automate repetitive response steps.
- **Playbook management** - Git-backed playbooks, Confluence, Notion.
  Version-controlled, reviewed.
- **Communication** - PagerDuty, Opsgenie, VictorOps for on-call;
  Statuspage for external communication.
- **Evidence preservation** - Velociraptor, KAPE, Magnet AXIOM for
  forensic collection during response.
- **Tabletop exercises** - Cyberbit, Immersive Labs, custom scenario
  documents. Regular, documented, with after-action reports.

## 6. Verification and Metrics

### Verification of Treatment

- **Control effectiveness testing** - each deployed control is tested
  after deployment and at least annually.
- **Residual risk re-scoring** - after treatment, the risk is
  re-assessed independently. The score must change; if not, the
  treatment was ineffective.
- **Cost actual vs planned** - treatment cost is tracked; overspend
  indicates scope creep or poor estimation.
- **Timeline adherence** - percentage of milestones met on schedule.
- **Acceptance audits** - sample accepted risks; verify signature,
  rationale, review date.

### Metrics of Treatment

- **Treatment completion rate** - percentage of plans completed by
  target date. Target: >80%.
- **Average treatment cycle time** - days from plan approval to
  verification.
- **Residual risk reduction** - aggregate risk before vs after.
- **Acceptance rate** - percentage of risks accepted vs treated.
  High acceptance rate indicates either good appetite calibration or
  weak treatment capacity.
- **Treatment ROI** - risk reduction per unit cost. Requires
  quantitative scoring.

### Verification of Response

- **Tabletop frequency** - at least twice per year per major scenario.
- **Playbook currency** - reviewed in the last 12 months.
- **Mean time to detect (MTTD)** - from incident start to detection.
- **Mean time to respond (MTTR)** - from detection to containment.
- **Post-incident review completion** - 100% of major incidents.

### Common Verification Steps

1. Sample 5 treatment plans; check owner, cost, timeline, verification
   method, residual acceptance.
2. Trace 3 plans to evidence of completion (screenshot, config, test
   report).
3. Sample 3 response playbooks; verify trigger, roles, escalation.
4. Verify 2 tabletop exercises in the last year with after-action
   reports.

## 7. Anti-Patterns

- **Plan without owner.** A plan with no named owner is a wish.
- **Mitigation without verification.** A control that is not tested
  is a hope.
- **Acceptance without signature.** Not acceptance; abandonment.
- **Transfer without reading the contract.** Insurance and SLAs have
  exclusions; assume nothing.
- **Risk displacement disguised as treatment.** Moving the risk to a
  vendor or cloud is not removing it; it is exchanging it. Document
  the new risk.
- **Response plan as a PDF.** A response plan nobody has read is
  decoration. Test it.
- **Post-incident review as blame.** Reviews must find root cause,
  not fault, or no one will report future incidents.
- **Residual risk as zero.** Every treatment leaves some risk. Zero
  residual risk is either a miscalculation or a lie.

## 8. Certification Alignment

- **CISSP** - Domain 1 (Security and Risk Management): risk
  treatment, risk response, business continuity.
- **CISM** - Domain 2 (Information Risk Management): risk response,
  control implementation.
- **CRISC** - Domain 3 (Risk Response and Reporting): risk response
  options, control design, monitoring.
- **CISA** - Domain 5 (Protection of Information Assets): control
  implementation and testing.
- **ISO 27001 LI/LA** - Clause 6.1.3 (Information security risk
  treatment), Clause 8.3 (Treatment of risk), Annex A.5.7 (Threat
  intelligence).
- **CySA+** - Domain 4 (Incident Response and Management): response
  process, playbooks, post-incident activity.

## 9. References

- ISO 31000:2018 - Risk Management Guidelines - https://www.iso.org/standard/65694.html
- ISO/IEC 27005:2022 - Information Security Risk Management - https://www.iso.org/standard/80585.html
- NIST SP 800-39 - Managing Information Security Risk - https://csrc.nist.gov/pubs/sp/800/39/final
- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide - https://csrc.nist.gov/pubs/sp/800/61/r2/final
- CISA - Incident and Vulnerability Response Playbooks - https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
- SANS Institute - Incident Handler's Handbook - https://www.sans.org/white-papers/33901/
- FAIR Institute - Factor Analysis of Information Risk - https://www.fairinstitute.org/
- Open Group - Risk Taxonomy (O-RT) Standard - https://www.opengroup.org/openfair
