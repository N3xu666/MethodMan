# Security Strategy and Metrics

A security strategy converts the governance structure (files 01-04) into a multi-year plan with measurable outcomes. Metrics are how the strategy is proven, funded, and adjusted. A strategy without metrics is a wish; metrics without a strategy are trivia.

## 1. Overview

Security strategy answers three questions at the executive level:

- **Where are we going?** A 2-3 year vision of the security posture, tied to business goals.
- **How will we get there?** A roadmap of initiatives, sequenced by risk and dependency.
- **How will we know?** A small set of metrics that track progress, detect regression, and inform decisions.

A strategy document has four parts:

- **Current state**: a maturity assessment against a framework (CSF 2.0 or CIS Controls IG1/2/3), plus the top risks from the register.
- **Target state**: the maturity level the organization aims for within the planning horizon (typically 24-36 months), and the risk reduction this delivers.
- **Roadmap**: initiatives with owners, budgets, dependencies, and target dates.
- **Metrics**: the indicators that show whether the roadmap is on track and whether the posture is improving.

Key principle: fewer metrics, better chosen. Ten metrics that drive decisions beat fifty metrics on a dashboard.

## 2. Where in the Organization

```
Board / Audit Committee  <-- quarterly report: posture, top risks, program health
    ^
    |  (approves strategy + budget)
    |
CISO  -->  Strategy + metrics + reporting
    |
    +--> Security Leadership Team  (translates strategy into roadmaps)
    +--> GRC  (tracks metrics, verifies evidence, reports to board)
    +--> Control Owners  (deliver initiatives, provide metric inputs)
    |
    v
Executives / Risk Committee  (reviews execution, resolves escalations)
```

The strategy is owned by the CISO, approved by the board or executive committee, and executed by the whole organization. The metrics are collected by GRC and reported to the board at a defined cadence (quarterly for most organizations, monthly for high-risk ones).

## 3. Threats and Failure Modes

- **Strategy as a slide deck.** A beautiful vision, no roadmap, no budget, no metric. It dies at the first reorg.
- **Metric theater.** Dashboards full of activity metrics (training sessions, policies published, tools deployed) that do not measure risk reduction. The board is reassured; the posture is unchanged.
- **Metric gaming.** The team optimizes the metric, not the outcome. Example: "reduce critical vulnerability count" is achieved by reclassifying critical as high.
- **Unfunded roadmap.** The strategy lists 40 initiatives; the budget funds 3. The roadmap is fiction.
- **Strategy without current state.** A target state is defined without knowing where the organization is now; the roadmap skips foundational controls.
- **CISO turnover.** The strategy is the CISO's personal plan; when the CISO leaves, the strategy is abandoned. Durable strategies live in governance documents, not in one person's slide deck.
- **Metric sprawl.** Every team adds its own metric; the board sees 80 metrics and focuses on none.
- **Annual planning only.** The strategy is set once a year and never revisited; by month 6 it is out of date, by month 12 it is wrong.

## 4. Controls and Implementation

### 4.1 Current State Assessment

- **Maturity model**: CSF 2.0 tier model (Partial / Risk-Informed / Repeatable / Adaptive) or CIS IG coverage (IG1/IG2/IG3 percentage). Choose one, do not mix.
- **Risk register input**: the top 10 risks, their current treatment status, and the gap between current and accepted residual risk.
- **Control testing results**: last audit findings, pen-test findings, continuous-monitoring drift.
- **Business input**: strategic initiatives, M&A, regulatory deadlines, customer commitments.

### 4.2 Target State and Roadmap

- **Target maturity**: for each CSF function (or CIS IG tier), state the maturity level aimed at, and why. Example: "Protect: Tier 3 in 24 months, driven by customer contractual requirements."
- **Initiative list**: 5-15 initiatives, each with: title, CSF subcategories addressed, owner, dependencies, budget, target quarter, expected risk reduction.
- **Sequencing**: foundational before advanced (inventory before detection, MFA before SIEM). CIS IG1 before IG2, IG2 before IG3.
- **Funding model**: per-initiative budget, plus a run-cost line for what is already deployed. Most strategy failures are run-cost failures: the new tool is funded, the team to operate it is not.

### 4.3 Metric Design

A useful metric has five properties:

- **Tied to a decision.** Ask "what would we do differently if this number moved?" If no answer, drop the metric.
- **Directional.** Clear whether up or down is good (incidents down is good; MFA coverage up is good).
- **Leading or lagging.** Mix of both: leading (patch compliance) predicts; lagging (incidents) confirms.
- **Cheap to collect.** If a metric requires manual work every month, it decays. Automate or drop.
- **Hard to game.** Count outcomes (verified controls, confirmed findings) rather than activity (meetings held, tools deployed).

### 4.4 Metric Catalog (example)

Program health:

- **Coverage**: percentage of controls with a named owner and a current test result.
- **Maturity**: CSF tier per function, trending.
- **Exception aging**: median age of approved policy exceptions, trending.
- **Risk register currency**: percentage of entries reviewed within the review window.

Operational metrics:

- **Critical patch compliance**: percentage of critical patches applied within SLA, by platform.
- **MFA coverage**: percentage of accounts (human and service) with MFA, by criticality tier.
- **EDR coverage**: percentage of endpoints with active EDR, verified by a live check (not by license count).
- **Backup restore success**: percentage of restore tests that succeeded in the last quarter.
- **Privileged access review**: percentage of privileged accounts reviewed within the last 90 days.

Outcome metrics:

- **Confirmed incidents by severity**: count, trending.
- **MTTD / MTTR**: median time to detect / respond, by severity.
- **Recurring findings**: percentage of audit findings repeated from the previous cycle. This is the most honest metric in most programs.
- **Customer-triggered security reviews**: number of customer questionnaires that required escalation, trending.

### 4.5 Reporting Cadence

- **Monthly**: operational metrics to the CISO and security leadership team. Short, exception-focused.
- **Quarterly**: strategy progress, top risks, incidents, audit findings to the board or audit committee. Three slides, not thirty.
- **Annual**: full program review, updated maturity assessment, refreshed strategy for the next planning cycle.

The quarterly report is the single most important artifact for governance: it is where the board decides whether the program is funded. A report that lists only successes is a report the board learns to distrust.

## 5. Tooling

- **GRC platforms**: track initiatives, owners, evidence, and metrics; report out. OneTrust, Archer, ServiceNow GRC.
- **BI tooling**: Power BI, Looker, Grafana. The report layer; needs an underlying data source.
- **Continuous control monitoring**: tools that pull metrics automatically (vulnerability scanners, EDR, IAM, backup verification).
- **Strategy management**: not a security tool; often a wiki (Confluence), a shared document with version control, or a project portfolio tool (Jira Align, Aha!).
- **Board reporting**: a templated deck refreshed quarterly, with the same structure so the board tracks trend, not new content.

## 6. Verification and Metrics

Verifying the strategy itself (meta-verification):

- **Roadmap delivery**: percentage of initiatives delivered on schedule, by quarter.
- **Budget vs actual**: on-budget initiatives vs plan, per quarter.
- **Metric stability**: are the metrics moving in the intended direction, or are they noise? Two to three quarters of trend are needed before a conclusion.
- **Audit repeat findings**: are the same findings recurring? If yes, the underlying initiative is not working.
- **Board feedback**: does the board engage with the report (ask questions, request follow-ups)? A silent board is a disengaged board.

Meta-meta-verification: is the strategy still the right strategy? Every 12 months, ask whether the assumptions behind the target state still hold (business context, threat landscape, regulations, technology). A strategy that is not re-evaluated annually is a strategy the organization has outgrown.

## 7. Anti-Patterns

- **Vanity metrics.** Reports that always show green, regardless of reality. The best security metrics show trend and risk, not status.
- **Metric overload.** More than 15 metrics on a board report; the board focuses on none.
- **Strategy as a personal project.** The CISO's slide deck. When the CISO leaves, the strategy is gone.
- **Annual-only planning.** The plan is set in Q4 and never revisited. By Q2 it is stale.
- **Roadmap as a wish list.** 40 initiatives, 3 funded, 37 forgotten. Fewer, funded, sequenced.
- **Run-cost blindness.** New initiatives are funded; operations (people, licenses, maintenance) are not.
- **Board reporting as marketing.** Successes only, no incidents, no failures. The board learns to distrust the report and the CISO.
- **Metrics without action.** A dashboard exists; no decisions are tied to it. The dashboard becomes decoration.

## 8. Certification Alignment

This file supports the following certification domains:

- **CompTIA Security+**: governance, risk, compliance; metrics and reporting.
- **ISC2 CISSP**: Domain 1 (Security and Risk Management) - security strategy, metrics, reporting.
- **ISACA CISM**: Domain 1 (Information Security Governance) - strategy, governance, reporting to the board.
- **ISACA CISA**: audit metrics, control monitoring, reporting to the audit committee.
- **ISO 27001 Lead Implementer / Lead Auditor**: Clause 6 (Planning), Clause 9 (Performance evaluation), management review.

## 9. References

- NIST Cybersecurity Framework 2.0 - https://www.nist.gov/cyberframework
- ISACA CISM Review Manual - https://www.isaca.org/credentialing/cism
- ISC2 CISSP CBK - https://www.isc2.org/certifications/cissp
- NIST SP 800-55 (Performance Measurement) - https://csrc.nist.gov/publications/detail/sp/800-55/rev-1/final
- CIS Controls v8 - https://www.cisecurity.org/controls
- ISO/IEC 27001:2022 (Clause 6, 9) - https://www.iso.org/standard/27001