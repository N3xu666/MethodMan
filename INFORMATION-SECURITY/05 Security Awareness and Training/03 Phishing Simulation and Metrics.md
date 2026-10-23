# Phishing Simulation and Metrics

Phishing simulation is the primary behavioral measurement tool of an awareness program. Done well, it produces a continuous signal about how the workforce recognizes, reacts to, and reports phishing. Done badly, it becomes a punishment mechanism that damages trust and hides the very behavior the program needs to observe.

## 1. Overview

A phishing simulation is a controlled exercise where the security team sends a fake phishing email to employees, using the same techniques an attacker would. The goal is not to catch people; the goal is to measure and improve three behaviors:

- **Recognition** - does the employee notice characteristics of a phishing email?
- **Action** - what does the employee do when they recognize it? Click? Enter credentials? Open the attachment? Or report it?
- **Reporting** - does the employee use the corporate reporting channel, and how quickly?

The output of a simulation is behavioral data: click rate, credential submission rate, attachment open rate, report rate, time-to-first-report, and report-to-click ratio. These metrics feed the awareness program, the risk register, and executive reporting.

A simulation program is successful when report rate rises and click rate falls, while employee trust remains intact. A program that reduces clicks by threatening employees has failed even if the click rate number looks good.

## 2. Where in the Organization

Phishing simulation touches several functions and must be coordinated with them:

- **Security team** - owns the simulation program, designs the campaigns, triages reports, and delivers feedback.
- **IT / email administration** - allowlists the simulation platform's sending infrastructure and ensures no legitimate security control (spam filter, DMARC, attachment sandbox) blocks the simulation.
- **Legal and privacy** - reviews campaign design and data handling. In some jurisdictions, employee monitoring and simulation data handling require formal notices or works council consultation.
- **HR** - aligned on the non-punitive policy: employees who click are not disciplined. HR is informed of the policy and its rationale.
- **Communications** - coordinates the announcement of the program to avoid confusion with real phishing.
- **Executive sponsor** - visibly supports the program and reinforces that reporting is valued.

Coordination with legal and HR is essential. A simulation program that begins without formal alignment on the non-punitive policy is likely to be weaponized internally or challenged by employee representatives.

## 3. Threats and Failure Modes

**External attacker techniques the simulation must replicate:**

- **Credential phishing** - a fake login page that captures username and password.
- **Attachment phishing** - a malicious or macro-enabled document.
- **Link-based payload** - a link that leads to an exploit kit or a malware download.
- **Business email compromise pretext** - impersonation of an executive or vendor requesting payment or sensitive data.
- **Vishing (voice) simulation** - a phone call with a helpdesk or IT support pretext.
- **QR code phishing (quishing)** - increasingly common; a QR code leads to a credential-harvesting page designed for mobile.
- **Conversation hijacking** - an email that replies to an existing thread as if from a known contact, to build trust.

**Internal failure modes of the simulation program:**

- **Punitive response** - employees who click are publicly shamed or sent to re-training. Trust is destroyed, reports drop, hidden clicks rise.
- **Unrealistic scenarios** - obviously fake emails that every employee identifies. Measures nothing.
- **Overly aggressive scenarios** - emails that are indistinguishable from a real attack, or that trigger anxiety, damaging trust.
- **No feedback loop** - the simulation produces data, but the data is never used to adjust training.
- **Same campaign repeatedly** - the same template sent quarter after quarter. Employees learn to recognize the template, not phishing.
- **No measurement of reporting** - click rate is tracked, report rate is not. The most important behavior is ignored.
- **Simulation confused with real attack** - poorly coordinated campaigns trigger helpdesk and SOC overload. The security team spends hours triaging its own simulation.
- **Missing allowlisting** - the email platform's anti-phishing controls block or quarantine the simulation, distorting the results.

## 4. Controls and Implementation

**4.1 Non-punitive policy.** Document and communicate the policy: employees who click are not disciplined. The purpose is learning and measurement. HR and legal approve the policy. This is the single most important control in the program.

**4.2 Campaign plan.** An annual campaign plan defines:

- **Cadence** - typically monthly or quarterly. Monthly for baseline program, quarterly for mature programs where micro-campaigns are used between quarterly campaigns.
- **Difficulty progression** - start with easy scenarios in Q1, progressively harder through Q4. Examples: obvious misspelled domain in Q1, homoglyph domain and accurate branding in Q4.
- **Role targeting** - finance receives invoice fraud scenarios, executives receive impersonation scenarios, helpdesk receives vishing scenarios, all employees receive generic credential phishing.
- **Scenario rotation** - never repeat the same template within a year. Each campaign uses a new pretext, sender display name, and credential page design.

**4.3 Scenario library.** A curated set of scenarios covering the main categories. Each scenario is documented with: pretext, sender, subject line, body, landing page, target roles, and educational outcome. The library is refreshed annually.

**4.4 Safe landing page design.** For credential-phishing simulations, the landing page does not capture real credentials. It shows an immediate teachable moment: "This was a simulation. Here is what you should have noticed." The teachable moment is the primary learning opportunity.

**4.5 Report button integration.** A one-click "Report Phishing" button in Outlook and Gmail routes reports to the security team. The button is tested before every campaign. Reports are acknowledged within minutes, and the reporter receives feedback on whether the email was a simulation or a real threat.

**4.6 Feedback loop for clickers.** Employees who click and land on the teachable moment page receive a brief explanation and, optionally, a short optional module. No public shaming. No mandatory re-training unless the same employee clicks repeatedly and their manager is involved privately.

**4.7 Positive reinforcement for reporters.** Frequent reporters are acknowledged: in a quarterly all-hands, in a dashboard, or via a direct message from the CISO. Positive reinforcement scales better than negative.

**4.8 Metrics pipeline.** The platform exports per-recipient data: sent, delivered, opened, clicked, submitted, reported. The data is aggregated into role, department and site-level views. The pipeline must handle non-response (employee on leave) correctly.

**4.9 Integration with training.** Campaign results feed the training program. If a department shows high click rates, their next training cycle includes additional relevant content. If a scenario has high click rates across the organization, the next baseline module covers it.

**4.10 Executive reporting.** Quarterly dashboard to CISO and sponsor: overall click rate, report rate, time-to-first-report, trend by department and role, top scenario categories, program roadmap.

## 5. Tooling

- **Phishing simulation platform** - sends campaigns, tracks interactions, provides teachable moment pages. Examples: KnowBe4, Proofpoint Security Awareness, Cofense PhishMe, Arctic Wolf Security Awareness, GoPhish (open source).
- **Email reporting add-in** - the "Report Phishing" button integrated into the mail client. Often bundled with the simulation platform.
- **Landing page hosting** - the platform hosts the credential page or routes to an external URL. Custom landing pages are designed to match the pretext.
- **Analytics and reporting** - platform dashboards, or a BI tool (Power BI, Looker, Grafana) that pulls platform data plus report volumes and incident data.
- **Phishing triage tooling** - the SOC's own tooling for real phishing reports (mail header analysis, URL detonation, attachment sandboxing). Simulated reports may be triaged by the same process, with clear tagging.
- **Allowlisting configuration** - the simulation platform's sending domain must be allowlisted in the corporate mail gateway and DMARC configuration to bypass standard anti-phishing controls.

Selection criteria: the tool must support custom landing pages, allowlisting by domain, per-recipient metrics, and a clean API for exporting data. It must also support SSO for administrative access.

## 6. Verification and Metrics

The following metrics form the core of a phishing simulation program. They are tracked per campaign and in aggregate.

**Primary metrics:**

- **Click rate** - percent of recipients who clicked the simulation link. Target: trending down quarter over quarter.
- **Credential submission rate** - percent of recipients who submitted credentials on the simulation page. Target: trending down. This is more serious than a click.
- **Attachment open rate** - percent of recipients who opened the attachment. Target: trending down.
- **Report rate** - percent of recipients who reported the simulation using the corporate reporting channel. Target: trending up. The most important metric.
- **Report-to-click ratio** - reports divided by clicks. Values above 1 indicate more reporting than clicking. Target: above 3.

**Secondary metrics:**

- **Time-to-first-report** - minutes from campaign launch to the first report. Faster is better.
- **Time-to-triage** - how quickly the security team acknowledges each report. Target: under 5 minutes during business hours.
- **Report accuracy** - percent of reports that were actual simulations or real phishing versus false reports. High accuracy suggests the workforce is learning.
- **Repeat clicker rate** - percent of recipients who clicked in more than one campaign. Identify repeat clickers for optional additional training, not punishment.

**Trend and comparison:**

- **Department comparison** - click and report rates by department. Identifies where content or delivery needs adjustment.
- **Role comparison** - executives, finance, IT and general employees. Different target rates for different roles are not appropriate; the goal is uniform improvement.
- **Year-over-year trend** - the long-term signal. A healthy program shows improvement over 12-24 months.

**Verification evidence for audit:** campaign reports, click/report data exports, triage logs, teachable moment screenshots, executive dashboard snapshots.

## 7. Anti-Patterns

- **Punishment for clickers.** Public shame, mandatory re-training, manager notification, HR record. Trust collapses, reports drop, real clicks go underground.
- **Tracking clickers to performance reviews.** Employees learn to avoid the test rather than to recognize phishing.
- **Same scenario every quarter.** A template that becomes recognizable is no longer a simulation.
- **Only measuring click rate.** The most important behavior - reporting - is ignored. A department with 0% clicks and 0% reports is indistinguishable from a department with 30% clicks and 30% reports on click rate alone, but very different on report rate.
- **Too-hard first campaign.** A sophisticated spear-phishing scenario in the first campaign of a new program produces anxiety and click rates near 100%. Start easy, progress gradually.
- **No teachable moment.** The employee lands on a fake login page, enters credentials, and the simulation ends silently. The learning opportunity is lost.
- **No feedback to reporters.** A report button that routes to an unmonitored inbox, or reports that are never acknowledged. Employees stop reporting.
- **Simulation indistinguishable from real attack.** During a real phishing wave, a simulation confuses the situation. Coordinate campaigns against the threat landscape.
- **Missing allowlisting.** The simulation is blocked by the mail gateway, the SOC sees no reports, and the campaign looks like 0% click rate. False negative.
- **No legal or HR alignment.** Data from the simulation enters performance reviews or is used against employees without notice. Legal and trust risk.

## 8. Certification Alignment

- **CISSP Domain 7 (Security Operations)** and **Domain 1 (Security and Risk Management)** - security awareness, social engineering, measuring awareness effectiveness.
- **CISM Domain 3 (Information Security Program Development and Management)** - program effectiveness measurement, metrics selection.
- **Security+ SY0-701 Domain 5 (Security Program Management and Oversight)** - security awareness, phishing, social engineering.
- **ISO 27001 Annex A 7.3 (Awareness, education and training)** - the standard requires that personnel are aware; phishing simulation is the evidence of behavioral compliance.
- **NIST CSF 2.0 PR.AT (Awareness and Training)** - awareness and training; phishing simulation is a leading indicator of PR.AT effectiveness.

Exam-relevant points: report rate is more valuable than click rate. Non-punitive policy is essential. Simulations must be legal, ethical, and coordinated with HR.

## 9. References

- Cofense Phishing Simulation Best Practices - https://cofense.com/
- KnowBe4 Phishing Simulation - https://www.knowbe4.com/phishing-simulation-training
- Proofpoint Security Awareness Training - https://www.proofpoint.com/us/products/security-awareness-training
- GoPhish Open Source Phishing Framework - https://getgophish.com/
- NIST SP 800-50 - Building an Information Technology Security Awareness and Training Program - https://csrc.nist.gov/pubs/sp/800/50/final
- SANS Phishing Simulation Guidance - https://www.sans.org/security-awareness-training/
- Anti-Phishing Working Group (APWG) - Phishing Activity Trends Report - https://apwg.org/trendsreports/