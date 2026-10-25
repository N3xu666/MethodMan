# Incident Response Lifecycle

The incident response lifecycle is the structured sequence of phases through which an incident is handled. It provides a common vocabulary, a checklist of activities, and a framework for measuring performance. The canonical lifecycle is defined in NIST SP 800-61 and used broadly across frameworks. Its phases are preparation, detection and analysis, containment, eradication, recovery, and post-incident activity.

## 1. Overview

The lifecycle is presented as sequential but operates as iterative. During containment, new indicators may emerge that send the team back to detection and analysis. During recovery, a system may show signs of compromise requiring another eradication phase. The lifecycle is a mental model and a checklist, not a rigid pipeline.

Each phase has entry criteria, exit criteria, defined activities, and defined outputs:

- **Preparation** - establish the capability before any incident occurs. IR plan, playbooks, team, tooling, training, communication plans, legal alignment.
- **Detection and Analysis** - identify that an incident has occurred, scope it, determine severity, and initiate the response.
- **Containment** - prevent further damage. Short-term containment isolates the affected systems. Long-term containment (in some frameworks a separate phase) allows business operations to continue while eradication is underway.
- **Eradication** - remove the cause of the incident. Malware removed, compromised accounts secured, vulnerable systems patched, backdoor eliminated.
- **Recovery** - restore systems to normal operation, with appropriate monitoring to confirm no re-infection.
- **Post-Incident Activity** - review what happened, extract lessons learned, produce action items, and update the IR capability.

The lifecycle is not unique to cybersecurity. It mirrors the structure of emergency management and crisis response, which is why the cross-functional coordination described below is essential.

## 2. Where in the Organization

Each phase is led by a specific role, but multiple functions participate.

- **Preparation** - the IR lead, with support from IT, legal, HR and executive leadership. This is where the IR plan, playbooks, training and retainer agreements are established.
- **Detection and Analysis** - the SOC (Tier 1, 2, 3), with support from threat intelligence and, for complex cases, external forensic analysts. The IR lead coordinates the transition from SOC to full incident response.
- **Containment** - the IR lead approves and directs. IT operations execute (isolate hosts, disable accounts, block network paths). Business unit leads provide input on business impact of containment actions.
- **Eradication** - IT operations and IR analysts execute. Vendor involvement if the incident involves a third-party product. Forensics preserves evidence before eradication.
- **Recovery** - IT operations restore systems. Business unit leads validate that systems are operational. IR team monitors for signs of re-infection.
- **Post-Incident Activity** - the IR lead facilitates the review. Legal, HR, communications and business units participate. Executive leadership receives the review summary.

The RACI matrix in the IR plan must map each phase to responsible, accountable, consulted and informed parties. Ambiguity in who approves containment or who decides to involve legal is a common source of delay.

## 3. Threats and Failure Modes

**Phase-specific failure modes:**

- **Preparation failures**: no playbooks, untested plans, missing retainer, no out-of-band communication, unclear roles, no executive authority to declare an incident, no communication templates, no legal alignment.
- **Detection and Analysis failures**: slow triage, missed indicators, alert fatigue causing real alerts to be dismissed, incomplete scope determination, no threat intelligence, analysis paralysis delaying containment.
- **Containment failures**: delayed containment due to approval chain, containment actions that destroy evidence, containment that disrupts more than necessary, containment that fails because the attacker has additional persistence.
- **Eradication failures**: incomplete removal of malware or persistence, failure to secure all compromised accounts, failure to patch the exploited vulnerability, backdoor in the backup restored systems.
- **Recovery failures**: restoration from compromised backups, restoring to a still-compromised state, premature end to monitoring, lack of business validation, extended downtime due to unclear restoration priorities.
- **Post-Incident failures**: blame-focused review, no action items, action items without owners or due dates, action items not closed, review not shared, recurring incidents because the root cause was never fixed.

**Cross-phase failure modes:**

- **Documentation gaps** - each phase's actions are not recorded. The review cannot reconstruct what happened.
- **Evidence destruction** - eradication proceeds before forensics, evidence lost, regulatory reporting impossible.
- **Communication breakdown** - each phase operates in isolation, stakeholders learn about the incident at the wrong phase.
- **No decision log** - key decisions (contain, pay ransom, notify) are not recorded. Disputes about what was decided become impossible to resolve.
- **No closure criteria** - incidents remain open indefinitely because no one defined what "done" means.

## 4. Controls and Implementation

**4.1 Phase entry and exit criteria.** Each phase has documented criteria for entering and exiting. Example: analysis exits when scope is determined and initial indicators are understood; containment exits when the attacker's access is disrupted and no new compromise indicators appear.

**4.2 Preparation controls.**

- Documented IR plan and playbooks (see Fundamentals file).
- Named IR team with defined roles.
- Communication plan with out-of-band channels tested.
- Retainer agreement with a forensics firm and an IR provider.
- Legal alignment on reporting obligations and litigation hold.
- Executive pre-authorization to isolate hosts and disable accounts in defined scenarios.
- Regular tabletop exercises.

**4.3 Detection and Analysis controls.**

- SIEM, EDR, NDR in place with tuned detection rules.
- Threat intelligence enrichment for detected indicators.
- Triage matrix mapping alert type to initial response.
- Severity classification scheme (e.g. P1/P2/P3/P4) with defined notification thresholds.
- Scoping methodology: what is affected, what is not, what might be affected.
- IOC documentation as analysis proceeds.

**4.4 Containment controls.**

- Short-term containment: isolate affected hosts, disable compromised accounts, block malicious IPs, restrict outbound traffic.
- Long-term containment: segment the network, force password resets, implement MFA on exposed services, apply emergency patches.
- Containment actions recorded with time, actor and justification.
- Evidence preserved before destructive containment (memory capture, disk image where feasible and appropriate).
- Business impact assessment before containment actions that disrupt critical systems.

**4.5 Eradication controls.**

- Malware removed, but only after forensics analysis where the investigation requires it.
- All compromised accounts secured, not only the first identified account.
- All persistence mechanisms identified and removed: scheduled tasks, registry entries, services, web shells, SSH keys, cloud IAM credentials.
- Exploited vulnerability patched.
- Root cause addressed, not just the symptom.
- Verification step: confirm the eradication was complete before proceeding to recovery.

**4.6 Recovery controls.**

- Restoration from known-good backups (verified before restoration).
- Staged recovery with monitoring: restore small, monitor, expand.
- Re-introduction of systems into production after security validation.
- Enhanced monitoring for the recompromise indicators during and after recovery.
- Business validation before exit from recovery.
- Communication of restoration status to stakeholders.

**4.7 Post-Incident controls.**

- Blameless review within 1-2 weeks of incident closure.
- Documentation of timeline, decisions, actions and outcomes.
- Root cause analysis.
- Action items with owner, due date and priority.
- Sharing of lessons with broader teams.
- Update IR plan, playbooks and controls based on findings.
- Executive summary to leadership.

**4.8 Decision log.** Throughout all phases, key decisions are documented with: who decided, what was decided, when, and the reasoning. This is essential for legal, regulatory and post-incident review.

**4.9 Evidence management.** Chain of custody, secure storage, retention per legal and regulatory requirements. Access controlled and audited.

**4.10 Closure criteria.** The incident is formally closed when: all contained systems are restored and validated, monitoring period has passed without re-compromise, post-incident review is complete, action items are assigned, and stakeholders are notified of closure.

## 5. Tooling

Tooling is mapped to lifecycle phases:

- **Preparation**: SIEM, EDR, playbook platform (TheHive, Cortex), communication platforms, documentation repository, retainer management.
- **Detection and Analysis**: SIEM, EDR, NDR, threat intelligence platform, log analysis tools, Volatility, CyberChef, IOC lookup services (VirusTotal, MISP).
- **Containment**: EDR isolation, network ACL management, IAM administrative tools, firewall management.
- **Eradication**: antivirus/EDR removal, patch management, MDM for mobile, IAM for cloud credentials.
- **Recovery**: backup and restore tools (Veeam, Rubrik, Commvault, AWS Backup), configuration management (Ansible, Puppet, Chef), CI/CD for re-deployment.
- **Post-Incident**: case management, documentation (Confluence, Notion, SharePoint), ticketing for action items (Jira, ServiceNow).

SOAR platforms automate routine lifecycle activities: alert enrichment, containment actions, evidence collection. SOAR is not a substitute for the lifecycle, but it accelerates execution of defined steps.

## 6. Verification and Metrics

The lifecycle is verified by measuring performance phase by phase and end to end.

**Phase-specific metrics:**

- **Preparation**: percentage of playbooks tested in last 12 months, retainer readiness (annual check), percentage of IR team trained in current year.
- **Detection and Analysis**: mean time to detect (MTTD), mean time to triage, percentage of incidents correctly classified, false positive rate.
- **Containment**: mean time to contain (MTTC), percentage of incidents where containment was achieved before lateral movement, evidence preservation rate.
- **Eradication**: re-infection rate within 30 days of eradication, percentage of eradication actions verified by second analyst or tooling.
- **Recovery**: mean time to recover (MTTR), percentage of recovery actions from verified backups, business validation completion rate.
- **Post-Incident**: percentage of significant incidents with a documented review, percentage of action items closed on time, recurring incident rate with same root cause.

**End-to-end metrics:**

- **Time to full resolution** - mean time from detection to incident closure.
- **Percentage of incidents meeting SLA** - based on severity-specific SLA targets.
- **Percentage of P1 incidents with executive notification within defined timeframe** - communication compliance.

**Verification activities:**

- Tabletop exercise - tests preparation and coordination across phases.
- Red team simulation - tests detection, containment and eradication under controlled conditions.
- Playbook walkthrough - confirms that documented steps work against current tooling.
- Review of a closed incident - independent audit of the lifecycle documentation.

**Verification evidence for audit:** incident records with timestamps per phase, decision log, evidence chain of custody, post-incident reviews, action item closure records, exercise reports.

## 7. Anti-Patterns

- **Skipping preparation.** Team jumps straight into detection and analysis without a plan. Every incident is improvised.
- **Analysis paralysis.** Endless scoping, no containment. The attacker is not waiting.
- **Containment by destruction.** Host reformatted before forensics. Evidence gone, root cause unknown, re-compromise likely.
- **Eradication without root cause.** Malware removed, but the vulnerable service remains exploitable. Re-infection within days.
- **Recovery without validation.** System restored from a backup that itself contains the compromise. New incident one week later.
- **"All clear" declared too early.** Short monitoring period, no validation. Re-compromise undetected for months.
- **Post-incident review skipped.** "Too busy to look back." The same incident repeats next quarter.
- **Blame review.** One person is identified as the cause, others are exonerated, root cause is hidden. No improvement.
- **Post-incident review full of items, none closed.** Action items accumulate, no one owns them, the repository grows without the capability improving.
- **Phases executed in strict waterfall.** Containment blocks analysis, eradication blocks containment. In real incidents, phases interleave.
- **No decision log.** Decisions are made verbally, no record. When regulators ask "when did you know, when did you contain, why did you choose not to notify," the answer is not available.
- **Communication deferred until all facts are known.** Executives and legal learn about the incident weeks later. Regulatory deadlines are missed.

## 8. Certification Alignment

- **CISSP Domain 7 (Security Operations)** - incident response lifecycle, forensics, evidence handling.
- **CISM Domain 4 (Information Security Incident Management)** - plan, detection, response, review, integration with business continuity.
- **Security+ SY0-701 Domain 4 (Security Operations)** - incident response plan, phases of incident response, testing.
- **CySA+ (CS0-003)** - incident response, analysis, reporting, recovery.
- **ISO/IEC 27035** - Information security incident management. Lifecycle phases aligned with ISO.
- **NIST SP 800-61 Rev. 3** - the canonical lifecycle reference.
- **NIST CSF 2.0 RS (Respond)** - incident management, analysis, mitigation, reporting, communication.

Exam-relevant points: the phases of incident response are preparation, detection and analysis, containment, eradication, recovery, post-incident activity. Each phase has entry and exit criteria. Phases iterate in practice. Post-incident review is mandatory and blameless. Documentation and decision logs are legal and regulatory assets, not paperwork.

## 9. References

- NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management - https://csrc.nist.gov/pubs/sp/800/61/r3/final
- SANS Incident Handler's Handbook - https://www.sans.org/white-papers/33901/
- CISA Incident and Vulnerability Response Playbooks - https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
- ISO/IEC 27035 - Information Security Incident Management - https://www.iso.org/standard/78973.html
- NIST CSF 2.0 - Respond function - https://www.nist.gov/cyberframework
- ENISA Incident Response Reference Material - https://www.enisa.europa.eu/topics/incident-response
- SANS Digital Forensics and Incident Response Resources - https://www.sans.org/cyber-security-courses/incident-response/