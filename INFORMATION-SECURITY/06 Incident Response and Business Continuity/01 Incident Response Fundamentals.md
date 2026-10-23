# Incident Response Fundamentals

Incident response (IR) is the organized approach to addressing and managing a security incident. It covers the people, process and technology used to detect, contain, eradicate and recover from an incident, and to learn from it afterward. This file defines what an incident is, how IR fits into the organization, what threatens it, how to build a capability, and how to verify it works.

## 1. Overview

An incident is any event that actually or potentially jeopardizes the confidentiality, integrity or availability of information, or that constitutes a violation of security policy. Not every alert is an incident. The process of distinguishing a benign alert from a real incident is triage, and it sits at the front of the IR lifecycle.

The distinction between events, alerts and incidents matters:

- **Event** - any observable occurrence in a system or network. Most are normal.
- **Alert** - an event flagged by a detection control as potentially malicious or policy-violating.
- **Incident** - an alert or set of alerts that has been triaged and confirmed to require a response.

IR is not a technology problem. Most incident response failures are organizational: unclear ownership, missing playbooks, slow decision-making, poor communication, or an unwillingness to escalate. The technology exists; the process around it determines whether it is effective.

A mature IR capability has the following properties:

- Documented incident response plan, reviewed annually.
- Defined roles and responsibilities, with named people in each role.
- Documented playbooks for the top incident types.
- A communication plan covering internal, executive, customer and regulatory channels.
- Evidence preservation procedures aligned with legal and forensic requirements.
- Post-incident review process that produces actionable improvement.
- Regular testing through tabletop exercises and, for mature programs, full simulations.

The IR program exists to reduce the time between detection and containment, reduce the damage of each incident, reduce the recurrence of the same incident type, and satisfy legal and regulatory reporting obligations.

## 2. Where in the Organization

IR is a cross-functional capability. The following roles are involved:

- **Incident Response Manager / IR Lead** - owns the incident from declaration to closure. Coordinates the response, makes or escalates decisions, and interfaces with executive leadership.
- **SOC analysts (Tier 1, Tier 2, Tier 3)** - detect, triage and investigate. Tier 1 handles initial triage, Tier 2 investigates and contains, Tier 3 handles advanced analysis and threat hunting.
- **Forensics analysts** - preserve evidence, perform disk and memory forensics, support legal and regulatory requirements.
- **IT operations** - execute containment actions (isolate hosts, disable accounts, block network paths), restore systems, and apply patches.
- **Legal counsel** - advise on legal obligations, regulatory reporting, litigation hold, and privilege. In some jurisdictions, legal must be involved before any external communication.
- **Communications / PR** - manage external messaging, customer notifications and press.
- **HR** - involved when an incident involves an employee, insider threat, or employee data.
- **Executive leadership / Crisis management team** - make business-impacting decisions (shut down a system, notify customers, pay a ransom - not recommended, but a decision), and own the external relationship with regulators and major customers.
- **Business unit leads** - provide context on business impact, help prioritize restoration, and manage their own communications.
- **Third-party providers** - MSSP, incident response retainer, forensics firm, cyber insurance carrier. Defined in advance with clear escalation paths.

The IR lead is the single point of coordination. In smaller organizations, one person may hold multiple roles, but the responsibilities must be assigned explicitly, not implicitly.

## 3. Threats and Failure Modes

**Threat types the IR capability must handle:**

- **Ransomware** - encryption of endpoints and servers, exfiltration and double extortion. The most disruptive incident class in recent years.
- **Business email compromise (BEC)** - account takeover, fraudulent payment requests, executive impersonation. High financial impact, low technical sophistication.
- **Credential compromise** - stolen credentials used for initial access and lateral movement.
- **Data breach** - exfiltration of customer, employee or intellectual property data. Regulatory and reputational impact.
- **Insider threat** - malicious or negligent employee action. Different investigative and legal considerations from external attack.
- **Supply chain compromise** - malicious code in a trusted vendor, or compromised vendor access.
- **Denial of service** - disruption of service availability. Often extortion-related.
- **Web application compromise** - defacement, data theft, injection attacks.
- **Cloud misconfiguration exposure** - public storage buckets, over-permissive IAM.

**Internal failure modes of the IR capability:**

- **No IR plan.** Response happens ad hoc, key steps are skipped, evidence is destroyed.
- **Unclear ownership.** No one is empowered to declare an incident. Escalation goes in circles.
- **Missing playbooks.** Every incident requires inventing the process from scratch.
- **Slow triage.** Alerts sit for hours or days. By the time IR begins, the attacker has completed the objective.
- **No containment authority.** IT operations waits for approval while the attacker moves laterally.
- **Poor communication.** Executives learn about the incident from the news. Legal is not involved until late. Customers are notified after a media leak.
- **Evidence destroyed.** Systems are wiped and rebuilt before forensic analysis. Regulatory reporting becomes impossible.
- **No post-incident review.** The same incident recurs because the root cause is never fixed.
- **Untested plans.** The plan exists, has never been exercised. When tested in a real incident, it fails at multiple points.
- **Burnout.** The same small team handles every incident. Turnover increases, institutional knowledge is lost.
- **No retainer.** The organization has no pre-arranged relationship with a forensics firm or IR provider. By the time it engages one, hours or days are lost.

## 4. Controls and Implementation

**4.1 Incident response policy.** A top-level document approved by executive leadership that establishes the IR program, its purpose, scope, and authority. Defines the IR lead role and the authority to declare incidents, isolate systems, and involve other functions.

**4.2 Incident response plan.** The operational document that describes the IR lifecycle (see the dedicated file on lifecycle), roles and responsibilities, communication paths, escalation procedures, evidence handling, and reporting obligations. Reviewed annually and after major incidents.

**4.3 Playbooks.** Documented step-by-step procedures for the top 5-10 incident types. Typical set: ransomware, business email compromise, phishing wave, credential compromise, data exfiltration, insider threat, DDoS, cloud misconfiguration, malware on endpoint, lost device. Each playbook has: detection criteria, initial triage steps, containment actions, eradication steps, recovery steps, evidence collection, communication requirements, and closure criteria.

**4.4 Roles and RACI.** RACI matrix for every incident type and every phase. No ambiguity about who is responsible, who approves, who must be consulted and who is informed.

**4.5 Communication plan.** Defined channels and templates for internal, executive, customer and regulator communication. Includes pre-approved language for common scenarios (ransomware, data breach, third-party incident). Communication is a rehearsal, not an improvisation.

**4.6 Detection and triage.** Detection comes from SIEM, EDR, network sensors, threat intelligence, user reports and third-party notifications. Triage prioritizes based on severity, asset criticality, and confidence. Documented triage matrix maps alert type to initial response.

**4.7 Evidence preservation.** Systems are imaged and memory captured before remediation. Chain of custody is documented. Forensic analysis uses tools that do not modify evidence. Evidence is retained per legal and regulatory requirements.

**4.8 Retainer and external resources.** Pre-arranged relationship with a forensics firm, an IR retainer, and cyber insurance. The retainer contract defines the engagement process, response time commitments and points of contact.

**4.9 Post-incident review.** Within 1-2 weeks of incident closure, a blameless post-incident review identifies: what happened, what worked, what did not, root causes, and action items. Each action item has an owner and a due date. The review is documented and shared with stakeholders.

**4.10 Metrics and testing.** See the dedicated file on metrics and testing. At minimum: annual tabletop exercise, quarterly playbook review, monthly metric reporting.

**4.11 Training and awareness.** IR team members receive role-specific training. Executives receive training on their role in incident response (decisions they must make, communication expectations). The broader workforce knows how to report a suspected incident.

**4.12 Legal and regulatory alignment.** The IR plan explicitly identifies legal reporting obligations (GDPR 72-hour breach notification, SEC cybersecurity disclosure, HIPAA breach notification, NIS2, sector-specific rules). The reporting process is rehearsed before an incident occurs.

## 5. Tooling

- **SIEM** - central log aggregation and correlation. Examples: Splunk, Microsoft Sentinel, Elastic Security, IBM QRadar, Sumo Logic.
- **EDR / XDR** - endpoint detection and response, extended detection and response. Examples: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Carbon Black.
- **SOAR** - security orchestration, automation and response. Automates routine response actions. Examples: Palo Alto Cortex XSOAR, Splunk Phantom, Tines, Torq.
- **Network detection and response (NDR)** - network-level visibility and analytics. Examples: Darktrace, Vectra, ExtraHop.
- **Forensics tools** - disk imaging (FTK Imager, dd, Guymager), memory capture (LiME, WinPmem, Magnet RAM Capture), analysis (EnCase, FTK, Autopsy, Volatility, Redline).
- **Case management** - ticketing integrated with incident workflow. Examples: TheHive, ServiceNow Security Operations, Jira Service Management.
- **Threat intelligence platform** - enriches detection with IOC context. Examples: MISP, Recorded Future, Anomali.
- **Secure communication** - out-of-band channels for incident coordination when email is compromised. Examples: dedicated Signal group, secure conferencing, out-of-band phone bridge.
- **Documentation and evidence store** - a secure repository for incident artifacts, chain of custody, and post-incident reports. Access-controlled and auditable.

The toolchain should integrate, not just coexist. The SIEM feeds the SOAR, the SOAR opens the case, the case links to evidence, the post-incident review references the case. Disconnected tools create manual handoffs that slow response.

## 6. Verification and Metrics

The IR capability itself is verified through testing and metrics.

**Verification activities:**

- **Tabletop exercises** - scenario-based discussion exercises with key stakeholders. At least annually. Tests decision-making and communication, not just technical response.
- **Simulations / red team exercises** - controlled adversary emulation, testing detection and response end-to-end. At least annually for mature programs.
- **Playbook validation** - quarterly review of each playbook against current threats, tools, and roles. Verify the steps work as written.
- **Retainer readiness check** - annual confirmation that the retainer contact, escalation path and response time commitment are current.
- **Communication drill** - test the communication plan with a no-notice simulation of an executive notification and a customer notification.

**Metrics (see dedicated file for detail):**

- **Mean time to detect (MTTD)** - time from attacker action to detection.
- **Mean time to respond (MTTR)** - time from detection to containment.
- **Mean time to recover (MTTR-recovery)** - time from containment to full restoration.
- **Percentage of incidents with documented post-incident review** - target above 90% for significant incidents.
- **Percentage of high-severity playbooks tested in the last 12 months** - target 100%.
- **Action items closed on time** - percentage of post-incident action items closed by due date.
- **Repeat incident rate** - incidents with the same root cause recurring within 12 months. Target near zero.

**Verification evidence for audit:** IR plan (dated, version-controlled), playbooks, RACI matrix, tabletop reports, simulation reports, post-incident reviews, training records, retainer contracts.

## 7. Anti-Patterns

- **No plan.** "We'll figure it out when it happens." Every response is improvised.
- **Plan on a shelf.** Documented, never read, never tested, never updated. Fails on first contact with reality.
- **Plan is technical only.** No communication plan, no legal involvement, no executive decision-making framework.
- **No authority to act.** No one can isolate a compromised host without three levels of approval. Attacker moves freely during the delay.
- **Under-testing.** Tabletop exercise is optional and never happens. The plan's assumptions are never validated.
- **Blame culture.** Post-incident review identifies the individual who "clicked" and stops there. Root cause (training, process, technical control) is never addressed.
- **No legal involvement.** Company reports a breach to regulators without legal review of the language and scope. Creates additional legal exposure.
- **Unilateral communication.** Executives learn about the incident from a journalist. Uncoordinated messaging creates panic and inconsistency.
- **Fighting the incident with the incident.** SOC communicates via corporate email while the corporate email is under attack. Out-of-band channels are essential.
- **No retainer.** Forensics firm engaged after the incident. Days are lost to procurement and onboarding.
- **No documentation.** Incident resolved, nothing written. Next incident of the same type starts from zero.
- **The heroes syndrome.** A single person handles every incident, burns out and leaves. Institutional knowledge is not distributed.

## 8. Certification Alignment

- **CISSP Domain 7 (Security Operations)** - incident response, forensics, business continuity. Domain 1 (Security and Risk Management) - legal and regulatory aspects.
- **CISM Domain 4 (Information Security Incident Management)** - incident response plan, detection, response, post-incident review.
- **Security+ SY0-701 Domain 4 (Security Operations)** - incident response procedures, forensics, incident response plan. Domain 5 (Security Program Management and Oversight) - incident response plans, communication.
- **CySA+ (CS0-003)** - incident response, threat detection, analysis and reporting.
- **ISO/IEC 27035** - Information security incident management. Annex A 5.24-5.28 of ISO 27001 cover incident management planning, response, learning.
- **NIST SP 800-61 Rev. 3** - Incident response recommendations. Incorporates cybersecurity risk management throughout.
- **NIST CSF 2.0 RS (Respond) and RC (Recover)** - incident response, incident management, incident mitigation, recovery planning.

Exam-relevant points: the incident response lifecycle has phases: preparation, detection and analysis, containment, eradication, recovery, post-incident activity. The IR plan requires executive approval and authority to act. Legal must be involved before external communication. Post-incident review is blameless and produces actionable items.

## 9. References

- NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management - https://csrc.nist.gov/pubs/sp/800/61/r3/final
- SANS Incident Handler's Handbook - https://www.sans.org/white-papers/33901/
- CISA Incident and Vulnerability Response Playbooks - https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
- ISO/IEC 27035 - Information Security Incident Management - https://www.iso.org/standard/78973.html
- NIST CSF 2.0 - Respond and Recover functions - https://www.nist.gov/cyberframework
- ENISA Incident Response Reference Material - https://www.enisa.europa.eu/topics/incident-response
- ISO/IEC 27001:2022 Annex A 5.24 - Planning information security incident management, through Annex A 5.28 - Collection of evidence