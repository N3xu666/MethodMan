# Crisis Management and Communications

A cybersecurity incident becomes a crisis when its consequences exceed what routine incident response can handle: regulatory exposure, customer trust damage, media attention, or business interruption at scale. Crisis management is the discipline of leading the organization through that larger disruption. Crisis communications is the practice of telling the right story to the right audience at the right time, without making the situation worse.

## 1. Overview

Crisis management is distinct from incident response. Incident response is technical and operational: contain, eradicate, recover. Crisis management is strategic and cross-functional: decide, communicate, coordinate, and preserve the organization's ability to operate and its reputation. The two run in parallel during a significant incident, led by different people, with a shared understanding of the situation.

Crisis communications is a component of crisis management, not a substitute for it. Statements that promise more than is true, that blame a party too early, or that are silent when silence creates a vacuum are all worse than a statement that says "we are investigating, we will update you at a defined time."

Core elements of a crisis management framework:

- **Crisis definition** - documented criteria that distinguish an incident from a crisis. Triggers include data exfiltration of customer PII, ransomware that disrupts operations beyond a threshold, regulatory notification obligations, media exposure, executive or insider involvement, and cross-border impact.
- **Crisis management team (CMT)** - the group that leads the crisis response. Typically: CEO or COO (chair), CISO, general counsel, CFO, head of communications, head of HR, head of operations, and a designated crisis coordinator.
- **Crisis command center** - physical or virtual location with reliable out-of-band communications, separate from the compromised environment.
- **Decision authority** - who can authorize specific actions: customer notification, regulatory filing, payment of ransom (not recommended), shutdown of systems, public statement.
- **Communications plan** - audiences, channels, timelines, templates, and spokespersons for each audience.
- **Escalation path** - how the incident is escalated from incident response to crisis management. The trigger is predefined; the decision to escalate is not made in the heat of the moment.
- **Documentation** - decision log throughout the crisis. Regulators, boards and courts will want to know what was decided and when.

A crisis ends when the acute phase is over and the organization is operating under a stable, if reduced, posture. The post-crisis review follows, and the lessons feed back into both crisis management and incident response.

## 2. Where in the Organization

The crisis management team is a standing body, not convened ad hoc. It has:

- **Chair** - typically CEO or COO, unless the crisis is operational and the CEO delegates to the COO or CISO. The chair makes final strategic decisions.
- **Crisis coordinator** - ensures the CMT runs to its plan, keeps the decision log, tracks actions and external deadlines. Often a business continuity or risk manager.
- **CISO / security lead** - provides the technical situation picture, advises on impact and risk, but is not the crisis decision-maker.
- **Legal counsel** - advises on regulatory obligations, notification, litigation exposure, privilege, and the language of external statements.
- **Communications lead** - drafts and delivers external and internal communications, manages media relationships, coordinates with PR agencies.
- **CFO** - financial impact assessment, insurance, banking relationships, investor communications.
- **HR lead** - employee communication, internal investigations, employee wellbeing, coordination with law enforcement on insider matters.
- **Operations lead** - business continuity activation, alternate processes, customer-impact decisions.
- **Board and audit committee** - informed and, for material incidents, engaged. The board may have its own notification and reporting obligations.

The CISO is not the crisis manager. The CISO provides the technical picture, the incident response leadership provides the timeline and scope, and the CMT makes the cross-functional decisions.

## 3. Threats and Failure Modes

**Crisis-specific threats:**

- **Simultaneous crises** - a cyber incident during an unrelated operational crisis (weather, supplier failure, executive resignation) that competes for attention and resources.
- **Regulatory clock** - legal deadlines (GDPR 72 hours, SEC 4 business days for material incidents, NIS2 timelines) start at the moment of awareness, not the moment of full understanding. Delay in forming the crisis team consumes the deadline.
- **Media exposure before internal coordination** - a journalist publishes before leadership has aligned messaging.
- **Customer notification before scope is known** - customers are told too much, too little, or too early. All three have reputational and legal consequences.
- **Ransom negotiation pressure** - the attacker's deadline creates urgency that overrides good decision-making.
- **Law enforcement coordination complexity** - engaging law enforcement can be beneficial or can complicate certain response actions. The decision has timing consequences.

**Failure modes of crisis management and communication:**

- **No crisis definition.** Every incident escalates to the CMT, or no incident ever does. Both are wrong.
- **No CMT pre-formed.** The team is assembled in the crisis. Roles are unclear, trust is not established, communication is slow.
- **No decision authority.** The CMT cannot authorize customer notification because that requires CEO approval, who is unreachable because primary communications are compromised.
- **Communications deferred.** The organization says nothing while silence is filled with speculation. The narrative is set by others.
- **Premature attribution.** Publicly blaming a specific attacker or vendor before facts are established. Legal risk, reputational risk, and potentially strategic harm.
- **Over-promising.** "No customer data was accessed" said before analysis is complete, then contradicted by evidence a week later. Trust destroyed in a single statement.
- **Under-communicating.** Minimum statements that leave customers, regulators and employees uncertain and anxious.
- **Inconsistent messaging.** Different executives say different things to different audiences. Media and employees receive different versions.
- **Missing internal communication.** Employees learn about the crisis from external sources. Internal rumor fills the gap.
- **No out-of-band channels.** CMT communicates via corporate email, which is compromised. Or via corporate chat, which is unavailable.
- **Law enforcement engaged late** - creates problems for evidence preservation, for law enforcement relationships, and for regulatory obligations.
- **No decision log.** The CMT made decisions but the reasoning is not documented. Regulators and courts see inconsistent or absent rationale.
- **No post-crisis review.** The organization returns to normal, the crisis response is celebrated, and no lessons are captured.

## 4. Controls and Implementation

**4.1 Crisis definition and escalation criteria.** Documented criteria for declaring a crisis. Examples:

- Confirmed data exfiltration of customer PII affecting more than N individuals.
- Ransomware disrupting a critical business function for more than 4 hours.
- Regulatory notification obligation triggered.
- Media inquiry about the incident.
- Involves an executive or insider.
- Impacts more than one country or regulatory jurisdiction.

The escalation decision is made by the IR lead or the CISO, and the CMT is convened by the crisis coordinator.

**4.2 Standing CMT and deputies.** The CMT is named, with a deputy for each role. Named people have contact details maintained. Alternates are trained to the same standard. The CMT meets quarterly in non-crisis mode, to review the plan, discuss recent incidents (blameless), and prepare.

**4.3 Crisis management plan.** Documented, covering:

- Crisis definition and escalation.
- CMT roles and deputies.
- Command center location (physical and virtual).
- Communication channels and out-of-band paths.
- Decision authority matrix.
- Documentation requirements.
- Coordination with external parties (law enforcement, regulators, vendors, insurers).
- Closure and post-crisis review process.

**4.4 Communications plan.** Organized by audience, with templates and timelines:

- **Employees**: internal memo, intranet banner, manager cascade, FAQ. Within hours of crisis declaration.
- **Executives and board**: briefing note, briefing session. Within hours.
- **Customers**: personalized communication for affected customers, general statement for others. Timeline depends on the situation, but not later than legal deadlines.
- **Regulators**: formal notification per jurisdiction. Within legal deadlines (72 hours for GDPR, 4 business days for SEC material incidents, etc.).
- **Vendors and partners**: notification if they are affected or need to act.
- **Media and public**: press statement, spokesperson briefings, social media.
- **Law enforcement**: coordination through legal.

**4.5 Communication templates.** Pre-approved language for common scenarios:

- "We are investigating a security incident that may affect some of our services."
- "We have notified the relevant authorities and are cooperating with their investigation."
- "We are not aware of any impact to customer data at this time."
- "We will provide further updates at [specific time]."

Templates are adapted to the specific situation, but starting from a pre-approved base prevents rushed, problematic language.

**4.6 Out-of-band communication.** CMT communication does not rely on the corporate email or chat. Examples:

- Dedicated Signal or WhatsApp group.
- Conference bridge with a dial-in number outside the corporate PBX.
- Pre-arranged meeting location.
- Pre-distributed emergency contact list (also in physical form).

Out-of-band channels are tested as part of tabletop exercises.

**4.7 Decision log.** Every material decision is logged: decision, alternatives considered, reasoning, who decided, when. The log is maintained throughout the crisis and is part of the permanent record.

**4.8 Legal coordination.** Legal is engaged at crisis declaration, not later. Legal advises on:

- Notification obligations (regulators, individuals, contractual counterparties).
- Litigation hold.
- Privilege for internal investigation.
- Law enforcement coordination.
- Content of external statements.

**4.9 Law enforcement coordination.** The decision to engage law enforcement is made by the CMT (typically through legal). Advantages: investigative resources, coordination on attacker attribution, leverage with regulators, evidence for prosecution. Disadvantages: potential loss of control over the disclosure timeline, involvement of additional parties, potential impact on ransom negotiation. The decision is documented.

**4.10 Media relations.** A designated spokesperson (or small set of spokespersons) speaks to media. Individual executives do not give ad hoc comments. The communications lead drafts, legal reviews, CMT approves.

**4.11 Post-crisis review.** Within 2-4 weeks of crisis closure, a comprehensive review:

- Timeline of the crisis.
- CMT performance.
- Communications effectiveness.
- Legal and regulatory handling.
- Business impact.
- Lessons learned.
- Action items with owners and deadlines.

The review is shared with the CMT, the board and, at the appropriate level of detail, with the broader organization.

## 5. Tooling

- **Crisis communication platform** - emergency notification systems that send SMS, voice, email and app notifications to large populations. Examples: Everbridge, OnSolve, xMatters, AlertMedia.
- **Out-of-band communication** - Signal, WhatsApp, secure conferencing (Zoom with encryption, Teams with E2EE where available), dial-in conference services independent of corporate infrastructure.
- **Secure documentation** - a secure repository for the CMT to share documents, decision log and status updates. Examples: secure SharePoint site, dedicated encrypted workspace.
- **Incident and crisis management platform** - integrated case management for the CMT, with decision logging and communications tracking. Examples: Fusion Risk Management, Archer, ServiceNow crisis management module.
- **Media monitoring** - track external mentions of the crisis. Examples: Meltwater, Brandwatch, Google Alerts (minimum).
- **Legal hold and eDiscovery platforms** - for preserving evidence and internal communications.
- **Secure video conferencing** - with the ability to operate independently of the compromised environment.

The toolchain is a vehicle, not a solution. A crisis without a plan and a trained CMT cannot be run with tools alone.

## 6. Verification and Metrics

Crisis management and communications are verified through drills and measured through performance in real crises.

**Verification activities:**

- **Tabletop exercise (Crisis)**: at least annually, separate from IR tabletops. Tests CMT coordination, decision-making and communications. Scenario-based, with injected complications.
- **Communication drill**: no-notice test of internal and executive notification. Can be run quarterly.
- **Out-of-band test**: verify the CMT can communicate via the defined channels without corporate infrastructure.
- **Media training**: designated spokespersons trained annually in media handling.
- **Legal participation drill**: legal engaged as part of the exercise, confirming their readiness.
- **Board briefing drill**: the board receives a briefing as part of the exercise, confirming their readiness.

**Metrics (for post-crisis review):**

- **Time to CMT convening** - from crisis declaration to first CMT meeting. Target: under 30 minutes for critical crises.
- **Time to internal communication** - from crisis declaration to employee notification. Target: under 4 hours.
- **Time to regulatory notification** - from awareness to submission. Measured against the applicable deadline.
- **Time to external communication** - from CMT decision to public statement. Target: under 24 hours for a public incident.
- **Decision log completeness** - all material decisions logged. Target: 100%.
- **CMT participation rate** - percentage of CMT members who attended the crisis or their deputy attended. Target: 100%.
- **Action items from post-crisis review closed on time** - target 90%.

**Verification evidence for audit:** crisis management plan (dated, version-controlled), CMT roster with alternates, communication templates, tabletop exercise reports, communication drill logs, media training records, post-crisis review documents, decision logs.

## 7. Anti-Patterns

- **The CISO runs the crisis.** The CISO provides the technical picture, but strategic decisions are cross-functional. A crisis run by the CISO ends up as a technical discussion, and business, legal and communications are late.
- **No crisis definition.** Every incident escalates to the CEO, or none does. Either extreme wastes resources or leaves the organization exposed.
- **CMT assembled ad hoc.** No pre-formed team, no training, no trust. When crisis comes, they meet for the first time.
- **Communication via email during an email incident.** The primary channel is compromised. The CMT coordinates through the channel that is under attack.
- **Silence as strategy.** "We will not comment until we know more." Meanwhile, media, customers and regulators fill the vacuum. The narrative is set by others.
- **Premature attribution.** Publicly blaming "Russian hackers" or a specific vendor before facts. Legal and reputational risk.
- **Over-promising.** "No data was accessed" said too early, contradicted later. Trust destroyed.
- **Legal engaged too late.** Notification deadlines missed, privilege lost, litigation exposure created.
- **Media statements before customer notification.** Customers learn through the news. The relationship is damaged.
- **Inconsistent messaging.** CEO says X, CTO says Y, communications team says Z. Third parties receive different versions.
- **No decision log.** Decisions made verbally, no record. Regulators and courts see inconsistent rationale.
- **Law enforcement engaged too late.** Evidence lost, relationship damaged, coordination complicated.
- **Post-crisis review skipped.** "We got through it, time to move on." The same crisis recurs next year.
- **Review that names individuals.** Blame-driven post-crisis review. No one reports honestly next time.

## 8. Certification Alignment

- **CISSP Domain 1 (Security and Risk Management)** - legal and regulatory concerns, business continuity. Domain 7 (Security Operations) - incident response, crisis communication.
- **CISM Domain 4 (Information Security Incident Management)** - crisis management and business continuity. Domain 2 (Information Security Governance) - executive communication and reporting.
- **Security+ SY0-701 Domain 4 (Security Operations)** and **Domain 5 (Security Program Management and Oversight)** - incident response, communication, business continuity.
- **ISO/IEC 27001 Annex A 5.24-5.28** - incident management planning and response, plus **Annex A 5.29 (Information security during disruption)**.
- **ISO 22301** - Business continuity management, with crisis management as an element.
- **NIST CSF 2.0 RS.CO (Incident Response Communication) and RS.MA (Incident Management)** - incident communication and management.
- **NIST SP 800-61 Rev. 3** - incident response, including crisis communication.

Exam-relevant points: crisis management is distinct from incident response; the CISO is not the crisis decision-maker. Communication plans include employees, customers, regulators, vendors, media, and law enforcement. Legal is engaged at crisis declaration. Decision logs are mandatory. Premature attribution and over-promising are common failure modes.

## 9. References

- NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management - https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST CSF 2.0 - Respond function, Communication - https://www.nist.gov/cyberframework
- CISA Crisis Communications Planning - https://www.cisa.gov/topics/emergency-communications
- FTC Data Breach Response: A Guide for Business - https://www.ftc.gov/business-guidance/resources/data-breach-response-guide-business
- SEC Cybersecurity Disclosure Rules - https://www.sec.gov/rules/final/2023/33-11216.pdf
- GDPR Article 33 - Notification of a personal data breach to the supervisory authority - https://gdpr-info.eu/art-33-gdpr/
- ENISA Incident Response Reference Material - https://www.enisa.europa.eu/topics/incident-response
- ISO/IEC 27001:2022 Annex A 5.29 - Information security during disruption