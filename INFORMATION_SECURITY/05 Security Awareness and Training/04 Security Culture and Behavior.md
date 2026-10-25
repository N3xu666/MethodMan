# Security Culture and Behavior

Security culture is the shared set of beliefs, values and assumptions that determine how people actually behave with respect to security, independent of what the policy says. It is the difference between an employee who reports a suspicious email because they want to, and an employee who reports because they fear being caught not reporting.

## 1. Overview

Culture is often described as "the way things are done around here when no one is watching." In security terms, it is what an employee does when the correct secure action is inconvenient, uncertain, or socially costly, and there is no immediate consequence either way.

Security culture is distinct from, but related to, the awareness program:

- **Awareness** produces knowledge: the employee knows what phishing looks like.
- **Training** produces skill: the employee can recognize phishing and knows the reporting procedure.
- **Culture** produces the default behavior: the employee reports phishing without hesitation because reporting is what people here do, and because reporting is valued rather than questioned.

A strong security culture has the following observable characteristics:

- Employees report suspicious activity without fear of blame.
- Security is treated as a shared responsibility, not a security team problem.
- Leaders visibly model secure behavior and prioritize security over convenience when the two conflict.
- Employees ask security questions early, not after the incident.
- Near-misses are discussed openly and used to improve, not to assign fault.
- Security is embedded in business processes, not bolted on as an afterthought.

Culture is measured, not assumed. The measurement instruments are surveys, incident reporting behavior, near-miss reporting rates, and qualitative input from employee focus groups.

## 2. Where in the Organization

Culture is set at the top and shaped at the middle. It lives in every business unit.

- **Executive leadership** - sets the tone. If executives bypass security controls for convenience, the culture is "security is optional for important people." If executives are publicly supportive of security and follow the same rules, the culture reflects it.
- **Middle managers** - the most important cultural layer. Managers interpret policy into daily practice. A manager who complains about security requirements teaches the team that security is a burden.
- **Security team** - the visible face of security for most employees. Tone, responsiveness, and framing of interactions determine whether employees see security as a partner or an obstacle.
- **HR** - the process owner for onboarding, performance management and incident response involving employees. HR alignment on non-punitive reporting is essential.
- **Internal communications** - shapes the narrative. Security communications written in a partnership tone contribute to culture; those written in a compliance tone erode it.
- **Every employee** - culture is the aggregate of individual decisions. It is shaped by the examples set by peers.

The most common organizational failure is that culture is delegated to the security awareness team, while the actual behavior modeled by executives and managers contradicts the program. Culture is not a communications problem; it is a leadership problem.

## 3. Threats and Failure Modes

**Cultural failure modes that undermine security:**

- **Blame culture.** Employees who make mistakes are shamed or disciplined. Result: incidents and near-misses are hidden, response is delayed, root cause is never fixed.
- **Compliance theater.** Security is measured by forms submitted, not by outcomes. Employees learn to satisfy the form.
- **Security as an obstacle.** Security reviews delay projects, block tools, and add friction without visible benefit. Employees route around them.
- **Executive exceptionalism.** Leaders bypass controls, request exceptions, or are visibly exempt from training. Everyone notices.
- **Silent security team.** The security team only appears when something goes wrong. Employees associate security with incidents and punishment.
- **Fear of asking.** Employees do not ask security questions because they fear being seen as ignorant or as a problem.
- **Productivity above security, always.** Every trade-off favors delivery speed. Security is deferred until an incident forces attention.
- **No near-miss reporting.** Only incidents are reported; near-misses are invisible. The organization cannot learn from what almost happened.
- **Macho culture.** Security is treated as a test of toughness. Vulnerability, uncertainty, or asking for help are seen as weakness.
- **Cyclical attention.** Security is prioritized after each incident, then decays once the memory fades.

**Behavioral threats the culture must resist:**

- **Normalized deviance.** Small deviations from policy gradually become the norm (sharing passwords with a trusted colleague, bypassing MFA "just this once").
- **Optimism bias.** "It won't happen to me." Employees underestimate their personal risk.
- **Social proof.** "Everyone else does it." If colleagues disable MFA or share credentials, the behavior spreads.
- **Authority bias.** A request from a senior person bypasses policy without question.
- **Urgency pressure.** Under time pressure, security steps are skipped.

## 4. Controls and Implementation

Culture cannot be dictated, but it can be deliberately shaped through specific practices.

**4.1 Leadership modeling.** Executive leaders:

- Complete the same awareness training as everyone else, visibly and on time.
- Follow the same security policies, including MFA, secure devices and password practices.
- Publicly acknowledge security decisions that favored safety over speed.
- Include security in all-hands meetings with the same priority as business results.

**4.2 Middle manager engagement.** Middle managers are the cultural transmission layer. Engagement practices:

- Managers receive a brief summary of their team's phishing simulation results with the message: your team's numbers, your call to action.
- Managers include a security topic in their team meeting at least quarterly.
- Managers are trained to respond to employee reports with positive acknowledgment, not skepticism.

**4.3 Non-punitive reporting.** Formalize and communicate that reporting is valued and that employees who report a mistake are protected from disciplinary action. HR policy documents this. The CISO restates it periodically.

**4.4 Near-miss reporting channel.** A dedicated near-miss reporting form and process. Near-misses are analyzed in the same way as incidents, with a focus on process improvement rather than blame.

**4.5 Security team accessibility.** The security team is visible and approachable:

- Regular office hours for questions.
- A "security ask" channel in the collaboration platform.
- Security team members attend business unit meetings periodically.
- Fast, respectful response to all questions, no matter how basic.

**4.6 Tone of communication.** All security communications are written in a partnership tone, not a compliance tone. The framing is "here is how we protect each other," not "you must comply."

**4.7 Recognition programs.** Employees who report real phishing, catch a security issue, or ask a good question are recognized. Recognition is frequent, specific and public where appropriate.

**4.8 Post-incident learning.** After an incident, the response includes a blameless post-mortem. Findings focus on process, not individual. The post-mortem summary is shared with affected teams as a learning opportunity.

**4.9 Culture survey.** An annual or semi-annual survey measuring security culture. Questions cover:

- Perceived importance of security to leadership.
- Comfort reporting mistakes.
- Perceived responsiveness of the security team.
- Perceived priority of security versus delivery speed.
- Confidence in recognizing and responding to threats.

Survey results are tracked over time and shared with executive leadership.

**4.10 Integration with business processes.** Security is embedded in how work is done, not added as a gate:

- Security review is part of project intake, not an afterthought.
- Security requirements are included in the definition of done.
- Security considerations appear in design reviews and code reviews.
- Security metrics appear in business unit dashboards.

## 5. Tooling

Culture is primarily built through practices, not tooling. Tooling supports the practices.

- **Culture survey platform** - for the annual security culture survey. Examples: Qualtrics, CultureAmp, SurveyMonkey, Microsoft Forms. Custom surveys aligned with known frameworks (e.g. the CLTRe security culture framework, or the SANS Security Culture survey).
- **Recognition platform** - for employee recognition. Examples: Bonusly, Kudos, internal recognition programs.
- **Incident and near-miss reporting tool** - the ticketing system used for security reports, with a near-miss category.
- **Anonymous reporting channel** - a form or hotline for employees who do not want to be identified.
- **Collaboration platform channels** - the "security ask" and near-miss channels in Slack/Teams.
- **Business intelligence** - dashboards that combine survey results, reporting volumes and incident trends.

The toolchain is optional. Many of the strongest culture interventions are practices (leadership modeling, tone, recognition) rather than tools.

## 6. Verification and Metrics

Cultural health is measured through a combination of quantitative and qualitative instruments.

**Quantitative metrics:**

- **Security culture survey score** - the aggregate score from the annual survey, tracked over time. Target: year-over-year improvement.
- **Near-miss reporting rate** - number of near-misses reported per quarter. Rising volume is often a positive sign (more trust to report) rather than negative.
- **Time-to-report** - the interval between an incident and the first report from an employee. Faster reporting indicates stronger culture.
- **Voluntary security questions** - the volume of voluntary questions asked through the security team's channels. Rising volume suggests security is approachable.
- **Security exception requests** - how many employees request exceptions. High numbers indicate friction; low numbers with visible bypassing indicate a culture problem.
- **Post-incident survey** - brief survey of employees involved in an incident, on how supported they felt during the response.

**Qualitative metrics:**

- **Focus groups** - small group interviews with employees from different business units and levels. What do they believe about security? What prevents them from speaking up?
- **Incident post-mortems** - narrative evidence from post-mortems on whether blame was assigned.
- **Exit interviews** - departing employees often reveal cultural issues they would not raise otherwise.

**Maturity model for culture:**

- **Level 1 - Compliance.** Policy exists, employees complete training. Security is treated as external.
- **Level 2 - Awareness.** Employees recognize common threats. Reporting channels exist. Culture is not yet a stated priority.
- **Level 3 - Shared responsibility.** Employees feel responsible for security in their area. Leadership visibly supports. Culture survey in place.
- **Level 4 - Trusted reporting.** Non-punitive reporting is real, not just written. Near-misses are reported. Security team is approachable.
- **Level 5 - Embedded.** Security is part of how the business operates. Culture is continuously measured and improved. Incidents are learning events, not blame events.

**Verification evidence for audit:** survey results, near-miss logs, recognition records, post-mortem narratives, culture maturity assessment.

## 7. Anti-Patterns

- **Tone deaf leadership.** Executive asks for an exception to MFA policy. All the awareness work for the quarter is undone in one visible action.
- **Punishing reporters.** Employee reports a suspected incident that turns out to be a false positive. They are told their report wasted time. They and their colleagues stop reporting.
- **Security as an obstacle.** Security review adds weeks to a project with no clear explanation or path forward. Employees learn to route around it.
- **Compliance-tone communications.** Security messages written in the imperative ("You must...") without context or partnership. Creates resistance.
- **Ignoring near-misses.** Only incidents are reported and analyzed. Near-misses are invisible, learning opportunities missed.
- **Culture survey with no follow-up.** Survey measures culture, results are shared, no changes result. Employees lose trust in the process.
- **Anonymous reporting that is not anonymous.** Employees suspect their identity is tracked. Trust collapses when this is discovered.
- **Annual security day.** A once-per-year celebration of security with no ongoing practices. Culture does not work that way.
- **Security team only visible during incidents.** Every interaction with security is a response to a problem. Employees associate security with trouble.
- **Framing security as "you versus us."** The security team and the business as adversaries. Misaligned from every angle.

## 8. Certification Alignment

- **CISSP Domain 1 (Security and Risk Management)** and **Domain 7 (Security Operations)** - security culture, awareness, human factors.
- **CISM Domain 3 (Information Security Program Development and Management)** - program ownership, culture and behavior, integration with business processes.
- **Security+ SY0-701 Domain 5 (Security Program Management and Oversight)** - awareness, human factors, security culture.
- **ISO 27001 Annex A 7.3 (Awareness, education and training)** and **Annex A 5.4 (Management responsibilities)** - the standard implicitly requires a culture in which policies are followed; Annex A 5.4 assigns responsibility for information security to management.
- **NIST CSF 2.0 PR.AT (Awareness and Training)** and **GV.RR (Roles, Responsibilities and Authorities)** - awareness and training, plus clear roles and responsibilities.

Exam-relevant points: culture is set at the top and shaped at the middle. Security culture is measured, not assumed. A non-punitive reporting culture is required for effective incident response.

## 9. References

- SANS Security Culture Framework - https://www.sans.org/security-awareness-training/security-culture/
- CLTRe Security Culture Framework - https://www.cltre.net/
- NIST SP 800-50 - Building an Information Technology Security Awareness and Training Program - https://csrc.nist.gov/pubs/sp/800/50/final
- ENISA Cybersecurity Culture - https://www.enisa.europa.eu/topics/cybersecurity-education
- CISA Cybersecurity Culture - https://www.cisa.gov/topics/cybersecurity-best-practices
- Lance Spitzner - The Security Culture Playbook (book)
- ISO/IEC 27001:2022 Annex A 5.4 - Management responsibilities, and Annex A 7.3 - Awareness, education and training