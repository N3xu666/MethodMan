# Training Design and Delivery

Training design determines whether employees learn anything. Delivery determines whether they remember it. Both are engineering problems, not communications problems. This file covers how to design role-appropriate curricula, how to choose delivery formats that respect the learner's time and cognitive load, and how to integrate training with the employee lifecycle.

## 1. Overview

Effective security training follows established instructional design principles rather than intuition. A well-designed module has clear learning objectives, content that matches the objectives, activities that require the learner to apply knowledge, and an assessment that measures whether the objective was met.

The dominant design frameworks are:

- **ADDIE** - Analysis, Design, Development, Implementation, Evaluation. A linear instructional design model used broadly in corporate training.
- **Bloom's Taxonomy** - a hierarchy of learning objectives from remembering to creating. Awareness training typically targets the lower levels (remember, understand, apply) while role-specific training may target analyze and evaluate.
- **Kirkpatrick Model** - a four-level evaluation framework: reaction, learning, behavior, results. Widely used to demonstrate training effectiveness.
- **Microlearning** - delivery of short, focused units (3-10 minutes) that fit into the employee's workflow rather than interrupting it.

The design should be informed by the risk register and by data from phishing simulations and incident reviews. If the previous quarter saw three incidents involving misdirected email, the next quarter's training should reinforce correct email handling.

Delivery is the operational layer: LMS configuration, calendar scheduling, communication cadence, integration with onboarding, and feedback collection.

## 2. Where in the Organization

Training design and delivery is a collaboration between:

- **Security team** - subject matter experts. Own the content's accuracy and alignment with the threat model.
- **Learning and development (L&D) / HR** - instructional designers and LMS administrators. Own the pedagogical quality and the delivery logistics.
- **Internal communications** - owns the announcement, branding and tone of campaigns.
- **Business unit leads** - provide input on scheduling, workload impact and content relevance to their teams.
- **IT** - provides LMS integration, SSO, reporting feeds.

The program owner coordinates these stakeholders. Without L&D involvement, content tends to be accurate but pedagogically weak. Without security involvement, content tends to be well-produced but irrelevant to the actual threats.

## 3. Threats and Failure Modes

Design and delivery failures map to the following patterns:

- **Cognitive overload** - a single module attempting to cover every possible threat in 90 minutes. Retention approaches zero. Employees click through to complete, not to learn.
- **Death by slides** - passive lecture format with no application. Compliance is achieved, understanding is not.
- **Content that does not match the role** - developers receiving the same module as finance. Neither group finds it relevant.
- **Annual-only cadence** - one module per year, no reinforcement, no immediate application. Knowledge decays within weeks.
- **No feedback loop** - employees cannot ask questions, feedback surveys are ignored, mistakes are not addressed constructively.
- **Interrupting workflow** - scheduling training during peak business periods, mandating long synchronous sessions, blocking productivity tools until completion.
- **Accessibility gaps** - content not available in required languages, no captions on videos, not screen-reader compatible. Excludes a portion of the workforce.
- **Missing assessment** - completion tracked, knowledge not assessed. An employee who clicked through every slide is counted as trained.
- **Stale scenario content** - scenarios from threats that no longer exist or no longer target the organization.

## 4. Controls and Implementation

**4.1 Curriculum architecture.** Define a curriculum structure with three tiers:

- **Baseline** - mandatory for all employees. Covers phishing, passwords and MFA, data handling, incident reporting, acceptable use.
- **Role-specific** - mandatory for defined roles. Finance, HR, IT, executives, developers, helpdesk.
- **Continuous** - optional microlearning, newsletters, ad-hoc campaigns. Keeps awareness alive between formal modules.

**4.2 Learning objectives.** Each module has 3-5 learning objectives written in measurable terms. Example: "After this module, the employee will be able to identify three characteristics of a phishing email and demonstrate reporting it through the corporate reporting channel."

**4.3 Content development.** Content is developed against the learning objectives. For each objective, there is:

- A short explanation (context).
- A worked example (what the attacker does, what the employee should notice).
- An application activity (scenario, quiz question, or simulation).

Content is written at the appropriate reading level for the audience. Assume the employee has no security background. Avoid jargon and acronyms without explanation.

**4.4 Microlearning design.** Each module is broken into units of no more than 10 minutes. Each unit covers one concept and one application. Units are modular and can be reordered or refreshed independently. The mobile app version is designed first, since it is the most constrained.

**4.5 Role-specific content.** Content for high-risk roles is developed separately. Example for finance:

- Business email compromise: identifying executive impersonation, verifying payment changes by phone on a known-good number.
- Invoice fraud: vendor verification, callback procedures.
- Approval workflow security: shared mailboxes, delegation pitfalls.

Example for developers:

- Secure coding basics (injection, secrets in source, dependency risks).
- Recognizing supply chain attacks and typosquatting.
- The security review workflow and how to escalate concerns.

**4.6 Delivery cadence.** A recommended annual structure:

- **Q1**: baseline module for all employees (30-45 min, split into micro-units).
- **Q2**: role-specific module for high-risk roles (20-30 min) + a phishing simulation campaign.
- **Q3**: refresh baseline module (10-15 min refresher) + a themed campaign.
- **Q4**: role-specific update + phishing campaign + year-end summary.

Between formal modules, monthly microlearning emails or chat messages keep awareness active.

**4.7 Assessment design.** Each module ends with an assessment that tests application, not recall. Example questions: "Here is an email - what would you do?" with multiple plausible options. Passing threshold: 80%, with immediate feedback on wrong answers and a re-attempt option.

**4.8 LMS configuration.** Each employee is enrolled in the appropriate curriculum based on their role. The LMS sends reminders, tracks completion and syncs with the HR system for onboarding and offboarding. SSO integration is mandatory to avoid the "forgot password" dead-end.

**4.9 Communication plan.** Each module is announced by internal communications with the same quality as a business announcement, not as a compliance notice. The framing matters: "Here is a real attack that hit our industry last month and how to spot it" beats "You are required to complete training by Friday."

**4.10 Accessibility.** Content is available in the languages the organization operates in. Videos have captions. Documents are screen-reader compatible. Where required by regulation, a non-online alternative is offered.

## 5. Tooling

- **Authoring tools** - for producing modules. Examples: Articulate Storyline, Adobe Captivate, H5P (open source), or LMS-native authoring.
- **Learning Management System (LMS)** - the delivery and tracking platform. Examples: Docebo, TalentLMS, Cornerstone, Moodle (open source), or a commercial platform bundled with a phishing simulator.
- **Content libraries** - subscription libraries of ready-made modules. Examples: SANS Securing The Human, KnowBe4, Proofpoint, Cofense.
- **Video conferencing** - for live sessions, town halls, fireside chats on security topics.
- **Survey tools** - for collecting reaction and feedback (Kirkpatrick Level 1). Examples: Microsoft Forms, Google Forms, SurveyMonkey.
- **Assessment tools** - embedded in the LMS, or external (H5P quizzes, custom web apps).
- **Communication tools** - intranet, email campaign platform, Slack/Teams for microlearning delivery.

The selected toolchain should minimize the number of separate logins the employee needs. If the LMS, phishing simulator and content library all have separate accounts, adoption suffers.

## 6. Verification and Metrics

Design and delivery effectiveness is measured using the Kirkpatrick model, extended with phishing simulation data.

- **Level 1 - Reaction**: post-module survey. Did the employee find the content relevant, clear, and appropriately timed? Target: average rating above 4/5.
- **Level 2 - Learning**: assessment score at end of module. Target: 80% pass rate on first attempt, 95% after re-attempts.
- **Level 3 - Behavior**: phishing simulation click rate and report rate. Role-specific incident trends. Target: quarterly improvement.
- **Level 4 - Results**: incident rate attributable to human error. Time to detection of a real phishing email. Trend over time.

Supplementary metrics:

- **Time to complete** - compares the estimated duration to actual completion time. A large gap suggests the module is too long or the learner is skipping.
- **Drop-off rate** - percent of employees who start a module but do not complete it in the first session.
- **Retry rate** - how many employees fail the assessment on first attempt and must retry. A high retry rate with high eventual pass rate is acceptable; a high retry rate with low eventual pass suggests content-to-assessment mismatch.
- **Accessibility usage** - number of employees who use captions, screen reader, or alternative formats. Indicates whether the accessibility investment is reaching its audience.

Verification evidence for audit: module completion records, assessment scores, post-module survey results, accessibility log, LMS configuration snapshots.

## 7. Anti-Patterns

- **The 90-minute marathon.** A single long module that covers everything, with the only goal being completion. Cognitive load prevents retention.
- **Skip-to-the-end design.** Modules that allow skipping to the final quiz, which is then guessed. The employee completes, does not learn.
- **Quiz that tests memory.** "What does the acronym BEC stand for?" instead of "Here is an email, what would you do?". Tests recall, not application.
- **One size fits all.** The same module for developers and finance. Neither finds it relevant, both click through.
- **Forced synchronous sessions.** Live webinars at a fixed time for a global workforce. Attendance drops, and a recording alone is not equivalent.
- **Mandatory completion without assessment.** Completion is tracked, learning is not verified.
- **Production quality over content accuracy.** A beautifully produced video that teaches the wrong thing, or is outdated by the time it ships.
- **No post-launch evaluation.** Module shipped, completion tracked, but no review of whether it changed anything. Feedback surveys not read.
- **Accessibility as an afterthought.** Captions and screen-reader compatibility added only after an employee complains.

## 8. Certification Alignment

- **CISSP Domain 1 (Security and Risk Management)** and **Domain 7 (Security Operations)** - awareness and training as risk treatment and operational control. Training design, delivery and evaluation.
- **CISM Domain 3 (Information Security Program Development and Management)** - developing and delivering the security awareness program, measuring program effectiveness.
- **Security+ SY0-701 Domain 5 (Security Program Management and Oversight)** - security awareness and training, user guidance and training.
- **ISO 27001 Annex A 7.3** - awareness, education and training. The standard requires competence and awareness, not just completion.
- **NIST CSF 2.0 PR.AT** - awareness and training. Specifically, "all personnel are provided with awareness and training, and are equipped to perform their security-related duties".

Exam-relevant points: training design is not communications - it is instructional design. Assessment should test application, not recall. Role-specific training targets higher-risk roles with tailored content.

## 9. References

- NIST SP 800-50 - Building an Information Technology Security Awareness and Training Program - https://csrc.nist.gov/pubs/sp/800/50/final
- NIST SP 800-16 - Information Technology Security Training Requirements - https://csrc.nist.gov/pubs/sp/800/16/final
- Kirkpatrick Partners - The Kirkpatrick Model - https://www.kirkpatrickpartners.com/the-kirkpatrick-model/
- SANS Security Awareness Training Design - https://www.sans.org/security-awareness-training/
- ENISA Cybersecurity Education and Awareness - https://www.enisa.europa.eu/topics/cybersecurity-education
- H5P Interactive Content - https://h5p.org/
- Articulate Storyline - https://www.articulate.com/storyline/