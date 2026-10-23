# Business Continuity and Disaster Recovery

Business continuity (BC) and disaster recovery (DR) are the disciplines that keep an organization operating through disruption. BC is the broader capability: it plans for the continued delivery of critical business functions during and after a disruption, regardless of cause. DR is the technology-focused subset: it plans for the restoration of IT systems and data after a disruption. The two are related but not interchangeable; an organization can have a good DR plan and still fail at business continuity because the people, processes and facilities are not addressed.

## 1. Overview

Disruptions come from many sources: cyber incidents, natural disasters, power outages, pandemics, supply chain failures, and third-party service outages. A mature BC/DR capability addresses all of them, not only cyber threats, because the recovery approach and dependencies are often shared.

Core BC/DR concepts:

- **Business Impact Analysis (BIA)** - the process of identifying critical business functions, their dependencies, and the impact of their disruption over time. The BIA is the foundation of everything else.
- **Recovery Time Objective (RTO)** - the maximum acceptable time to restore a function or system after disruption. Expressed in hours or days.
- **Recovery Point Objective (RPO)** - the maximum acceptable amount of data loss, expressed in time. Determines backup frequency.
- **Maximum Tolerable Downtime (MTD)** - the maximum time a business function can be unavailable before unacceptable harm occurs. The MTD constrains the RTO.
- **Critical business functions** - the processes that must continue or be restored first. Identified in the BIA.
- **Continuity plan** - the document describing how to maintain critical functions during disruption, including alternate sites, alternate processes, manual workarounds, and communication.
- **Disaster recovery plan** - the document describing how to restore IT systems and data, including backup strategy, recovery procedures, and validation.

The relationship between RTO, RPO and MTD:

- MTD is set by the business. "We cannot be without this function for more than 48 hours."
- RTO must be less than or equal to MTD. "We will restore this function within 24 hours."
- RPO determines data loss tolerance. "We can lose up to 4 hours of data."
- RTO and RPO have cost implications. A 4-hour RTO costs more than a 48-hour RTO. The BIA justifies the investment.

BC/DR is not a one-time project. It is a program, with annual review, regular testing, and continuous improvement. The plan without testing is a hypothesis.

## 2. Where in the Organization

BC/DR is cross-functional and executive-sponsored.

- **Business Continuity Manager** - owns the BC program. Runs the BIA, drafts the continuity plans, coordinates testing, reports to leadership.
- **Disaster Recovery Coordinator** - typically within IT. Owns the DR plan, backup strategy, restoration procedures, and DR testing.
- **Executive sponsor** - the CEO or COO. BC/DR is a business-level concern, not an IT concern. Executive sponsorship is essential for funding and for enforcing participation in BIA and testing.
- **Business unit leads** - participate in the BIA, define criticality and RTO/RPO for their functions, and validate the continuity plan from their perspective.
- **IT operations and infrastructure** - implement backups, replication, failover, and recovery procedures. Validate the DR plan.
- **Facilities management** - alternate sites, utilities, physical access.
- **HR** - workforce continuity: remote work capability, crisis communication with employees, staff availability during disruption.
- **Legal and compliance** - regulatory requirements for continuity (e.g. financial services, healthcare), notification obligations, contract clauses with customers and vendors.
- **Communications** - external and internal communication during disruption.
- **Supply chain and procurement** - identify and manage dependencies on third-party providers, negotiate continuity clauses, maintain alternate vendor lists.
- **Risk management** - integrate BC/DR into the enterprise risk register.

The BC program typically reports to the COO, CFO or CRO, not the CISO. Cyber incident response is part of the security function, but BC/DR is a business function. When the two are coordinated, they share the same governance and communication plan.

## 3. Threats and Failure Modes

**Disruption sources the BC/DR capability must handle:**

- **Cyber incidents** - ransomware, destructive malware, data breach, denial of service. Increasingly the dominant cause of disruptive events.
- **Natural events** - flood, fire, earthquake, hurricane, extreme weather.
- **Infrastructure failures** - power outage, network outage, cooling failure, data center fire.
- **Pandemic and workforce disruption** - loss of a significant portion of the workforce, site closure.
- **Supply chain failures** - critical vendor outage, cloud provider regional failure, software supply chain compromise.
- **Regulatory and legal events** - sudden regulatory action freezing systems or data.
- **Physical security events** - theft, sabotage, armed intrusion.
- **Third-party and outsourced service outage** - outsourced IT, cloud, SaaS provider incidents.

**Internal failure modes of the BC/DR capability:**

- **No BIA.** Plans are built without knowing which functions are critical. Recovery priority is guesswork.
- **Plan exists, never tested.** When tested in a real disruption, assumptions fail: backups do not restore, contacts are outdated, alternate sites are not accessible.
- **DR only, no BC.** IT recovers systems, but business processes are not re-established because people, alternate processes and communications were never planned.
- **RTO/RPO declared, not achievable.** Business leaders promise 1-hour RTO, backups are nightly, actual recovery is 3 days. Every incident becomes a regulatory and contractual problem.
- **Backups not verified.** Backup jobs succeed, but restorations fail. The compromise of a backup repository goes undetected for months.
- **Single point of failure not identified.** Cloud region outage takes down the service because a critical component was only deployed in one region.
- **No alternate site.** Primary office and data center in the same flood zone. Disruption eliminates both.
- **No communication plan.** Employees learn about disruption from external news. Leadership cannot coordinate.
- **No defined leadership during crisis.** Decision-making stalls because roles and authority are unclear.
- **Vendor dependency unmanaged.** Cloud provider goes down, no alternate path. The organization is not a customer of the provider - it is a tenant of the provider's outage.
- **BC/DR reviewed once, then forgotten.** Plans are dated. Personnel changed, systems changed, assumptions stale.

## 4. Controls and Implementation

**4.1 Business Impact Analysis.** Identify all business functions. For each: description, dependencies (systems, people, facilities, vendors), impact over time (1 hour, 4 hours, 1 day, 1 week), and RTO/RPO targets. Approved by business unit leads and executive leadership. Reviewed annually and after major changes.

**4.2 Risk assessment.** Identify threats to critical functions. Map likelihood and impact. Prioritize. Integrate into the enterprise risk register.

**4.3 BC strategy.** Based on the BIA, define the strategies for continuing critical functions during disruption:

- Alternate site (hot, warm, cold).
- Alternate process (manual workaround, paper-based).
- Alternate workforce (remote work, cross-trained staff).
- Alternate supplier (dual sourcing for critical vendors).
- Cloud-based resilience (multi-region deployment, auto-scaling).

**4.4 DR strategy.** Define the technology approach:

- Backup strategy (frequency determined by RPO, retention per legal requirements, off-site / air-gapped copies).
- Replication (synchronous, asynchronous, geo-redundant).
- Failover (active-active, active-passive, manual vs automatic).
- Recovery procedures (documented, tested, with clear ownership).

**4.5 Backup and restore controls.**

- 3-2-1 rule: at least three copies of data, on two different media, one copy off-site.
- Immutable backups: backup repositories that cannot be modified or deleted by compromised accounts.
- Air-gapped backups: physical separation from the production network.
- Restore testing: at least quarterly restoration of a random sample of data, verified against the source.
- Encryption of backups at rest and in transit.
- Separation of backup credentials from production credentials.

**4.6 Plan documentation.** The BC plan and DR plan are documented, with:

- Scope and assumptions.
- Roles and responsibilities, with alternates.
- Contact lists (primary and alternate).
- Procedures for each critical function.
- Decision authority during disruption.
- Communication plan and templates.
- Test schedule and history.

**4.7 Testing program.** Multiple test types, sequenced by maturity:

- **Tabletop exercise** - discuss the plan, identify gaps, no systems affected. Quarterly to annually.
- **Walkthrough** - detailed review of procedures with the responsible people. Semi-annually.
- **Simulation** - partial execution, systems affected in a controlled way. Annually.
- **Full failover test** - live failover of production, with rollback. Annually to bi-annually for critical systems.

Test results feed into plan updates. A test that does not produce findings is suspect.

**4.8 Communication plan.** Internal (employees, executives), external (customers, vendors, regulators, media) and out-of-band (when primary communication channels are affected). Templates for common scenarios, contact lists kept current.

**4.9 Vendor continuity.** For every critical vendor: contract clauses for continuity and notification, alternate vendor list, internal contingency plan if vendor fails. Annual vendor review.

**4.10 Integration with IR.** Cyber incident response plans and BC/DR plans are coordinated. When a cyber incident triggers a disruption, the two plans activate together. Shared decision log, shared communication plan.

**4.11 Training and awareness.** Key personnel trained on their roles in BC/DR. Employees aware of the BC plan and their responsibilities during disruption.

**4.12 Continuous improvement.** Plan updates driven by test results, incidents, organizational changes, technology changes, vendor changes. Annual review cycle.

## 5. Tooling

- **BC/DR planning software** - document management, BIA tools, test tracking. Examples: Fusion Risk Management, LogicManager, Archer, Castellan, or custom tools.
- **Backup and recovery** - Veeam, Rubrik, Commvault, Cohesity, AWS Backup, Azure Backup, Google Cloud Backup and DR.
- **Replication and failover** - VMware Site Recovery Manager, Azure Site Recovery, AWS Elastic Disaster Recovery, Zerto.
- **Immutability and air-gapping** - object lock (S3, Azure Blob), tape (LTO) for air-gapped copies, dedicated immutable storage appliances (Rubrik, Cohesity).
- **High availability infrastructure** - load balancers, geo-DNS, active-active data centers.
- **Communication platforms** - out-of-band conferencing, emergency notification systems (Everbridge, OnSolve, xMatters).
- **Document management** - for plan storage and versioning. Examples: SharePoint, Confluence, dedicated BC/DR tools.
- **Test management** - track tests, findings, remediation. Often part of BC/DR software or ITSM (ServiceNow).

The toolchain should support the actual RTO/RPO targets. A backup tool that takes 24 hours to restore cannot support an RTO of 4 hours.

## 6. Verification and Metrics

BC/DR effectiveness is verified through testing and measured through ongoing metrics.

**Verification activities:**

- **BIA refresh** - annually and after major organizational change. Confirm that RTO/RPO reflect current business needs.
- **Tabletop exercise** - at least annually for each critical function.
- **Full failover test** - at least annually for critical systems. Documented, with go/no-go criteria and rollback plan.
- **Restore testing** - at least quarterly, random sample of data. Confirm backups are restorable, not just that jobs succeed.
- **Vendor continuity check** - annual review of critical vendor contracts and alternate plans.
- **Communication drill** - at least annually, testing employee notification and executive coordination.
- **Plan review** - at least annually for the full plan, more frequently for changed components.

**Metrics:**

- **Percentage of critical functions with documented RTO/RPO** - target 100%.
- **Percentage of RTO/RPO validated by test** - target 100% for critical functions within 12 months.
- **Actual RTO achieved during tests** vs. target RTO. Gap analysis is more useful than the target alone.
- **Backup restore success rate** - percentage of tested restores that succeed. Target 100%.
- **Time since last full DR test** - per critical system.
- **Action items from BC/DR tests closed on time** - target 90% or above.
- **Critical vendor reviews completed on time** - target 100%.

**Verification evidence for audit:** BIA document (dated, version-controlled), approved RTO/RPO per function, BC plan and DR plan, test reports, failover logs, restore verification records, vendor review reports.

## 7. Anti-Patterns

- **Plan without BIA.** Priorities are guesswork. The first-critical system restored is not the one that matters.
- **RTO of 1 hour, backups of 1 day.** Business promise incompatible with technical capability. Every incident becomes a dispute.
- **Testing = checking backup jobs.** Backup job success does not mean restore will succeed. Restores must be tested, not jobs.
- **DR only, no BC.** IT recovers, but the business does not because no one planned for the people and processes around the systems.
- **Single-region deployment with critical service.** "We're in the cloud, so we're resilient." A regional outage disproves the belief.
- **Air-gapped backups not immutable.** Backup repository accessible from production. Ransomware encrypts the backups first.
- **Alternate site too close to primary site.** Same flood zone, same power grid, same region. Both sites go down together.
- **Plan for the last disruption.** Focused on the cyber incident from last year; unprepared for the pandemic, the flood, or the cloud vendor.
- **Communication plan does not include out-of-band.** Primary comms channel is affected, no way to reach employees.
- **No leadership in crisis.** Decisions stall because roles are unclear, no one has authority to authorize failover.
- **Vendor dependency unmanaged.** No contract clauses, no alternate vendor, no internal contingency. The vendor's outage is the organization's outage.
- **Test without action.** Findings are documented and never remediated. Next test repeats the same findings.

## 8. Certification Alignment

- **CISSP Domain 7 (Security Operations)** - business continuity, disaster recovery, continuity planning.
- **CISM Domain 4 (Information Security Incident Management)** - integration of incident management and business continuity. Domain 3 (Information Security Program Development and Management) - program governance.
- **Security+ SY0-701 Domain 4 (Security Operations)** - business continuity, disaster recovery, continuity of operations.
- **ISO 22301** - Security and resilience - Business continuity management systems. Requirements and guidance.
- **ISO/IEC 27001 Annex A 5.29 (Information security during disruption) and Annex A 5.30 (ICT readiness for business continuity)** - information security requirements for continuity.
- **NIST SP 800-34 Rev. 1** - Contingency planning guide.
- **NIST CSF 2.0 RC (Recover)** - recovery planning, improvements, communications.

Exam-relevant points: BIA drives RTO/RPO. MTD constrains RTO. Backups must be tested, not just observed. BC and DR are distinct disciplines that share governance. DR testing is mandatory; untested plans are hypotheses.

## 9. References

- ISO 22301 - Security and Resilience - Business Continuity Management Systems - https://www.iso.org/standard/75106.html
- NIST SP 800-34 Rev. 1 - Contingency Planning Guide for Federal Information Systems - https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final
- NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management - https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA Business Continuity Planning - https://www.cisa.gov/topics/emergency-communications/business-continuity-planning
- NIST CSF 2.0 - Recover function - https://www.nist.gov/cyberframework
- BCI Good Practice Guidelines - https://www.thebci.org/training-qualifications/good-practice-guidelines.html
- ISO/IEC 27001:2022 Annex A 5.29 and 5.30 - Information security during disruption, ICT readiness for business continuity