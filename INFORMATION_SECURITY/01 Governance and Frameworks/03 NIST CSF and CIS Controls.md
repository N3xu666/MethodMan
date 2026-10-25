# NIST CSF and CIS Controls

Two complementary frameworks cover the operational side of security governance. NIST Cybersecurity Framework (CSF) gives a strategic structure: identify, protect, detect, respond, recover. CIS Controls give a prioritized, prescriptive set of safeguards with implementation groups. Together they convert a policy set into an operable program.

## 1. Overview

### 1.1 NIST CSF

The NIST Cybersecurity Framework was published in 2014 in response to Executive Order 13636. Version 2.0 was released in 2024. It is a voluntary framework, widely adopted by critical infrastructure, government contractors, and increasingly by commercial organizations because it maps cleanly to other standards.

Structure of CSF 2.0:

- **6 Functions**: Govern (new in 2.0), Identify, Protect, Detect, Respond, Recover.
- **Categories** (22): subdivisions of each Function (e.g. "Asset Management" under Identify).
- **Subcategories** (106): specific outcomes (e.g. "ID.AM-01: Inventories of hardware managed by the organization are maintained").
- **Informative References**: mapping to other standards (ISO 27001, CIS Controls, COBIT).

CSF is outcome-oriented: it says "this outcome must be achieved", not "use this tool". It is not certifiable, but it is a strong scaffold for building a program or for communicating with the board.

### 1.2 CIS Controls

CIS Controls (Center for Internet Security) v8 (2021) define 18 top-level controls, subdivided into 153 safeguards. Each safeguard has an Implementation Group (IG1, IG2, IG3) that describes the size and maturity of the organization for which it is appropriate.

- **IG1**: essential cyber hygiene (small organizations, low data sensitivity). 56 safeguards.
- **IG2**: intermediate (mid-size organizations, sensitive data). 130 safeguards.
- **IG3**: advanced (large organizations, regulated industries, critical infrastructure). All 153 safeguards.

CIS Controls are prescriptive: each safeguard says what to configure or what to enable. They are the most "operational" of the major frameworks and the easiest to hand to an engineering team.

## 2. Where in the Organization

```
Board / Executives <---- reporting ---- CISO
    |                                    |
    |                                    +--> CSF (strategy + board reporting)
    |                                    +--> CIS Controls (engineering priorities)
    |
    +--> Security Team (engineering)
    +--> Risk Owners (accept/treat decisions)
    +--> Audit (verification, mapped to CSF subcategories)
```

NIST CSF is commonly used at the executive and program level: it gives the board six functions to track and a vocabulary that non-specialists understand. CIS Controls are used at the engineering level: they are assigned to teams as concrete tasks.

The two frameworks map to each other. NIST publishes an "Informative References" mapping in CSF 2.0, and CIS Controls v8 includes a mapping to CSF, ISO 27001 and NIST 800-53.

## 3. Threats and Failure Modes

- **Framework shopping.** The organization picks the framework that "looks best" rather than the one that fits its risk profile, sector, or customer requirements. A mid-size SaaS company with a CIS Controls program is in a better position than the same company with a partially-implemented ISO 27001.
- **CSF as a checklist.** The six functions become a slide in a board deck, but no subcategory is mapped to an owner or a metric. CSF is a skeleton; without muscle (CIS safeguards, ISO 27001 controls, internal controls) it does not protect anything.
- **Implementation Group inflation.** The organization claims IG3 coverage because it is "more secure", but half of IG1 is not done. Coverage is a continuum; IG1 complete is better than IG3 at 40%.
- **Mapping-only exercise.** A matrix that maps CSF subcategories to ISO 27001 controls exists and is never used. Mapping is only valuable if it reduces duplicated work or feeds an audit.
- **Framework without cadence.** CIS Controls are implemented in a one-time project; six months later half of them have drifted. Controls need continuous verification (see section 6).
- **CSF 1.1 vs 2.0 confusion.** Many training materials and job descriptions still reference CSF 1.1 (five functions, no Govern). CSF 2.0 added Govern specifically because governance was the weakest link in 1.1 adoptions.

## 4. Controls and Implementation

### 4.1 NIST CSF 2.0 Functions

- **Govern (GV)**: organizational context, risk management strategy, roles, policy, oversight. This is the new function in 2.0; it codifies what 1.1 assumed.
- **Identify (ID)**: asset management, risk assessment, improvement.
- **Protect (PR)**: identity management, awareness, data security, platform security, technology infrastructure resilience.
- **Detect (DE)**: continuous monitoring, adverse event analysis.
- **Respond (RS)**: incident management, analysis, reporting, mitigation.
- **Recover (RC)**: incident recovery plan execution, recovery communication.

Each function has Categories and Subcategories. The full catalog is at the NIST CSF 2.0 Reference Tool (see References).

### 4.2 CIS Controls v8 (18 Controls)

```
1.  Inventory and Control of Enterprise Assets
2.  Inventory and Control of Software Assets
3.  Data Protection
4.  Secure Configuration of Enterprise Assets and Software
5.  Account Management
6.  Access Control Management
7.  Continuous Vulnerability Management
8.  Audit Log Management
9.  Email and Web Browser Protections
10. Malware Defenses
11. Data Recovery
12. Network Infrastructure Management
13. Network Monitoring and Defense
14. Security Awareness and Skill Training
15. Service Provider Management
16. Application Software Security
17. Incident Response Management
18. Penetration Testing
```

### 4.3 Prioritization with Implementation Groups

The IG model lets an organization prioritize: complete all IG1 safeguards first, then IG2, then IG3. The CIS publishes the mapping; roughly:

- **IG1** covers controls 1-6 basic safeguards, plus essential parts of 7-18. This is the "hygiene" baseline: inventory, patching, MFA on admin accounts, backups, basic logging.
- **IG2** adds the operational controls: centralized log management, network segmentation, secure configuration baselines, phishing training.
- **IG3** adds advanced controls: application-level controls, red teaming, threat hunting, formal pen testing programs.

For most organizations, IG1 complete + IG2 in progress is a strong posture; IG3 is reserved for regulated or high-target environments.

### 4.4 Combining CSF and CIS

A practical mapping:

- Use CSF 2.0 to structure the program and report to the board.
- Use CIS Controls (IG1 -> IG2 -> IG3) to plan engineering work.
- Map CIS safeguards to CSF subcategories once; keep the mapping in the GRC tool or wiki.
- Report board-level progress in CSF function terms, and team-level progress in CIS control terms.
- Use ISO 27001 as the certifiable layer if certification is required (see file 02).

## 5. Tooling

- **NIST CSF 2.0 Reference Tool**: the official browser, with subcategory text and informative references. https://csf.tools/ is a widely used mirror with mappings to other standards.
- **CIS Controls Navigator**: the official CIS tool with safeguard search, IG filtering, and mapping to CSF / ISO / NIST 800-53.
- **CIS-CAT Pro**: the CIS Benchmark assessment tool; complementary to CIS Controls but focused on technical configuration, not on the control program.
- **GRC platforms**: any GRC tool that ships CSF 2.0 and CIS Controls v8 templates (OneTrust, Archer, ServiceNow GRC, Vanta, Drata).
- **Excel / Google Sheets**: a workable starting point for the mapping and status tracking below ~100 controls. Above that, the spreadsheet rots.

## 6. Verification and Metrics

CSF and CIS Controls do not define an audit process; the organization must build one.

- **CSF-driven reporting**: report progress by function (Govern / Identify / Protect / Detect / Respond / Recover). Each function gets a maturity score (1-5), a trend, and top gaps.
- **CIS safeguard tracking**: each safeguard is marked Not Started / In Progress / Implemented / Verified. "Implemented" means the tool is deployed; "Verified" means the control was tested and passed.
- **Coverage**: percentage of IG1/IG2/IG3 safeguards in each state.
- **Control drift**: safeguards that were "Verified" six months ago but no longer work (detected via continuous monitoring).
- **Mapping accuracy**: does the CSF subcategory claim match the CIS safeguard evidence? An auditor cross-checks.

Anti-metrics: number of CSF subcategories "addressed" in a slide, number of CIS safeguards claimed without evidence.

## 7. Anti-Patterns

- **CSF without CIS (or equivalent)**: strategy without operations. The board sees a beautiful heat map; the SIEM is unconfigured.
- **CIS without CSF**: engineering without strategy. Teams implement controls that nobody prioritizes; the board cannot see the program.
- **IG3 claim with IG1 gaps**: the most common self-assessment failure. Auditors and pen testers detect it quickly.
- **Mapping without maintenance**: a CSF-to-ISO-to-CIS matrix that is not updated when the framework version changes (CSF 1.1 -> 2.0, CIS v7 -> v8).
- **CIS Benchmark == CIS Controls confusion**: the Benchmarks are hardening guides for specific products (Windows Server, Apache, AWS); the Controls are the program-level safeguards. Both are useful, they are not the same thing.
- **Framework as a shield**: "we are aligned with CSF" as a response to a customer security questionnaire. Alignment is not certification; questionnaires ask for evidence.

## 8. Certification Alignment

This file supports the following certification domains:

- **CompTIA Security+**: governance, risk, compliance domain; frameworks and controls.
- **ISC2 CISSP**: Domain 1 (Security and Risk Management) - frameworks; Domain 7 (Security Operations) - operational controls.
- **ISACA CISM**: Domain 1 (Information Security Governance) - governance framework; Domain 3 (Information Security Program) - program controls.
- **ISACA CISA**: auditing information systems - control frameworks and their evidence.
- **ISO 27001 Lead Implementer / Lead Auditor**: mapping between ISO Annex A and CSF / CIS.

## 9. References

- NIST Cybersecurity Framework 2.0 - https://www.nist.gov/cyberframework
- NIST CSF 2.0 Reference Tool - https://csf.tools/reference/nist-cybersecurity-framework/v2-0/
- CIS Controls v8 - https://www.cisecurity.org/controls
- CIS Controls Navigator - https://controls-assessment-specification.readthedocs.io/
- CIS Benchmarks - https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-53 Rev. 5 - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final