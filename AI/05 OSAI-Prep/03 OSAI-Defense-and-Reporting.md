# OSAI Defense and Reporting

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## 1. Overview

The OSAI exam is scored on two axes: exploitation and documentation. A perfect exploit with a weak report is a weak finding. This file covers the defensive and reporting side of the exam: how to select controls, how to structure the report, how to present evidence under non-determinism, and how to write a remediation that a reader can act on.

The defensive half of the exam is not an afterthought. For every finding, the grader expects a preventive control, a detection control, and a verification step.

## 2. Reconnaissance / Enumeration

Before writing the report, gather the defensive context of the target:

- **Existing controls.** Authentication, authorization, rate limits, input validation, output encoding, logging, monitoring.
- **Deployment model.** Self-hosted vs API-based. This changes the available controls.
- **Data sensitivity.** What data does the application touch? PII, credentials, proprietary documents?
- **Regulatory context.** If the target were real, what regulations would apply (GDPR, HIPAA, SOC 2)?
- **Threat model.** Who is the adversary? A curious user, an authenticated insider, a remote attacker?

The controls you recommend should fit this context. A generic "add input validation" is weak; "reject documents containing instruction-like patterns before indexing" is actionable.

## 3. Common Attack Vectors

For each attack class from file 02, the defensive mapping:

| Attack | Preventive Control | Detection Control |
|--------|--------------------|--------------------|
| Direct prompt injection | Input validation, output encoding, human-in-the-loop | Log + anomaly detection on prompt patterns |
| Indirect prompt injection | Strip hidden content, delimit retrieved data | Detect instruction-like patterns in retrieved content |
| Insecure output handling | Treat output as untrusted, encode before rendering | Log every output sink, alert on unexpected sinks |
| System prompt extraction | Do not put secrets in the system prompt | Detect extraction attempts (role-play, encoding) |
| Agent tool abuse | Enforce restrictions in code, least privilege | Log every tool call, alert on out-of-policy paths |
| RAG index poisoning | Validate on ingestion, restrict writers | Monitor for anomalous documents and queries |
| Embedding inversion | Do not expose raw embeddings | Alert on bulk embedding reads |
| Supply chain | Pin versions, verify hashes, internal registry | Monitor for new packages and unexpected downloads |
| Traditional app sec | Standard authn/authz, rate limiting | Standard WAF and access logs |

## 4. Exploitation Recipes

This section is not about new exploits. It is about how to write the exploit up so that a grader can reproduce it and a defender can act on it.

### 4.1 Structure of a finding

1. **Title.** Short, specific, includes the vector and the impact.
2. **Severity.** CVSS v3.1 base score, with the vector string. If CVSS is not a good fit (prompt injection often is not), use a qualitative rating and justify.
3. **Affected component.** Endpoint, feature, or artifact.
4. **Description.** One paragraph: what is wrong and why it matters.
5. **Reproduction steps.** Numbered, exact. Include the request body and the response.
6. **Evidence.** Raw request/response, screenshot, or transcript. Mask secrets.
7. **Impact.** What an attacker gains, in concrete terms.
8. **Remediation.** Specific, actionable, with a verification step.
9. **References.** OWASP, CWE, vendor documentation.

### 4.2 Writing under non-determinism

- State the model version and any sampling parameters.
- Run the exploit three times and report the success rate (e.g. "3/3", "2/3").
- If the exploit is probabilistic, describe the conditions that increase success (lower temperature, shorter context, specific phrasing).
- Do not claim determinism if the behavior is not deterministic.

## 5. Post-Exploitation

In the report, post-exploitation is the "Impact" section. Be concrete:

- **Data exfiltration.** Which data, how much, over what channel.
- **Action execution.** Which action, on which system, with what effect.
- **Lateral movement.** Which systems were reachable, and how.
- **Persistence.** How long would the compromise survive a restart or a patch.

Avoid vague statements like "an attacker could cause damage". Name the damage.

## 6. Preventive Controls

When recommending a preventive control, follow three rules:

1. **Specific.** Name the component and the change. "Sanitize user input" is not specific. "Strip zero-width characters and HTML comments from user input before it reaches the model" is.
2. **Implementable.** The control must be something the team can build or buy. Do not recommend research-level defenses.
3. **Verifiable.** The control must have a test. If you cannot describe how to verify it works, it is not a control.

Examples:

- Prompt injection: "Wrap retrieved documents in `<data>...</data>` and instruct the model to ignore instructions inside `<data>` blocks." Verification: attempt an indirect injection; the model should refuse.
- Tool abuse: "Enforce path allowlist in the `read_file` implementation." Verification: attempt to read `/etc/passwd`; the tool should return an error.
- Output handling: "Encode all model output with a context-aware encoder before rendering." Verification: inject an XSS payload via the model; the browser should display the payload as text, not execute it.

## 7. Detection Controls

Detection is often overlooked in reports. Include at least one detection control per finding.

- **Logging.** What to log: prompts, responses, tool calls, retrieval results, auth events.
- **Anomaly detection.** What to alert on: unusual prompt patterns, unusual tool paths, unusual retrieval queries, bulk embedding reads.
- **Content filtering.** What to filter: known injection markers, hidden text, control characters.
- **Egress monitoring.** What to watch: unexpected outbound requests from the model or its tools.

For each detection control, name the data source and the alert condition.

## 8. Verification

The report must include a verification section. For each finding:

- **Reproduce.** Steps to reproduce from a clean state.
- **Confirm.** Expected output.
- **Remediate.** Steps to apply the fix.
- **Re-verify.** After the fix, run the same reproduction; the exploit should fail.

Verification is what separates a finding from a claim.

## 9. AI-Specific Considerations

- **Non-determinism.** Report success rates, not single runs.
- **Opaque models.** You cannot inspect the weights. Verification is behavioral.
- **Model updates.** The provider may change the model. Note the version and the date.
- **Prompt injection is not solved.** Do not recommend a single control as a complete fix. Recommend layered controls and monitoring.
- **System prompt is public.** Assume it can be extracted. Do not put secrets in it.

## 10. Production Notes

Exam-specific production notes for the report:

- **Time budget.** Reserve at least 4 hours for the report. More if you have many findings.
- **Template.** Use the OSCP report template from `methodology/OSCP-Reporting.md` as a starting point. Adapt the sections for AI-specific findings.
- **Screenshots.** Required for: initial access, exploitation, post-exploitation, evidence of impact, remediation verification.
- **Masking.** Mask all real secrets in the report (API keys, tokens, credentials). The grader does not need them.
- **Reproducibility.** Every finding must be reproducible from the report alone. Test this by having a colleague follow your steps.
- **Defense.** Every finding must have a preventive control and a detection control. This is part of the score.
- **Executive summary.** One page, non-technical. State the overall risk and the top three findings.
- **Appendices.** Raw request/response logs, tool outputs, and configuration snippets go in appendices, not in the body.

## 11. References

- OffSec exam and report guidelines. https://help.offsec.com/
- OSCP Reporting methodology (this repo). ../../methodology/OSCP-Reporting.md
- OWASP LLM Top 10 2025. https://genai.owasp.org/llm-top-10/
- OWASP API Security Top 10. https://owasp.org/API-Security/
- NIST AI Risk Management Framework. https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATLAS. https://atlas.mitre.org/
- CVSS v3.1 specification. https://www.first.org/cvss/v3.1/specification-document
