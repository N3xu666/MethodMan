# OSAI Exam Overview

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## 1. Overview

The OffSec AI (OSAI) certification validates the ability to assess and exploit AI systems in an authorized engagement, and to document the results in a professional report. It is the AI counterpart to OSCP: a hands-on, lab-based exam with a time limit, multiple targets, and a required report.

This file describes the exam structure, the expected domains, the report format, and a preparation plan. It is a planning document, not a substitute for the official OffSec syllabus. Always check the current OffSec course page for the authoritative requirements.

## 2. Reconnaissance / Enumeration

Exam reconnaissance is about understanding the environment before the clock starts.

### 2.1 Environment

- **Targets.** Expect a mix of LLM applications, RAG pipelines, agents, and possibly a model supply chain component.
- **Access.** You are given credentials and network access to a lab. The lab is isolated; no internet access is assumed unless stated.
- **Tools.** A Linux VM with common pentest tooling, plus a browser and API clients (curl, httpie, Python).
- **Time.** Typically 24 hours, in the same format as OSCP+ (exam + report).

### 2.2 What to enumerate first

- The application's entry points: chat UI, API endpoints, file upload, webhooks.
- The model behind the application: which provider, which version, which system prompt (if leaked).
- The retrieval layer: is there a vector database? What documents are indexed?
- The agent layer: what tools are exposed? What are their permissions?
- The deployment: is there an admin panel? A debug endpoint? A model registry?

### 2.3 Non-determinism

Model outputs vary between runs. When enumerating, note:

- The temperature and sampling settings, if visible.
- Whether the application uses greedy decoding (deterministic) or sampling.
- Whether a "seed" parameter is accepted.

For evidence, capture multiple runs and record the variance.

## 3. Common Attack Vectors

The exam is expected to test the following attack classes. Each maps to one or more OWASP LLM Top 10 items.

- **Prompt injection.** Direct (user input) and indirect (via retrieved documents or tool output).
- **System prompt extraction.** Eliciting the system prompt through role-play, translation, or encoding tricks.
- **Jailbreaks.** Bypassing safety filters to produce disallowed output.
- **Insecure output handling.** Injecting content that is later executed (XSS, SQLi, command injection) when the output is rendered or processed.
- **RAG poisoning.** Inserting malicious documents into the retrieval index.
- **Embedding inversion.** Reconstructing text from embeddings.
- **Agent tool abuse.** Using the agent's tools for unauthorized actions (file read, HTTP request, code execution).
- **MCP attacks.** Exploiting the Model Context Protocol to inject tools or escalate privileges.
- **Supply chain.** Loading a malicious model or dependency.
- **Traditional app sec.** SSRF, IDOR, authn/authz flaws in the AI application's surrounding code.

## 4. Exploitation Recipes

This section describes the general shape of an exam exploit, not specific payloads.

### 4.1 Shape of a finding

A complete finding includes:

1. **Title.** Short, specific (e.g. "Indirect prompt injection via uploaded PDF leads to unauthorized tool call").
2. **Severity.** CVSS or a qualitative rating, with justification.
3. **Affected component.** Endpoint, feature, or artifact.
4. **Reproduction steps.** Numbered, deterministic where possible.
5. **Evidence.** Request/response, screenshot, or transcript. Mask secrets.
6. **Impact.** What an attacker gains.
7. **Remediation.** Concrete, actionable.

### 4.2 Reproducibility under non-determinism

- Use a fixed seed if the API supports it.
- Run the exploit three times and report the success rate.
- If a payload works intermittently, document the conditions (temperature, context length, model version).
- Save the exact request body and headers.

### 4.3 Chaining

Many exam scenarios require chaining: a prompt injection that leaks a token, which is then used to access an admin endpoint, which then exposes a model registry. Plan the chain, document each hop.

## 5. Post-Exploitation

Post-exploitation in OSAI is about demonstrating impact, not about maintaining access.

- **Data access.** Read documents, chat history, or model weights that should not be accessible.
- **Action execution.** Trigger a tool that performs an action (send email, create user, run code).
- **Persistence.** Rarely tested; if tested, it is via a poisoned document in the RAG index.
- **Lateral movement.** From the AI application to the surrounding infrastructure (database, object store, internal API).

## 6. Preventive Controls

For each finding, be ready to propose a preventive control.

- **Input validation.** Sanitize user input; strip control characters and known injection markers.
- **Output encoding.** Treat model output as untrusted; encode before rendering.
- **Retrieval filtering.** Only retrieve from an allowlisted set of documents. Reject documents with embedded instructions.
- **Tool sandboxing.** Tools run with the least privilege required. No shell access.
- **Least privilege.** The model and its tools have only the permissions needed.
- **Rate limiting.** Prevent brute-force extraction of the system prompt or the index.
- **Human-in-the-loop.** High-impact actions require confirmation.

## 7. Detection Controls

- **Logging.** Log every prompt, response, tool call, and retrieval result.
- **Anomaly detection.** Unusual prompt patterns, unusual tool invocations, unusual retrieval queries.
- **Egress monitoring.** Alert on the model or tools making unexpected outbound requests.
- **Content filtering.** Detect known injection patterns in user input and retrieved documents.
- **Prompt leak detection.** Detect attempts to extract the system prompt.

## 8. Verification

- Reproduce every finding from a clean state.
- Capture the exact request and response for each step.
- Confirm that the remediation would break the chain.
- Run the exploit multiple times to establish a success rate.

## 9. AI-Specific Considerations

- **Non-determinism.** The same prompt may produce different outputs. Document variance.
- **Opaque models.** You cannot inspect the weights. You infer behavior from prompts and outputs.
- **Context limits.** Long conversations may truncate earlier messages, changing behavior.
- **System prompt is not a security control.** Do not rely on it to enforce policy.
- **Model updates.** The provider may update the model mid-engagement. Note the version.

## 10. Production Notes

Exam-specific production notes:

- **Time budget.** 24 hours total. Reserve at least 4 hours for the report.
- **Report format.** OffSec requires a specific structure. Use the template from `methodology/OSCP-Reporting.md` as a starting point and adapt it for AI findings.
- **Screenshots.** Required for key steps: initial access, exploitation, post-exploitation, evidence of impact.
- **Masking.** Mask any real secrets in the report (API keys, tokens, credentials).
- **Reproducibility.** A finding that cannot be reproduced by the grader is a weak finding.
- **Defensive section.** Include a defensive recommendation for each finding. This is part of the score.
- **No internet.** Assume the lab has no internet. Prepare a local model stack for practice.

## 11. References

- OffSec AI (OSAI) certification page. https://www.offsec.com/courses/
- OffSec exam and report guidelines. https://help.offsec.com/
- OWASP LLM Top 10 2025. https://genai.owasp.org/llm-top-10/
- OWASP API Security Top 10. https://owasp.org/API-Security/
- MITRE ATLAS. https://atlas.mitre.org/
- NIST AI Risk Management Framework. https://www.nist.gov/itl/ai-risk-management-framework
