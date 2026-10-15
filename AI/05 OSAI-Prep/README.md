# 05 OSAI Prep

Preparation material for the OffSec AI (OSAI) certification. This subcategory consolidates the offensive and defensive knowledge from the other AI subcategories into an exam-oriented format: what OSAI tests, how scenarios are structured, what evidence is required, and how to report findings.

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## Scope

OSAI is OffSec's certification for AI security practitioners. It tests the ability to:

- Identify and exploit vulnerabilities in AI systems (LLM applications, RAG pipelines, agents, model supply chains).
- Assess the security posture of an AI deployment end-to-end.
- Document findings in a professional report with reproducible evidence.
- Recommend and justify defensive controls.

The exam is hands-on and lab-based, in the same spirit as OSCP: a time-boxed environment with multiple targets, a required report, and a passing score based on both exploitation and documentation.

## Files

| # | File | Status |
|---|------|--------|
| 01 | OSAI Exam Overview | planned |
| 02 | OSAI Attack Scenarios | planned |
| 03 | OSAI Defense and Reporting | planned |

## Format

All files use the two-track format (Offensive / Defensive), 11 sections:

1. Overview
2. Reconnaissance / Enumeration
3. Common Attack Vectors
4. Exploitation Recipes
5. Post-Exploitation
6. Preventive Controls
7. Detection Controls
8. Verification
9. AI-Specific Considerations
10. Production Notes
11. References

## Related

- [AI](../README.md) - parent category
- [OWASP LLM Top 10](../01%20OWASP-LLM-Top-10-2026/README.md) - core vulnerability classes
- [RAG and Embeddings](../02%20RAG-and-Embeddings/README.md) - retrieval pipeline attacks
- [Agents and MCP](../03%20Agents-and-MCP/README.md) - agent and tool abuse
- [AI Supply Chain](../04%20AI-Supply-Chain/README.md) - model and data provenance

## References

- OffSec AI (OSAI) certification. https://www.offsec.com/courses/
- OWASP LLM Top 10 2025. https://genai.owasp.org/llm-top-10/
- OWASP API Security Top 10. https://owasp.org/API-Security/
- MITRE ATLAS. https://atlas.mitre.org/
- NIST AI Risk Management Framework. https://www.nist.gov/itl/ai-risk-management-framework

## Exam Domains (Expected)

The OSAI exam is expected to cover the following domains. The exact weighting is not published; this list is a planning aid based on OffSec's public course descriptions and the OWASP LLM Top 10.

| Domain | Weight (est.) | Core Topics |
|--------|---------------|-------------|
| Prompt and input attacks | High | Direct/indirect injection, jailbreaks, system prompt extraction |
| Retrieval and RAG | High | Embedding inversion, index poisoning, context manipulation |
| Agents and tools | High | Tool abuse, MCP attacks, privilege escalation via tools |
| Model and data supply chain | Medium | Model provenance, pickle, dependency confusion |
| Traditional app sec in AI context | Medium | Authn/authz, SSRF, IDOR, rate limiting in AI apps |
| Defense and reporting | High | Controls, detection, evidence, professional report |

## Preparation Strategy

1. **Master the OWASP LLM Top 10.** Every category in this repo maps to one or more LLM Top 10 items.
2. **Practice hands-on.** Set up a local LLM stack (Ollama, vLLM, or a hosted API) with a RAG pipeline and an agent. Attack your own stack.
3. **Build a report template.** The exam requires a professional report. Practice writing one for every lab you complete.
4. **Learn the defensive side.** OSAI is not only offensive. You must explain how to detect and prevent each attack.
5. **Time-box.** Practice completing a full assessment in 24 hours, then in 12, then in 6.

## Differences from OSCP

| Aspect | OSCP | OSAI |
|--------|------|------|
| Target | Network/host exploitation | AI/ML applications and pipelines |
| Primary skill | Privilege escalation, pivoting | Prompt/input attacks, model and data abuse |
| Tools | nmap, Metasploit, custom exploits | LLM APIs, prompt frameworks, ML tooling |
| Report | Required, with screenshots | Required, with reproducible prompts and outputs |
| Determinism | High (a shell is a shell) | Low (model outputs vary) |
| Defense focus | Limited | Significant (controls and detection are tested) |

## Key Takeaways

- The exam rewards both exploitation and documentation.
- Reproducibility matters: a finding without a reproducible prompt and output is weak.
- Non-determinism is a feature of the domain, not a bug. Document the variance.
- Defensive reasoning is part of the score.
