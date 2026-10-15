# OWASP Top 10 for LLM Applications (2026)

Reference material for the OWASP Top 10 for Large Language Model
Applications, 2026 edition. One file per risk (LLM01-LLM10), each in
the two-track format (Offensive / Defensive).

## Why This Exists

LLM applications introduce an attack surface that traditional web
security does not cover: prompt injection, insecure output handling,
training-data poisoning, model denial of service, and supply-chain
risks in the model itself. The OWASP LLM Top 10 is the reference list
for these risks. This subcategory documents each one with concrete
offensive techniques and defensive controls.

## Format

Every file uses the two-track structure:

    ## 1. Overview
    ## 2. Reconnaissance / Enumeration
    ## 3. Common Attack Vectors
    ## 4. Exploitation Recipes
    ## 5. Post-Exploitation
    ## 6. Preventive Controls (Defensive)
    ## 7. Detection Controls (Defensive)
    ## 8. Verification
    ## 9. AI-Specific Considerations
    ## 10. Production Notes
    ## 11. References

## Files

| # | Risk | File |
|---|---|---|
| 01 | LLM01: Prompt Injection | [LLM01.md](./LLM01.md) |
| 02 | LLM02: Insecure Output Handling | [LLM02.md](./LLM02.md) |
| 03 | LLM03: Training Data Poisoning | [LLM03.md](./LLM03.md) |
| 04 | LLM04: Model Denial of Service | [LLM04.md](./LLM04.md) |
| 05 | LLM05: Supply Chain Vulnerabilities | [LLM05.md](./LLM05.md) |
| 06 | LLM06: Sensitive Information Disclosure | [LLM06.md](./LLM06.md) |
| 07 | LLM07: Insecure Plugin Design | [LLM07.md](./LLM07.md) |
| 08 | LLM08: Excessive Agency | [LLM08.md](./LLM08.md) |
| 09 | LLM09: Overreliance | [LLM09.md](./LLM09.md) |
| 10 | LLM10: Model Theft | [LLM10.md](./LLM10.md) |

> **Note:** risk numbers and titles follow the OWASP LLM Top 10 2025
> edition. If the 2026 edition renumbers or renames a risk, the file
> will be updated and the change noted in the file itself.

## References

- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP GenAI Security Project - https://genai.owasp.org/
- MITRE ATLAS - https://atlas.mitre.org/

## Authorized Use Only

For authorized security testing and educational purposes only.
See SECURITY.md in the repository root.
