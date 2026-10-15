# LLM09: Overreliance

> OWASP LLM Top 10 2025 - LLM09
> Category: AI Security / OWASP-LLM-Top-10-2026
> Format: Two-track (Offensive / Defensive)

---

## 1. Overview

Overreliance is the class of risks that arise when a human or a
downstream system trusts the output of an LLM without verification,
even though the model can be confidently wrong. The model produces
plausible-sounding text with no built-in signal of uncertainty. A
user who treats that text as fact, or a system that acts on it
without validation, inherits the model errors as if they were facts.

Overreliance is unique in the OWASP LLM Top 10 because the primary
vulnerability is not in the model or the application - it is in the
human process. The model does what it always does: generate likely
text. The failure is the assumption that likely text is correct text.

Three failure modes are common:

- **Hallucination accepted as fact.** The model invents a citation,
  a function name, a CVE, a law, a medical dosage. The user acts on
  it.
- **Model output as a decision.** The model produces a
  recommendation (approve this loan, flag this transaction, block
  this user) and the downstream system enforces it without review.
- **Model output as code or config.** The model generates a script,
  a query, or a configuration snippet that is applied without
  review.

Realistic attack surfaces:

- **Legal, medical, and financial advice.** High-stakes domains
  where a wrong answer has real consequences.
- **Code generation.** LLM-generated code that is deployed without
  review.
- **Automated decisioning.** Loan approvals, fraud detection,
  content moderation.
- **Research and citation.** LLM-produced citations that do not
  exist.
- **Customer communication.** Auto-sent replies with wrong
  information.
- **Security tooling.** LLM-generated detection rules, playbooks,
  or IOCs.

## 2. Reconnaissance / Enumeration

For an AI system you are assessing, map the reliance:

- **Where does model output go?** To a user, to a downstream system,
  to a customer, to a public channel.
- **Is the output reviewed by a human before it is used?** By whom,
  with what expertise, and how often?
- **Is the output validated mechanically?** Schema, type, range,
  link resolution, unit test.
- **What is the cost of a wrong output?** Reputation, money, safety,
  legal.
- **Does the model have a way to say "I do not know"?** Does the
  application surface uncertainty?
- **Is there a citation or provenance check?** Does the output
  reference sources, and are the sources verified?
- **Is the model used in a domain where it has known weaknesses?**
  Arithmetic, recent events, niche domains, other languages.

```text
Questions to ask during scoping:
- Where is model output consumed?
- Who reviews it before use?
- What mechanical validation is applied?
- What is the cost of a wrong output?
- Does the model express uncertainty?
- Are citations verified?
```

## 3. Common Attack Vectors

- **Hallucinated citation.** The model invents a paper, a case, a
  CVE, or a law. The user cites it publicly.
- **Hallucinated API.** The model invents a library function. The
  developer pastes it and gets an import error or, worse, a
  typosquatted package.
- **Hallucinated security guidance.** The model produces a
  detection rule, a mitigation, or an IOC that does not exist.
- **Confident wrong answer in a high-stakes domain.** Medical
  dosage, legal deadline, financial threshold.
- **Automated decision without review.** The model classifies a
  user or transaction; the system acts on the classification.
- **Prompt-influenced decision.** An attacker crafts input that
  makes the model produce the classification the attacker wants,
  and the system trusts the classification.
- **Model output injected into a downstream system.** SQL, shell,
  HTML - the classic injection surfaces, now fed by an LLM.

## 4. Exploitation Recipes

### 4.1 Hallucinated citation

Prompt: "Give me three peer-reviewed papers on the security of
prompt injection, with DOIs."

The model produces three plausible-sounding papers. At least one
of the DOIs does not resolve, or resolves to a different paper.
A user who cites the paper without checking propagates a
non-existent reference.

### 4.2 Hallucinated package name

Prompt: "Write a Python snippet that uses the latest OpenAI SDK."

The model invents a function name or an import path. A developer
who pastes it into a build file may pull a typosquatted package
with the invented name.

### 4.3 Automated decisioning without review

A fraud-detection pipeline feeds a transaction description to an
LLM and asks "is this fraud?". The LLM output (yes/no) is used
directly to block the transaction. An attacker crafts a
description that makes the model say "yes" for a legitimate
transaction (denial of service) or "no" for a fraudulent one.

### 4.4 Model output as code

Prompt: "Write a bash script that rotates the API keys."

The model produces a script with a subtle bug (wrong variable,
wrong path, missing error handling). The script is run in
production without review.

## 5. Post-Exploitation

After a successful overreliance exploit, the attacker may:

- **Inject misinformation.** The model output is published with
  the operator credibility.
- **Cause financial loss.** Wrong decisions, wrong trades, wrong
  refunds.
- **Cause safety incidents.** Wrong medical, legal, or engineering
  advice.
- **Damage reputation.** Public hallucinations attributed to the
  operator.
- **Introduce vulnerabilities.** Model-generated code with subtle
  bugs, model-generated rules with blind spots.
- **Supply chain attacks via invented names.** A typosquatted
  package matching a hallucinated name.

## 6. Preventive Controls (Defensive)

- **Human review for high-stakes output.** Legal, medical,
  financial, security, and code output requires review by a
  qualified human.
- **Mechanical validation.** Schema validation, type checks,
  range checks, link resolution, unit tests, compile checks.
- **Citation verification.** If the model cites a source, verify
  the source exists and supports the claim.
- **Package existence check.** Before installing a model-named
  package, verify the package exists, is maintained, and matches
  the intended one.
- **Uncertainty surfacing.** Show the user when the model is
  uncertain. Do not hide it behind confident prose.
- **Domain restrictions.** Restrict the model to domains where it
  is reliable, or add a domain-specific verifier.
- **Decision review.** Automated decisions above a threshold
  require human sign-off.
- **Sandbox for model-generated code.** Never run model-generated
  code in production without review and a sandbox.
- **Feedback loop.** Track when the model is wrong, and feed that
  back into the review process.

## 7. Detection Controls (Defensive)

- **Log model output and downstream action.** For each decision
  or action, record the model output that triggered it.
- **Alert on high-impact decisions.** Blocking a user, approving
  a loan, deploying code.
- **Detect citation patterns.** A model output that includes
  citations is a candidate for verification.
- **Detect invented API names.** Compare model-generated code
  against the actual library API.
- **Detect package typosquats.** A package name close to a
  popular one is suspicious.
- **Monitor user feedback.** Users reporting wrong output is a
  signal that review is not working.

## 8. Verification

- **Citation test.** Ask the model for three citations. Verify
  each one resolves and matches.
- **Package test.** Ask the model for a code snippet. Verify
  every imported package exists and is the intended one.
- **Decision test.** Feed a known legitimate input through the
  decision pipeline. Confirm the human review step catches a
  wrong decision.
- **Code review test.** Generate a non-trivial script. Confirm
  that a reviewer can identify the model-introduced bugs.
- **Uncertainty test.** Ask the model a question outside its
  knowledge. Confirm the application surfaces the uncertainty.
- **Domain test.** Ask a domain-specific question with a known
  answer. Confirm the model is correct, or the verifier catches
  the error.

## 9. AI-Specific Considerations

- **Confidence is not accuracy.** The model produces fluent text
  regardless of correctness. Fluency is not a signal of truth.
- **Hallucination is not a bug.** It is a property of how the
  model works. It cannot be fully eliminated; it must be managed.
- **Model outputs are probabilistic.** The same prompt can give
  different answers. Repeated calls do not average to the truth.
- **The model does not know what it does not know.** It cannot
  reliably refuse to answer; it will produce plausible text.
- **High-stakes domains amplify the risk.** The same hallucination
  is a minor inconvenience in chat and a safety incident in
  medicine.
- **Overreliance scales with convenience.** The easier the model
  is to use, the more likely users are to skip verification.

## 10. Production Notes

- **Define a review policy.** Which outputs require review, by
  whom, with what sign-off.
- **Instrument the review.** Track how often review happens,
  how often it catches errors.
- **Train the reviewers.** Reviewers must know the model
  limitations and the domain.
- **Keep a hallucination log.** A record of known model failures
  helps tune the prompts and the review process.
- **Do not automate the automation.** A model that reviews
  another model output is not a review; it is a second model
  with the same failure mode.
- **Publish a disclaimer.** Users should know they are reading
  model output. Do not present it as verified fact.

## 11. References

- OWASP LLM09: Overreliance - https://genai.owasp.org/llmrisk/llm09-overreliance/
- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS - https://atlas.mitre.org/
- NIST AI RMF - https://www.nist.gov/itl/ai-risk-management-framework
- Ji et al., "Survey of Hallucination in Natural Language Generation" - https://arxiv.org/abs/2202.03629
