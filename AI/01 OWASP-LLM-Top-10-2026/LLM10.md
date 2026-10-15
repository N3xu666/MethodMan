# LLM10: Model Theft

> OWASP LLM Top 10 2025 - LLM10
> Category: AI Security / OWASP-LLM-Top-10-2026
> Format: Two-track (Offensive / Defensive)

---

## 1. Overview

Model theft is the class of attacks that result in an attacker
obtaining a copy of a model the operator owns, or reconstructing a
functionally equivalent model without authorization. The stolen
asset is not a document or a database - it is the weights, the
architecture, the training investment, and the fine-tuning effort.
A stolen model can be hosted by the attacker, sold, further
fine-tuned, probed for its training data, or used to attack the
original service.

Model theft is not always a single dramatic event. It happens at
several levels of fidelity:

- **Full weight extraction.** The attacker obtains the model file
  itself (via a compromised storage bucket, a leaked artifact, or
  an insider).
- **Distillation.** The attacker queries the model many times and
  trains a smaller model to imitate its outputs.
- **Architecture extraction.** The attacker reconstructs the model
  architecture and hyperparameters from side channels.
- **Hyperparameter extraction.** The attacker recovers training
  configuration, learning rate, batch size, or fine-tuning recipe.
- **Training data reconstruction.** The attacker recovers samples
  of the training data, which may reveal the model behavior and
  the data.

Realistic attack surfaces:

- **Model hosting infrastructure.** S3 buckets, model registries,
  CI/CD pipelines, developer laptops.
- **Inference APIs.** Public endpoints that can be queried at scale.
- **Fine-tuning services.** A provider that hosts a fine-tuned model
  has access to the weights.
- **Model marketplaces.** A model sold or shared on a marketplace
  may be redistributed.
- **Employee access.** A departing employee can copy a checkpoint.
- **Side channels.** Timing, response length, and error messages
  leak information about the model.
- **Prompt extraction.** The system prompt is part of the model
  intellectual property.

## 2. Reconnaissance / Enumeration

For an AI system you are assessing, map the model custody:

- **Where does the model file live?** Object storage, artifact
  registry, container image, developer laptop.
- **Who has read access?** Employees, contractors, CI/CD, third
  parties.
- **Is the model served behind an API, or distributed?** An API
  is queried; a distributed model is copied.
- **Is there rate limiting on the API?** Distillation requires
  many queries; rate limits raise the cost.
- **Is the model output logged?** Logs contain the training signal
  for distillation.
- **Are error messages verbose?** Verbose errors leak architecture
  and versions.
- **Is there a watermark in the weights?** Some models embed a
  fingerprint for later ownership verification.

```text
Questions to ask during scoping:
- Where is the model artifact stored?
- Who has read access?
- Is the serving API rate-limited?
- Is the output logged and for how long?
- Is the model watermarked?
- Are there side channels (timing, errors, response length)?
```

## 3. Common Attack Vectors

- **Storage bucket misconfiguration.** An S3 or GCS bucket with
  the model file is left public or with weak IAM.
- **CI/CD pipeline leak.** Model artifacts stored in a build
  cache or artifact registry with weak access control.
- **Insider exfiltration.** An employee copies the checkpoint to
  a personal drive before leaving.
- **API distillation.** The attacker queries the model many
  times and trains a smaller copy.
- **Side-channel extraction.** Timing and response length reveal
  the model architecture.
- **Model hub takeover.** A publisher account on a public hub is
  compromised and the model is replaced or exfiltrated.
- **Fine-tuning provider leak.** The provider that performs the
  fine-tune retains a copy of the weights.
- **Token leakage.** An API key that grants model access is leaked
  in a public repo or a log.
- **Prompt extraction.** The system prompt is reconstructed via
  repeated queries.
- **Weight inference.** In federated learning, gradient updates
  can be inverted to recover training data and, in some setups,
  the model.

## 4. Exploitation Recipes

### 4.1 Storage bucket misconfiguration

A model checkpoint is stored in s3://company-models/base-v3.pt.
The bucket policy allows public read. An attacker who guesses or
finds the bucket name downloads the checkpoint.

```bash
aws s3 ls s3://company-models/ --no-sign-request
aws s3 cp s3://company-models/base-v3.pt . --no-sign-request
```

### 4.2 API distillation

The attacker has API access. They send 1,000,000 prompts through
the API and record the outputs. Then they fine-tune a small open
model (e.g. a 1B parameter model) to match the outputs. The result
is a functionally similar model at a fraction of the cost.

```python
# Pseudocode
prompts = load_prompts()
for p in prompts:
    output = api.generate(p)
    save(p, output)
# Then fine-tune a small model on (prompt, output) pairs
```

### 4.3 Timing side channel

The attacker measures the response time to inputs of varying
length. The slope reveals the model size (layers, hidden
dimension). Repeated measurements average out noise.

### 4.4 API key leak

A developer commits a notebook with the API key. The key grants
access to the model API and to the model registry. The attacker
uses the key to download the checkpoint.

## 5. Post-Exploitation

After a successful model theft, the attacker may:

- **Host the model.** Serve the stolen model, undercutting the
  operator pricing.
- **Sell the model.** On a grey-market marketplace.
- **Fine-tune and re-publish.** A stolen base model becomes the
  foundation of a competitor product.
- **Extract training data.** Probe the stolen model for memorized
  samples.
- **Remove safety fine-tuning.** The stolen model can be
  re-aligned with no safety.
- **Attack the original service.** Knowing the model, the attacker
  can craft adversarial inputs.
- **Bypass content filters.** The stolen model has no filter.

## 6. Preventive Controls (Defensive)

- **Access control on model artifacts.** Least privilege, MFA,
  audit log on every read.
- **No public buckets.** Bucket policies deny public read by
  default. Alert on any change.
- **Encrypt at rest and in transit.** KMS-managed keys. Rotate.
- **Watermark the weights.** Embed a fingerprint that survives
  fine-tuning.
- **Rate limit the API.** Per-user and per-key limits. Distillation
  needs volume; rate limits make it expensive.
- **Log API output.** For audit, but be aware logs are a
  distillation target too.
- **Minimize output detail.** Do not return logprobs, model name,
  version, or architecture details unless needed.
- **Obfuscate error messages.** A generic error message reveals
  less than a stack trace.
- **Restrict fine-tuning providers.** Contract, audit, and require
  deletion of weights after the job.
- **Insider controls.** Offboarding checklist, DLP on model
  artifacts, alert on mass download.
- **Model provenance.** Sign the model artifact. Verify before
  serving.
- **Distillation detection.** Detect bulk API usage patterns that
  match distillation.

## 7. Detection Controls (Defensive)

- **Log every read of a model artifact.** Who, when, from where.
- **Alert on mass download.** A user downloading the full model
  from storage, or a spike in API queries.
- **Alert on API usage patterns.** Sequential, exhaustive, or
  grid-like query patterns indicate distillation.
- **Detect output log scraping.** An account that consistently
  logs full outputs from every request.
- **Detect unusual query distribution.** A distillation attacker
  often queries with inputs from a broad distribution, unlike a
  normal user.
- **Monitor for the model in the wild.** Search public hubs and
  marketplaces for your model fingerprint.
- **Alert on bucket policy change.** A bucket becoming public is
  a critical alert.

## 8. Verification

- **Bucket policy test.** Confirm every model bucket denies public
  read. Test with an unauthenticated client.
- **IAM test.** Confirm a low-privilege user cannot download the
  model.
- **Rate limit test.** Confirm the API enforces per-user and
  per-key limits.
- **Output minimization test.** Confirm the API does not return
  logprobs, model version, or internal details by default.
- **Watermark test.** Confirm the watermark survives a round of
  fine-tuning and can be detected in a suspect model.
- **Distillation detection test.** Simulate a distillation query
  pattern and confirm the detector fires.
- **Insider test.** Confirm offboarding revokes access to model
  artifacts and that mass download alerts fire.

## 9. AI-Specific Considerations

- **A model is an asset.** It is the product of training cost,
  data, and expertise. It deserves the same protection as source
  code.
- **Distillation is cheap.** A functionally similar model can be
  trained for a fraction of the original cost, from API access.
- **The API is the model.** In a hosted setup, the API is the
  only barrier between the attacker and the weights.
- **Watermarks are not magic.** A determined attacker can attempt
  to remove or launder the watermark.
- **Side channels are real.** Timing, error messages, and output
  length leak more than operators expect.
- **Federated learning has unique risks.** Gradient inversion can
  recover training data; in some setups, the model.
- **The system prompt is IP.** It encodes the operator prompt
  engineering and internal policy.

## 10. Production Notes

- **Treat models like source code.** Versioned, signed, access
  controlled, audited.
- **Least privilege on artifacts.** Production serving reads from
  a read-only path. Only CI/CD writes new versions.
- **Separate environments.** The training environment does not
  share credentials with serving.
- **Contractual controls.** Fine-tuning providers sign deletion
  and non-retention clauses.
- **Offboarding checklist.** Revoke access to model artifacts,
  API keys, and registries.
- **Incident playbook.** If theft is suspected: identify the
  artifact, rotate keys, notify, monitor for the model in the
  wild, prepare legal.
- **Watermark and monitor.** A watermark only helps if you look
  for it. Monitor public hubs and marketplaces.

## 11. References

- OWASP LLM10: Model Theft - https://genai.owasp.org/llmrisk/llm10-model-theft/
- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS - https://atlas.mitre.org/
- NIST AI RMF - https://www.nist.gov/itl/ai-risk-management-framework
- Carlini et al., "Stealing Part of a Production Language Model" - https://arxiv.org/abs/2403.06634
