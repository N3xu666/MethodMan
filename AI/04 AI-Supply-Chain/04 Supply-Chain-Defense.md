# Supply Chain Defense

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## 1. Overview

Defense for the AI supply chain is the discipline of ensuring that every artifact - data, model, code, dependency, container - is authentic, unmodified, and appropriate for its intended use. This file consolidates the preventive and detective controls from files 01-03 into a coherent program.

The core principle: **verify, do not trust.** Every artifact is treated as untrusted until it has been verified against an authoritative source. This applies to public models, internal datasets, and vendor-supplied components alike.

## 2. Reconnaissance / Enumeration

Defensive reconnaissance is an inventory of everything the AI system depends on, with a trust level and a verification status for each item.

### 2.1 Artifact inventory

- **Datasets.** Source, version, hash, license, last review date.
- **Base models.** Source, revision, hash, signature, architecture, license.
- **Fine-tunes and adapters.** Base model, training data, hyperparameters, hash.
- **Python packages.** Name, version, hash, source index, CVE status.
- **Container images.** Registry, digest, base image, build provenance.
- **Infrastructure.** Training cluster, storage, model registry, inference endpoints.
- **Secrets and credentials.** Scope, rotation schedule, storage location.

### 2.2 Trust levels

- **Authoritative.** Internal artifact, built from verified sources, signed by the org.
- **Vetted external.** Public artifact that has been reviewed, hashed, and pinned.
- **Untrusted.** Public artifact that has not been reviewed. Cannot be used in production.

### 2.3 Verification status

For each artifact, record:

- Last verification date.
- Verification method (hash, signature, behavioral test).
- Result (pass, fail, not verified).
- Reviewer (human or automated).

## 3. Common Attack Vectors

Defense is designed against the attack classes in files 02 and 03. The summary:

- **Dataset poisoning.** Malicious samples in a training or fine-tuning dataset.
- **Dependency confusion.** Public package overrides an internal one, or a typosquatted package is installed.
- **Backdoored model.** A model that behaves normally except on a trigger.
- **Serialization exploit.** A model file that executes code on load.
- **Account takeover.** A maintainer account is compromised; a malicious version is published.
- **Distribution tampering.** A mirror or registry serves a modified artifact.
- **Trust abuse.** `trust_remote_code=True` executes attacker-supplied code.

Each of these is addressed by one or more controls in sections 6 and 7.

## 4. Exploitation Recipes

Defense is best validated by attempting the attack. This section maps each attack class to a defense validation exercise.

### 4.1 Validate pickle protection

1. Obtain a benign `.pt` file.
2. Confirm that loading with `weights_only=True` succeeds.
3. Craft a malicious pickle file.
4. Confirm that `picklescan` flags it.
5. Confirm that loading with `weights_only=True` fails or blocks the payload.

### 4.2 Validate dependency confusion protection

1. In a sandbox, publish a test package to a local index with the same name as an internal one.
2. Confirm that `pip install` resolves to the internal index, not the public one.
3. Confirm that the CI pipeline installs from a lockfile with hashes.
4. Confirm that an unexpected package version raises an alert.

### 4.3 Validate behavioral regression tests

1. Take a baseline model. Record outputs on a fixed prompt set.
2. Modify the model (e.g. swap one weight).
3. Re-run the tests. Confirm that the diff is detected.
4. Confirm that a clean model passes the same tests.

### 4.4 Validate egress restrictions

1. On a training host, attempt `curl http://attacker.example`.
2. Confirm that the request is blocked or alerted.
3. Confirm that allowlisted endpoints remain reachable.

## 5. Post-Exploitation

This section describes what to do when a supply chain compromise is detected. The goal is to limit blast radius and restore trust.

- **Isolate.** Cut network access to affected training and inference hosts.
- **Rotate.** Rotate all credentials that may have been exposed (cloud, model hub, internal APIs).
- **Roll back.** Revert to the last known-good model, dataset, and dependency set.
- **Re-train.** If a dataset was poisoned, re-train from a clean, verified snapshot.
- **Notify.** Inform downstream consumers of the model or package.
- **Post-mortem.** Document how the compromise happened and which control failed.
- **Update controls.** Add a detection or prevention control that would have caught it.

## 6. Preventive Controls

### 6.1 Artifact integrity

- **Pin everything.** Python packages by hash, models by revision SHA, containers by digest.
- **Sign artifacts.** Sigstore for models and containers. GPG for releases.
- **Hash databases.** Known-good SHA-256 for every artifact. Block anything not in the database.
- **Internal registry.** Mirror approved artifacts. No direct pulls from public hubs in production.
- **SBOM for ML.** Machine-readable inventory of models, datasets, and dependencies.

### 6.2 Safe formats and loading

- **safetensors by default.** No pickle in production.
- **`weights_only=True`** for any PyTorch load.
- **No `trust_remote_code=True`** unless the repo has been audited and pinned.
- **Allowlisted architectures.** Only built-in architectures in production.

### 6.3 Build and training isolation

- **No outbound network** from training jobs. Only allowlisted endpoints.
- **Separate credentials** per stage (data, training, packaging, deployment).
- **Read-only input.** Training jobs cannot write to the dataset store or the model registry.
- **Ephemeral environments.** Containers are rebuilt from a verified base image each run.

### 6.4 Promotion gate

A model is promoted to production only if:

1. It is signed by a trusted key.
2. Its hash matches the known-good value.
3. It passes behavioral regression tests.
4. It was trained on a frozen, hashed dataset.
5. It was built from a lockfile-pinned dependency set.
6. A human has reviewed the model card and the diff.

## 7. Detection Controls

### 7.1 Continuous monitoring

- **Hash monitoring.** Any artifact whose hash changes without a promotion event triggers an alert.
- **Commit monitoring.** Watch pinned model repos for new commits, force-pushes, and maintainer changes.
- **Install monitoring.** Alert on new packages, especially typosquat candidates.
- **Egress monitoring.** Alert on non-allowlisted outbound traffic from training and inference hosts.
- **Behavioral drift.** Run the fixed prompt set periodically; alert on unexpected changes.

### 7.2 Scanning in CI

- **`picklescan`** on every model file.
- **`modelscan`** on every model file.
- **`pip-audit`** and OSV-Scanner on every dependency tree.
- **Container scanning** (Trivy, Grype) on every built image.
- **SBOM generation** on every build.

### 7.3 Incident detection

- **Unusual model access.** A model that is suddenly downloaded by many users may have been typosquatted or compromised.
- **Unusual training runs.** A new training job from an unexpected source.
- **Anomalous inference.** Outputs that differ from the baseline on known inputs.
- **Credential use from unexpected locations.** Model hub tokens used from a new IP.

## 8. Verification

- Run the defense validation exercises from section 4 at least once per quarter.
- Confirm that every production model passes the promotion gate.
- Confirm that every production dependency is pinned by hash.
- Confirm that behavioral regression tests are up to date and passing.
- Confirm that the SBOM is complete and stored with each artifact.
- Confirm that incident response playbooks are documented and tested.

## 9. AI-Specific Considerations

- **Behavioral testing is the only reliable detection for a backdoor.** Hash checks catch tampering but not a model that was trained with a backdoor from the start.
- **Non-determinism requires tolerance.** Fixed seeds or greedy decoding for reproducible tests.
- **Model cards are not audited.** Treat them as claims, not facts.
- **Fine-tunes inherit risk.** A clean fine-tune on a backdoored base model is still backdoored.
- **Distillation propagates backdoors.** A student model trained on a poisoned teacher inherits the behavior.
- **The dependency tree is large.** Automated scanning is mandatory; manual review does not scale.

## 10. Production Notes

- **One promotion path.** All production models come through the same gate. No exceptions.
- **One registry.** All production artifacts live in one internal registry with access controls and audit logs.
- **One SBOM per artifact.** Stored alongside the artifact, referenced in the incident playbook.
- **Rotation schedule.** Cloud credentials, model hub tokens, and signing keys rotate on a fixed schedule.
- **Tabletop exercises.** Once a quarter, run an incident scenario (poisoned dataset, compromised dependency).
- **Metrics.** Track: number of unverified artifacts, number of failed promotion gates, number of incidents detected by each control.

## 11. References

- NIST SP 800-218A - Secure Software Development Practices for Generative AI. https://csrc.nist.gov/pubs/sp/800/218/a/final
- OWASP LLM Top 10 2025 - LLM05 Supply Chain Vulnerabilities. https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/
- SLSA - Supply-chain Levels for Software Artifacts. https://slsa.dev/
- Sigstore. https://www.sigstore.dev/
- in-toto - Supply chain integrity. https://in-toto.io/
- CycloneDX - SBOM standard. https://cyclonedx.org/
- SPDX - SBOM standard. https://spdx.dev/
- picklescan. https://github.com/mmaitre314/picklescan
- modelscan. https://github.com/protectai/modelscan
- Trivy - container and artifact scanning. https://github.com/aquasecurity/trivy
- pip-audit. https://github.com/pypa/pip-audit
- OSV-Scanner. https://github.com/google/osv-scanner
- MITRE ATLAS. https://atlas.mitre.org/
