# Supply Chain Fundamentals

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## 1. Overview

The AI supply chain is the sequence of stages that turns raw data into a deployed model. Each stage consumes an artifact from the previous stage and produces a new artifact for the next. A compromise at any stage propagates downstream and is often invisible at the point of consumption.

This file defines the stages, the artifacts, the trust boundaries, and the attacker model. It is the foundation for the next three files: model provenance, dataset and dependency attacks, and supply chain defense.

## 2. Reconnaissance / Enumeration

Map the target's AI supply chain before attacking or defending it. The goal is to answer: what artifacts are used, where do they come from, and who controls them.

### 2.1 Artifact inventory

- **Data sources.** Public datasets (Common Crawl, LAION, The Pile), scraped web, licensed corpora, internal logs.
- **Models.** Base checkpoints (Llama, Mistral, Qwen), fine-tunes, adapters, embedding models, tokenizers, rerankers.
- **Code.** Training frameworks (PyTorch, JAX), inference servers (vLLM, TGI, Ollama), quantization tools (GPTQ, AWQ, GGUF), orchestration (Ray, Kubeflow).
- **Dependencies.** Python packages, CUDA/cuDNN, container base images, model hubs, package registries.
- **Infrastructure.** Training clusters, storage buckets, model registries, inference endpoints.

### 2.2 Provenance questions

For each artifact, ask:

- Where was it downloaded from? Is that source authoritative?
- Is it pinned to an immutable version (hash, commit SHA) or a mutable tag (`latest`)?
- Is there a signature or attestation? Who signed it?
- Has it been modified since publication?
- Who has write access to the source?

### 2.3 Public exposure enumeration

- Model cards and README files often leak training data sources, hyperparameters, and internal project names.
- Hugging Face model repos expose file lists, commit history, and sometimes API tokens in notebook cells.
- GitHub repos for training scripts expose data paths, S3 buckets, and WandB API keys in configs.
- Package metadata (PyPI, npm) exposes maintainer emails and linked repos.

## 3. Common Attack Vectors

Attacks on the AI supply chain fall into five classes. Each is covered in depth in the next three files; this section is the map.

### 3.1 Data poisoning

- **Pretraining poisoning.** Inject malicious samples into a large corpus (e.g. Common Crawl). Hard to detect, affects many downstream models.
- **Fine-tuning poisoning.** Inject a small number of trigger samples into a fine-tuning dataset. Produces a backdoored model with high reliability.
- **RLHF poisoning.** Corrupt preference data so the model learns to prefer harmful outputs in a specific context.

### 3.2 Model tampering

- **Backdoored base model.** Publish a model that behaves normally except on a trigger.
- **Weight modification.** Modify published weights to change specific behaviors without retraining.
- **Adapter injection.** Ship a LoRA adapter that adds a backdoor while the base model stays clean.

### 3.3 Serialization exploits

- **Pickle deserialization.** `torch.load()` on an untrusted `.pt`/`.pth` file executes arbitrary Python.
- **ONNX custom operators.** Crafted ONNX graphs can trigger memory corruption in runtimes.
- **GGUF parsing bugs.** Malformed GGUF files can crash or exploit the loader.

### 3.4 Dependency confusion

- **Typosquatting.** Publish `transfromers` (typo) or `transformerss` to PyPI. A typo in a requirements file installs the malicious package.
- **Namespace confusion.** Internal package name collides with a public one. `pip install` prefers the public, attacker-controlled version.
- **Model hub typosquatting.** Publish a model named `meta-llama/Llama-2-7b` (with a different org) to confuse users.

### 3.5 Compromised distribution

- **Account takeover.** Compromise a maintainer account on PyPI, npm, or Hugging Face. Push a malicious version under the same name.
- **Registry compromise.** Attack the registry itself (rare, but has happened: PyPI, npm incidents).
- **Mirror poisoning.** A corporate mirror of PyPI serves a tampered version.

## 4. Exploitation Recipes

This section shows one representative recipe per attack class. Detailed recipes are in files 02 and 03.

### 4.1 Recipe - dependency confusion (namespace collision)

Setup: a company has an internal package named `company-utils`. It is not published on PyPI.

1. Publish a package named `company-utils` on PyPI with a malicious `setup.py`.
2. The victim's `pip install company-utils` resolves to the PyPI version (public wins by default unless configured otherwise).
3. The malicious `setup.py` runs on install and exfiltrates environment variables, including any cloud credentials.

Detection: `pip install` logs the source URL. A `pip config` that pins an internal index avoids the issue.

### 4.2 Recipe - pickle deserialization on model load

Setup: the victim downloads a `.pt` file from a model hub and loads it.

1. Craft a pickle payload that runs `os.system` on load.
2. Wrap it in a file that looks like a legitimate `state_dict`.
3. Upload to the hub. When the victim calls `torch.load("model.pt")`, the payload runs.

Mitigation: use `safetensors` (no code execution on load). If pickle is required, load with `weights_only=True` in recent PyTorch.

## 5. Post-Exploitation

Once an attacker controls a supply chain artifact, the persistence and impact options are broad.

- **Silent backdoor.** The model behaves normally except on a trigger. Detection requires behavioral testing.
- **Data exfiltration.** A malicious training script or inference server can send prompts, outputs, or weights to an attacker-controlled endpoint.
- **Lateral movement.** A compromised training cluster often has access to data lakes, model registries, and cloud credentials.
- **Persistence.** A backdoored dependency is re-installed on every build. A backdoored base model is inherited by every fine-tune.

## 6. Preventive Controls

- **Pin everything.** Hashes for Python packages, commit SHAs for models, digests for containers.
- **Verify signatures.** Sigstore, in-toto attestations, GPG signatures on releases.
- **Use safe formats.** `safetensors` instead of pickle. Avoid `torch.load` on untrusted files.
- **Isolate build and training.** No outbound network from training jobs. Separate credentials per stage.
- **Mirror and audit.** Internal mirror of PyPI/Hugging Face with a review process for new artifacts.
- **SBOM for ML.** Track every artifact, version, and source in a machine-readable format.

## 7. Detection Controls

- **Behavioral regression tests.** A fixed set of prompts with expected outputs. Any new model version must pass.
- **Weight diffing.** Compare checksums between the expected and actual weights. Detects tampering.
- **Network egress monitoring.** Training and inference jobs should have a narrow allowlist.
- **File hash databases.** Known-good hashes for every artifact. Any mismatch is an incident.
- **Anomaly detection on installs.** Alert on new packages, new model downloads, new base images.

## 8. Verification

- Re-download every artifact from the authoritative source and compare hashes.
- Re-run behavioral tests on a model before promoting it.
- Audit the dependency tree for known-bad packages (pip-audit, safety, OSV).
- Verify signatures with `cosign verify` or `sigstore verify`.
- Confirm that no training job has outbound network access to unexpected hosts.

## 9. AI-Specific Considerations

- **Weights are opaque.** You cannot review them like source code. Behavioral testing is the only reliable detection.
- **Non-determinism.** The same input can produce different outputs. Tests must allow for variance or use greedy decoding.
- **Model provenance is weak.** Many model hubs do not require verified identity. A model's author is often unverified.
- **Fine-tunes inherit risk.** A clean fine-tune on a backdoored base model is still backdoored.
- **Data is code.** Poisoning a dataset is as impactful as injecting code, but harder to review.

## 10. Production Notes

- **Registry allowlist.** Only pull models from an internal registry that mirrors approved upstream sources.
- **Signing as gate.** No model is promoted to production without a verified signature and a passing behavioral test.
- **SBOM in CI.** Generate an ML SBOM on every build. Store alongside the artifact.
- **Incident response.** Pre-define what to do if a dependency is compromised: rotate credentials, roll back, re-train, notify.
- **Least privilege for training.** Training jobs should not have write access to the model registry. Promotion is a separate step.

## 11. References

- NIST SP 800-218A - Secure Software Development Practices for Generative AI and Dual-Use Foundation Models. https://csrc.nist.gov/pubs/sp/800/218/a/final
- OWASP LLM Top 10 2025 - LLM05 Supply Chain Vulnerabilities. https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/
- SLSA - Supply-chain Levels for Software Artifacts. https://slsa.dev/
- Sigstore - Software signing and transparency. https://www.sigstore.dev/
- in-toto - Supply chain integrity framework. https://in-toto.io/
- safetensors - Safe model serialization format. https://github.com/huggingface/safetensors
- PyTorch `weights_only` documentation. https://pytorch.org/docs/stable/generated/torch.load.html
- MITRE ATLAS - Adversarial Threat Landscape for AI Systems. https://atlas.mitre.org/
