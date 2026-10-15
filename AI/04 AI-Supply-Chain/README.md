# 04 AI Supply Chain

Supply chain security for AI systems: data, models, weights, code, dependencies, and infrastructure. This subcategory covers how the AI supply chain is structured, where trust boundaries fail, and how attacks propagate from an upstream artifact to a downstream deployment.

> [!CAUTION]
> Educational content for authorized security testing only. Do not use the techniques described here against systems you do not own or have explicit permission to test.

## Scope

The AI supply chain spans four artifact classes:

- **Data** - pretraining corpora, fine-tuning datasets, RLHF preference data, evaluation sets.
- **Models** - base checkpoints, fine-tuned weights, adapters (LoRA, QLoRA), embedding models, tokenizers.
- **Code** - training scripts, inference servers, quantization tools, deployment wrappers, agent frameworks.
- **Dependencies** - Python packages, CUDA libraries, container base images, model hubs, package registries.

A failure in any one class propagates downstream. A poisoned dataset produces a backdoored model. A backdoored model is redistributed as a "fine-tune" and reaches production. A typosquatted package exfiltrates weights during training.

## Files

| # | File | Status |
|---|------|--------|
| 01 | [Supply Chain Fundamentals](./01%20Supply-Chain-Fundamentals.md) | done |
| 02 | [Model Provenance](./02%20Model-Provenance.md) | done |
| 03 | [Dataset and Dependency Attacks](./03%20Dataset-and-Dependency-Attacks.md) | done |
| 04 | [Supply Chain Defense](./04%20Supply-Chain-Defense.md) | done |

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
- [OWASP LLM Top 10](../01%20OWASP-LLM-Top-10-2026/README.md) - LLM05 (Supply Chain Vulnerabilities)
- [RAG and Embeddings](../02%20RAG-and-Embeddings/README.md) - embedding supply chain
- [Agents and MCP](../03%20Agents-and-MCP/README.md) - tool and plugin supply chain

## References

- NIST SP 800-218A - Secure Software Development Practices for Generative AI
- OWASP LLM Top 10 2025 - LLM05 Supply Chain Vulnerabilities
- SLSA (Supply-chain Levels for Software Artifacts) - https://slsa.dev/
- Sigstore - https://www.sigstore.dev/
- in-toto - https://in-toto.io/

## Attack Surface Summary

| Stage | Artifact | Primary Threat | Trust Assumption |
|-------|----------|----------------|------------------|
| Data collection | Raw corpus | Poisoning, provenance loss | Public data is honest |
| Preprocessing | Cleaned dataset | Tampering in transit | Pipeline is trusted |
| Training | Model weights | Backdoor insertion | Compute is isolated |
| Fine-tuning | Adapters | Malicious base model | Base is benign |
| Packaging | Model file | Serialization exploit | Format is safe |
| Distribution | Model hub | Typosquatting, account takeover | Registry is honest |
| Deployment | Inference server | Dependency confusion | Pins are correct |
| Consumption | Application | Prompt injection via upstream | Provider is trusted |

## Design Principle

The AI supply chain inherits every weakness of the traditional software supply chain and adds four new ones:

1. **Opaque artifacts** - model weights are binary blobs. You cannot read them like source code. You need behavioral testing to detect a backdoor.
2. **Non-deterministic behavior** - the same model can behave differently across runs. This makes anomaly detection harder.
3. **Data as code** - a dataset is not just input, it shapes behavior. Poisoning a dataset is equivalent to injecting code.
4. **Continuous update** - models are re-trained, re-fine-tuned, re-quantized constantly. Each version is a new attack opportunity.

## Threat Model Template

When assessing an AI supply chain, answer these questions:

- Where do the weights come from? Public hub, vendor, or trained in-house?
- Is the training data documented? Can you trace every sample to a source?
- Are dependencies pinned to immutable versions (hashes, not tags)?
- Is the model file format safe to load (safetensors vs pickle)?
- Who can push a new version to the registry? Is that action logged and reviewed?
- Can you detect a behavioral change between model versions?
- What is the blast radius if the inference server is compromised?
