# RAG and Embeddings

Reference material for Retrieval-Augmented Generation (RAG) systems
and the embedding models that power them. Four files, each in the
two-track format (Offensive / Defensive).

## Why This Exists

RAG is the dominant pattern for grounding LLM answers in private data:
documents are chunked, embedded into vectors, stored in a vector
database, and retrieved at query time to feed the model. This pipeline
introduces an attack surface that neither the LLM Top 10 nor
traditional web security covers directly: the embedding layer, the
vector store, the retrieval logic, and the trust boundary between
retrieved content and the model's instruction hierarchy.

## Format

Every file uses the two-track structure:

```
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
```

## Files

| # | Topic | File | Status |
|---|-------|------|--------|
| 01 | RAG Fundamentals | 01 RAG-Fundamentals.md | planned |
| 02 | Embedding Attacks | 02 Embedding-Attacks.md | planned |
| 03 | RAG Injection | 03 RAG-Injection.md | planned |
| 04 | RAG Defense | 04 RAG-Defense.md | planned |

## Scope

- 01 RAG-Fundamentals: pipeline stages, chunking, embedding models,
  vector stores, retrieval strategies (dense, sparse, hybrid, rerank).
- 02 Embedding-Attacks: embedding inversion, adversarial embeddings,
  vector-store poisoning, model stealing via the embedding API,
  cross-tenant leakage.
- 03 RAG-Injection: indirect prompt injection via retrieved documents,
  dormant poisoned documents, tool-call injection, cross-document
  injection, trust-level confusion.
- 04 RAG-Defense: per-user and per-tenant access control on the vector
  store, document provenance, retrieval caps, input filtering on
  retrieved content, output filtering and citation verification,
  monitoring and anomaly detection.

## References

- Retrieval-Augmented Generation (Lewis et al., 2020): https://arxiv.org/abs/2005.11401
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Authorized Use Only

For authorized security testing and educational purposes only.
See SECURITY.md in the repository root.
