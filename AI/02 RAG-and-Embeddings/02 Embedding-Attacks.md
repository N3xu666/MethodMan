# Embedding Attacks

The embedding layer is the least scrutinized part of a RAG pipeline
and one of the most valuable to an attacker. Vectors are treated as
opaque identifiers, but they are lossy encodings of the original text.
An attacker who can read, write, or query vectors can often recover
the text, control what gets retrieved, or steal the embedding model
itself. This file covers the attack classes against the embedding
layer and the vector store.

## 1. Overview

The embedding layer has four properties that make it attackable:

- **Vectors are reversible.** Given enough query pairs, a model's
  embedding function can be approximated well enough to invert
  vectors back to text (embedding inversion).
- **Similarity is the only contract.** The store returns whatever is
  closest. An attacker who can write vectors controls what "closest"
  means for a target query.
- **Shared stores are common.** Multi-tenant deployments often share
  one vector collection. Without strict metadata filtering, one tenant
  can retrieve another tenant's chunks.
- **The embedding API is a query oracle.** Even without direct store
  access, an attacker who can call the embedding endpoint can probe
  the model, steal it, or craft inputs that land close to a target.

This file covers: embedding inversion, adversarial embeddings,
poisoning, model stealing via the embedding API, and cross-tenant
leakage. Injection through retrieved content is covered separately in
03 RAG-Injection.md.

## 2. Reconnaissance / Enumeration

**2.1 Identify the embedding model.** Embedding models have
fingerprints:

- Vector dimension (384, 768, 1024, 1536, 3072) narrows the family.
- API response shape and error messages.
- Tokenizer behavior: send inputs that tokenize differently across
  models and observe the distance between outputs.
- Rate limits and pricing, if the API is public.

Common models: OpenAI text-embedding-3-small / -large, Cohere embed,
Voyage, BGE, E5, GTE, sentence-transformers (all-MiniLM-L6-v2 is the
most common open baseline).

**2.2 Identify the vector store.** Store fingerprints:

- ID format (UUIDv4, hex, sequential).
- Latency profile (in-memory vs. disk-backed vs. managed service).
- Metadata filter syntax accepted at query time.
- Default top-K and score thresholds (infer from response sizes).

Common stores: Pinecone, Weaviate, Qdrant, Chroma, Milvus, pgvector,
Redis Stack, Elasticsearch dense vectors.

**2.3 Map the trust boundary.** Determine:

- Who can write to the store? (Ingestion service account, admin API,
  any user who can upload a document.)
- Who can read? (Per-user filter, per-tenant namespace, or shared.)
- What metadata is attached to each vector? (Source, ACL tags,
  timestamps.)

## 3. Common Attack Vectors

**3.1 Embedding inversion.** Reconstruct the original text from a
vector. Even when the vector is not directly exposed, the store's
similarity API can be used as an oracle: repeatedly query with
candidate texts and compare distances.

**3.2 Adversarial embeddings.** Craft a vector that is close to a
target query's embedding without containing the target content. If the
store accepts vectors directly (bypassing the ingestion pipeline), the
attacker bypasses all content-based filters.

**3.3 Embedding poisoning.** Write vectors that dominate the top-K
for a class of queries. The attacker does not need to be semantically
close to the query - only closer than the legitimate chunks.

**3.4 Model stealing via the embedding API.** Recover a functional
copy of the embedding model by querying it on a large corpus and
training a local student model on the (text, vector) pairs.

**3.5 Cross-tenant leakage.** In a shared store without per-tenant
metadata filtering, a query from tenant A retrieves chunks from
tenant B. This is the RAG equivalent of an IDOR.

## 4. Exploitation Recipes

**4.1 Embedding inversion (black-box).**

    # For a set of candidate texts, query the embedding API and
    # record the vectors. Train an inversion model on (vector, text)
    # pairs. Apply it to the target vector.

    import openai, numpy as np
    from sklearn.linear_model import Ridge

    def embed(text):
        r = openai.embeddings.create(
            model="text-embedding-3-small", input=text)
        return np.array(r.data[0].embedding)

    corpus = [line.strip() for line in open("corpus.txt")]
    X = np.array([embed(t) for t in corpus])
    # Train a ridge regression per token position (simplified).
    # See Morris et al. 2023 for the full vec2text method.

**4.2 Adversarial embedding.**

    # If the store accepts raw vectors, compute a vector that is
    # closer to the target query than any legitimate chunk.
    target = embed("how do I reset the admin password")
    # Fine-tune any base vector until cosine(target, v) is maximal.
    # The vector does not need to correspond to any real text.

**4.3 Poisoning the store.**

    # Write many near-duplicate chunks that all mention the target
    # topic. Each one is individually plausible; together they
    # dominate the top-K.
    for i in range(500):
        text = f"Password reset procedure (variant {i}): ..."
        vec = embed(text)
        store.upsert(id=f"poison-{i}", vector=vec, metadata={"src": "user"})

**4.4 Stealing the embedding model.**

    # Query the target embedding API on a large public corpus.
    # Train a student model that reproduces the vectors.
    # The student can then be used offline for inversion or
    # adversarial crafting without rate limits.
    pairs = [(t, embed(t)) for t in large_corpus]
    student = SentenceTransformer("all-MiniLM-L6-v2")
    student.fit(pairs)  # simplified

**4.5 Cross-tenant leakage.**

    # Query with a term that is likely present in another tenant's
    # documents (product names, employee names, internal codenames).
    # If chunks come back with foreign tenant metadata, the filter
    # is missing.
    results = store.query(embed("acme internal roadmap"), top_k=10)
    for r in results:
        print(r.metadata.get("tenant"), r.text[:80])

## 5. Post-Exploitation

- **Reconstruct secrets.** Invert vectors for chunks that contain
  credentials, tokens, or personal data.
- **Silently bias retrieval.** Poisoned chunks shift answers without
  changing any source document - hard to detect by reading the source.
- **Persistent.** Poisoned vectors survive until the collection is
  rebuilt. Deleting the source document is not enough if the vector
  was written directly.

## 6. Preventive Controls (Defensive)

- **Do not expose raw vector write APIs.** Only the ingestion service
  should write vectors. Enforce this with network policy and auth.
- **Enforce metadata filters at query time.** Per-user and per-tenant
  filters must be applied by the store, not by the client.
- **Cap write rate per source.** A single source (one user, one
  upload endpoint) must not be able to insert thousands of chunks
  in a short window.
- **Detect near-duplicates at ingestion.** Reject or flag chunks
  whose embedding is within a small distance of many existing chunks.
- **Rotate the embedding model version deliberately.** Treat a model
  change as a re-index event, and log it.

## 7. Detection Controls (Defensive)

- **Monitor write volume per source.** A spike from one source is
  the strongest signal for poisoning.
- **Monitor retrieval concentration.** If one document dominates
  the top-K across many unrelated queries, it is either very relevant
  or poisoned.
- **Track embedding drift.** Periodically re-embed a fixed probe set
  and compare against the historical vectors. Drift indicates a model
  swap or a compromised ingestion pipeline.
- **Audit cross-tenant queries.** Log every query's filter and verify
  that the filter was non-empty for non-admin users.

## 8. Verification

- Test that raw vector writes are rejected without the ingestion
  service's credentials.
- Test that a query with no metadata filter returns only the caller's
  tenant.
- Test that a flood of near-duplicate chunks from one source is rate
  limited.
- Test that the embedding model version is pinned and logged.

## 9. AI-Specific Considerations

- Embedding inversion quality depends on the model: larger models
  with more dimensions are harder to invert, but not immune.
- Adversarial embeddings are transferable across models in the same
  family - a vector crafted against one model often works against
  its siblings.
- Vector stores are not designed to be adversarial inputs. Do not
  assume that the store's own validation (dimension, range) is
  sufficient.

## 10. Production Notes

- Store vectors with a model ID and version. Reject queries that mix
  models.
- Keep an immutable audit log of every vector write: source, time,
  operator, chunk hash.
- Rebuild the collection on a schedule from source documents. This
  is the only reliable way to remove undetected poisoning.

## 11. References

- Text Embeddings Reveal (Almost) As Much As Text (Morris et al., 2023): https://arxiv.org/abs/2310.06816
- Sentence-BERT (Reimers and Gurevych, 2019): https://arxiv.org/abs/1908.10084
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
