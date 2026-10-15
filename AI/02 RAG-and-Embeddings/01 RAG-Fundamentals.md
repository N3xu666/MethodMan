# RAG Fundamentals

Retrieval-Augmented Generation (RAG) is the dominant pattern for
grounding a large language model in private data that was not part of
its training set. Instead of fine-tuning the model on every document,
the system retrieves relevant chunks at query time and passes them to
the model as context. This file covers the pipeline end to end:
ingestion, chunking, embedding, storage, retrieval, and generation.

## 1. Overview

A RAG system has two pipelines that share one artifact - the vector
store:

- **Ingestion (offline).** Documents are collected, parsed, split into
  chunks, embedded into vectors, and written to a vector store with
  metadata. Runs once per document or on a schedule.
- **Query (online).** A user question is embedded with the SAME model,
  the vector store returns the top-K most similar chunks, those chunks
  are inserted into the prompt, and the model generates an answer.

The security-relevant boundary is between "retrieved content" and
"model instructions". Retrieved content is data, not instructions -
but most current models cannot reliably tell the two apart. That is
the root cause of the injection class covered in 03 RAG-Injection.md.

## 2. Pipeline Stages

**2.1 Document ingestion.** Sources: file shares, wikis, ticketing
systems, email archives, databases, web crawls, object storage. Each
source has its own parser (PDF, DOCX, HTML, Markdown, plain text).
Parser bugs and parser trust are part of the attack surface: a
malicious PDF can carry hidden text that the parser extracts but the
human reviewer never sees.

**2.2 Chunking.** A long document is split into chunks small enough to
fit the retrieval window and the model context. Chunk size is a
trade-off: too small loses context, too large dilutes relevance.

Chunking strategies:

- **Fixed-size.** Split every N characters or tokens with an overlap
  (e.g. 1000 chars, 200 overlap). Fast, predictable, ignores structure.
- **Recursive.** Split on paragraph, then sentence, then character,
  until each chunk fits the limit. Preserves structure better.
- **Semantic.** Split where the embedding similarity between adjacent
  sentences drops below a threshold. Higher quality, more compute.
- **Structure-aware.** Split on document structure (Markdown headings,
  HTML sections, code blocks). Best for technical documentation.

**2.3 Embedding.** Each chunk is passed through an embedding model
that returns a dense vector (typically 384-3072 dimensions). The
vector captures semantic meaning: similar text produces similar
vectors. Embeddings are computed once at ingestion and stored.

**2.4 Storage.** Vectors are written to a vector store (also called a
vector database) together with the original chunk text and metadata:
source document, section, author, access-control tags, timestamp.
The metadata is what makes per-user filtering possible - see
04 RAG-Defense.md.

**2.5 Retrieval.** At query time the user question is embedded with
the same model, and the store returns the top-K chunks by similarity
(cosine, dot product, or Euclidean distance, depending on the store).

Retrieval strategies:

- **Dense retrieval.** Vector similarity only. Good at semantic
  matching ("how do I reset a password" matches "credential recovery
  procedure"), weak at exact terms (error codes, product IDs).
- **Sparse retrieval.** Keyword-based (BM25, TF-IDF). Good at exact
  terms, weak at paraphrase.
- **Hybrid.** Combine dense and sparse scores. Standard in production
  systems because it covers both cases.
- **Reranking.** Retrieve a large candidate set (e.g. top-100), then
  rerank with a cross-encoder model that scores each (query, chunk)
  pair directly. More accurate, more expensive. Only the top-N after
  reranking go into the prompt.

**2.6 Generation.** The retrieved chunks are assembled into a prompt
and sent to the LLM. Typical prompt shape:

    You are a helpful assistant. Answer the question using ONLY the
    context below. If the context does not contain the answer, say so.

    Context:
    ---
    <chunk 1>
    ---
    <chunk 2>
    ---
    <chunk 3>

    Question: <user question>
    Answer:

## 3. Common Attack Vectors

This section lists the attack classes at a high level. Each is
covered in detail in its own file.

- **Embedding attacks** (02 Embedding-Attacks.md): inverting vectors
  back to text, crafting adversarial embeddings, poisoning the vector
  store, stealing the embedding model through its API, leaking data
  across tenants in a shared store.
- **Injection through retrieval** (03 RAG-Injection.md): planting a
  document that contains instructions for the model, which fire when
  the document is retrieved for a target query. This is indirect
  prompt injection and is the highest-impact RAG-specific risk.
- **Access-control bypass** (04 RAG-Defense.md, defensive): retrieving
  chunks the user is not authorized to see because the vector store
  does not enforce per-user or per-tenant filtering.
- **Denial of service** (see 01 OWASP-LLM-Top-10-2026/LLM04.md):
  flooding the store with near-duplicate chunks so the top-K is always
  poisoned, or forcing expensive reranking on every query.

## 4. Exploitation Recipes

**4.1 Enumerate the pipeline.** From the outside, identify the
embedding model (API response shapes, error messages), the vector
store (latency profile, ID formats), and the chunk size (long answers
that quote pasted context verbatim reveal chunk boundaries).

**4.2 Probe the retrieval boundary.** Ask a question whose answer is
in a document the user should NOT be able to reach. If the answer
comes back, per-user filtering is missing.

**4.3 Plant a document.** If the ingestion pipeline accepts
user-supplied content (support tickets, uploaded PDFs, wiki edits),
plant a document that contains an instruction. Craft it so that it is
retrieved for a target query but invisible to a human reviewer
(white text, metadata fields, comments).

**4.4 Measure chunk boundaries.** Send questions with known answers
that span chunk boundaries. The model's answer quality drops at the
boundary - this leaks the chunk size and overlap.

## 5. Post-Exploitation

Once the attacker can influence retrieval, the impact depends on what
the model can do:

- **Data exfiltration.** Instruct the model to include a secret from
  another chunk in its answer, or to render it as a Markdown image URL
  that the client fetches.
- **Tool abuse.** If the model has tool access (search, email, code
  execution), injected instructions can trigger tools on the attacker's
  behalf. See 03 RAG-Injection.md.
- **Persistent poisoning.** A document that survives re-indexing keeps
  firing on every matching query until it is removed from the source
  and the store is rebuilt.

## 6. Preventive Controls (Defensive)

- **Treat retrieved content as untrusted input.** It crosses a trust
  boundary the same way a user-supplied string does.
- **Enforce access control at retrieval time.** Filter by user or
  tenant BEFORE ranking, not after. See 04 RAG-Defense.md.
- **Cap retrieval.** Limit the number of chunks, total context size,
  and per-source contribution.
- **Separate instructions from data in the prompt.** Use a structured
  format (JSON, XML tags) that the model is trained to respect, and
  state explicitly that context is data only.

## 7. Detection Controls (Defensive)

- **Log every retrieval.** Store query, retrieved chunk IDs, scores,
  and the final answer. This is the audit trail for incident response.
- **Anomaly detection on retrieval patterns.** A sudden spike in
  queries that all retrieve the same document suggests targeted
  probing or a planted document.
- **Content provenance tracking.** Every chunk carries its source.
  If the source is user-supplied, flag it in the logs.
- **Output monitoring.** Detect secrets, canary tokens, or URLs
  leaving through the answer.

## 8. Verification

- Test per-user isolation: user A must not retrieve user B's chunks.
- Test injection: plant a benign document with a unique canary
  instruction, query for it, verify the model obeys or refuses.
- Test retrieval caps: a query that matches 10,000 chunks must return
  at most K.
- Test reranking isolation: a reranker must not see chunks filtered
  out by the access-control layer.

## 9. AI-Specific Considerations

- The embedding model is a security boundary. If it can be swapped
  (via config injection, dependency confusion, or API key theft), the
  attacker controls what "similar" means.
- Chunk overlap is a leak channel: a secret split across two chunks
  can be reconstructed by asking for both.
- Metadata is not always trustworthy. If it is set at ingestion from
  document content, an attacker who controls the content controls the
  metadata.

## 10. Production Notes

- Pin the embedding model version. A silent upgrade changes every
  vector and invalidates the store.
- Re-embed on model change. Do not mix vectors from two models in one
  store.
- Monitor store size and query latency. Both are early indicators of
  poisoning or DoS.
- Keep the source-of-truth documents separate from the vector store.
  If the store is compromised, rebuild from source.

## 11. References

- Retrieval-Augmented Generation (Lewis et al., 2020): https://arxiv.org/abs/2005.11401
- Dense Passage Retrieval (Karpukhin et al., 2020): https://arxiv.org/abs/2004.04906
- Sentence-BERT (Reimers and Gurevych, 2019): https://arxiv.org/abs/1908.10084
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
