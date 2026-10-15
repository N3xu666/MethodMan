# RAG Defense

RAG defense is the set of controls that keep the retrieval pipeline
from becoming an attacker-controlled channel. The three attack classes
covered earlier - embedding attacks, retrieval poisoning, and indirect
injection - each require a different defensive layer, but they share
one principle: treat every vector, every chunk, and every retrieved
passage as untrusted input that must be filtered, capped, and logged.

## 1. Overview

A RAG system has four trust boundaries:

- **Ingestion boundary.** Between source documents and the vector
  store. Controls: sanitization, provenance tagging, rate limits.
- **Storage boundary.** Between tenants and users inside the store.
  Controls: metadata filters, namespaces, encryption at rest.
- **Retrieval boundary.** Between the store and the prompt. Controls:
  access control, retrieval caps, reranking isolation.
- **Output boundary.** Between the model and the user or tool. Controls:
  output filtering, citation verification, tool allow-lists.

Every control in this file maps to one of these four boundaries. A
control that does not have a clear boundary is hard to test and easy
to bypass.

## 2. Access Control on the Vector Store

Access control is the single most important RAG defense. If the store
enforces per-user and per-tenant isolation, cross-tenant leakage and
most data-exfiltration attacks fail before the model sees anything.

**2.1 Metadata-based filtering.**

    # Every vector carries ACL metadata at write time.
    store.upsert(
        id=chunk_id,
        vector=embed(chunk_text),
        metadata={
            "tenant": "acme",
            "acl_groups": ["engineering", "oncall"],
            "source": "internal-wiki",
            "owner": "alice@acme.example",
        },
    )

    # At query time, the filter is applied by the store, not by the
    # client. The client cannot override it.
    results = store.query(
        vector=embed(question),
        top_k=10,
        filter={"tenant": current_tenant,
                "acl_groups": {"$in": current_user.groups}},
    )

**2.2 Namespaces and collections.** Stronger than metadata filters:
each tenant gets its own collection. This eliminates filter-bypass
bugs at the cost of operational overhead.

**2.3 Row-level security in the store.** If the store supports it
(pgvector with PostgreSQL RLS, Weaviate multi-tenancy), use it. The
filter is enforced by the database engine, not by application code.

**2.4 Principle.** The filter must be enforced server-side, from the
authenticated user's identity, before ranking. Never trust a filter
sent by the client.

## 3. Document Provenance and Trust Levels

Every chunk must carry its origin. Provenance is what allows the
system to apply different rules to different sources.

**3.1 Trust levels.**

- **Trusted.** Internal documents written by vetted authors, version
  controlled. Full weight in retrieval.
- **Semi-trusted.** Internal documents from ticketing systems, wikis,
  or email. Sanitized at ingestion, flagged in the prompt.
- **Untrusted.** User-uploaded files, external web content. Treated
  as adversarial. Often excluded from the prompt entirely, or
  wrapped in a strict data-only format.

**3.2 Provenance in the prompt.** When a chunk is inserted into the
prompt, include its trust level as a visible marker:

    <context trust="untrusted" source="support-ticket-12345">
    ...chunk text...
    </context>

**3.3 Provenance in the logs.** Every retrieval logs the chunk ID,
the source document, the trust level, and the user who triggered the
query. This is the audit trail for incident response.

## 4. Retrieval Caps

Caps limit the blast radius of a single query. They do not prevent
injection, but they reduce its impact and make it easier to detect.

- **Max chunks per query.** Typically 5-20. Never unbounded.
- **Max tokens of context.** Bound the total prompt size. Prevents a
  single large document from dominating.
- **Max contribution per source.** A single document must not
  contribute more than N chunks to one query. Prevents a planted
  document from flooding the context.
- **Min relevance score.** Drop chunks below a similarity threshold.
  Reduces the chance that a weak match (crafted by the attacker) is
  retrieved.
- **Max distinct sources.** A query must draw from at most M sources.
  Prevents cross-document injection patterns.

## 5. Input Filtering on Retrieved Content

Before a retrieved chunk enters the prompt, apply content-level
filters. These are the last line of defense and should not be relied
on alone.

- **Strip control characters and hidden text.** Zero-width spaces,
  right-to-left overrides, HTML comments, CSS-hidden text.
- **Detect instruction-like phrases.** "Ignore previous instructions",
  "system override", "as an AI", "new system prompt", "disregard".
  This is a heuristic, not a guarantee.
- **Detect encoded payloads.** Long base64 blobs, hex strings, and
  unusual Unicode that does not match the document's language.
- **Detect URLs and contact addresses** in untrusted chunks. Flag or
  strip them.
- **Normalize whitespace and case** before pattern matching, so the
  attacker cannot evade filters with trivial transformations.

## 6. Output Filtering and Citation Verification

The output boundary is where the model can leak data or trigger
actions. Two controls matter most:

**6.1 Output filtering.** Scan the model's answer for:

- Known secrets (canary tokens, API keys, internal hostnames).
- URLs pointing outside the allow-list.
- Base64 or hex blobs that were not in the user's input.
- Contact addresses not present in the retrieved context.

**6.2 Citation verification.** Require the model to cite the chunk ID
for every factual claim. Verify:

- The cited chunk was actually retrieved for this query.
- The claim is supported by the chunk text (LLM-as-judge or string
  match for key phrases).
- No claim is made without a citation (or the answer is marked as
  unverified).

**6.3 Tool allow-list.** If the model has tool access, restrict it:
tools the user cannot call cannot be triggered by injection. Every
tool call is authorized against the user's identity, not the model's.

## 7. Monitoring and Anomaly Detection

- **Retrieval concentration.** One document dominating the top-K for
  many unrelated queries is a poisoning signal.
- **Injection canaries.** Plant benign documents with a unique
  instruction. If the model ever follows it, the pipeline is
  compromised.
- **Ingestion rate.** A sudden spike of new documents from one source
  is an early warning.
- **Output anomaly.** Answers that suddenly contain URLs, base64, or
  unusual formatting.
- **Cross-tenant query audit.** Any query whose filter was empty or
  defaulted to "all" is a potential access-control bug.

## 8. Verification

A RAG defense is only as good as its tests. Minimum test suite:

- **Isolation test.** User A cannot retrieve user B's chunks, in any
  combination of groups or tenants.
- **Injection canary.** A planted canary document must not affect any
  answer.
- **Cross-document canary.** Split a canary across two documents;
  verify neither alone nor together triggers it.
- **Encoded canary.** Base64 and Unicode-obfuscated canary payloads
  must be stripped or ignored.
- **Tool-injection canary.** A canary instruction that would call a
  benign tool must not cause the tool call.
- **Exfiltration canary.** A canary secret in the store must not
  appear in any answer, and must not be renderable as an image URL.
- **Retrieval cap.** A query matching many chunks returns at most K.
- **Provenance log.** Every retrieval is logged with chunk ID, source,
  trust level, and user.

## 9. AI-Specific Considerations

- The model is not a security boundary. Treat its output as untrusted
  until filtered.
- System prompt hardening helps but does not replace access control.
  A leaked chunk is leaked regardless of what the model says.
- Fine-tuning for instruction hierarchy reduces injection success but
  does not eliminate it. Test after every model change.
- Reranker models have their own training data and may exhibit
  unexpected biases. Test the reranker separately from the retriever.

## 10. Production Notes

- Log everything: queries, retrieved chunk IDs, trust levels, filters
  applied, model version, prompt version, and output. Without this,
  incident response is guesswork.
- Rebuild the collection from source on a schedule. This is the only
  reliable way to remove undetected poisoning.
- Version the prompt. A prompt change can break the injection
  defenses; test canaries before rolling out.
- Rotate canary tokens. A canary that appears in logs for months is
  no longer a canary.

## 11. References

- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP GenAI Security Project: https://genai.owasp.org/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- Not what you've signed up for (Greshake et al., 2023): https://arxiv.org/abs/2302.12173
