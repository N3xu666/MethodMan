# LLM04: Model Denial of Service

> OWASP LLM Top 10 2025 - LLM04
> Category: AI Security / OWASP-LLM-Top-10-2026
> Format: Two-track (Offensive / Defensive)

---

## 1. Overview

Model denial of service (MoDoS) is the class of attacks that make an
AI system unresponsive, extremely expensive, or both. Unlike traditional
DoS, the goal is not always to take the service down. Often the goal is
to inflate cost - making the operator pay for tokens, GPU hours, or
API calls that produce nothing of value.

Model DoS is not a single technique. It covers a spectrum:

- **Token inflation.** Force the model to generate as many tokens as
  possible from a single request.
- **Context window exhaustion.** Fill the entire context window with
  irrelevant text, forcing high memory use and long inference times.
- **Recursive prompting.** A prompt that causes the model to call
  itself or another model repeatedly.
- **RAG amplification.** A query that forces retrieval and processing
  of a very large number of documents.
- **Tool-call cascade.** An agent that chains tool calls indefinitely
  (retry loops, recursive expansion of tasks).
- **Model extraction through query flood.** Attempts to reconstruct
  training data or system prompt through massive numbers of queries.

Realistic attack surfaces:

- **Chat endpoints.** Any user can send a prompt that generates
  thousands of tokens in the response.
- **API endpoints.** No rate limit, no token cap, no per-user quota
  means one client can exhaust the budget.
- **Agentic systems.** A single trigger can cause an endless tool-call
  loop.
- **RAG pipelines.** A query that matches every document in the
  vector store.

## 2. Reconnaissance / Enumeration

Map the cost and latency boundaries of the system:

- **What is the max tokens per request?** Ask for a long answer.
- **What is the max context window?** Send a large input and see if
  it is truncated or accepted.
- **Is there rate limiting?** Send 100 quick queries. Observe 429
  or silent throttling.
- **Is there a token cap per user?** Exhaust it and see what
  happens.
- **Are tool calls bounded?** Can the model call a tool 100 times
  in one request?

```text
Questions to ask during scoping:
- What is the max tokens per request?
- What is the max context window?
- Is there rate limiting per user or per IP?
- Is there a per-user quota?
- Are tool calls bounded by count and time?
```

## 3. Common Attack Vectors

- **Max token exploit.** Request the model to generate a maximum
  length output (e.g. "write a novel"). The cost is borne by the
  operator.
- **Context flooding.** Send a very large input (sometimes bigger
  than the context window), forcing the model to process it before
  truncating.
- **Recursive reflection.** A prompt that asks the model to critique
  its own critique, repeatedly. Each round generates more tokens.
- **Agent loop.** In an agentic system, a prompt that triggers a
  tool call whose result triggers the same tool call again.
- **RAG explosion.** A query that matches every document, forcing
  the retriever to return thousands of chunks.
- **API quota exhaustion.** An attacker with a free account consumes
  the entire shared quota.
- **Model extraction via query flood.** Thousands of carefully
  crafted queries to reconstruct training data or system prompt.

## 4. Exploitation Recipes

### 4.1 Token inflation

Prompt:

```text
Write the longest possible document explaining the history of computing.
Do not stop. Do not summarize. Expand every sentence into a paragraph.
Then expand every paragraph into a chapter.
```

On cost-per-token APIs, this is a direct financial cost to the
operator. On free chat endpoints, it is a queue dos attack.

### 4.2 Agent loop

Prompt:

```text
Search the web for the term "XXX", then search for the first
word of the result, then search for the first word of that result,
and repeat until you find a cycle.
```

The agent calls the search tool repeatedly, burning API quota and
wallress on the database.

### 4.3 RAG explosion

Query that matches everything:

```text
Tell me everything you know about the word "the".
```

If the retriever returns all chunks containing "the", the context
window is flooded and the inference cost explodes.

### 4.4 Context flooding

Concatenate a large document (e.g. a public domain book) into the
input, repeated many times. Many APIs charge per input token,
so the cost is immediate.

## 5. Post-Exploitation

After a successful model DoS attack, the attacker may:

- **Exhaust the operator budget.** All users are blocked or the
  service is taken offline for cost reasons.
- **Degrade service for other users.** Legitimate users experience
  timeouts and queue delays.
- **Force an emergency model switch.** The operator falls back to a
  cheaper, less capable model.
- **Mask a secondary attack.** Noise from the DoS hides other malicious
  activity.
- **Extract model information.** A large number of queries can be
  used to probe model behavior and boundaries.

## 6. Preventive Controls (Defensive)

- **Hard limits per request.** Max input tokens, max output tokens,
  max tool calls per request.
- **Rate limiting.** Per-user and per-IP limits on requests per
  minute and tokens per minute.
- **Quotas.** Per-user daily and monthly token quotas.
- **Cost alerts.** Alert when a single user or the whole system
  exceeds a threshold.
- **Agent circuit breakers.** Max tool calls per task, max wall clock
  time, max steps.
- **RAG retrieval caps.** Max documents returned, max chunk size,
  relevance threshold.
- **Caching.** Cache repeated prompts and repeated retrieval results.
- **Model choice.** Use a smaller model for simple queries; reserve
  the large one for complex tasks.
- **Graceful degradation.** Under load, serve a simpler response
  rather than failing entirely.

## 7. Detection Controls (Defensive)

- **Log token usage per request and per user.** The first signal of
  a DoS attack is an anomalous token usage pattern.
- **Alert on cost spikes.** Compare hourly cost to the rolling average.
- **Alert on request rate spikes per user.** One account sending
  1000x the normal request volume.
- **Detect recursive patterns.** The same prompt or near-duplicate
  repeated many times.
- **Detect agent loops.** The same tool call repeated within a task.
- **Monitor latency.** Sudden increase in p95 latency indicates
  context flooding.

## 8. Verification

- **Token cap test.** Request max length output and confirm the
  cap is enforced.
- **Rate limit test.** Send 100 quick requests and confirm 429 is
  returned before the quota is exhausted.
- **Agent loop test.** Send a prompt that could loop and confirm the
  circuit breaker stops it.
- **RAG explosion test.** Query that matches everything and confirm
  the retrieval cap limits the result.
- **Cost alert test.** Artificially generate high cost and confirm
  the alert fires.

## 9. AI-Specific Considerations

- **Token cost is asymmetric.** A tiny input can generate a huge
  output. The attacker pays little; the operator pays a lot.
- **Latency is user-visible.** Even a partial DoS degrades the
  experience for all users.
- **Agents change the equation.** A loop is not just more tokens;
  it is more tool calls, more database writes, more side effects.
- **Context limits are not abuse protection.** The model will accept
  a large input and just truncate it after paying to process it.
- **Model DoS can be a side effect, not a target.** A prompt invasion
  that causes a loop is both an integrity and an availability issue.

## 10. Production Notes

- **Cost is a security metric.** Treat cost alerts with the same
  urgency as latency alerts.
- **Quotas must be per-user.** A global quota means one abusive
  user blocks everyone else.
- **Retry logic is an attack surface.** Automatic retries on
  timeout can amplify a DoS.
- **Tool budgets are not optional.** Every agent needs a max
  tool-call count and a clock time limit.
- **Document the cost model.** Operators should know the worst-case
  cost of a single request.

## 11. References

- OWASP LLM04: Model Denial of Service - https://genai.owasp.org/llmrisk/llm04-model-denial-of-service/
- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- NIST AI RMF - https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATLAS - https://atlas.mitre.org/
