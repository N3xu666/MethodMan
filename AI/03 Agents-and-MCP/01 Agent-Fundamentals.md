# Agent Fundamentals

An LLM agent is a model wrapped in a loop that lets it take actions:
call tools, read and write state, and decide what to do next based on
the result. This file covers the agent loop, planning, memory, tool
calling, and multi-agent topologies. It is the foundation for the
attack and defense files that follow.

## 1. Overview

A minimal agent loop:

1. **Observe.** Receive the user goal and the current state.
2. **Think.** The model produces a plan or a next action.
3. **Act.** The action is executed (tool call, code run, API request).
4. **Observe result.** The result is appended to the state.
5. **Repeat** until the model decides the goal is met or a budget is
   exhausted.

The loop is what makes an agent useful and what makes it dangerous.
Every iteration is another chance for the model to take an action,
and every action runs with the agent's credentials. An injection that
would be a harmless bad answer in a chatbot becomes a tool call with
real side effects in an agent.

MCP (Model Context Protocol) is the standard that defines how the
model discovers and calls tools. It is covered in 02 MCP-Protocol.md.

## 2. Agent Architectures

**2.1 ReAct.** Reason + Act. The model alternates between a reasoning
step and an action step. Simple, widely used, easy to inject because
the reasoning step can be steered by injected context.

**2.2 Plan-and-execute.** The model first produces a full plan, then
executes it step by step. Less flexible but easier to audit: the plan
is a discrete artifact that can be reviewed before execution.

**2.3 Reflexion / self-critique.** The model critiques its own output
and retries. Adds a feedback loop that an attacker can exploit by
poisoning the critique step.

**2.4 Multi-agent.** Two or more agents with different roles:
planner, executor, critic, researcher. Communication is usually
through a shared message bus or a delegation tool. Injection
propagates between agents (see 03 Agent-Injection.md).

**2.5 Hierarchical.** A manager agent delegates to sub-agents. The
manager's instructions become the sub-agent's system prompt. An
attacker who controls the manager's context controls every sub-agent.

## 3. Memory

Agents use several kinds of memory:

- **Working memory.** The current context window: messages, tool
  results, scratchpad.
- **Episodic memory.** Past interactions, retrieved by similarity.
  Often a vector store (see 02 RAG-and-Embeddings).
- **Semantic memory.** Facts about the world or the user, stored as
  structured data or embeddings.
- **Procedural memory.** Learned skills, tool definitions, prompts.

Memory is a persistence layer. Poisoned memory survives across
sessions and across users if the memory store is shared. It is one of
the highest-impact injection targets.

## 4. Tool Calling

A tool is a function the model can invoke. The model is given a
schema (name, description, parameters) and produces a structured call.

Example tool schema:

    {
      "name": "send_email",
      "description": "Send an email to a recipient.",
      "parameters": {
        "to": {"type": "string"},
        "subject": {"type": "string"},
        "body": {"type": "string"}
      }
    }

The model's output for a call:

    {"tool": "send_email",
     "arguments": {"to": "user@example.com",
                   "subject": "Report",
                   "body": "..."}}

The orchestrator validates the call against the schema and executes
it. The validation is the security boundary: a schema that allows
arbitrary strings in a `to` field allows the injection to send mail
anywhere.

**4.1 Tool categories and risk.**

- **Read-only, scoped.** Search a specific index, read a specific
  file. Low risk.
- **Read-only, broad.** Read any file, browse any URL. Medium risk:
  exfiltration channel.
- **Write, scoped.** Append to a specific log, write to a specific
  table. Medium risk: integrity.
- **Write, broad.** Send email, post to any URL, run code. High risk:
  the agent becomes a general-purpose attacker tool.

The first defense is to keep the tool set as small and as scoped as
the task allows.

## 5. MCP Basics

MCP (Model Context Protocol) standardizes how a model discovers and
uses external capabilities. Three primitives:

- **Tools.** Functions the model can call. Same as tool calling above.
- **Resources.** Data the model can read (files, database rows, API
  responses). Read-only by convention.
- **Prompts.** Reusable prompt templates exposed by the server.

MCP servers expose these primitives over a transport. Common
transports:

- **stdio.** The server runs as a subprocess of the client. Trusted
  by convention, dangerous if the server is not vetted.
- **SSE / Streamable HTTP.** The server runs remotely. Must be
  authenticated and authorized.

MCP is covered in detail in 02 MCP-Protocol.md.

## 6. Common Attack Vectors

High-level list; each is covered in its own file.

- **Tool-call injection.** Retrieved or user-supplied content
  instructs the model to call a tool with attacker-controlled
  arguments.
- **Goal hijacking.** The injected content replaces the user's goal
  with the attacker's goal.
- **Memory poisoning.** The attacker writes to episodic or semantic
  memory, influencing future sessions.
- **Multi-agent propagation.** A compromised sub-agent injects the
  manager, which injects other sub-agents.
- **Confused deputy.** The agent has more authority than the user,
  and the attacker uses the agent to reach resources the user cannot.
- **MCP supply chain.** A malicious or compromised MCP server
  presents tools that look benign but exfiltrate data or execute
  code.

## 7. Post-Exploitation

Once an agent is under attacker influence:

- **Action on target.** The agent executes tools with its own
  credentials - often more privileged than the user.
- **Persistence via memory.** Poisoned memory survives restarts and
  affects future sessions.
- **Lateral movement.** The agent can call other agents, other MCP
  servers, or internal APIs the user cannot reach directly.
- **Data exfiltration.** Through tool calls (HTTP requests, email,
  rendered images) or through the final answer.

## 8. Verification

- Test that the agent cannot call a tool that is not in its declared
  tool set.
- Test that every tool call is logged with the agent's identity, not
  the user's.
- Test that a canary instruction in retrieved content does not
  trigger a tool call.
- Test that the agent loop respects its iteration and token budget.
- Test that memory writes are attributed to the correct session and
  user, and that a poisoned entry does not affect other sessions.
- Test that inter-agent messages are validated against a schema, not
  passed through as free text.
## 9. Production Notes

- **Log every agent step.** Observation, thought, action, result.
  Without this, incident response is guesswork.
- **Bound the loop.** Max iterations, max tokens, max wall time.
  Prevents runaway agents and denial-of-service.
- **Snapshot and replay.** Store enough state to replay a session
  for forensics.
- **Separate agent identity from user identity.** Every tool call is
  authorized against the agent's own identity, not the user's.

## 10. AI-Specific Considerations

- The model's reasoning is not a security control. It can be steered
  by anything in its context.
- The same prompt can produce different behavior across model
  versions. Re-test after every model change.
- Multi-agent systems multiply the attack surface: each inter-agent
  message is an injection vector.
- Agent frameworks (LangChain, LlamaIndex, AutoGen, CrewAI) have
  their own bugs. Track their advisories.

## 11. References

- ReAct: Synergizing Reasoning and Acting in Language Models (Yao et al., 2022): https://arxiv.org/abs/2210.03629
- Model Context Protocol specification: https://modelcontextprotocol.io/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
