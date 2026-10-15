# Agents and MCP

Reference material for autonomous LLM agents and the Model Context
Protocol (MCP) that connects them to tools, data, and other agents.
Four files, each in the two-track format (Offensive / Defensive).

## Why This Exists

An agent is an LLM that can take actions: call tools, read and write
files, send messages, run code, and delegate to other agents. MCP is
the emerging standard for exposing those capabilities to a model in a
uniform way. Both change the threat model fundamentally: an injection
is no longer a bad answer, it is a tool call with the agent's
credentials. This subcategory documents the agent and MCP attack
surface, the exploitation recipes, and the controls that keep an agent
inside its intended authority.

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
| 01 | Agent Fundamentals | [01 Agent-Fundamentals.md](./01%20Agent-Fundamentals.md) | done |
| 02 | MCP Protocol and Attacks | [02 MCP-Protocol.md](./02%20MCP-Protocol.md) | done |
| 03 | Agent Injection | [03 Agent-Injection.md](./03%20Agent-Injection.md) | done |
| 04 | Agent Defense | [04 Agent-Defense.md](./04%20Agent-Defense.md) | done |

## Scope

- 01 Agent-Fundamentals: agent loop, planning, memory, tool calling,
  multi-agent topologies, MCP basics.
- 02 MCP-Protocol: MCP servers, transports (stdio, SSE, streamable
  HTTP), tool/resource/prompt primitives, confused deputy, server
  spoofing, supply chain.
- 03 Agent-Injection: tool-call injection, goal hijacking, memory
  poisoning, multi-agent propagation, confused-deputy chains.
- 04 Agent-Defense: tool allow-lists, per-tool authorization, human
  in the loop for high-impact actions, sandboxing, audit and replay.

## References

- Model Context Protocol specification: https://modelcontextprotocol.io/
- ReAct: Synergizing Reasoning and Acting in Language Models (Yao et al., 2022): https://arxiv.org/abs/2210.03629
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Authorized Use Only

For authorized security testing and educational purposes only.
See SECURITY.md in the repository root.
