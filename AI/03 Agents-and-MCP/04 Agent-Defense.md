# Agent Defense

Agent defense is the set of controls that keep an autonomous LLM
inside its intended authority. The three attack files in this
subcategory - Agent Fundamentals, MCP Protocol, and Agent Injection -
all describe ways to steer the agent. This file describes the
controls that bound it: least privilege on tools, per-call
authorization, human-in-the-loop for high-impact actions, sandboxing,
memory isolation, and audit. The controls are layered, because no
single control is sufficient against a steerable model.

## 1. Overview

An agent has four security layers, each of which must hold:

- **Identity.** The agent runs as its own identity, not the user's,
  and not as an all-powerful service account.
- **Authorization.** Every tool call is authorized against the agent's
  policy and the user's identity, at call time.
- **Sandbox.** The tool runs in an isolated environment with only the
  resources it needs.
- **Audit.** Every step is logged: goal, observation, thought,
  action, result, identity, timestamp.

If any of these is missing, an injection that reaches the agent
becomes an action with the agent's full authority. The goal of agent
defense is to make that authority small, scoped, and observable.

## 2. Identity and Least Privilege

**2.1 Separate identity per agent.** Each agent gets its own
credentials. Do not reuse the user's session token. Do not share one
credential across multiple agents.

**2.2 Scope credentials to the task.** An agent that reads tickets
does not need write access. An agent that queries a database does not
need DDL. Apply the same least-privilege rules you would apply to a
microservice.

**2.3 Short-lived credentials.** Rotate tokens frequently. An
injection that steals a token should have a narrow window of use.

**2.4 Separate credentials per tool.** A compromise of one tool does
not give access to another. Tools that touch different systems use
different identities.

**2.5 No ambient authority.** The agent should not inherit the
deployer's or the user's credentials via environment variables or
metadata endpoints.

## 3. Per-Call Authorization

Authorization must be enforced on every tool call, not only at agent
startup.

- **Policy check.** Each call is evaluated against a policy: is this
  agent, for this user, allowed to call this tool with these
  arguments?
- **Argument validation.** The schema is not enough. Check that
  arguments are within the intended scope: file paths inside the
  sandbox, URLs on an allow-list, recipient addresses on a
  corporate domain.
- **Rate limiting.** Per tool, per agent, per user.
- **Confirmation for high impact.** Code execution, email, file
  writes outside the sandbox, financial actions: require an explicit
  human confirmation that shows the arguments.
- **Deny by default.** New tools, new arguments, new destinations:
  deny until explicitly allowed.

## 4. Human in the Loop

For high-impact actions, the agent should propose and the human
should approve. This is the last line of defense.

**4.1 What counts as high impact.**

- Code execution (shell, eval, subprocess).
- Email or messaging to external addresses.
- File writes, especially outside a sandbox directory.
- Network requests to non-allow-listed hosts.
- Financial or account-changing actions.
- Actions on behalf of the user that the user did not ask for.

**4.2 How to present the request.** Show the tool name, the full
arguments, the user goal the action is supposed to serve, and the
result of the policy check. Do not hide details behind a "proceed"
button.

**4.3 When to interrupt.** Before the action, not after. Once the
action executes, the damage is done.

**4.4 When not to interrupt.** For read-only, scoped, low-risk
actions, an approval prompt on every call is noise. Reserve the
interruption for actions that can change state or leave the trust
boundary.

## 5. Sandboxing

The tool runs in an environment that limits what it can reach.

**5.1 Filesystem.** A filesystem tool sees only a designated
directory. Path traversal is blocked by the sandbox, not by argument
validation alone.

**5.2 Network.** Network tools reach only an allow-list of hosts.
The sandbox enforces the allow-list at the network layer, not in the
tool.

**5.3 Process.** Code-execution tools run in a container or VM with
no access to the host, no access to the agent's credentials, and no
persistent storage except a designated scratch directory.

**5.4 Memory.** Agent memory is per-user and per-session by default.
Shared memory requires an explicit policy and an audit trail.

## 6. Input and Output Filtering

**6.1 Input filtering on non-user content.** Tool results, memory
entries, and inter-agent messages are scanned for instruction-like
phrases, hidden text, HTML comments, and encoded payloads before they
enter the context.

**6.2 Output filtering.** The agent's answer and its tool-call
arguments are scanned for:

- Known secrets (canary tokens, credentials, internal hostnames).
- URLs and email addresses not on the allow-list.
- Base64 or hex blobs that were not in the user's input.
- Contact addresses not present in the original request.

**6.3 Structured context.** Wrap retrieved and tool content in a
format the model is trained to treat as data (XML tags, JSON fields).
State explicitly in the system prompt that only the system prompt
carries instructions.

**6.4 Canary instructions.** Plant benign canary instructions in
tool results, memory, and inter-agent messages. If the agent ever
follows a canary, the filtering has failed.

## 7. Logging and Audit

- **Every step.** Observation, thought, action, result, identity,
  timestamp, model version, prompt version.
- **Every tool call.** Tool name, arguments, result, policy decision.
- **Every memory read and write.** Key, value, source, session.
- **Every inter-agent message.** Sender, receiver, content, schema
  validation result.
- **Every approval.** Who approved what, when, with what displayed
  context.

The audit trail must be append-only and stored outside the agent's
reach. An agent with a log-deletion tool can be injected to use it.

## 8. Verification

Minimum test suite for an agent deployment:

- **Tool allow-list.** The agent cannot call a tool that is not in
  its declared set.
- **Identity isolation.** Tool calls are authorized against the
  agent's identity, not the user's.
- **Policy enforcement.** A call that violates policy is denied,
  with the reason logged.
- **Argument validation.** Path traversal, off-allow-list URLs, and
  external email addresses are rejected.
- **Canary injection.** A canary instruction in each input channel
  (tool result, memory, inter-agent message) does not cause a tool
  call.
- **High-impact gating.** Email, code execution, financial actions
  require human approval.
- **Loop bounds.** A runaway injection terminates within the
  configured iteration and token budget.
- **Memory isolation.** A poisoned entry for user A does not affect
  user B.
- **Audit completeness.** Every step is logged with all required
  fields.

## 9. AI-Specific Considerations

- The model is not a security boundary. Treat its output as
  untrusted until filtered.
- System prompt hardening helps but is not sufficient. A leaked
  secret is leaked regardless of what the model says.
- Model updates change behavior. Re-run the test suite after every
  model change.
- Different agent frameworks implement authorization differently.
  Verify the framework's behavior, do not assume.
- Multi-agent systems require per-agent identity and per-message
  validation. Shared trust is a single point of failure.

## 10. Production Notes

- Version the agent prompt, tool set, and policy together. A change
  in any one can break the defenses.
- Rotate credentials on a fixed schedule, and immediately after any
  suspected injection.
- Rebuild the agent's environment from a known-good image on a
  schedule. This removes undetected persistence.
- Keep a playbook for injection incidents: how to identify the
  injected source, how to remove it, how to replay the audit log.
- Review the tool set on a schedule. Tools accumulate; each one is
  a new action the agent can take on behalf of an attacker.

## 11. References

- Not what you've signed up for (Greshake et al., 2023) - https://arxiv.org/abs/2302.12173
- Model Context Protocol specification - https://modelcontextprotocol.io/
- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS - https://atlas.mitre.org/
- NIST AI Risk Management Framework - https://www.nist.gov/itl/ai-risk-management-framework
