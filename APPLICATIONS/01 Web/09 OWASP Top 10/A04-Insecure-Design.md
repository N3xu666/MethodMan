# A04:2021 - Insecure Design

> OWASP Top 10:2021 - A04
> OWASP Top 10:2025 - A06 (renumbered; see `2021-vs-2025.md`)
>
> Risks related to design and architectural flaws. Unlike implementation
> bugs, a secure implementation of an insecure design is still insecure.
> Insecure design cannot be fixed by better coding - it requires changes
> to the design itself, the requirements, and the threat model.

---

## Table of Contents

- [1. What Insecure Design Is](#1-what-insecure-design-is)
- [2. Common Design Flaws](#2-common-design-flaws)
- [3. Threat Modeling (AppSec)](#3-threat-modeling-appsec)
- [4. Secure Design Principles](#4-secure-design-principles)
- [5. Detection and Testing Workflow (Pentest)](#5-detection-and-testing-workflow-pentest)
- [6. Exploitation Recipes (Pentest)](#6-exploitation-recipes-pentest)
- [7. Risk Context (AppSec)](#7-risk-context-appsec)
- [8. Root Causes (AppSec)](#8-root-causes-appsec)
- [9. Preventive Controls (AppSec)](#9-preventive-controls-appsec)
- [10. Detection Controls (AppSec)](#10-detection-controls-appsec)
- [11. Verification (AppSec)](#11-verification-appsec)
- [12. OSCP Notes](#12-oscp-notes)
- [13. Production Notes](#13-production-notes)
- [14. References](#14-references)

---

## 1. What Insecure Design Is

Insecure design is a category of weakness that originates in the
design phase, not in the implementation phase. The code may be
correct, the libraries up to date, the input validated - and the
application is still vulnerable because the design itself allowed a
misuse that no amount of coding can prevent.

**Example of the distinction:**

- *Implementation bug:* the password reset endpoint checks the token
  but forgets to check expiration. Fixed by adding one `if` statement.
- *Insecure design:* the password reset endpoint identifies the user
  by email alone, with no secondary proof of ownership. No amount of
  validation fixes this - the design must change to require a token,
  a security question, or an out-of-band verification.

**Why this matters:**

- Insecure design cannot be found by scanners. Scanners test
  implementation; design flaws require reading the requirements,
  understanding the intended workflow, and reasoning about abuse
  cases.
- Insecure design cannot be patched. It can only be redesigned. The
  cost of fixing a design flaw after release is orders of magnitude
  higher than fixing it on a whiteboard.
- Insecure design is the root of many other OWASP categories. A
  missing rate limit (A04) enables credential stuffing (A07). A
  business logic flaw (A04) enables unauthorized access (A01).

**What this file covers:**

- The pentest track: how to find design flaws in a live application
  (business logic, race conditions, rate limiting, workflow bypass).
- The AppSec track: how to prevent them at design time (threat
  modeling, secure design principles, design review, security
  requirements).

---

## 2. Common Design Flaws

Insecure design is not a single bug class. It is a family of
architectural mistakes. The most common ones in web applications:

### 2.1 Business Logic Flaws

The application implements a workflow that can be manipulated to
achieve a result the designer did not intend.

**Examples:**

- Price manipulation: the client sends the price as a form field,
  and the server trusts it. Change `price=100` to `price=1`.
- Coupon abuse: a coupon is applied twice because the server does
  not track usage. Apply, remove, apply again.
- Quantity manipulation: negative quantity in a cart results in a
  credit instead of a charge.
- Workflow bypass: the checkout has 5 steps, but step 5 does not
  verify that steps 1-4 were completed. Jump directly to step 5.
- Currency confusion: prices in USD, payment in a weaker currency,
  no exchange-rate check on the server.

**Real-world pattern (conceptual):**

An e-commerce site allows a gift card to be applied to an order.
The server validates the gift card code and deducts the balance.
But it does not lock the card during the transaction. An attacker
submits the same card in 10 parallel requests. All 10 succeed, and
the card is overdrawn. The balance check and the balance deduction
are two separate operations (TOCTOU - see 2.2).

### 2.2 Race Conditions (TOCTOU)

Time-of-Check to Time-of-Use: the application checks a condition,
then acts on it, and between the check and the act, the condition
changes.

**Examples:**

- Coupon reuse: check balance, use coupon, deduct balance. Two
  parallel requests both pass the check before either deducts.
- Vote manipulation: check if user has voted, record vote. Two
  parallel requests both pass the check.
- Account creation: check if username exists, create user. Two
  parallel requests both pass, one wins with an unexpected state.
- Balance withdrawal: check balance >= amount, deduct amount. Two
  parallel requests both pass, account goes negative.
- File upload: check extension, save file. Race the check with a
  symlink swap.

**How to detect:** send N parallel requests for the same action and
look for N successes where only one was expected.

### 2.3 Missing or Insufficient Rate Limiting

The application allows an action to be repeated without limit,
enabling enumeration, brute force, or resource exhaustion.

**Examples:**

- Login endpoint with no rate limit: credential stuffing at scale.
- Password reset with no rate limit: email enumeration + spam.
- OTP verification with no rate limit: brute force a 6-digit code.
- API endpoint with no rate limit: scrape the entire database.
- Search or filter with no rate limit: DoS via expensive queries.

**Design-level question:** what is the *intended* rate of this
action? A login is expected once per session. A password reset is
expected rarely. The design should state this; the implementation
should enforce it.

### 2.4 Trust Boundary Violations

The application trusts data from a source that should not be
trusted, or performs an action that crosses a trust boundary
without validation.

**Examples:**

- Trusting client-side validation: the price, role, or quantity is
  validated in JavaScript and sent to the server, which trusts it.
- Trusting an internal header: `X-Forwarded-For: 127.0.0.1` is
  trusted as proof of internal origin.
- Trusting a JWT claim: `role: admin` in a JWT that is not
  signature-verified.
- Implicit trust between microservices: service A calls service B
  with no authentication, assuming the network is safe.

### 2.5 Insufficient Separation of Duties

A single user or role can perform an action that should require
two independent actors (maker-checker, four-eyes principle).

**Examples:**

- A user can both create a payment and approve it.
- A user can both request a refund and approve it.
- An admin can change their own audit log.
- A developer can deploy to production without review.

### 2.6 Fail-Open Behavior

When a component fails, the system defaults to allowing the
action, instead of denying it.

**Examples:**

- Authentication service is down: the application allows access
  instead of returning 503.
- Policy engine is unreachable: requests are allowed by default.
- Signature verification library throws an exception: the handler
  catches it and continues as if the signature was valid.

**Design principle:** fail closed. When in doubt, deny.

### 2.7 Unbounded Resource Consumption

The application accepts input that can cause disproportionate
resource use (memory, CPU, disk, network).

**Examples:**

- Image upload with no size limit: a 10 GB file exhausts disk.
- Regex with catastrophic backtracking: a short input freezes the
  CPU (ReDoS).
- Recursive API call with no depth limit: stack overflow.
- GraphQL query with no complexity limit: one query joins the
  entire database.

### 2.8 Predictable or Guessable Identifiers

The application uses identifiers that can be enumerated or
predicted, enabling unauthorized access (see also A01).

**Examples:**

- Sequential order IDs: `/orders/1001`, `/orders/1002` - enumerate
  all orders.
- Timestamp-based tokens: password reset token is the current Unix
  time.
- Short random tokens: 4-digit OTP is brute-forced in minutes.
- Weak UUIDs: UUID v1 leaks MAC address and timestamp.

### 2.9 Missing Anti-Automation

The design assumes a human user, but the API can be called by a
script. No CAPTCHA, no proof-of-work, no behavioral analysis.

**Examples:**

- Registration form with no CAPTCHA: mass account creation.
- Comment form with no anti-automation: spam.
- API with no bot detection: scraping, credential stuffing,
  inventory hoarding.

---

## 3. Threat Modeling (AppSec)

Threat modeling is the structured process of identifying what can go
wrong in a system, before it is built. It is the primary preventive
control for A04. There is no single correct method - the goal is to
ask the right questions early.

**The four questions (Adam Shostack):**

1. What are we building? (data flow diagram)
2. What can go wrong? (threat enumeration)
3. What are we going to do about it? (mitigations)
4. Did we do a good job? (validation)

### 3.1 STRIDE

A mnemonic for threat categories, developed at Microsoft. For each
component and each data flow in the diagram, ask these six questions:

| Letter | Threat | Violates | Example |
|--------|--------|----------|---------|
| S | Spoofing | Authentication | Attacker impersonates a user |
| T | Tampering | Integrity | Attacker modifies a request in transit |
| R | Repudiation | Non-repudiation | User denies performing an action |
| I | Information disclosure | Confidentiality | Data leaks to unauthorized party |
| D | Denial of service | Availability | Service is overwhelmed |
| E | Elevation of privilege | Authorization | User gains admin rights |

**How to use it:** draw the data flow diagram. For each box (process,
data store) and each arrow (data flow), walk through the six letters.
Write down the threats that apply. Not every letter applies to every
element - that is expected.

### 3.2 DREAD

A scoring model for ranking threats, also from Microsoft. For each
identified threat, assign a score 1-10 on five axes:

| Letter | Axis | Question |
|--------|------|----------|
| D | Damage | How bad is the impact? |
| R | Reproducibility | How easy is it to reproduce? |
| E | Exploitability | How much skill is required? |
| A | Affected users | How many users are impacted? |
| D | Discoverability | How easy is it to find? |

Average the five scores. Higher = higher priority. DREAD is
controversial (subjective scoring), but useful for triage when you
have more threats than time.

**Modern alternatives:** CVSS for vulnerabilities, FAIR for risk
quantification. DREAD is a lightweight starting point.

### 3.3 Attack Trees

A tree where the root is the attacker's goal, and each branch is a
way to achieve it. Leaves are concrete actions.

**Example: goal = "read another user's order":**

```text
read another user's order
+-- guess sequential order ID (IDOR)
|   +-- enumerate /orders/1001..9999
|   +-- no rate limit on the endpoint
+-- steal a session token
|   +-- XSS in the order page
|   +-- session fixation
+-- call the API directly
    +-- no authorization check on /api/orders/:id
    +-- JWT not verified
```

Attack trees make design flaws visible: each leaf is either
"prevented" or "not prevented" in the design. If a leaf has no
control, that is a finding.

### 3.4 Data Flow Diagrams (DFD)

The input to STRIDE and attack trees. A DFD shows:

- **External entities** (users, external systems).
- **Processes** (services, functions).
- **Data stores** (databases, files, caches).
- **Data flows** (arrows between the above).
- **Trust boundaries** (dashed lines: where data crosses from one
  trust level to another).

Trust boundaries are where most design flaws live. Every arrow that
crosses a boundary needs validation, authentication, and
authorization.

### 3.5 When to Threat Model

- **New feature design:** before writing code.
- **Architecture change:** before merging the design doc.
- **New integration:** before connecting to a third party.
- **Incident post-mortem:** to find the design gap that allowed it.

Threat modeling is not a one-time event. It is repeated whenever
the design changes.

---

## 4. Secure Design Principles

These are the principles that, when applied at design time, prevent
the flaws in section 2. They are not new - most come from Saltzer
and Schroeder (1975) and are still the foundation of secure
architecture.

### 4.1 Least Privilege

Every user, process, and service should have the minimum privileges
needed to perform its function.

- The web server should not run as root.
- The database user for the web app should not have DROP TABLE.
- The microservice should not have access to all other services.
- The support agent should not see full credit card numbers.

**Design question:** what is the minimum this component needs?

### 4.2 Fail Securely (Fail Closed)

When a check fails or a component is unavailable, deny access.
Never default to allow.

- Auth service down -> 503, not "allow through".
- Policy engine unreachable -> deny, not "allow by default".
- Signature verification throws -> reject, not "accept anyway".
- Rate limiter fails -> reject, not "unlimited".

**Anti-pattern:** `try { check(); } catch { /* ignore */ }` - this
is fail-open.

### 4.3 Defense in Depth

Do not rely on a single control. Layer them.

- Authentication + authorization + audit log, not just
  authentication.
- Input validation on client + server + database constraint.
- WAF + application-level validation + output encoding.

**Design question:** if this control fails, what is the next one?

### 4.4 Separation of Duties

Critical actions require more than one actor. No single user can
complete a high-risk workflow alone.

- Payment creation and payment approval are separate roles.
- Code author and code reviewer are separate people.
- Deployment approver is not the developer who wrote the code.

**Design question:** can one compromised account complete this
workflow?

### 4.5 Economy of Mechanism

Keep the design simple. Complexity is the enemy of security.

- Fewer components = fewer trust boundaries.
- Fewer code paths = fewer places for a check to be missing.
- Fewer features = smaller attack surface.

**Design question:** can this be simpler without losing function?

### 4.6 Complete Mediation

Every access to every resource must be checked, every time. No
caching of authorization decisions across users or sessions.

- Check authorization on every request, not just at login.
- Re-check after privilege changes.
- Do not cache "is admin" for the session lifetime.

### 4.7 Open Design

Security should not depend on the secrecy of the design. Assume the
attacker knows the architecture. Assume the source code will leak.
Security comes from keys, not from obscurity.

### 4.8 Psychological Acceptability

The security mechanism should be usable. If users find it too
difficult, they will bypass it.

- Passwords that are impossible to remember -> written on sticky
  notes.
- MFA that breaks every week -> users disable it.
- Overly complex approval workflow -> users share accounts.

**Design question:** will real users actually follow this?

### 4.9 Least Astonishment

The system should behave as users expect. Surprises are where bugs
and design flaws hide.

- A GET request should not modify state.
- A "cancel" button should not charge the user.
- A "delete" action should not be reversible silently.

---

## 5. Detection and Testing Workflow (Pentest)

Finding design flaws is fundamentally different from finding
implementation bugs. There is no scanner, no payload list, no
fuzzing wordlist. The process is: understand the intended behavior,
then attempt to make the application do something else.

### 5.1 Understand the Intended Workflow

Before testing, map the application as the designer intended:

- Read the UI: what does each button do?
- Read the API docs (if available): what is each endpoint for?
- Read the JavaScript: what parameters does the client send?
- Identify trust boundaries: where does data cross from client to
  server, from server to database, from one service to another?

### 5.2 Business Logic Testing

For each workflow, ask:

- Can I skip a step? (send the request for step 3 without doing
  step 1 and 2).
- Can I repeat a step? (apply a coupon twice).
- Can I reverse the order? (cancel before ordering).
- Can I send a negative or zero value? (`quantity=-1`).
- Can I change a hidden field? (price, role, status).
- Can I use a different currency or unit? (USD vs EUR).
- Can I reuse a token or code? (one-time coupon, used twice).

### 5.3 Race Condition Testing

Send N parallel requests for the same action, where the design
expects one.

**Tools:**

- `curl` with `&` (simple, up to ~10 parallel).
- `xargs -P N` for larger parallelism.
- Burp Suite Turbo Intruder (dedicated race condition mode).
- Custom Python with `asyncio` + `aiohttp`.

**Example with curl:**

```bash
for i in {1..20}; do
  curl -s -X POST "https://target/api/redeem" \
    -H "Cookie: session=..." \
    -d "coupon=SAVE10" &
done
wait
```

Look for more than one "success" response. In Burp Suite, use
"Send group in parallel (single-packet attack)" for the most
reliable race testing.

**Example endpoints to test:**

- Coupon redemption
- Vote / like / upvote
- Account creation (username uniqueness)
- Password reset (token single-use)
- Balance transfer / withdrawal
- File upload (same filename twice)
- Friend request (mutual, race creates duplicate)

### 5.4 Rate Limiting Testing

For each endpoint, measure how many requests per time window are
accepted before the server blocks or throttles:

- Login: try 100 wrong passwords, count how many return
  "invalid credentials" before 429.
- Password reset: send 100 requests, count how many emails are sent.
- OTP: try 1000 6-digit codes, count how many are accepted.
- Search: send 1000 requests, measure latency drift.

**Bypass techniques (if rate limit is present):**

- Change `X-Forwarded-For` / `X-Real-IP` header per request.
- Use different `User-Agent` strings.
- Add trailing whitespace or case changes to username.
- Use Unicode confusables in the email field.
- Use IPv6 vs IPv4 addresses from the same host.

### 5.5 Workflow / State Machine Testing

If the application has explicit states (order: pending -> paid ->
shipped -> delivered), test:

- Can I jump to a later state? (set status=shipped directly).
- Can I go back? (refund after delivery, un-cancel an order).
- Can I be in two states at once? (paid and cancelled).
- Can I trigger a transition without the prerequisite action?

### 5.6 Identifiers and Enumeration

For each resource, check if the identifier is:

- Sequential (1001, 1002, ...).
- Predictable (timestamp, hash of a known value).
- Short (4-6 digits, brute-forceable).
- Reusable across tenants.

**Test:** try the ID +/- 1, ID of another known user, ID = 0, ID =
-1, very large ID. Watch for error messages that leak existence.

### 5.7 What You Cannot Test

Some design flaws are not visible from outside:

- Internal trust boundaries between microservices.
- Separation-of-duties rules that are not enforced in the UI.
- Fail-open behavior that only triggers when a component is down.
- Threat model gaps in code paths you cannot reach.

For these, the AppSec track (design review, threat model) is the
only way to find them.

---

## 6. Exploitation Recipes (Pentest)

Design flaws do not have standard payloads. What follows are
recipes: concrete sequences for the most common flaw classes.

### 6.1 Coupon / Gift Card Double-Spend

**Flaw:** the server checks the coupon balance, then deducts it,
with a gap between the two operations. No lock, no atomic update.

**Recipe:**

1. Add the coupon to a cart, reach the payment page.
2. Capture the "apply coupon" request in Burp.
3. Send the request 20 times in parallel (Turbo Intruder or
   "Send group in parallel").
4. If more than one succeeds, the coupon was applied multiple
   times.
5. Check the final balance: if it went below zero, the race is
   exploitable for unlimited credit.

### 6.2 Price Manipulation

**Flaw:** the client sends the price, the server trusts it.

**Recipe:**

1. Add an item to the cart, go to checkout.
2. In Burp, intercept the "place order" request.
3. Change `price=99.99` to `price=0.01`.
4. Forward. If the order is placed at the new price, the server
   does not validate against the catalog.

### 6.3 Workflow Bypass

**Flaw:** a later step does not verify that earlier steps were
completed.

**Recipe:**

1. Start the workflow (e.g. checkout step 1).
2. Capture the request for the final step (e.g. "confirm order").
3. Send the final-step request directly, without completing
   intermediate steps.
4. If the order is confirmed, the workflow is not enforced
   server-side.

### 6.4 Rate Limit Bypass via Header Rotation

**Flaw:** the rate limiter keys on `X-Forwarded-For`, which is
client-controlled.

**Recipe:**

1. Confirm the rate limit exists: send 100 requests, get 429.
2. Resend with `X-Forwarded-For: <random IP>` on each request.
3. If all succeed, the limit is keyed on a spoofable header.

### 6.5 Negative Quantity

**Flaw:** the cart accepts negative quantities, and the total is
computed arithmetically.

**Recipe:**

1. Add item A (price 100) with quantity 1.
2. Add item B (price 100) with quantity -1.
3. If the total is 0 instead of rejecting the negative quantity,
   you can combine items to reduce the price arbitrarily.

### 6.6 Password Reset Token Race

**Flaw:** the reset token is checked, then invalidated, with a gap.

**Recipe:**

1. Request a password reset for your own account, capture the
   token.
2. Send the "reset password" request 20 times in parallel with the
   same token, each with a different new password.
3. If more than one succeeds, the token was not single-use.

### 6.7 Account Enumeration via Timing

**Flaw:** the login endpoint responds faster for non-existent users
than for existing ones (or vice versa).

**Recipe:**

1. Send 100 login requests for known-existing usernames, measure
   average response time.
2. Send 100 requests for random usernames, measure average.
3. A consistent difference of >50 ms indicates a timing oracle.

**Note:** this overlaps with A07 (Identification and Authentication
Failures). The design flaw is the different code path; the
implementation leaks the timing.

---

## 7. Risk Context (AppSec)

**Why this is a top-10 category.** Insecure design is ranked A04
because it is the root cause behind many high-impact breaches that
cannot be explained by a single coding bug. When a breach is
described as "the attacker abused a legitimate feature", the
underlying cause is almost always a design flaw.

**Real-world pattern.** A typical insecure-design breach looks like
this:

1. A feature is built to be convenient: one-click export,
   shareable link, guest checkout.
2. The convenience removes a control that the design assumed was
   present (authentication, rate limit, ownership check).
3. The feature works as designed; the design is the flaw.
4. No scanner finds it, because nothing is "broken".

**Why scanners miss it.** Scanners test implementation. A design
flaw is not a deviation from the code's intent - the code does
exactly what the design says. Only a human who understands the
intended workflow can recognize that the workflow itself is unsafe.

**AppSec relevance.** A04 is the category where architecture review
and threat modeling pay off. A one-hour threat model before
building a feature can prevent a redesign that costs weeks.

---

## 8. Root Causes (AppSec)

Why do teams ship insecure designs? The reasons are structural,
not personal:

**1. No threat modeling in the design phase.** Teams jump from
requirements to code. The design is not questioned for abuse cases.

**2. Requirements are functional only.** "Users can reset their
password" is functional. "A password reset cannot be used to
enumerate accounts or take over another user's account" is a
security requirement. Without it, the design satisfies the
functional goal and misses the security one.

**3. Convenience over control.** The design prioritizes the happy
path: fastest checkout, fewest clicks, least friction. Security
controls are treated as friction and removed.

**4. No abuse-case review.** The design is reviewed for "does it
work?", not for "how can it be misused?".

**5. Missing security architects.** Design decisions are made by
product and engineering, without a security representative in the
room.

**6. No reference architecture.** Every team designs its own auth,
its own rate limiting, its own workflow engine. Inconsistency
means the weakest design sets the bar.

**7. Time pressure.** Design review is the first thing cut when
the deadline approaches.

---

## 9. Preventive Controls (AppSec)

These are the controls that prevent A04 at the design phase.

**Threat modeling as a required step.** Every new feature and
architecture change goes through a threat model (STRIDE or
equivalent). The output is a list of threats and the controls that
address them. No threat model, no merge.

**Security requirements alongside functional requirements.** For
every feature, write the security requirement next to the
functional one. "Users can reset password" pairs with "Password
reset cannot be used to enumerate accounts or take over another
user's account".

**Reference architectures.** Pre-approved design patterns for
common needs (authentication, rate limiting, payment, file upload).
Teams use the reference instead of designing from scratch.

**Design review with a security representative.** A security
engineer reviews the design doc before code is written. This is
the highest-leverage control in the list.

**Abuse-case workshops.** For each feature, ask "how would I abuse
this?". Write the answers down. Each answer is either a
mitigation or an accepted risk.

**Fail-closed by default.** Design every check to deny when it
cannot decide. Make "allow" the explicit choice, not the default.

**Centralized workflow engine.** Use one workflow engine for all
state machines. The engine enforces step order, and no team can
accidentally skip it.

**Atomic operations for balance-changing actions.** Use database
transactions, locks, or compare-and-swap for anything that
decrements a balance, consumes a token, or changes a counter.

---

## 10. Detection Controls (AppSec)

Design flaws are hard to prevent completely. Detection is the
second line.

**Log unusual workflow transitions.** An order that goes from
"created" to "shipped" without passing "paid" is a signal.

**Alert on parallel actions from the same user.** Twenty
"redeem coupon" requests in one second is not normal behavior.

**Alert on cross-tenant resource access.** In a multi-tenant
system, any access from tenant A to a resource of tenant B is a
signal (see also A01).

**Monitor negative or zero values in critical fields.** A price of
0 or a negative quantity in an order is worth a look.

**Rate-limit at the infrastructure layer, not only in the app.**
If the app-level rate limiter fails open, the infrastructure
layer (WAF, API gateway) still enforces a limit.

**Canary tokens and honeytokens.** Place fake coupons, fake
password reset tokens, or fake admin endpoints. Any use is
suspicious by definition.

---

## 11. Verification (AppSec)

How to prove the design controls actually work.

**Review the design doc for security requirements.** Every
functional requirement should have a paired security requirement.
Missing pairs are findings.

**Walk the threat model.** Re-run the STRIDE analysis on the
implemented system and compare to the design. Differences are
gaps between design and implementation.

**Test each state transition.** For every workflow, verify that
each transition requires the correct prerequisite. Automate this
as integration tests.

**Race condition tests in CI.** For critical operations (coupon
redeem, vote, balance change), include a test that sends N
parallel requests and asserts exactly one success. This catches
regressions when someone removes a lock.

**Rate limit tests in CI.** For login, password reset, OTP
verification, and any enumeration-prone endpoint, assert that the
limit is enforced. Include a test for the header-rotation bypass.

**ASVS mapping.** Relevant ASVS 4.0.3 chapters: V1 (Architecture,
Design and Threat Modeling), V11 (Business Logic), V13 (API and
Web Service).

**OWASP resources for verification:**

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG - Business Logic Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP Cheat Sheet - Business Logic Security: https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling

---

## 12. OSCP Notes

> [!IMPORTANT]
> OSCP report: for business logic flaws, screenshot the normal
> workflow and the manipulated request side by side. Show the
> parameter you changed and the server's response.

> [!IMPORTANT]
> OSCP report: for race conditions, screenshot the parallel
> requests and the server's responses. One success is expected;
> multiple successes prove the flaw.

Key patterns for OSCP:

- Business logic bugs are more common than they look. Always test
  the intended workflow end-to-end and try to skip steps.
- Race conditions on CTF boxes often appear as "vote twice",
  "redeem twice", or "withdraw twice".
- If a form has a hidden price, role, or status field, try changing
  it - it is a classic design flaw.
- On OSCP exam machines, design flaws are less common than
  implementation bugs. Do not spend too long if the machine is
  clearly a "known CVE" box.

---

## 13. Production Notes

- **Threat modeling is not optional.** If it is not enforced, it
  will not happen. Make it a gate in the design review process.
- **Design reviews are cheaper than redesigns.** One hour of review
  prevents weeks of rework. Make the ROI visible to product.
- **Security requirements are part of the definition of done.** A
  feature is not done until its security requirements are met.
- **Atomic operations for state changes.** Any design that changes
  a balance, consumes a token, or moves a workflow forward must be
  atomic. If it is two operations, it is a race condition.
- **Rate limiting belongs in the design, not in a middleware after
  thought.** Decide the intended rate for each action during
  design.
- **Fail closed.** Every check that can fail must default to deny.
- **Centralize the workflow engine.** One engine, one set of rules.
  No team-specific shortcuts.
- **Test abuse cases, not just happy paths.** The test suite should
  include at least one test per known abuse case.

---

## 14. References

**OWASP:**

- OWASP Top 10:2021 - A04 - https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP Top 10:2025 - A06 (renumbered) - https://owasp.org/Top10/2025/
- OWASP ASVS - https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG - Business Logic Testing - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP Cheat Sheet - Business Logic Security - https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
- OWASP Threat Modeling - https://owasp.org/www-community/Threat_Modeling
- OWASP Cheat Sheet - Threat Modeling - https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html

**Books and papers:**

- Adam Shostack, "Threat Modeling: Designing for Security" (2014).
- Saltzer and Schroeder, "The Protection of Information in Computer Systems" (1975) - the original secure design principles.

**Internal cross-references:**

- [A01 - Broken Access Control](./A01-Broken-Access-Control.md)
- [2021-vs-2025.md](./2021-vs-2025.md)
- [README.md](./README.md)

---

*File version: 2026-10-13 (pass 73, W3.2).*
