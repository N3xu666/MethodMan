# OWASP API Security Top 10 (2023)

The OWASP API Security Top 10 is a separate list from the OWASP Web Top 10. The threat model is different: no browser, no session cookies by default, machine clients with long-lived tokens, and authorization decisions that depend on object-level ownership rather than URL paths.

This file is the coverage map for the API category. Every category below links to the file in this directory that covers it.

---

## The 2023 categories

| # | Category | Primary file | Supporting files |
|---|----------|-------------|------------------|
| API1 | Broken Object Level Authorization | 02 REST.md | 08 Vulnerabilities/IDOR.md, 07 Authentication.md |
| API2 | Broken Authentication | 07 Authentication.md | 02 REST.md, 09 API-Gateway.md |
| API3 | Broken Object Property Level Authorization | 02 REST.md | 08 Vulnerabilities/Mass-Assignment.md |
| API4 | Unrestricted Resource Consumption | 08 Rate-Limiting.md | 03 GraphQL.md (batching, depth) |
| API5 | Broken Function Level Authorization | 02 REST.md | 05 API-Gateway.md |
| API6 | Unrestricted Access to Sensitive Business Flows | 08 Rate-Limiting.md | 02 REST.md |
| API7 | Server Side Request Forgery | 08 Vulnerabilities/SSRF.md | 02 REST.md, 06 SOAP.md |
| API8 | Security Misconfiguration | 05 API-Gateway.md | 03 GraphQL.md (introspection), 04 gRPC.md (reflection) |
| API9 | Improper Inventory Management | 05 API-Gateway.md | 04 gRPC.md |
| API10 | Unsafe Consumption of APIs | 02 REST.md | 06 SOAP.md |

---

## API1 - Broken Object Level Authorization (BOLA)

The API receives an object identifier (numeric ID, UUID, slug) and returns the object without checking whether the caller owns it. Classic IDOR at the API layer.

Detection: enumerate identifiers across user boundaries, check whether the response differs from a 403/404.

Covered in: `02 REST.md` (recipe), `08 Vulnerabilities/IDOR.md` (general technique).

---

## API2 - Broken Authentication

Weak token generation, missing expiry, tokens in URLs, no rate limit on login, JWT algorithm confusion, OAuth2 misconfiguration.

Covered in: `07 Authentication.md` (JWT, OAuth2, API keys, mTLS), `02 REST.md` (login enumeration), `09 API-Gateway.md` (gateway-level auth).

---

## API3 - Broken Object Property Level Authorization

Also known as mass assignment (too many properties accepted on write) and excessive data exposure (too many properties returned on read).

Detection: send extra fields in a PATCH/PUT and check whether they are persisted. Request an object and check whether internal fields (role, is_admin, password_hash) are returned.

Covered in: `02 REST.md`, `08 Vulnerabilities/Mass-Assignment.md`.

---

## API4 - Unrestricted Resource Consumption

No rate limit, no pagination limit, no query depth limit, no execution timeout. Leads to DoS, cost amplification (cloud billing), and brute-force enablers.

Covered in: `08 Rate-Limiting.md` (bypass techniques), `03 GraphQL.md` (batching and depth attacks).

---

## API5 - Broken Function Level Authorization

The endpoint is hidden from the UI (admin panel, internal route) but reachable directly. Verb tampering (GET -> POST -> DELETE) can expose methods the developer forgot to protect.

Covered in: `02 REST.md` (verb tampering), `05 API-Gateway.md` (route protection).

---

## API6 - Unrestricted Access to Sensitive Business Flows

A legitimate endpoint is abused at scale: mass account creation, coupon reuse, ticket scalping, OTP brute force. Not a code bug - a business logic gap.

Covered in: `08 Rate-Limiting.md`, `02 REST.md`.

---

## API7 - Server Side Request Forgery

The API fetches a URL provided by the client (webhook callback, image import, PDF generator) without validating the destination.

Covered in: `08 Vulnerabilities/SSRF.md` (general technique), `02 REST.md` (API-specific surface), `06 SOAP.md` (XXE-based SSRF).

---

## API8 - Security Misconfiguration

CORS wildcard, missing HTTPS enforcement, verbose error messages, debug endpoints, introspection enabled in production, gRPC reflection enabled in production.

Covered in: `05 API-Gateway.md`, `03 GraphQL.md`, `04 gRPC.md`.

---

## API9 - Improper Inventory Management

Old API versions still reachable (/v1/ when /v3/ is current), undocumented endpoints, shadow APIs, deprecated endpoints with weaker auth.

Detection: fuzz version prefixes, check the OpenAPI/Swagger spec for endpoints not linked from the UI.

Covered in: `05 API-Gateway.md`, `04 gRPC.md`.

---

## API10 - Unsafe Consumption of APIs

The application trusts a third-party API response without validation. A compromised or spoofed upstream can inject data that reaches a dangerous sink (SQL, template, shell).

Covered in: `02 REST.md`, `06 SOAP.md`.

---

## Relationship to OWASP Web Top 10

The Web Top 10 and the API Top 10 overlap in primitives (injection, authn, authz, SSRF) but differ in emphasis:

- Web Top 10 leads with A01 Broken Access Control (broad), API Top 10 splits it into API1 (object), API3 (property), API5 (function).
- Web Top 10 has A03 Injection (SQLi, XSS, etc.), API Top 10 does not have a dedicated injection category - injection at the API layer is covered by the underlying vulnerability (SQLi, NoSQLi, SSTI) and usually manifests through BOLA-adjacent endpoints.
- Web Top 10 has A07 Identification and Authentication Failures, API Top 10 has API2 Broken Authentication (narrower, focused on token mechanics).

The API category references the Web category where the underlying primitive is the same. See `../01 Web/08 Vulnerabilities/`.

---

## References

- OWASP API Security Top 10:2023 - https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API Security Top 10:2019 (previous edition) - https://owasp.org/API-Security/editions/2019/en/0x11-t10/
- OWASP API Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/API_Security_Cheat_Sheet.html
- PortSwigger API testing - https://portswigger.net/web-security/api-testing