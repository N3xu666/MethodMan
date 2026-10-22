# Load Balancers and Proxies (Offensive and Defensive)

> [!CAUTION]
> This reference is for authorized penetration testing and defensive engineering only. Every technique here assumes written authorization and an isolated lab or a production change window approved by the asset owner.

## 1. Overview

A load balancer distributes traffic across a pool of backends; a proxy mediates traffic between a client and a server. Both sit between the user and the application, both terminate connections, and both are frequently the least-understood device on the path. That gap between "it just forwards traffic" and "it parses, rewrites, and makes routing decisions" is where the attack surface lives.

The families worth knowing:

- **L4 load balancer.** Distributes by IP and port (or by a hash of the five-tuple). HAProxy in TCP mode, F5 LTM in performance L4, AWS NLB, IPVS. Fast and mostly content-blind. Health checks and session persistence are the interesting parts.
- **L7 load balancer.** Parses HTTP, routes by host, path, header, or cookie. HAProxy in HTTP mode, NGINX, Envoy, F5 with an HTTP profile, AWS ALB. Powerful and parser-heavy: every rewrite rule, every header manipulation, and every routing decision is a place where the LB and the backend can disagree.
- **Reverse proxy.** Terminates TLS and fronts servers (NGINX, Apache mod_proxy, Envoy, Traefik). It is both a load balancer and a policy point: caching, compression, header injection, and access control all live here.
- **Forward proxy.** Mediates client egress (Squid, corporate web proxies). Frequently misconfigured as an open relay, and a classic SSRF pivot.
- **API gateway.** An L7 proxy with auth, rate limiting, and request transformation in front of APIs. Kong, Apigee, AWS API Gateway, Envoy-based gateways. Its job is to be the single policy point for the API, which makes it a single point of bypass if the policy is wrong.

The recurring theme: the load balancer and the backend must parse the request identically. Any difference between the two parsers is a potential request smuggling, cache poisoning, or access-control bypass.

## 2. Reconnaissance / Enumeration

Enumeration of a load balancer or proxy has one goal: understand the topology and the parsing behavior. Where the LB ends and the backend begins is exactly where the bugs are.

### Offensive

- **Detect the load balancer.** Multiple A records for one hostname, varying `Server` headers across requests, differing TLS certificates, and cookie names that hint at the vendor (BIGipServer, AWSALB, ARRAffinity, X-Msg). Round-robin DNS and anycast hide it further.
- **Fingerprint the product.** `Server` header, error page format, default health-check paths, and response to malformed requests. An HAProxy 503 page looks different from an NGINX 502 and from an F5 reset.
- **Map the backends.** Send a request with a unique marker (a random header value, a distinctive query param) and watch for it to reflect; differing `Date`, `ETag`, or `X-Backend` headers reveal multiple backends. A backend that occasionally appears is a direct-routable node worth scanning.
- **Find the origin.** If the LB fronts a cloud-hosted app, the origin may be directly reachable: historical DNS, certificate transparency, SPF records, and error messages often leak the real IP. A direct-to-origin request that bypasses the WAF is a finding.
- **Probe the parsing behavior.** Send the same logical request in several wire forms: `Content-Length` vs `Transfer-Encoding`, duplicate headers, absolute-form URI (`GET http://host/ HTTP/1.1`), and unusual methods. Differences in the response reveal parser disagreements.
- **Check the management and stats interfaces.** HAProxy stats page, NGINX `stub_status`, Envoy admin (`/stats`, `/config_dump`), and F5 management UI. Exposed admin on a load balancer is a high-value target.

### Defensive

- **Inventory every listener and its backend pool.** Every VIP should map to a documented service and a documented pool. A listener nobody owns is a finding.
- **Confirm the LB is the only path to the backend.** The backend must not be reachable directly from the internet. Verify with a scan from outside and a request to the origin IP.
- **Baseline the parser behavior.** Know how the LB normalizes headers so that an abnormal request in the logs is recognizable.

## 3. Common Attack Vectors

Load balancer and proxy attacks fall into three groups: parser differentials, origin exposure, and the proxy as a pivot.

**Parser differentials (the LB and backend disagree):**

- **HTTP request smuggling.** The classic `Content-Length` / `Transfer-Encoding` conflict between the front end and the back end. The front end sees one request, the back end sees two; the smuggled second request bypasses the front-end access control entirely.
- **HTTP/2 downgrade smuggling.** An HTTP/2 front end that converts to HTTP/1.1 for the back end can be tricked into treating header content as a new request (the H2.CL and H2.TE classes).
- **Header normalization bugs.** Underscore vs hyphen, duplicate `Content-Length`, whitespace before the colon, and obs-fold (line folding) are normalized differently by different parsers. Any differential is a bypass.
- **Cache poisoning via the LB.** A cache key that ignores a header the backend uses (for example `X-Forwarded-Host`) lets an attacker poison the cache for every user.
- **Path normalization.** `..%2f`, `%2e%2e/`, double slashes, and dot-segment removal differ between the LB's route match and the backend's file resolution. A path that routes to a public handler but resolves to a protected file is an access-control bypass.

**Origin exposure (bypass the LB entirely):**

- **Direct-to-origin access.** If the origin IP is discoverable and accepts traffic, the attacker bypasses the WAF, the rate limiter, and every LB rule. Historical DNS, certificate transparency, and error messages are the usual leak channels.
- **Host header injection.** An LB that routes by `Host` and a backend that trusts `Host` for password-reset links or cache keys create both poisoning and account-takeover paths.
- **IP allow-list bypass.** An origin that accepts traffic from "the LB IP" is bypassable if the attacker can spoof or if the allow-list is misconfigured (for example `X-Forwarded-For` trusted blindly).

**Proxy as a pivot:**

- **Open forward proxy.** A forward proxy that accepts connections from anyone is an SSRF pivot and an anonymization service. Test from an untrusted segment.
- **SSRF via the reverse proxy.** The proxy fetches a backend URL; if the URL is attacker-influenced, the proxy becomes an SSRF primitive into the internal network.
- **TLS termination weak spots.** Weak ciphers, missing HSTS, and a TLS certificate that is not pinned between LB and backend allow interception or downgrade on the internal hop.

The common thread: the LB is a parser, and every parser differential with the backend is a bug. The proxy is a pivot, and every request it fetches on the attacker's behalf is a capability.

## 4. Exploitation Recipes

All commands and tests below are run only against systems you own or have written authorization to test.

### Recipe 1 - Detect and fingerprint the load balancer

```bash
# Multiple A records and varied Server headers
dig +short target.example A
for i in 1 2 3 4 5; do curl -sI https://target.example/ | grep -iE '^(server|date|x-)'; done

# Vendor hint from cookie names
curl -sI https://target.example/ | grep -i set-cookie
```

Expected: multiple A records, `Server` or `Date` varying across requests, and cookies named `BIGipServer*`, `AWSALB`, `ARRAffinity`, or similar identify the product.

### Recipe 2 - Probe parser behavior

```bash
# Absolute-form URI (some proxies route it, some backends do not)
curl -s -o /dev/null -w "%{http_code}\n" --request-target 'http://target.example/' https://target.example/

# Duplicate Content-Length (front end vs backend disagree)
printf 'POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: 6\r\nContent-Length: 7\r\n\r\nAAAAAA' | openssl s_client -quiet -connect target.example:443

# Header with a leading space before the colon (some parsers normalize, some reject)
printf 'GET / HTTP/1.1\r\nHost: target.example\r\nContent-Length : 0\r\n\r\n' | openssl s_client -quiet -connect target.example:443
```

Expected: any response difference between a normal request and these malformed ones (status code, body, timing, or a connection reset) is a parser differential worth investigating.

### Recipe 3 - Find the origin

```bash
# Certificate transparency for subdomains and historical hosts
curl -s "https://crt.sh/?q=%25.target.example&output=json" | jq -r '.[].name_value' | sort -u

# Direct-to-origin test (replace with a candidate IP from CT or DNS history)
curl -sk -H "Host: target.example" https://203.0.113.10/ -o /dev/null -w "%{http_code}\n"
```

Expected: a `200` from the direct origin IP with the target `Host` header means the origin is exposed and the LB/WAF can be bypassed.

### Recipe 4 - Cache poisoning test

```bash
# Prime the cache with a value in a header the backend may reflect
curl -s -H "X-Forwarded-Host: attacker.example" https://target.example/ -o /dev/null -w "%{http_code}\n"

# Request the same resource from a clean client and check for the injected value
curl -s https://target.example/ | grep -i "attacker.example"
```

Expected: if the injected host appears in the second, clean response, the cache key ignores `X-Forwarded-Host` and the cache is poisonable.

### Recipe 5 - Check the management and stats interfaces

```bash
# HAProxy stats, NGINX stub_status, Envoy admin
for path in "/haproxy?stats" "/nginx_status" "/stats" "/config_dump" "/server_info"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.example${path}")
  echo "${path} -> ${code}"
done
```

Expected: a `200` on any of these paths means the stats or admin interface is exposed to the internet, which is a critical finding.

## 5. Post-Exploitation

Once a load balancer or proxy is compromised, the post-exploitation options are network-wide, because the device sits on the path of every request.

**Configuration and topology exfiltration.** The running config contains every VIP, every backend pool, every health-check endpoint, every TLS certificate and private key, and on an API gateway every route and every upstream credential. Treat it as the map of the application estate.

**Traffic manipulation.** A proxy under attacker control can rewrite requests, inject headers, redirect responses, and strip security headers. On a TLS-terminating reverse proxy this includes full request and response visibility.

**Persistence.** A modified route that forwards a specific path to an attacker-controlled backend, an added admin user on the management UI, or a rewritten health check that keeps a rogue backend in rotation. On an API gateway, an added route or a modified auth plugin is durable persistence.

**Cache poisoning at scale.** A compromised or misconfigured cache can serve a malicious response to every user of a poisoned URL. This is a one-to-many attack: a single poisoned entry affects all clients.

**Pivot into the backend network.** The LB has network reach to every backend pool. From the LB, the attacker can reach services that were never exposed externally, and can speak to them without the LB's own access control in the way.

**Logging suppression.** Disabling access logs, excluding the attacker's source, or rewriting the log format so that the malicious request is not recorded.

## 6. Preventive Controls

Load balancer and proxy hardening is topology discipline plus parser discipline.

**Topology:**

```text
! The LB is the only path to the backend
! Backend accepts traffic only from the LB IP (network ACL, not header trust)
! Origin IP is not discoverable from the internet
! Management and stats interfaces are on a dedicated network
! TLS terminates at the LB and is re-encrypted to the backend (no clear-text hop)
```

- **Network-level origin protection.** The backend accepts traffic only from the load balancer's IP, enforced by a network ACL, not by trusting `X-Forwarded-For`.
- **Origin IP hygiene.** Do not leak the origin through DNS history, certificate transparency for internal names, SPF records, or error messages. Verify with the origin-discovery recipes above.
- **Management plane isolation.** The stats page, the admin API, and the vendor management UI are on a dedicated management network with an allow-list. Envoy admin and HAProxy stats are never exposed to the internet.
- **TLS on every hop.** TLS terminates at the LB and is re-established to the backend. A clear-text internal hop is an interception surface.

**Parser discipline:**

- **One HTTP version end to end.** Avoid HTTP/2 to HTTP/1.1 downgrades where possible; where they are unavoidable, use a front end that normalizes strictly (reject ambiguous `Content-Length`/`Transfer-Encoding`, reject obsolete line folding).
- **Strict header validation.** Reject duplicate `Content-Length`, whitespace before the colon, and both `Content-Length` and `Transfer-Encoding` in the same request. This closes the smuggling class at the front end.
- **Cache key completeness.** The cache key includes every header the backend uses to vary the response (`Host`, `X-Forwarded-Host` if trusted, `Accept-Encoding`, cookies where relevant). An incomplete cache key is a poisoning bug.
- **Path normalization parity.** The LB's route match and the backend's file resolution must agree on dot segments, encoded slashes, and double slashes. Any difference is an access-control bypass.

**API gateway:**

- **Auth at the gateway, defense in depth at the backend.** The gateway is the single policy point, but the backend must not assume the gateway is the only caller. Validate tokens at both layers.
- **Rate limiting and schema validation.** Reject requests that do not match the published schema; this removes a whole class of parser-differential bugs.
- **Upstream credential isolation.** The gateway's credentials to each backend are scoped to that backend only.

## 7. Detection Controls

**Configuration and route changes:**

- Every route, pool, or certificate change is logged and alerted. A change outside a change window is a high-severity alert.
- Config diffing: compare the running config against the last known-good baseline on a schedule.

**Management plane activity:**

- Successful and failed logins to the stats page, the admin API, and the vendor management UI.
- New admin users and API token creation.
- Admin access from unexpected networks.

**Request anomalies:**

- A request whose `Content-Length` and `Transfer-Encoding` disagree, or that has duplicate `Content-Length`. This is the signature of a smuggling attempt.
- A request that reflects an attacker-controlled header in a cached response (cache poisoning in progress).
- A spike in 4xx from one source with malformed headers, which is the signature of a parser-differential scan.

**Topology anomalies:**

- A request that reaches a backend from an IP other than the load balancer. This is either a misconfiguration or a direct-to-origin bypass.
- A backend that leaves the pool unexpectedly and returns, which is the signature of a health-check manipulation attempt.

**Example HAProxy and Envoy telemetry:**

```text
! HAProxy: log the front end, the backend, and the termination state
log /dev/log local0
option httplog
! Envoy: access log with request headers for smuggling detection
access_log /dev/stdout
```

The high-value SIEM alert is a chain: a rule or route change, followed by a new backend in the pool, followed by traffic to that backend. Each event alone is noise; together they are a compromised load balancer.

## 8. Verification

How to verify that the load balancer is enforcing what it claims.

**Verify the topology:**

```bash
# The backend must refuse traffic that does not come from the LB
curl -s -o /dev/null -w "%{http_code}\n" http://203.0.113.10/
# Expect: timeout or 403, NOT 200

# The management interface must not answer from the internet
curl -s -o /dev/null -w "%{http_code}\n" https://target.example/haproxy?stats
# Expect: 404 or 403, NOT 200
```

**Verify the parser discipline:**

```bash
# Duplicate Content-Length must be rejected, not normalized
printf 'POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: 6\r\nContent-Length: 7\r\n\r\nAAAAAA' | openssl s_client -quiet -connect target.example:443
# Expect: 400 or connection close, NOT a request that reaches the backend

# Content-Length plus Transfer-Encoding must be rejected
printf 'POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | openssl s_client -quiet -connect target.example:443
# Expect: 400 or connection close
```

**Verify the cache key:**

- Send a request with a unique `X-Forwarded-Host` value, then request the same resource from a clean client. The injected value must not appear in the clean response. If it does, the cache key is incomplete.

**Verify TLS on the internal hop:**

- On the LB, confirm that the backend connection uses TLS and validates the backend certificate. A clear-text backend hop is a finding even if everything else is correct.

**The verification habit:** after every route, pool, or certificate change, re-run the topology tests and the parser-differential probes. A silent route change is the most common load-balancer compromise.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**

- Domain 3: Network Operations - load balancing, proxy, high availability.
- Domain 2: Network Implementation - traffic shaping and QoS.

**Cisco CCNA (200-301):**

- Domain 4: IP Services - NAT, first-hop redundancy (the HA equivalent).
- Domain 5: Security Fundamentals - proxy, application filtering.

**F5 Certified Administrator (201):**

- LTM fundamentals, virtual servers, pools, health monitors, persistence.

**CompTIA Security+ (SY0-701):**

- Domain 3: Implementation - load balancers, proxies, TLS termination.

**Cross-references:**

- 01 Network Fundamentals covers the layer 1-3 basics the load balancer distributes.
- 02 Routing and Switching covers the routing the LB pool relies on.
- 04 Network Protocols covers HTTP and TLS at the parsing level.
- 05 Traffic Analysis and Forensics covers how the LB's logs are captured and correlated.

## 10. Production Notes

**The load balancer is a parser, and the parser is the attack surface.** Most teams think of the LB as a dumb distributor. It is not: it parses HTTP, rewrites headers, and makes routing decisions. Every place where its parser and the backend's parser can disagree is a bug. Test those places deliberately.

**The origin is the weak link.** A hardened LB in front of an origin that is directly reachable from the internet protects nothing. Discovering and closing the origin path is the first step of any LB assessment.

**The management plane is the real perimeter.** An exposed HAProxy stats page or Envoy admin endpoint turns the LB from a control into an entry point. Isolate the management plane first, before any routing tuning.

**The cache is a one-to-many weapon.** A cache poisoning bug on an LB is worse than the same bug on a backend, because a single poisoned entry serves every user. Cache-key completeness is not optional.

**The API gateway concentrates risk.** The gateway is the single policy point for every API. That is its value and its risk: a bug in the gateway policy is a bug in every API at once. Test the gateway as its own attack surface.

**TLS termination is a trust decision.** Terminating TLS at the LB means the LB sees clear-text requests. That is a legitimate design, but it makes the LB a high-value target. Protect it accordingly.

## 11. References

- NIST SP 800-52 Rev. 2 (Guidelines for TLS Implementations) - https://csrc.nist.gov/pubs/sp/800/52/r2/final
- NIST SP 800-41 Rev. 1 (Guidelines on Firewalls and Firewall Policy) - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger - HTTP Request Smuggling - https://portswigger.net/web-security/request-smuggling
- PortSwigger - Web Cache Poisoning - https://portswigger.net/web-security/web-cache-poisoning
- HAProxy Documentation - https://docs.haproxy.org/
- NGINX Documentation - https://nginx.org/en/docs/
- Envoy Proxy Documentation - https://www.envoyproxy.io/docs
- F5 - BIG-IP Documentation - https://my.f5.com/manage/s/
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics
