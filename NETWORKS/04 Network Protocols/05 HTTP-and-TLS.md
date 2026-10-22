# HTTP and TLS

## 1. Overview

HTTP (HyperText Transfer Protocol, RFC 9110) is the application protocol of the web. TLS (Transport Layer Security, RFC 8446) provides confidentiality, integrity, and authentication for HTTP and other protocols. HTTPS is HTTP over TLS.

Both protocols have been repeatedly abused: HTTP request smuggling, response splitting, header injection, and downgrade attacks on HTTP; TLS stripping, weak cipher suites, certificate validation bypass, and protocol downgrade on TLS. This file covers the mechanics, the offensive techniques, and the defensive controls.

## 2. Reconnaissance / Enumeration

### HTTP enumeration

- `curl -I https://example.com` - fetch headers only.
- `nikto -h https://example.com` - web server scanner.
- `whatweb https://example.com` - fingerprint frameworks, CMS, and server.
- `httpx -u https://example.com -title -tech-detect -status-code` - fast HTTP probing.

### TLS enumeration

- `openssl s_client -connect example.com:443 -servername example.com` - inspect the certificate chain and negotiated cipher.
- `nmap --script ssl-enum-ciphers -p 443 example.com` - list supported cipher suites and TLS versions.
- `testssl.sh example.com` - comprehensive TLS configuration audit (protocols, ciphers, certificate, vulnerabilities).
- `sslyze --regular example.com` - another TLS scanner.

## 3. Common Attack Vectors

### HTTP request smuggling

When a front-end proxy and a back-end server disagree on how to parse `Content-Length` and `Transfer-Encoding`, an attacker can smuggle a second request through the first. The smuggled request is processed by the back-end with the front-end's authentication context.

### HTTP response splitting

If user input is reflected into a response header, an attacker can inject CRLF (`\r\n`) sequences and add arbitrary headers or a second response body. The impact is cache poisoning, XSS, and session fixation.

### HTTP downgrade / SSL stripping

An on-path attacker intercepts the initial HTTP request, keeps the victim on HTTP, and proxies HTTPS to the real server. The victim sees no lock icon, but the attacker sees all traffic in plaintext. Tools: `sslstrip`, `bettercap`.

### TLS downgrade

If the server supports old TLS versions (1.0, 1.1) or weak ciphers (RC4, 3DES), an attacker can force a downgrade and then break the weaker cipher.

### Certificate validation bypass

Clients that do not validate certificates (or that accept self-signed ones) are vulnerable to MITM. Mobile apps and IoT devices are the usual offenders.

## 4. Exploitation Recipes

### SSL stripping with bettercap

```bash
sudo bettercap -iface eth0
# inside bettercap:
# set arp.spoof.targets 10.10.10.50
# arp.spoof on
# set http.proxy.sslstrip true
# http.proxy on
# net.sniff on
```

bettercap ARP-spoofs the victim, proxies HTTP, and strips HTTPS redirects. The victim sees plain HTTP while the attacker sees the full request and response.

### TLS downgrade test with testssl.sh

```bash
./testssl.sh --protocols --ciphers https://example.com
```

The output lists which TLS versions and cipher suites the server accepts. If TLS 1.0 or RC4 appears, the server is downgradable.

### HTTP request smuggling test with smuggler

```bash
python3 smuggler.py -u https://example.com
```

smuggler sends pairs of requests with conflicting `Content-Length` and `Transfer-Encoding` headers and reports whether the front-end and back-end disagree.

## 5. Post-Exploitation

After a successful HTTP or TLS attack, the attacker can:

- Read and modify traffic in plaintext (SSL stripping).
- Poison caches with smuggled responses (request smuggling).
- Steal session cookies (response splitting + XSS).
- Bypass client authentication by terminating TLS at the attacker (certificate validation bypass).

## 6. Preventive Controls

- **HSTS** (HTTP Strict Transport Security): `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Forces the browser to use HTTPS for the domain.
- **TLS 1.2+ only**: disable TLS 1.0, 1.1, SSLv3. Disable RC4, 3DES, and export ciphers.
- **Certificate pinning** in mobile apps and IoT devices.
- **Reject ambiguous requests**: if both `Content-Length` and `Transfer-Encoding` are present, return 400.
- **Normalize CRLF** in reflected input: strip `\r` and `\n` from header values.
- **CSP** (Content Security Policy) to limit the impact of injected scripts.
- **OCSP stapling** and **Certificate Transparency** monitoring.

## 7. Detection Controls

- **Zeek** `http` analyzer logs method, URI, status, user-agent, and headers; a request with both `Content-Length` and `Transfer-Encoding` is a smuggling signal.
- **Zeek** `ssl` analyzer logs TLS versions and cipher suites; a sudden drop to TLS 1.0 is a downgrade signal.
- **IDS rules**: alert on `Transfer-Encoding: chunked` combined with `Content-Length`; on CRLF in header values; on TLS 1.0/1.1 handshakes; on self-signed certificates from known servers.
- **Certificate Transparency logs**: monitor for unexpected certificates issued for your domains.

## 8. Verification

- On the server: `testssl.sh --protocols https://example.com` should show only TLS 1.2 and 1.3.
- HSTS: `curl -sI https://example.com | grep -i strict-transport-security` should show the header.
- Smuggling: send a request with both `Content-Length` and `Transfer-Encoding`; the server should return 400.
- Certificate validation: connect with `openssl s_client` and verify the chain; a self-signed certificate should fail unless explicitly trusted.

## 9. Case Studies

- **SSL stripping (Moxie Marlinspike, 2009)**: demonstrated that HTTPS is only as strong as the initial redirect; without HSTS, an on-path attacker can keep the victim on HTTP.
- **HTTP request smuggling (PortSwigger research, 2019-2021)**: a class of vulnerabilities affecting major CDNs and reverse proxies; the fix is strict parsing and rejecting ambiguous requests.
- **Let's Encrypt and Certificate Transparency (2015+)**: made TLS certificates free and auditable, reducing the impact of rogue certificates.

## 10. Legal and Ethical Notes

SSL stripping, request smuggling, and TLS downgrade attacks on systems you do not own or have explicit written authorization to test are illegal in most jurisdictions. In a penetration test, these techniques must be listed in the scope and rules of engagement. On shared infrastructure, even passive traffic capture may violate terms of service.

## 11. References

- RFC 9110 (HTTP Semantics) - https://www.rfc-editor.org/rfc/rfc9110
- RFC 8446 (TLS 1.3) - https://www.rfc-editor.org/rfc/rfc8446
- RFC 6797 (HSTS) - https://www.rfc-editor.org/rfc/rfc6797
- OWASP HTTP Request Smuggling - https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
- testssl.sh - https://testssl.sh/
- smuggler - https://github.com/defparam/smuggler
- bettercap http.proxy module - https://www.bettercap.org/modules/ethernet/proxies/http.proxy/
- Zeek HTTP analyzer - https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html
- Zeek SSL analyzer - https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html

## Certification Alignment

- CompTIA Network+ (N10-009): Objective 1.5 (ports and protocols), Objective 3.2 (attacks), Objective 5.3 (troubleshooting)
- Cisco CCNA (200-301): 4.1 (Layer 2 security), 5.5 (security concepts), 1.6 (troubleshooting)
