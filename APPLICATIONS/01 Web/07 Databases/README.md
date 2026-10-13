# Databases

> Part of [01 Web](../README.md) in the [Web Application Testing Cheatsheet](../README.md).

**Contents:**

- [1. Overview](#1-overview)
- [2. Detection - which DB is it?](#2-detection---which-db-is-it)
- [3. Enumeration without credentials](#3-enumeration-without-credentials)
- [4. Common misconfigurations](#4-common-misconfigurations)
- [5. From web app to DB](#5-from-web-app-to-db)
- [6. Per-DB quick reference](#6-per-db-quick-reference)
- [7. Post-exploitation](#7-post-exploitation)
- [8. OSCP notes](#8-oscp-notes)
- [9. References](#9-references)

---

## 1. Overview

Databases are the payoff of a web pentest. Every step before them (recon,
fingerprinting, injection) is preparation. Once you reach the DB, you get
credentials, hashes, file read/write, and often direct RCE.

This file is an **introductory index**: how to tell which DB you are likely looking at,
what it leaks without credentials, and which sibling file to open next.
Each database has its own dedicated page; this README is the shared entry point,
not a substitute for those pages.

**Per-database pages in this folder:**

- [MySQL.md](./MySQL.md)
- [PostgreSQL.md](./PostgreSQL.md)
- [MSSQL.md](./MSSQL.md)
- [MongoDB.md](./MongoDB.md)
- [Redis.md](./Redis.md)
- [SQLite.md](./SQLite.md)
- [Oracle.md](./Oracle.md)

### 1.1 Why databases matter

Four reasons, in order of impact:

1. **Credentials** - user tables almost always contain password hashes or
   plaintext passwords. Reused credentials pivot to SSH, RDP, admin panels.
2. **File read/write** - most DB engines can read and write local files
   (`LOAD_FILE`, `pg_read_file`, `xp_cmdshell`, `COPY ... TO PROGRAM`).
   Read `/etc/passwd`, `web.config`, `wp-config.php`. Write a webshell.
3. **Command execution** - MySQL UDF, MSSQL `xp_cmdshell`, PostgreSQL
   `COPY ... TO PROGRAM`, MongoDB `$where` with JS. Direct OS command.
4. **Lateral movement** - linked MSSQL servers, PostgreSQL `dblink`,
   MySQL federated tables. From one DB to another host.

### 1.2 Default ports

| DB | Default port | Common deviations | Protocol |
|----|--------------|-------------------|----------|
| MySQL / MariaDB | 3306 | 3307, 13306, 33060 (X Protocol) | MySQL wire |
| PostgreSQL | 5432 | 5433, 15432 | PG wire |
| MSSQL | 1433 | 1434 (browser), dynamic high ports | TDS |
| Oracle | 1521 | 1522, 1526, 2483 | TNS |
| MongoDB | 27017 | 27018, 27019 | MongoDB wire |
| Redis | 6379 | 6380, 16379 | RESP |
| Elasticsearch | 9200 (HTTP), 9300 (transport) | 9201 | HTTP/JSON |
| CouchDB | 5984 | 6984 (TLS) | HTTP/JSON |
| Cassandra | 9042 (CQL), 7000 (gossip) | 9142 | CQL binary |
| Memcached | 11211 | 11212 | text / binary |
| SQLite | n/a (file) | - | file |

### 1.3 Auth models

| DB | Default auth | Notes |
|----|--------------|-------|
| MySQL | password | `caching_sha2_password` (8.x), `mysql_native_password` (5.x) |
| PostgreSQL | password + `pg_hba.conf` | `trust`, `md5`, `scram-sha-256`, `peer` |
| MSSQL | password | Windows auth (NTLM/Kerberos) or SQL auth |
| Oracle | password | OS auth, password, external |
| MongoDB | none (legacy) / SCRAM | Pre-3.0 no auth by default |
| Redis | none | `requirepass` optional; often no auth |
| Elasticsearch | none (pre-7) | X-Pack security optional |

---

## 2. Detection - which DB is it?

### 2.1 Port-based

```bash
# Version detection on every open port
nmap -sV -Pn -p- --min-rate 5000 <TARGET>

# Targeted per-DB NSE scripts
nmap -p 3306 --script mysql-info,mysql-enum <TARGET>
nmap -p 5432 --script pgsql-brute <TARGET>
nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password <TARGET>
nmap -p 27017 --script mongodb-info,mongodb-databases <TARGET>
nmap -p 6379 --script redis-info <TARGET>
nmap -p 1521 --script oracle-tns-version <TARGET>
```

Expected output (MySQL example):

```text
3306/tcp open  mysql   MySQL 8.0.32-0ubuntu0.22.04.2
| mysql-info:
|   Protocol: 10
|   Version: 8.0.32-0ubuntu0.22.04.2
```

### 2.2 Banner grabbing

```bash
# Raw connect - most DBs greet you with a banner
nc -nv <TARGET> 3306    # MySQL
nc -nv <TARGET> 5432    # PostgreSQL (needs startup packet)
nc -nv <TARGET> 6379    # Redis (type PING)
nc -nv <TARGET> 27017   # MongoDB (binary - use mongosh)
```

### 2.3 Error-message fingerprinting (from web app)

The fastest way: cause a SQL error and read the message.

| Error text contains | DB |
|---------------------|-----|
| `You have an error in your SQL syntax` | MySQL |
| `Warning: mysql_` | MySQL (PHP) |
| `PostgreSQL.*ERROR` / `pg_query` | PostgreSQL |
| `Microsoft OLE DB Provider for SQL Server` | MSSQL |
| `Unclosed quotation mark after the character string` | MSSQL |
| `ORA-01756` / `ORA-00933` | Oracle |
| `SQLite3::query` / `SQLite format 3` | SQLite |
| `MongoError` / `MongoServerError` | MongoDB |
| `sqlite3.OperationalError` | SQLite (Python) |

### 2.4 Response-header hints (app stack, not the DBMS)

HTTP response headers identify the **application stack** (language, framework,
web server). They do NOT identify the database. Treat the table below as a
weak prior for which DB is *plausible* given the stack - never as proof.
Confirm with error-message fingerprinting (2.3) or a direct connect.

| Header / body marker | App stack hint | DB commonly paired (guess only) |
|----------------------|----------------|----------------------------------|
| `X-Powered-By: PHP` | PHP | MySQL / MariaDB (typical LAMP) |
| `X-Powered-By: Express` | Node.js / Express | MongoDB or PostgreSQL (both common) |
| `Server: Microsoft-IIS` + `.aspx` | IIS / ASP.NET | MSSQL (common) |
| `X-AspNet-Version` | ASP.NET | MSSQL (common) |
| `Server: gunicorn` / `Werkzeug` | Python (Django/Flask) | PostgreSQL / MySQL / SQLite (no single default) |
| `Set-Cookie: JSESSIONID` + `.jsp` | Java / servlet container | Oracle / PostgreSQL / MySQL (no single default) |

### 2.5 Default credentials

| DB | Username | Password | Notes |
|----|----------|----------|-------|
| MySQL | `root` | (empty) | Fresh installs often empty |
| PostgreSQL | `postgres` | `postgres` | Common in Docker |
| MSSQL | `sa` | (empty) / `sa` | `sa` disabled on modern |
| Oracle | `scott` | `tiger` | Classic demo account |
| Oracle | `system` | `manager` | Common default |
| MongoDB | - | - | Pre-3.0 no auth at all |
| Redis | - | - | No auth by default |
| Elasticsearch | - | - | No auth pre-7.0 |

### 2.6 Decision tree

```text
Open port?
  |
  +-- 3306 / 3307 / 33060 ----------> MySQL / MariaDB  -> MySQL.md
  +-- 5432 / 5433 ------------------> PostgreSQL       -> PostgreSQL.md
  +-- 1433 / 1434 / dynamic --------> MSSQL            -> MSSQL.md
  +-- 1521 / 1526 ------------------> Oracle           -> Oracle.md
  +-- 27017 / 27018 ----------------> MongoDB          -> MongoDB.md
  +-- 6379 / 6380 ------------------> Redis            -> Redis.md
  +-- 9200 / 9300 ------------------> Elasticsearch    -> (link: 02 Frameworks)
  +-- 5984 / 6984 ------------------> CouchDB          -> (link: 02 Frameworks)
  +-- 9042 -------------------------> Cassandra        -> (link: 02 Frameworks)
  +-- 11211 ------------------------> Memcached        -> (link: 02 Frameworks)
  +-- no port, file-based ----------> SQLite           -> SQLite.md
  |
  +-- HTTP app with SQL errors?
        |
        +-- error mentions MySQL -----> MySQL.md
        +-- error mentions PG --------> PostgreSQL.md
        +-- error mentions MSSQL -----> MSSQL.md
        +-- error mentions ORA -------> Oracle.md
```

---

## 3. Enumeration without credentials

### 3.1 What each DB leaks unauthenticated

| DB | Unauthenticated leak |
|----|----------------------|
| MySQL | Version + auth plugin via handshake |
| PostgreSQL | Version via error / startup message |
| MSSQL | Version via TDS pre-login |
| MongoDB | Full DB list + collections (pre-3.0) |
| Redis | Full keyspace (`KEYS *`, `INFO`, `CONFIG GET`) |
| Elasticsearch | Full index list + docs (`/_cat/indices`) |
| Memcached | Full keyspace (`stats items`, `get`) |

### 3.2 nmap NSE scripts

| DB | Scripts |
|----|---------|
| MySQL | `mysql-info`, `mysql-enum`, `mysql-brute`, `mysql-databases`, `mysql-users`, `mysql-variables`, `mysql-empty-password` |
| PostgreSQL | `pgsql-brute` |
| MSSQL | `ms-sql-info`, `ms-sql-config`, `ms-sql-empty-password`, `ms-sql-brute`, `ms-sql-dump-hashes`, `ms-sql-xp-cmdshell` |
| Oracle | `oracle-tns-version`, `oracle-brute`, `oracle-sid-brute`, `oracle-enum-users` |
| MongoDB | `mongodb-info`, `mongodb-databases`, `mongodb-brute` |
| Redis | `redis-info`, `redis-brute` |

### 3.3 Metasploit auxiliary scanners

| DB | Module |
|----|--------|
| MySQL | `auxiliary/scanner/mysql/mysql_login`, `mysql_hashdump`, `mysql_enum` |
| PostgreSQL | `auxiliary/scanner/postgres/postgres_login`, `postgres_hashdump`, `postgres_sql` |
| MSSQL | `auxiliary/scanner/mssql/mssql_login`, `mssql_hashdump`, `mssql_enum` |
| MongoDB | `auxiliary/scanner/mongodb/mongodb_login` |
| Redis | `auxiliary/scanner/redis/redis_login` |

### 3.4 Common unauth bugs

- **Redis without `requirepass`** - full keyspace, `CONFIG SET dir` + `CONFIG SET dbfilename` -> write SSH key or webshell.
- **MongoDB pre-3.0** - no auth by default. `show dbs` returns everything.
- **Elasticsearch pre-7.0** - no auth by default. `/_cat/indices` returns everything.
- **Memcached** - no auth by design. `stats items` + `get` returns all cached data.
- **CouchDB** - admin party mode (pre-1.0): anyone is admin.

---

## 4. Common misconfigurations

| Misconfig | Impact | Detection |
|-----------|--------|-----------|
| Exposed to internet | Direct attack surface | Port scan from outside |
| Weak / default creds | Full DB access | `hydra`, `nmap --script *-brute` |
| Anonymous / trust auth | No creds needed | `pg_hba.conf` `trust`, MySQL empty password |
| No TLS | Creds sniffable on wire | `nmap --script ssl-*` returns nothing |
| Over-privileged service account | Privilege escalation | `SHOW GRANTS`, `\du` |
| `FILE` privilege (MySQL) | Read/write local files | `SHOW GRANTS FOR CURRENT_USER()` |
| `xp_cmdshell` enabled (MSSQL) | Direct RCE | `EXEC sp_configure xp_cmdshell` |
| `COPY ... TO PROGRAM` (PG) | Direct RCE | PG >= 9.3, superuser |
| MongoDB `$where` | JS execution | Any write access |

---