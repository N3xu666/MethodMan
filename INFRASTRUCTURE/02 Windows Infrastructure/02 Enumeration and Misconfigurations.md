## 1. Overview

Windows enumeration is the systematic process of mapping the local
attack surface: privileges, services, scheduled tasks, registry keys,
installed software, credentials in files, and network configuration.
Automated tools like winPEAS and Seatbelt speed this up, but manual
enumeration remains essential for understanding what is actually
exploitable.

**What enumeration answers:**

- What privileges and group memberships does the current user have?
- Which services run as SYSTEM or a privileged account, and are their
  permissions weak?
- Which scheduled tasks run as SYSTEM, and are they writable?
- Which registry keys contain credentials or weak ACLs?
- Which files on disk contain credentials?
- Which network shares, sessions, and trusts are reachable?
- What is the patch level, and are there known privesc CVEs?

**The three modes:**

- **Unauthenticated** - local access as a low-privileged user.
- **Authenticated** - local access with a known credential.
- **Remote** - authenticated access from another host (SMB, WinRM,
  RDP).

## 2. Reconnaissance / Enumeration

**Offensive - first commands:**

    # Who am I and what can I do?
    whoami /all

    # What OS and patch level?
    systeminfo
    wmic qfe list brief

    # What groups am I in?
    net user %USERNAME%
    net localgroup
    net localgroup Administrators

    # What is my hostname and domain?
    hostname
    echo %USERDOMAIN%

**Offensive - services:**

    # All services with binary paths
    wmic service get Name,DisplayName,PathName,StartMode,StartName

    # Non-Microsoft services
    Get-Service | Where-Object { $_.DisplayName -notmatch 'Microsoft' }

    # Service permissions (accesschk.exe from Sysinternals)
    accesschk.exe /accepteula -uwcqv "Everyone" *
    accesschk.exe /accepteula -uwcqv "Users" *
    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

    # Unquoted service paths
    wmic service get Name,DisplayName,PathName,StartMode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """"

**Offensive - scheduled tasks:**

    schtasks /query /fo LIST /v
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" }

    # Task binaries and permissions
    Get-ScheduledTask | ForEach-Object { $_.Actions } | Select-Object Execute,Arguments

**Offensive - registry:**

    # Autologon credentials
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    # AutoRun keys
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    # Uninstall keys (for version identification)
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

**Offensive - installed software and processes:**

    wmic product get Name,Version
    Get-Process | Select-Object Name,Id,Path,Company
    Get-CimInstance Win32_StartupCommand

    # Non-Microsoft binaries (potential DLL hijack targets)
    Get-Process | Where-Object { $_.Company -notmatch 'Microsoft' } | Select-Object Name,Path

**Offensive - network and shares:**

    netstat -ano
    net share
    net session
    ipconfig /all
    arp -a

**Offensive - credentials in files:**

    # Common locations
    dir /s /b C:\unattend.xml C:\Windows\Panther\*.xml C:\Windows\System32\sysprep\*.xml 2>nul

    # Search for passwords in common file types
    findstr /si password *.xml *.ini *.txt *.config *.conf *.json

    # PowerShell history
    type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

    # Configuration files
    Get-ChildItem -Path C:\ -Include *.config,*.xml,*.ini,*.txt -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password|passwd|pwd"

**Offensive - automated tools:**

    # winPEAS (comprehensive)
    .\winPEASx64.exe

    # Seatbelt (targeted)
    .\Seatbelt.exe -group=all
    .\Seatbelt.exe -group=system
    .\Seatbelt.exe -group=user

    # PowerUp (PowerShell)
    Import-Module .\PowerUp.ps1
    Invoke-AllChecks

    # SharpUp (C#)
    .\SharpUp.exe audit

**Defensive - what to baseline:**

- Service binary paths and permissions.
- Scheduled tasks with SYSTEM or admin principals.
- Registry values in Run, Winlogon, IFEO.
- Local admin group membership.
- Installed software and patch level.
- Autologon and AlwaysInstallElevated settings.
- Files with `password` in common config locations.

## 3. Common Misconfigurations

**Service misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Unquoted service path | `wmic service get PathName` shows spaces without quotes | Plant executable in path prefix |
| Weak service ACL | `accesschk -uwcqv Users *` | Reconfigure service binary path |
| Writable service binary | `icacls <service_path>` shows Users write | Replace binary |
| Writable service directory | `icacls <service_dir>` shows Users write | DLL hijack |

**Registry misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Autologon credentials | `reg query Winlogon /v DefaultPassword` | Plaintext password |
| AlwaysInstallElevated | `reg query HKLM/HKCU ... /v AlwaysInstallElevated` | Install MSI as SYSTEM |
| Writable AutoRun key | `reg query Run` + `accesschk` | Persistence as another user |
| Writable IFEO key | `reg query IFEO` | Debugger hijack |

**File misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Credentials in config files | `findstr /si password *.config` | Credential theft |
| Unattend.xml left on disk | `dir /s /b C:\unattend.xml` | Credential theft |
| PowerShell history | `type ConsoleHost_history.txt` | Credential theft |
| Writable service binaries | `icacls` | Binary replacement |

**Privilege misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| SeImpersonatePrivilege | `whoami /priv` | Potato attacks |
| SeAssignPrimaryTokenPrivilege | `whoami /priv` | Token impersonation |
| SeDebugPrivilege | `whoami /priv` | LSASS dump |
| SeBackupPrivilege | `whoami /priv` | Read any file |
| SeTakeOwnershipPrivilege | `whoami /priv` | Take ownership |

**Patch misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Missing kernel patches | `systeminfo` + manual CVE lookup | Kernel privesc |
| Outdated drivers | `driverquery` + manual lookup | BYOVD |
| Vulnerable software versions | `wmic product get` + CVE lookup | Application privesc |

## 4. Exploitation Recipes

**winPEAS - comprehensive enumeration:**

    .\winPEASx64.exe

    # Expected output (highlights):
    # [+] Basic System Information
    # [+] Users
    # [+] Processes
    # [+] Services Information
    #   [?] Check if you can modify any service binary
    # [+] Applications
    # [+] Network
    # [+] Windows Credentials
    #   [?] Looking for AutoLogon credentials
    #   DefaultPassword: <PASSWORD>
    # [+] Unquoted Service Paths
    # [+] Scheduled Tasks

**Seatbelt - targeted enumeration:**

    # System-focused checks
    .\Seatbelt.exe -group=system

    # User-focused checks
    .\Seatbelt.exe -group=user

    # Specific check
    .\Seatbelt.exe TokenPrivileges
    .\Seatbelt.exe AutoRuns
    .\Seatbelt.exe CredentialFiles

**PowerUp - PowerShell enumeration and exploitation:**

    Import-Module .\PowerUp.ps1
    Invoke-AllChecks

    # Expected output (highlights):
    # [*] Running Invoke-AllChecks
    # [+] Current User: CORP\user
    # [*] Checking for unquoted service paths...
    # ServiceName    : VulnService
    # Path           : C:\Program Files\Vuln App\service.exe
    # ...
    # [*] Checking for modifiable service binaries...
    # [*] Checking for AlwaysInstallElevated...

**Manual service ACL check with accesschk:**

    # Download accesschk.exe from Sysinternals
    accesschk.exe /accepteula -uwcqv "Users" *
    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

    # Expected output (vulnerable service):
    # RW VulnService
    #     SERVICE_QUERY_STATUS
    #     SERVICE_QUERY_CONFIG
    #     SERVICE_CHANGE_CONFIG
    #     ...

**Checking patch level against known CVEs:**

    # Get OS version and build
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

    # Get installed hotfixes
    wmic qfe list brief

    # Manual lookup: compare build number against known CVE patch levels
    # (e.g. Windows 10 21H2 build 19044.XXX, CVE-2023-28252 CLFS)

**Credential file search:**

    # Search for passwords in common config files
    findstr /si password *.xml *.ini *.txt *.config *.conf

    # PowerShell history
    type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

    # Unattend.xml
    dir /s /b C:\unattend.xml C:\Windows\Panther\*.xml 2>nul

    # Expected output (vulnerable):
    # <Password>
    #   <Value>BASE64_PASSWORD</Value>
    #   <PlainText>false</PlainText>
    # </Password>

    # Base64 passwords are trivially decoded:
    # [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("BASE64_PASSWORD"))

## 5. Post-Exploitation

**After enumeration identifies a vector:**

- Save output of winPEAS/Seatbelt to a file for offline review.
- Prioritize vectors by likelihood and noise:
  1. Credentials in files (silent).
  2. Autologon / Unattend (silent).
  3. Weak service ACLs (loud).
  4. Unquoted paths (loud).
  5. Token privileges (medium noise).
  6. Kernel exploits (very loud, may crash the system).

**After getting a new shell:**

- `whoami /all` again - the privilege context may have changed.
- Re-run winPEAS - the new context may unlock new vectors.
- Look for credentials in the new context's environment.

**On a new host:**

- Baseline services, tasks, registry, software.
- Search for credentials in files.
- Search for Kerberos tickets in memory or disk.
- Search for SSH keys, RDP files, PuTTY sessions.

**Persistence enumeration:**

- AutoRun keys.
- Scheduled tasks.
- Services.
- WMI subscriptions.
- Startup folder.

## 6. Risk Context

Windows enumeration is the phase where the attack surface becomes
visible. In most real-world privesc chains, the vulnerable
configuration was always present; nobody found it because nobody
looked.

**Blast radius of enumeration:** none by itself, but it enables every
subsequent phase.

**Why enumeration succeeds:**

- Default configurations leave many legacy features enabled (AutoRun,
  autologon, Unattend).
- Installers frequently create services with weak ACLs.
- Developers frequently store credentials in config files.
- Patch management is incomplete on most endpoints.
- Service accounts often have dangerous privileges.

**Why it matters defensively:**

- Every enumeration vector is also a detection opportunity.
- Baseline + alert on changes catches most persistence.
- Credential hygiene (no plaintext, no reuse) breaks most chains.

## 7. Root Causes

- **Legacy installers.** Unquoted paths, weak service ACLs.
- **Default insecure configurations.** AutoRun, autologon,
  AlwaysInstallElevated.
- **Weak file permissions.** Non-admin principals with write access to
  system directories.
- **Credentials in plaintext.** Config files, scripts, Unattend.
- **Missing patches.** Kernel vulnerabilities.
- **Over-privileged service accounts.** SeImpersonate, SeDebug.
- **No baseline.** Enumeration findings are invisible without a
  baseline.

## 8. Preventive Controls

**Service hardening:**

- Quote all service paths.
- Restrict service ACLs to administrators.
- Install services in admin-only directories.
- Use dedicated service accounts where possible.

**Registry hardening:**

- Disable autologon.
- Disable AlwaysInstallElevated.
- Restrict write access to AutoRun keys.
- Enable LSA Protection (RunAsPPL).

**Credential hygiene:**

- Remove Unattend.xml from deployed systems.
- Do not store plaintext passwords in config files.
- Clear PowerShell history on logoff.
- Use managed service accounts (gMSA).
- Enable Credential Guard.

**Patch management:**

- Patch kernel vulnerabilities within days.
- Remove or update legacy drivers.
- Use WDAC / AppLocker to block unauthorized binaries.

**Monitoring:**

- Enable PowerShell script block logging.
- Enable Sysmon with a modern configuration.
- Forward logs to a SIEM.
- Baseline and alert on registry changes, service creation,
  scheduled task creation.

## 9. Detection Controls

**Service-related enumeration:**

- Event 4697 (service installed via API).
- Event 7045 (service installed via SCM).
- Event 4688 (process creation) with parent `services.exe`.
- Sysmon event 13 (registry set) on service keys.

**Scheduled task enumeration:**

- Event 4698 (task created).
- Event 4702 (task updated).
- Event 106 (TaskScheduler operational).
- Sysmon event 1 with parent `schtasks.exe`.

**Registry enumeration:**

- Event 4657 (registry value modified).
- Sysmon events 12 / 13 / 14 (registry events).
- Alert on modifications to Run, Winlogon, IFEO keys.

**File enumeration:**

- Event 4663 (file access attempt).
- Sysmon event 11 (file create) in Temp, ProgramData, C:\Windows\Temp.
- Alert on reads of Unattend.xml after deployment.

**Credential access:**

- Event 4656 / 4663 - handle to LSASS.
- Event 4688 with `mimikatz`, `procdump`, `comsvcs.dll`.
- Sysmon event 10 (process access) with target `lsass.exe`.

**Automated enumeration tools:**

- Sysmon event 1 with `winPEAS`, `Seatbelt`, `PowerUp`, `SharpUp`.
- Event 4688 with `accesschk.exe`.

**General:**

- Honeytokens: fake credentials in config files, fake admin accounts.
- Baseline normal process activity; alert on anomalies.

## 10. Verification

**Offensive - did enumeration find a vector?**

- winPEAS/Seatbelt output reviewed; at least one privesc vector
  identified.
- Service with weak ACL or unquoted path confirmed.
- Credentials in files confirmed (test them).
- Patch level compared against known CVEs.
- Token privileges identified.

**Defensive - are misconfigurations absent?**

- All service paths are quoted.
- `accesschk -uwcqv Users *` returns no writable services.
- No credentials in config files (search + manual review).
- Autologon and AlwaysInstallElevated are disabled.
- All patches are current within 30 days.
- No service accounts have SeImpersonate beyond documented exceptions.

## 11. OSCP Notes

- winPEAS is the standard first tool. Run it, save output, review.
- Seatbelt for targeted checks (fast, quiet).
- PowerUp for PowerShell-native enumeration.
- Always check `whoami /priv` manually - automated tools sometimes miss
  privilege combinations.
- **Capture screenshots** of:
  - winPEAS/Seatbelt output showing the vector.
  - The specific misconfiguration (`accesschk` output, unquoted path).
  - The exploitation step.
- The `> [!IMPORTANT]` OSCP reporting note applies to the enumeration
  finding that leads to privesc.

## 12. Production Notes

- winPEAS is extremely loud: EDR flags the binary on execution.
- Seatbelt is quieter but also flagged.
- Manual enumeration (whoami, systeminfo, wmic) is much quieter but
  slower.
- In mature environments, combine manual enumeration with targeted
  PowerShell scripts (custom, less signatured).
- Credential hunting in files is often the only silent path.
- Assume enumeration will be detected; plan for speed.

## 13. References

**Microsoft documentation:**

- [Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [Registry documentation](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)

**MITRE ATT&CK:**

- [Discovery - System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [Discovery - File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/)
- [Discovery - Software Discovery (T1518)](https://attack.mitre.org/techniques/T1518/)

**Tools:**

- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

**Research:**

- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [FuzzySecurity - Windows Privilege Escalation Fundamentals](https://fuzzysecurity.com/tutorials/16.html)