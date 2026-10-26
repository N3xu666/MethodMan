# Mythical (HTB Pro Lab)

> Platform: Hack The Box Pro Lab  
> OS: Windows  
> Difficulty: Advanced  
> Status: Completed (26 Oct 2026)

---

## Certification

The successful completion of this lab is verified by the official Hack The Box certificate:

**[Open Certificate (PDF)](./Certificate.pdf)**

---

> [!WARNING]
> **HTB ToS Compliance:** This is a capability showcase, NOT a walkthrough. To respect HTB Terms of Service for active Pro Labs, specific commands, exploit payloads, and flag values are intentionally omitted. 

---

## Scenario Overview

The `Mythical` lab simulates a red team engagement with an assumed breach scenario. Starting with an active C2 (Mythic) beacon running as a low-privileged user on an internal Domain Controller (DC01), the objective is to escalate privileges within the first domain, pivot across a forest trust, and compromise a secondary DC.

## Skills Demonstrated

- **C2 Operations:** Managing the Mythic C2 framework, executing post-exploitation tasks, and adapting tooling to run via assembly execution.
- **Active Directory Enumeration & Attacks:** Enumerating trusts, users, and group memberships across a multi-forest environment.
- **ADCS Exploitation:** Chaining Active Directory Certificate Services misconfigurations (ESC4 to ESC1) and bypassing Strong Certificate Binding (KB5014754).
- **Inter-Forest Lateral Movement:** Extracting trust keys via `lsadump::trust`, forging cross-forest TGTs, and pivoting to secondary domain controllers.
- **MSSQL Exploitation:** Abusing the `msdb` database `TRUSTWORTHY` property to escalate from a standard user to `sysadmin`, and enabling `xp_cmdshell`.
- **Local Privilege Escalation:** Leveraging "Potato" exploits (`GodPotato`) to escalate from a service account (`NT SERVICE\MSSQL$SQLEXPRESS`) to `NT AUTHORITY\SYSTEM`.
- **Credential Dumping:** Extracting cleartext credentials and NTLM hashes from memory using Mimikatz.

## Tooling

- **Mythic C2:** Command and Control framework.
- **Impacket:** `make_token`, `Invoke-SMBExec`, and other utilities.
- **StandIn & Certipy:** ADCS template modification and certificate requesting.
- **Rubeus:** Extracting TGTs and asking for tickets.
- **Mimikatz:** DCSync, trust key dumping, and `sekurlsa` dumps.
- **GodPotato:** Windows privilege escalation.
- **keepass4brute & keepassxc-cli:** Cracking and extracting KeePass databases.
- **sqlcmd:** MSSQL interaction.

## Key Takeaways (Methodology)

- **ADCS ESC4 to ESC1:** Modifying a template's ACLs allows attackers to inject the `ENROLLEE_SUPPLIES_SUBJECT` flag, turning a benign template into a privilege escalation vector.
- **Strong Certificate Binding Bypass:** On modern Windows Server (2022+), standard certificate requests fail PKINIT. Injecting the target user's SID into the SAN extension is required to bypass this security feature.
- **Inter-Forest Trusts:** Possessing DA on one domain allows dumping trust keys, which can be used to forge TGTs across the forest boundary if the trust is not strictly configured.
- **MSSQL `TRUSTWORTHY`:** The `msdb` database is `TRUSTWORTHY` by default. Attackers with `db_owner` can use `EXECUTE AS OWNER` to escalate to `sysadmin`.
- **Potato Exploits:** `xp_cmdshell` grants the privileges of the SQL service account, which usually holds `SeImpersonatePrivilege`. Tools like `GodPotato` leverage this to escalate to `SYSTEM`.
