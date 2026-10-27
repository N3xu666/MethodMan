# Puppet (HTB Pro Lab)

> Platform: Hack The Box Pro Lab  
> OS: Windows / Linux  
> Difficulty: Intermediate  
> Status: Completed (27 Oct 2026)

---

## Certification

The successful completion of this lab is verified by the official Hack The Box certificate:

**[Open Certificate (PDF)](./Certificate.pdf)**

---

> [!NOTE]
> **HTB ToS Compliance:** This is a capability showcase, NOT a walkthrough. To respect HTB Terms of Service for active Pro Labs, specific commands, exploit payloads, and flag values are intentionally omitted.

---

## Scenario Overview

The `Puppet` lab simulates a red team engagement against Puppet Inc. Starting with an assumed breach via an internal Sliver C2 beacon on a Windows file server, the objective is to escalate privileges, pivot through a hybrid Active Directory environment, and exploit DevOps infrastructure to compromise the Domain Controller.

## Skills Demonstrated

- **C2 Operations:** Managing the Sliver C2 framework, operating through asynchronous beacons, and establishing interactive sessions.
- **Windows Privilege Escalation:** Exploiting PrintNightmare (CVE-2021-34527) to gain local administrator rights and bypassing UAC via SSPI Datagram Contexts (SspiUacBypass).
- **Credential Dumping & LSA Secrets:** Using Mimikatz to extract cleartext passwords and service account credentials from LSA secrets.
- **Lateral Movement & Pivoting:** Configuring port forwarding to pivot into internal networks and leveraging SMB shares to extract SSH keys.
- **Linux Privilege Escalation:** Cracking SSH key passphrases and abusing `sudo` misconfigurations with the `puppet` binary to gain `root`.
- **Infrastructure Exploitation (DevOps):** Weaponizing the Puppet Master server by deploying a malicious manifest (`site.pp`) to achieve remote code execution on high-value targets.
- **DPAPI Extraction:** Utilizing SharpDPAPI to extract SYSTEM-level DPAPI credentials (Task Scheduler) on the Domain Controller.

## Tooling

- **Sliver C2:** Command and Control framework.
- **PrintNightmare (CVE-2021-34527):** Windows privilege escalation.
- **SspiUacBypass:** UAC bypass via SSPI Datagram Contexts.
- **Mimikatz:** Credential dumping and LSA secrets extraction.
- **Impacket:** SMB client and lateral movement utilities.
- **John the Ripper:** SSH key passphrase cracking.
- **SharpDPAPI:** DPAPI credential extraction.

## Key Takeaways (Methodology)

- **Hybrid Environment Pivoting:** In modern networks, compromising a single Windows host is rarely the end. Pivoting into Linux infrastructure often provides the administrative leverage needed to compromise the domain.
- **DevOps Infrastructure is High-Value:** Configuration management tools like Puppet control the state of critical systems. Gaining root on a Puppet Master allows an attacker to push malicious manifests directly to Domain Controllers.
- **LSA Secrets:** Service accounts frequently run with high privileges. Dumping LSA secrets (`lsadump::secrets`) often reveals cleartext passwords for these accounts.
- **DPAPI SYSTEM Credentials:** Sensitive data (like scheduled task passwords) stored in SYSTEM context can be decrypted using tools like SharpDPAPI, bypassing the need for interactive user sessions.