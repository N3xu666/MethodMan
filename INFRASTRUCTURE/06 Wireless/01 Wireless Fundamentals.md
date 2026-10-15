# Wireless Fundamentals

802.11 primer for the rest of this subcategory: frame types, the
association handshake, WPA2 and WPA3 authentication, EAP methods for
enterprise networks, and where the trust boundaries sit. Read this
first if WPA2-PSK, WPA3-SAE, or EAP-TLS are unfamiliar.

> [!CAUTION]
> This file is educational. The attacks that build on it (files 02-05)
> require written authorization. Merely monitoring a wireless network
> you do not own may be illegal in some jurisdictions.

---

## 1. Overview

802.11 is the IEEE standard for wireless LANs. Every network has a
**BSSID** (the AP's MAC address) and an **SSID** (the network name).
Clients associate to an AP through a fixed handshake, then
authenticate with one of several methods:

- **Open** - no authentication, no encryption.
- **WEP** - obsolete, broken, but still seen on legacy hardware.
- **WPA** - TKIP, deprecated.
- **WPA2-Personal (PSK)** - pre-shared key, 4-way handshake.
- **WPA2-Enterprise (802.1X)** - RADIUS-based authentication, per-user
  credentials.
- **WPA3-Personal (SAE)** - Simultaneous Authentication of Equals,
  replaces PSK with a password-authenticated key exchange.
- **WPA3-Enterprise** - 802.1X with mandatory Protected Management
  Frames (PMF) and optional 192-bit mode.

The 802.11 frame types are:

- **Management frames:** beacon, probe request/response, authentication,
  association request/response, deauthentication, disassociation, action.
- **Control frames:** RTS, CTS, ACK, Block Ack.
- **Data frames:** carry the actual payload.

Management frames are unauthenticated in WPA2 by default, which is why
deauthentication attacks work. **Protected Management Frames (PMF,
802.11w)** fixes this and is mandatory in WPA3.

---

## 2. Reconnaissance / Enumeration

### 2.1 Monitor mode

To capture 802.11 frames, the wireless adapter must be in monitor
mode. Not all adapters support it; the chipset matters (Atheros
AR9271, Ralink RT3070, and many Alfa adapters are known-good).

```bash
# Identify the wireless interface
iw dev

# Enable monitor mode (modern approach with iw)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify
iw dev wlan0 info
```

Expected output:

```text
Interface wlan0
        type monitor
        channel 1 (2412 MHz), width: 20 MHz
```

Alternative (older): `airmon-ng start wlan0` creates `wlan0mon`.

### 2.2 Basic frame capture

```bash
# Capture all frames on channel 6
sudo tcpdump -i wlan0 -nn -e -c 20

# Or with airodump-ng (see file 02)
sudo airodump-ng wlan0
```

Expected output (beacon frame):

```text
12:34:56:78:9a:bc > ff:ff:ff:ff:ff:ff, Beacons, SSID: "CorpWiFi",
    BSSID: 12:34:56:78:9a:bc, Channel: 6, Privacy: WPA2
```

### 2.3 Identify the security type

Look at the **Privacy** and **Cipher** fields in the beacon:

- `Privacy: Open` - open network.
- `Privacy: WEP` - WEP (broken).
- `Privacy: WPA2` with `PSK` - WPA2-Personal.
- `Privacy: WPA2` with `802.1X` - WPA2-Enterprise (RADIUS).
- `Privacy: WPA3` with `SAE` - WPA3-Personal.
- `Privacy: WPA3` with `802.1X` - WPA3-Enterprise.

### 2.4 Identify EAP methods (enterprise)

For 802.1X networks, capture the EAP exchange during association:

```bash
sudo tcpdump -i wlan0 -nn 'eapol'
```

Look at the **EAP-Request/Identity**, then the **EAP-Response** from
the client. The method (PEAP, EAP-TLS, EAP-TTLS, EAP-FAST) is
identified in the EAP-Request from the server.

Expected output:

```text
EAP-Request, Identity
EAP-Response, Identity (username: CORP\\jdoe)
EAP-Request, PEAP (Start)
EAP-Response, PEAP (ClientHello)
```

---

## 3. Common Attack Vectors

### 3.1 Deauthentication (management frame)

Send forged deauth frames to a client, pretending to be the AP. The
client disconnects. Repeated deauth keeps it offline. Used to:

- Capture the 4-way handshake when the client reconnects.
- Force a client to connect to a rogue AP (evil twin).
- Cause denial of service.

**Mitigation:** PMF (802.11w) makes deauth frames authenticated.

### 3.2 Evil twin

Broadcast a fake AP with the same SSID as the legitimate one. Clients
connect to the attacker's AP (stronger signal). The attacker proxies
authentication to the legitimate AP or captures credentials directly.

**Two variants:**

- **Open evil twin** - fake open network, victim is tricked into using
  it (captive portal).
- **WPA2 evil twin** - attacker knows the PSK (e.g. from a previous
  capture), or relays 802.1X to a real RADIUS server.

### 3.3 KRACK (Key Reinstallation Attack)

Vulnerability in the WPA2 4-way handshake. The attacker manipulates
the handshake to reinstall a key the client already knows. Breaks
confidentiality and integrity of WPA2 traffic.

**Patched in 2017.** Modern OSes are not vulnerable, but legacy IoT
devices may still be.

### 3.4 Downgrade attacks

- **WPA3 -> WPA2 transition mode:** if the AP supports both, force the
  client to use WPA2 (which has the 4-way handshake weakness).
- **EAP method downgrade:** force the client to use a weaker EAP
  method (e.g. PEAP-MSCHAPv2 instead of EAP-TLS).

### 3.5 Rogue AP (not evil twin)

A completely separate AP, often set up by a user ("I need better Wi-Fi
in my office"). It may bypass network controls (no NAC, no firewall).
Common in corporate environments, easy to detect with a WIPS.

### 3.6 Ad-hoc / P2P

Direct client-to-client connections (Wi-Fi Direct, ad-hoc mode). May
bypass the corporate network entirely. Attackers can impersonate a
legitimate peer.

---

## 4. Exploitation Recipes

### 4.1 Capture management and data frames

```bash
# Capture all frames including management
sudo tcpdump -i wlan0 -nn -e -s 0 -w capture.pcap

# Filter by frame type (management = type 0, control = 1, data = 2)
sudo tcpdump -i wlan0 -nn 'wlan type mgt'
```

### 4.2 Deauth a single client

```bash
# Find the client MAC first (airodump-ng), then:
sudo aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT_MAC> wlan0
```

Expected output:

```text
20:15:32  Sending 64 directed DeAuth (code 7). STMAC: [CLIENT_MAC] [ 0| 0 ACKs]
20:15:33  Sending 64 directed DeAuth (code 7). STMAC: [CLIENT_MAC] [63|58 ACKs]
```

### 4.3 Capture the 4-way handshake

```bash
# Terminal 1: capture on the target channel
sudo airodump-ng -c 6 --bssid <BSSID> -w handshake wlan0

# Terminal 2: deauth a connected client to force reconnection
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0
```

`airodump-ng` shows `WPA handshake: <BSSID>` in the top-right corner
when the handshake is captured.

### 4.4 Build an evil twin (concept)

```bash
# Create a fake AP with the same SSID
sudo airbase-ng -e "CorpWiFi" -c 6 wlan0

# Or with hostapd (more configurable)
# /etc/hostapd/hostapd.conf:
#   interface=wlan0
#   ssid=CorpWiFi
#   channel=6
#   driver=nl80211
sudo hostapd /etc/hostapd/hostapd.conf
```

Combine with a DHCP server and a captive portal (see file 03 for
the full evil twin workflow).

### 4.5 Detect downgrade (concept)

Use `wireshark` to inspect the EAP exchange. If the server offers
PEAP-MSCHAPv2 but the client supports EAP-TLS, the attacker can
manipulate the negotiation to force the weaker method. Detection:
compare the offered methods against the client's supported list.

---

## 5. Post-Exploitation

Wireless attacks yield different artifacts depending on the target:

- **WPA2-PSK:** captured 4-way handshake or PMKID -> crack offline
  (file 03).
- **WPA3-SAE:** no offline attack; requires an active attack (file 04).
- **WPA2-Enterprise:** captured EAP exchange -> crack MSCHAPv2 offline
  (file 05), or relay the authentication.
- **Open network:** direct traffic capture (all frames visible).

Once associated to the wireless network, the attacker is on the same
Layer 2 segment as the wired clients. All Layer 2 attacks from file 05
(ARP spoofing, VLAN hopping, DNS/DHCP) apply.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | Medium (WPA2) to Critical (Enterprise credential theft) |
| Preconditions | Attacker in radio range (typically 50-100 m indoors) |
| Detectability | High - WIDS/WIPS detects rogue APs and deauth storms |
| Business impact | Network access, credential theft, lateral movement |

Wireless is often an overlooked **initial access** vector in
assessments. Physical proximity is the only requirement.

---

## 7. Root Causes (AppSec)

- Management frames are unauthenticated in WPA2 (fixed by PMF).
- WPA2-PSK is offline-crackable once the handshake is captured.
- WPS PIN is a small keyspace (brute-forceable in hours).
- WPA3 transition mode allows downgrade to WPA2.
- Enterprise 802.1X without server certificate validation allows
  evil twin with RADIUS impersonation.
- Legacy EAP methods (PEAP-MSCHAPv2) leak crackable material.
- Users trust SSIDs without verifying the AP's identity.

---

## 8. Preventive Controls (AppSec)

### 8.1 Use WPA3 where possible

- WPA3-Personal (SAE) removes the offline dictionary attack on the
  handshake.
- WPA3-Enterprise requires PMF and supports 192-bit mode (Suite B).
- For mixed environments, use WPA3 transition mode with PMF
  **required** (not optional).

### 8.2 Enable Protected Management Frames (PMF)

```text
# hostapd.conf
ieee80211w=2
```

Values: `0` = disabled, `1` = optional, `2` = required.

PMF prevents deauth and disassociation attacks.

### 8.3 Strong passphrases

```text
# Minimum recommended: 20+ characters, or a 5-word Diceware passphrase
# Example: "correct horse battery staple 7" (Diceware-style)
```

A strong passphrase does not stop the handshake capture, but it makes
the offline crack infeasible.

### 8.4 Disable WPS

```text
# hostapd.conf
wps_state=0
```

Or in the AP's web interface: disable WPS entirely.

### 8.5 Enterprise: enforce EAP-TLS with server cert validation

- Use EAP-TLS (client certificate) instead of PEAP-MSCHAPv2.
- Configure clients to validate the RADIUS server's certificate
  against a trusted CA.
- Deploy a private CA and distribute the root certificate via GPO/MDM.

### 8.6 Segment the wireless network

- Put guest Wi-Fi on a separate VLAN with no access to internal
  resources.
- Use a captive portal with per-user authentication.
- Apply the same firewall rules as a wired DMZ.

---

## 9. Detection Controls (AppSec)

### 9.1 WIDS / WIPS

A Wireless Intrusion Detection/Prevention System monitors the RF
spectrum for:

- Rogue APs (BSSIDs not in the authorized list).
- Evil twins (same SSID, different BSSID, suspicious patterns).
- Deauth storms (many deauth frames in a short window).
- MAC spoofing (same MAC on two different APs).

**Products:** Cisco DNA Center, Aruba AirWave, Aruba ClearPass,
Ekahau, Netscout, WatchGuard WIPS.

### 9.2 RF spectrum analysis

- **Ekahau Sidekick / Wi-Spy:** physical RF analysis.
- **Kismet:** open-source wireless IDS with logging.
- **Wireshark with monitor mode:** manual analysis.

### 9.3 EAP method anomalies

- A client using an EAP method it does not normally use
  (downgrade attempt).
- RADIUS server certificate mismatches.
- New devices in the enterprise wireless (MAC not in the inventory).

### 9.4 SIEM rules

- Alert on new BSSID with an authorized SSID.
- Alert on deauth storm (> N frames/sec on a channel).
- Alert on RADIUS authentication failures across many clients.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **PMF:** run `aireplay-ng --deauth` against a WPA3 client. The
   client should not disconnect (PMF drops the forged deauth).
2. **WPS disabled:** run `wash -i wlan0` and `reaver` against the AP.
   WPS should not be advertised, and the PIN should not be brute-forceable.
3. **EAP-TLS:** attempt an evil twin with a self-signed certificate.
   The client should refuse to connect (server cert validation fails).
4. **WIPS:** set up a rogue AP with the same SSID. The WIPS should
   alert within minutes.
5. **Guest isolation:** from the guest VLAN, try to reach an internal
   server. Should be blocked.

---

## 11. OSCP Notes

Wireless is **not** in the OSCP exam. It is relevant for:

- Real internal engagements where physical proximity is available.
- PEN-210 (OSCP+) covers wireless more deeply.
- Red team operations that include RF access.

For the report, focus on the **defensive controls**: WPA3, PMF,
EAP-TLS, WIPS. These show awareness beyond the standard OSCP scope.

---

## 12. Production Notes

- **Wireless requires special hardware.** Not all Wi-Fi adapters
  support monitor mode and packet injection. Check the chipset
  before buying.
- **Monitor mode disables normal network connectivity** on that
  adapter. Use a dedicated USB adapter for wireless attacks, keep
  the built-in Wi-Fi for internet.
- **WPA3 is the future.** As of 2026, most new enterprise APs
  support it. WPA2-PSK should be considered a fallback for legacy
  devices only.
- **Deauth attacks are loud.** Any WIPS will alert immediately.
  Assume detection.
- **Evil twins are also loud** if the WIPS monitors RF. In an
  unmonitored environment, they can go unnoticed for days.

---

## 13. References

- IEEE 802.11-2020 - Wireless LAN Medium Access Control (MAC) and
  Physical Layer (PHY) Specifications
- IEEE 802.11i-2004 - Medium Access Control Security Enhancements
- IEEE 802.11w-2009 - Protected Management Frames
- IEEE 802.11ax-2021 - Wi-Fi 6
- Wi-Fi Alliance - WPA3 Specification
- MITRE ATT&CK T1557 - Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1200 - Hardware Additions - https://attack.mitre.org/techniques/T1200/
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- Kali Linux documentation - Wireless Attacks
- `man iw`, `man tcpdump`, `man airmon-ng`
