# Wireless Defense

Monitoring, detection, and hardening of wireless networks. WIDS/WIPS
deployment, RF monitoring, wireless NAC, and the operational practices
that keep a wireless network secure. This file is defensive-only: it
does not introduce new attacks, it closes them.

> [!NOTE]
> This file has no offensive track. It is the defensive counterpart
> to files 01-05. Read those first to understand what is being
> defended against.

---

## 1. Overview

Wireless defense has four layers:

- **Configuration** - use the strongest available crypto (WPA3, PMF,
  EAP-TLS), disable what is not needed (WPS, WPA, TKIP).
- **Monitoring** - WIDS/WIPS to detect rogue APs, evil twins, deauth
  storms, and policy violations in real time.
- **Access control** - NAC (802.1X, MAB, profiling) to ensure only
  authorized devices join.
- **Segmentation** - guest VLANs, client isolation, firewall rules
  between wireless and wired networks.

A wireless network without monitoring is a black box: rogue APs and
evil twins can operate for months without being noticed. Monitoring
is not optional.

---

## 2. WIDS / WIPS

### 2.1 What they detect

- **Rogue APs** - BSSIDs not in the authorized inventory.
- **Evil twins** - same SSID, different BSSID, suspicious location.
- **Deauth storms** - many deauth frames in a short window.
- **MAC spoofing** - same MAC on two APs simultaneously.
- **WPS attacks** - repeated WPS PIN attempts.
- **SAE DoS** - SAE commit floods.
- **Policy violations** - clients using prohibited security types.

### 2.2 Deployment modes

- **Overlay** - dedicated sensors placed alongside production APs.
  Best detection, highest cost.
- **Integrated** - APs double as sensors when not serving clients.
  Lower cost, less coverage.
- **Hybrid** - sensors in critical areas, integrated elsewhere.

### 2.3 Products (2026)

- **Cisco DNA Center / Spaces** - enterprise, integrated with Catalyst.
- **Aruba AirWave / ClearPass** - HPE Aruba, popular in mid-market.
- **Ekahau** - site survey + WIPS.
- **Netscout (formerly Aerohive)** - cloud-managed.
- **WatchGuard WIPS** - SMB-focused.
- **Kismet** - open-source, manual monitoring.

### 2.4 Kismet as a lightweight WIDS

```bash
# Kismet with a WIDS configuration
sudo kismet -c wlan0

# In the web UI (http://localhost:2501):
#   - Add authorized BSSIDs to the "known" list
#   - Enable alerts for unknown BSSIDs
#   - Log everything to a database
```

Kismet is not a full WIPS but is useful for small environments and
for validating coverage.

---

## 3. Common Attack Vectors (defensive context)

This section describes the attacks that the controls in section 8
mitigate. Full details in files 01-05.

### 3.1 Rogue AP / evil twin

An attacker sets up an AP with the same SSID as the legitimate
network. Clients may connect to it (stronger signal, cached
credentials).

**Detection:** WIPS compares observed BSSIDs to the authorized
inventory. Any mismatch triggers an alert.

### 3.2 Deauth storm

An attacker floods the channel with deauth frames, disconnecting
clients. Used to force reconnection (handshake capture) or as DoS.

**Detection:** WIPS counts deauth frames per channel per unit time.

### 3.3 WPS brute force

An attacker sends thousands of WPS PIN attempts, trying to recover
the PSK.

**Detection:** WIPS counts WPS attempts per client MAC per unit time.

### 3.4 SAE DoS (WPA3)

An attacker sends many SAE commit messages, exhausting the AP's CPU.

**Detection:** WIPS counts SAE commit messages per second.

### 3.5 PMKID capture

An attacker passively captures PMKID from APs that support it.

**Detection:** not directly detectable (passive). Mitigation: disable
PMKID caching where possible, use WPA3.

### 3.6 EAP downgrade

An attacker offers a weaker EAP method during the handshake.

**Detection:** WIPS inspects the EAP negotiation and alerts on
unexpected methods.

### 3.7 Wireless client attacks

An attacker on the same wireless network can ARP-spoof, DNS-spoof,
or relay NTLM to other wireless clients.

**Detection:** standard network monitoring (NetFlow, IDS) plus
wireless client isolation.

---

## 4. Detection Recipes

### 4.1 Authorized BSSID inventory

```text
# Maintain a list of authorized BSSIDs with locations:
#   BSSID              Location           SSID
#   12:34:56:78:9A:BC  Floor 1, NE        CorpWiFi
#   12:34:56:78:9A:BD  Floor 1, NW        Corp-Enterprise
#   ...
# Compare observed BSSIDs against this list on a schedule.
```

### 4.2 Deauth storm detection (Wireshark)

```bash
# Filter for deauth frames
wlan.fc.type_subtype == 0x0c

# Count per second in Wireshark:
#   Statistics > IO Graph
#   Filter: wlan.fc.type_subtype == 0x0c
#   Plot: packets per second
```

A normal network has near-zero deauth frames. Any sustained rate
(> 10/sec) is suspicious.

### 4.3 Evil twin detection with Kismet

```bash
# In Kismet web UI:
#   1. Add authorized BSSIDs to the "known" list
#   2. Monitor the "Alerts" tab
#   3. Any BSSID with an authorized SSID but not in the list
#      triggers a "rogue AP" alert
```

### 4.4 WPS attack detection

```bash
# In Kismet or Wireshark:
#   Filter: wps.message_type == 0x07 (M7 - WPS exchange)
#   Count per source MAC; alert on > 10 per minute
```

### 4.5 RF spectrum analysis

```bash
# Ekahau Sidekick / Wi-Spy for physical RF analysis
# Detects interferers, rogue APs, and coverage anomalies
```

Physical RF analysis catches what packet-level monitoring misses:
interference sources, hidden devices, and unauthorized RF activity.

---

## 5. Post-Exploitation (defensive)

After a wireless incident:

- **Isolate the attacker's AP.** If it is on the corporate network,
  disconnect the port (if wired) or block the BSSID.
- **Revoke credentials** captured by the attacker (change passwords,
  reissue certificates, rotate PSK).
- **Hunt for lateral movement.** Wireless is often the entry point;
  check logs for subsequent activity on the wired network.
- **Update the authorized inventory.** If the rogue AP was a
  legitimate but undocumented device, add it.
- **Review the incident.** What detection failed? What process needs
  to change?

---

## 6. Risk Context

| Factor | Value |
|--------|-------|
| Typical severity | Varies (depends on the attack) |
| Preconditions | Attacker in radio range |
| Detectability | High with WIPS, Low without |
| Business impact | Network access, credential theft, lateral movement |

Wireless is often the **least monitored** part of a corporate
network. A WIPS closes this gap.

---

## 7. Root Causes

- No WIPS deployment (no visibility).
- No authorized AP inventory (cannot detect rogues).
- Legacy crypto (WPA, TKIP, WPS) enabled for compatibility.
- No server certificate validation on clients (enterprise).
- Weak PSK passphrases (personal).
- No client isolation on guest networks.
- Wireless VLAN bridged to the wired network.

---

## 8. Preventive Controls

### 8.1 Use WPA3 everywhere

- WPA3-Personal (SAE) for personal networks.
- WPA3-Enterprise (192-bit) for corporate.
- Disable transition mode where possible.
- Disable WPA2 fallback if all clients support WPA3.

```text
# hostapd.conf - WPA3-SAE only
wpa=2
wpa_key_mgmt=SAE
ieee80211w=2
sae_password=<STRONG_PASSPHRASE>
```

### 8.2 Enable PMF (mandatory)

```text
# hostapd.conf
ieee80211w=2
```

Required for WPA3, recommended for WPA2.

### 8.3 Disable WPS

```text
# hostapd.conf
wps_state=0
```

Or in the AP web UI.

### 8.4 Enforce EAP-TLS with server cert validation

For enterprise:

- Client certificates (EAP-TLS).
- Server certificate validation (check the RADIUS server's cert).
- Trusted CA distributed via GPO/MDM.

See file 05 for the exact GPO settings.

### 8.5 Deploy a WIPS

- Overlay sensors or integrated APs.
- Configure the authorized BSSID inventory.
- Tune alerts (deauth storms, rogue APs, WPS attacks).
- Integrate with the SIEM.

### 8.6 Segment wireless

- Guest VLAN with no access to internal resources.
- Client isolation on guest networks.
- Firewall between wireless and wired networks.
- Separate SSIDs for guest, corporate, and IoT.

### 8.7 NAC for wireless

- 802.1X for corporate devices.
- MAB + profiling for IoT and legacy devices.
- Posture checks (AV running, patched OS) before network access.

### 8.8 Monitor the RF environment

- Physical site surveys (annual or after major changes).
- RF spectrum analysis (interference, rogue devices).
- Walk the perimeter (parking lot, adjacent floors, coffee shops).

### 8.9 Strong passphrases

For WPA2-PSK (if still in use):

```text
# Minimum: 20+ random characters, or 5+ word Diceware passphrase
```

### 8.10 Update AP firmware

APs have vulnerabilities too. Patch regularly.

---

## 9. Detection Controls

### 9.1 WIPS alerts

| Alert | Threshold | Action |
|-------|-----------|--------|
| Rogue AP | New BSSID not in inventory | Investigate immediately |
| Evil twin | Same SSID, different BSSID | Investigate; may be a rogue AP |
| Deauth storm | > 10 deauth frames/sec/channel | Investigate; likely an attack |
| WPS brute force | > 10 WPS attempts/min/client | Investigate; likely an attack |
| SAE DoS | > 100 SAE commits/sec | Rate limit or block |
| MAC spoofing | Same MAC on two APs | Investigate |

### 9.2 SIEM integration

- Forward WIPS logs to the SIEM.
- Correlate with RADIUS logs (authentication failures, unusual methods).
- Correlate with NAC logs (device posture, MAB events).
- Alert on new BSSIDs with authorized SSIDs.

### 9.3 RADIUS log analysis

- Failed authentications (brute force indicator).
- Unusual EAP methods (downgrade indicator).
- Authentication from unexpected NAS (rogue AP indicator).
- Repeated failures for the same user (credential stuffing).

### 9.4 Physical monitoring

- Cameras near APs (to detect physical tampering).
- Door access logs (to correlate with RF anomalies).
- BSSID changes outside change windows.

### 9.5 Periodic audits

- Quarterly wireless site survey.
- Semi-annual authorized BSSID inventory review.
- Annual penetration test (wireless included).

---

## 10. Verification

Test the controls after deployment:

1. **WIPS coverage:** set up a rogue AP in each floor. The WIPS
   should detect it within minutes. If not, coverage is insufficient.
2. **Deauth detection:** run `aireplay-ng --deauth` against a test
   client. The WIPS should alert.
3. **WPS detection:** run `reaver` against a test AP. The WIPS should
   alert within 60 seconds.
4. **Certificate validation:** attempt an evil twin with a self-signed
   cert against a corporate client. The client should reject.
5. **NAC:** plug an unauthorized device into an AP. It should not get
   network access.
6. **Segmentation:** from the guest VLAN, try to reach a corporate
   server. Should fail.
7. **Client isolation:** from one guest client, try to reach another.
   Should fail.

---

## 11. OSCP Notes

Wireless defense is **not** in the OSCP exam. It is relevant for:

- Real-world blue team roles.
- PEN-210 (OSCP+) covers wireless.
- Security architecture discussions.

For the report, focus on:

- The defense-in-depth model (config + monitoring + NAC + segmentation).
- The WIPS deployment and its coverage.
- The verification steps (how you tested the controls).

---

## 12. Production Notes

- **WIPS is essential.** Without it, rogue APs and evil twins go
  undetected. If budget is limited, start with Kismet for critical
  sites.
- **Tune the alerts.** A WIPS that alerts on everything is ignored.
  Tune to the actual threat model (e.g. no alert for a nearby
  coffee-shop SSID, alert for a rogue AP inside the building).
- **Site surveys are not optional.** RF changes with every wall,
  furniture move, and neighboring network. Survey before and after
  major changes.
- **Wireless is a shared medium.** Client isolation is the only way
  to prevent client-to-client attacks on the same SSID.
- **Legacy devices are the enemy of security.** If a device only
  supports WPA/TKIP, put it on a separate SSID with strict firewall
  rules. Do not degrade the main network for one device.
- **NAC + WIPS + segmentation** is the triad. Any one alone is
  insufficient.

---

## 13. References

- Kismet - https://www.kismetwireless.net/ - open-source WIDS
- Ekahau - https://www.ekahau.com/ - site survey and WIPS
- Cisco DNA Center - https://www.cisco.com/c/en/us/products/cloud-systems-management/dna-center/index.html
- Aruba AirWave / ClearPass - https://www.arubanetworks.com/
- Netscout (Aerohive) - https://www.netscout.com/
- WatchGuard WIPS - https://www.watchguard.com/
- WPA3 Specification (Wi-Fi Alliance) - https://www.wi-fi.org/discover-wi-fi/security
- IEEE 802.11w-2009 - Protected Management Frames
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- NIST SP 800-97 - Establishing Wireless Robust Security Networks
- CIS Controls v8 - 12.6 (Network Infrastructure Management)
- MITRE ATT&CK T1557 - Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/
