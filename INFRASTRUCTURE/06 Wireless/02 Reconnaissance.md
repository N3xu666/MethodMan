# Wireless Reconnaissance

Passive and active discovery of 802.11 networks: what is broadcasting,
who is connected, what security is in use, what is hidden. This is the
first phase of any wireless assessment - it requires no interaction
with the target and is hard to detect when done passively.

> [!CAUTION]
> Passive monitoring of a wireless network you do not own may be
> illegal in some jurisdictions. Active probing (sending frames)
> is clearly intrusive. Only run these techniques against networks
> you own or have written authorization to test.

---

## 1. Overview

Wireless reconnaissance answers four questions:

- **What networks are in range?** SSIDs, BSSIDs, channels, signal strength.
- **Who is connected?** Client MACs, vendors, active sessions.
- **What security is in use?** WPA2-PSK, WPA3-SAE, 802.1X, open, WEP.
- **What is hidden?** Hidden SSIDs, non-broadcasting APs, rogue APs.

The two modes:

- **Passive:** listen to beacons and probe responses. No frames sent
  by the attacker. Undetectable without a WIPS watching for monitor-
  mode adapters (which is not standard).
- **Active:** send probe requests, association requests, or deauth
  frames. Detectable by WIPS and by clients (they see the frames).

For most engagements, start passive, then go active only if needed.

---

## 2. Reconnaissance / Enumeration

### 2.1 Put the adapter in monitor mode

See `01 Wireless Fundamentals` section 2.1. The adapter must be in
monitor mode before any tool below will work.

### 2.2 Airodump-ng (passive, classic)

```bash
sudo airodump-ng wlan0
```

Expected output (trimmed):

```text
BSSID              PWR  Beacons  #Data  CH  ENC   CIPHER  AUTH  ESSID
12:34:56:78:9A:BC  -45      120    340   6  WPA2  CCMP    PSK   CorpWiFi
12:34:56:78:9A:BD  -67       80     12   1  WPA2  CCMP    802.1X Corp-Enterprise
AA:BB:CC:DD:EE:FF  -80       20      0  11  WPA3  CCMP    SAE   GuestWiFi
```

Columns:

- **PWR** - signal strength (closer to 0 is stronger).
- **Beacons** - number of beacon frames (a busy AP sends more).
- **#Data** - data frames seen (encrypted, but the count is visible).
- **CH** - channel.
- **ENC/CIPHER/AUTH** - security configuration.
- **ESSID** - network name (empty = hidden SSID).

### 2.3 Airodump-ng with client list

```bash
sudo airodump-ng wlan0
# In the bottom section, airodump shows connected clients:
```

Expected output (bottom section):

```text
BSSID              STATION            PWR  Rate  Lost  Frames  Notes  Probes
12:34:56:78:9A:BC  AA:11:BB:22:CC:33  -50  54-54   0     120
12:34:56:78:9A:BC  DD:44:EE:55:FF:66  -60  48-48  10      85  CorpWiFi
```

Client MACs (STATION column) are the target list for deauth
(file 03) and evil twin (file 05).

### 2.4 Kismet (passive, logging-friendly)

```bash
sudo kismet -c wlan0
# Web UI: http://localhost:2501
```

Kismet logs to a database and can run for hours. Better than
airodump-ng for long engagements.

### 2.5 Wireshark with monitor mode

```bash
sudo wireshark
# Select wlan0 (monitor mode) as capture interface
# Apply filter: wlan.fc.type == 0 (management frames only)
```

Wireshark is best for inspecting specific frame contents (probe
requests, EAP exchanges, RSN information elements).

### 2.6 Wash (find WPS-enabled APs)

```bash
sudo wash -i wlan0
```

Expected output:

```text
BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
12:34:56:78:9A:BC   6  -45  1.0  No   Broadcom  CorpWiFi
AA:BB:CC:DD:EE:FF  11  -80  2.0  Yes  Realtek   LegacyAP
```

WPS 1.0/2.0 = WPS version. Lck = locked. See file 04 for WPS attacks.

### 2.7 hcxdumptool (modern, active)

```bash
sudo hcxdumptool -i wlan0 -o capture.pcapng --enable_status=1
```

Sends probe requests and captures PMKID from APs (file 03). More
active than airodump-ng, but also noisier.

### 2.8 Identify client vendors (MAC OUI)

```bash
# From airodump-ng client list, look up the OUI:
# AA:11:BB:22:CC:33 -> first 3 bytes "AA:11:BB"
curl -s "https://api.macvendors.com/AA:11:BB"
```

Or use a local OUI file: `/usr/share/wireshark/manuf`.

Expected output:

```text
Apple, Inc.
```

Vendor helps identify the client type (laptop, phone, IoT) and
suggests potential attack paths (e.g. IoT devices rarely support
WPA3 or PMF).

---

## 3. Common Attack Vectors

### 3.1 Passive mapping

Simply observe. Record all SSIDs, BSSIDs, channels, security types,
and connected clients over a period. The output is an RF map of the
target environment.

**Best practice:** run for at least 1 hour, ideally during business
hours, to capture the full client population. Walk the physical
perimeter to find rogue APs outside the building.

### 3.2 Hidden SSID discovery

Some APs do not broadcast their SSID in beacons (SSID field is empty).
Clients still send the SSID in probe requests when connecting.

```bash
# Listen for probe requests with hidden SSID
sudo airodump-ng wlan0
# Or with Wireshark filter:
#   wlan.fc.type_subtype == 0x04 (probe request)
```

When a client associates to a hidden AP, the SSID appears in the
association request. Capture that and the network is no longer hidden.

**Important:** hidden SSID is a cosmetic measure, not a security
control. It adds seconds to the recon phase.

### 3.3 Client fingerprinting via probe requests

Every client periodically broadcasts probe requests for networks it
has previously connected to. These leak:

- **Preferred Network List (PNL):** every SSID the client has saved.
- **Device type:** from the probe request information elements.
- **User behavior:** which networks the user connects to (home,
  coffee shops, airports).

This data can be used for social engineering and to identify clients.

### 3.4 Rogue AP discovery

Rogue APs = APs in the environment that are not authorized by IT.
Common sources: user-owned hotspots, printers with built-in APs,
mobile hotspots.

Detect by comparing observed BSSIDs to the authorized inventory. If
the inventory is not available, look for:

- SSIDs that look like corporate names but are not in the official list.
- BSSIDs from non-enterprise vendors (consumer routers, travel routers).
- Signal strength inconsistent with a known AP location.

### 3.5 Physical site survey

A walk-around with a laptop and a directional antenna maps coverage
and finds APs not visible from the central location. Useful for:

- Finding "hidden" APs behind walls or in ceilings.
- Identifying coverage gaps (an attacker can set up a rogue AP there).
- Locating the source of an unauthorized signal.

### 3.6 Wi-Fi 6 / 6 GHz reconnaissance

Wi-Fi 6E and Wi-Fi 7 add the 6 GHz band. Some tools do not yet
support it, and monitor-mode adapters for 6 GHz are rare. If the
target uses 6 GHz, check tool compatibility first.

---

## 4. Exploitation Recipes

### 4.1 Full passive capture (1 hour)

```bash
# Airodump-ng, all bands, one file per band
sudo airodump-ng --band abg -w survey wlan0
# Output: survey-01.cap, survey-01.csv, survey-01.kismet.csv
```

### 4.2 Focused capture on a target

```bash
# Single AP, single channel
sudo airodump-ng -c 6 --bssid 12:34:56:78:9A:BC -w target wlan0
```

Use this after the broad survey has identified the target AP.

### 4.3 Target a specific client

```bash
# Capture only traffic to/from a specific client MAC
sudo airodump-ng -c 6 --bssid 12:34:56:78:9A:BC \
    --showack -w client wlan0
# In the client list, note the STATION MAC for later use
```

### 4.4 Extract the preferred network list (PNL)

```bash
# From a pcap, extract probe request SSIDs
tshark -r survey-01.cap -Y "wlan.fc.type_subtype == 0x04" \
    -T fields -e wlan.ssid | sort -u
```

Expected output:

```text
CorpWiFi
HomeNetwork-5G
Starbucks
Airport_Free_WiFi
HotelGuest
```

Every SSID here is a potential attack vector (evil twin, file 03).

### 4.5 Extract EAP identities from a pcap

```bash
# Extract usernames from EAP-Response/Identity frames
tshark -r survey-01.cap -Y "eap.type == 1" \
    -T fields -e eap.identity | sort -u
```

Expected output:

```text
CORP\\jdoe
CORP\\asmith
host/laptop-042.corp.local
```

Domain usernames leak even in encrypted 802.1X. Useful for later
password spraying (see `05 Network Attacks`, file 06).

### 4.6 Physical survey with GPS logging

```bash
# Kismet with GPS (for outdoor surveys)
sudo kismet -c wlan0 --gps
```

Kismet logs GPS coordinates with each BSSID. Useful for war-driving
or mapping a large campus.

---

## 5. Post-Exploitation

Reconnaissance output feeds directly into the later files:

- **BSSID + channel + security** -> choose the right attack (file 03
  for WPA2, file 04 for WPA3/WPS, file 05 for enterprise).
- **Client MACs** -> deauth targets (file 03) and evil twin victims
  (file 05).
- **PNL** -> evil twin SSIDs to impersonate (user devices will
  auto-connect to their preferred networks).
- **EAP identities** -> username list for password spraying against
  the AD (see `01 Active Directory`).
- **Hidden SSID** -> now known, can be targeted.

The quality of the recon determines the success of the later phases.
Do not skip this step.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | Informational (recon itself) |
| Preconditions | Attacker in radio range |
| Detectability | Low (passive) to Medium (active probes) |
| Business impact | Enables all later attacks; leaks PNL and identities |

Reconnaissance is not a vulnerability. The vulnerabilities are the
weak security configurations and client behaviors that recon reveals.

---

## 7. Root Causes (AppSec)

- Beacons broadcast the SSID (by design).
- Probe requests broadcast the client's PNL (by design, though
  randomization is available in modern OSes).
- EAP-Identity leaks the domain username before any encrypted
  exchange.
- Hidden SSIDs are cosmetic, not security.
- No centralized inventory of authorized APs -> rogue APs go
  unnoticed.

---

## 8. Preventive Controls (AppSec)

### 8.1 MAC address randomization

Modern OSes (iOS 14+, Android 10+, Windows 10+) randomize the MAC
per network or per session. This breaks client tracking but does not
stop probe request analysis.

```text
# Enforce randomization on managed devices via MDM
# (iOS: Settings > Wi-Fi > network > Private Wi-Fi Address = On)
```

### 8.2 Probe request suppression

Some OSes (via MDM or registry) can suppress probe requests for
non-broadcast SSIDs. Reduces PNL leakage.

```text
# Windows registry (per adapter):
HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters
  ScanMode = 1  (passive scanning)
```

### 8.3 Do not rely on hidden SSID

Configure APs to broadcast the SSID. Hiding it adds no security and
complicates legitimate troubleshooting.

```text
# hostapd.conf - broadcast SSID (default)
ignore_broadcast_ssid=0
```

### 8.4 Authorized AP inventory

Maintain a list of authorized BSSIDs and their locations. Compare
against observed BSSIDs on a schedule (weekly or daily). Any
unmatched BSSID is a rogue AP candidate.

### 8.5 WIPS deployment

A WIPS (see `01 Wireless Fundamentals`, section 9.1) detects rogue
APs, evil twins, and deauth storms in real time. Essential for any
large deployment.

### 8.6 Guest network with client isolation

Guests should be on a separate VLAN with client isolation enabled.
Prevents guest-to-guest reconnaissance and lateral movement.

---

## 9. Detection Controls (AppSec)

### 9.1 WIPS-detected activities

- Monitor-mode adapters seen in the RF (rare, requires RF fingerprinting).
- Active probes (probe requests for SSIDs that do not exist).
- Unusual client MACs (not in the authorized inventory).

### 9.2 RF fingerprinting

APs and clients have subtle differences in their frame timing and
power output. RF fingerprinting can identify specific hardware, even
if the MAC is spoofed.

### 9.3 Probe request analysis (defensive)

Monitor probe requests in the environment to identify:

- Non-corporate SSIDs (clients have saved home/coffee-shop networks).
- Attack tools (some tools send distinctive probe requests).

### 9.4 SIEM rules

- Alert on new BSSIDs not in the authorized inventory.
- Alert on clients with randomized MACs connecting to corporate SSIDs
  (may indicate unauthorized devices).
- Alert on probe requests for known-malicious SSIDs (e.g. common
  evil twin names like "FreeWiFi", "Starbucks", "Airport").

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **MAC randomization:** from a managed device, connect to Wi-Fi.
   Check the AP's client list - the MAC should not match the device's
   hardware MAC.
2. **Rogue AP detection:** set up a rogue AP in the office. The WIPS
   should alert within minutes.
3. **Hidden SSID:** if any AP has `ignore_broadcast_ssid=1`, change
   it to 0. Re-run a passive scan - the SSID should now be visible.
4. **AP inventory:** run `airodump-ng` for 1 hour and compare the
   BSSID list to the authorized inventory. Any mismatch is a finding.
5. **Guest isolation:** from a guest device, try to reach another
   guest device. Should fail.

---

## 11. OSCP Notes

Wireless reconnaissance is **not** in the OSCP exam. It is relevant
for:

- Real internal engagements where physical access is available.
- Red team operations that include RF reconnaissance.
- Physical security assessments that include Wi-Fi coverage.

For the report, document the methodology (passive vs active), the
duration of the capture, and the findings (SSIDs, security types,
client behavior). Screenshots of airodump-ng output are useful.

---

## 12. Production Notes

- **Walk the perimeter.** Many rogue APs are just outside the
  building (in a parking lot, a neighboring office, or a coffee shop).
  You cannot find them from a single location.
- **Time matters.** A 15-minute scan misses clients that connect
  occasionally. Run for hours, ideally during business hours.
- **Passive is invisible.** Active probing is not. If the target has
  a WIPS, stay passive.
- **Store captures securely.** A pcap with EAP identities and client
  MACs is sensitive data. Encrypt it and delete after the engagement.
- **Do not scan at excessive power.** A high-gain antenna picks up
  networks from far away but may violate local RF regulations
  (max EIRP).

---

## 13. References

- [Aircrack-ng suite](https://www.aircrack-ng.org/) - airodump-ng,
  aireplay-ng, airmon-ng
- [Kismet](https://www.kismetwireless.net/) - wireless IDS and survey
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool) - modern
  PMKID capture
- [Wireshark](https://www.wireshark.org/) - frame analysis
- [Wash](https://github.com/t6x/reaver-wps-fork-t6x) - WPS scan
- [MACVendors API](https://macvendors.com/) - OUI lookup
- IEEE 802.11-2020 - Wireless LAN Medium Access Control
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks
- Kali Linux documentation - Wireless Attacks
- `man airodump-ng`, `man kismet`, `man wash`, `man tshark`