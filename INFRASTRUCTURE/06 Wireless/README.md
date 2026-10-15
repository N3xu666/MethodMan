# Wireless

Attacks against 802.11 networks: reconnaissance, WPA/WPA2 handshake
capture and cracking, WPA3 and WPS weaknesses, enterprise (802.1X)
attacks, and the controls that stop them. Each file covers the
offensive technique and the defensive control.

This is the sixth subcategory of `INFRASTRUCTURE/`. Wireless is a
shared medium: any client in radio range can observe and inject
frames, regardless of network segmentation on the wired side.

Writeups and references are in English. Every file follows the
Two-track format (Offensive / Defensive), same 13-section skeleton
as the other INFRASTRUCTURE subcategories.

---

## Scope

| # | File | Offensive focus | Defensive focus |
|---|------|-----------------|-----------------|
| 01 | [Wireless Fundamentals](./01%20Wireless%20Fundamentals.md) | 802.11 frames, WPA2/WPA3, EAP, RADIUS | WPA3, PMF, EAP-TLS |
| 02 | [Reconnaissance](./02%20Reconnaissance.md) | airodump-ng, kismet, wash, hcxdumptool | SSID hygiene, rogue AP detection |
| 03 | [WPA/WPA2 Attacks](./03%20WPA%20WPA2%20Attacks.md) | Handshake capture, PMKID, deauth, evil twin | WPA3, PMF, strong passphrases, WIDS |
| 04 | [WPA3 and WPS Attacks](./04%20WPA3%20and%20WPS%20Attacks.md) | Dragonblood, WPS PIN, pixie dust | Disable WPS, WPA3-SAE, patched firmware |
| 05 | [Enterprise (802.1X) Attacks](./05%20Enterprise%20802.1X%20Attacks.md) | Evil twin + RADIUS, EAP downgrade, cert attacks | EAP-TLS, server cert validation, NAC |
| 06 | [Wireless Defense](./06%20Wireless%20Defense.md) | (defensive focus) | WIDS/WIPS, 802.11w, WPA3-Enterprise, NAC, monitoring |

---

## How to use this subcategory

- **Offensive track** - detection, tooling, exploitation recipes.
  Aimed at a pentester with written authorization.
- **Defensive track** - controls, detection rules, verification.
  Aimed at a blue teamer or a sysadmin hardening the same network.

Each file is self-contained. Read `01 Wireless Fundamentals` first if
the 802.11 terminology is unfamiliar, then return to the specific
attack or defense file.

---

## Relationship to other categories

| Category | Relationship |
|----------|--------------|
| `INFRASTRUCTURE/05 Network Attacks` | After associating to a wireless network, the same Layer 2 attacks apply (ARP, VLAN, DNS/DHCP). |
| `INFRASTRUCTURE/01 Active Directory` | Enterprise wireless (802.1X) often authenticates against AD; captured credentials feed AD attacks. |
| `INFRASTRUCTURE/02 Windows Infrastructure` | Certificate-based EAP-TLS depends on the Windows PKI. |
| `INFRASTRUCTURE/04 Network Services` | RADIUS, DNS, DHCP all serve the wireless network. |

---

## References

- IEEE 802.11 - Wireless LAN Medium Access Control
- IEEE 802.11i - WPA2 (RSN)
- IEEE 802.11w - Protected Management Frames (PMF)
- IEEE 802.11ax - Wi-Fi 6
- WPA3 Specification (Wi-Fi Alliance)
- MITRE ATT&CK T1557 - Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1200 - Hardware Additions - https://attack.mitre.org/techniques/T1200/
- NIST SP 800-153 - Guidelines for Securing Wireless Local Area Networks

---

## Authorized Use Only

All techniques in this subcategory are for **authorized penetration
testing, CTF environments (Hack The Box, OSCP labs), and educational
purposes only**. Deauthenticating clients, capturing handshakes, or
operating a rogue AP against a network you do not own or have written
permission to test is illegal in most jurisdictions.

See the repository [SECURITY.md](../../SECURITY.md) for the full
policy and the abuse-report contact.
