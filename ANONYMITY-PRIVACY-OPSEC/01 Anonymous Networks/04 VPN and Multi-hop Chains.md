# 04 VPN and Multi-hop Chains

VPNs (Virtual Private Networks) are encrypted tunnels between a client
and a VPN server. On their own, a VPN does **not** provide anonymity:
the VPN provider knows your real IP and can log it. VPNs become an
anonymity tool only when combined with other networks (Tor, I2P) or
with multiple providers in a chain. This file covers VPN types,
multi-hop chains, VPN-over-Tor, Tor-over-VPN, and the mistakes that
break the threat model.

> [!CAUTION]
> **Authorized Use Only.**
>
> VPNs are legal in most jurisdictions, but using a VPN to evade
> lawful investigation, commit unauthorized access, or traffic illegal
> material is prohibited. Running your own VPN server on a VPS is
> legal in most countries but may violate the VPS provider's AUP.
> See `../../../SECURITY.md` for the repository's authorized-use
> policy.

---

## 1. Overview

A VPN is a point-to-point encrypted tunnel between a client and a
VPN server. All traffic from the client is routed through the tunnel
and exits from the VPN server's IP. From the destination's point of
view, the traffic originates from the VPN server, not the client.

**Key properties:**

- **Encrypted tunnel** - the local network (ISP, Wi-Fi) sees only
  encrypted traffic to the VPN server, not the final destination.
- **IP substitution** - the destination sees the VPN server's IP.
- **Trust model** - the VPN provider sees all your traffic and knows
  your real IP (from the connection). A VPN **relocates trust** from
  the ISP to the VPN provider; it does not eliminate it.

**What a VPN is NOT:**

- Not an anonymity network. The VPN provider can log your real IP,
  timestamps, and destinations. A court order or a rogue provider
  deanonymizes you.
- Not a replacement for Tor. Tor distributes trust across three
  relays; a VPN concentrates it in one provider.
- Not a magic bullet against a global adversary. Traffic correlation
  still applies if the adversary observes both ends.

**Multi-hop chains** extend the trust model by using two or more
providers in sequence. The goal is that no single provider knows
both the client's real IP and the destination. This works only if
the providers do not collude.

---

## 2. Threat Model

**A VPN alone defends against:**

- **Local network adversary (ISP, Wi-Fi)** - sees only encrypted
  traffic to the VPN server.
- **Destination server** - sees the VPN server's IP, not the client's.
- **Geographic restrictions** - the VPN server's IP may be in a
  different jurisdiction.

**A VPN alone does NOT defend against:**

- **The VPN provider** - sees your real IP, your destinations, and
  (if the tunnel terminates at the provider) the plaintext of
  unencrypted traffic.
- **A global passive adversary** - can correlate traffic entering
  the VPN server with traffic leaving it (timing, volume).
- **Law enforcement with a court order** - a VPN provider that logs
  can be compelled to hand over logs. A provider that does not log
  cannot, but you must trust that claim.
- **Browser/application leaks** - WebRTC, DNS, and direct
  connections can bypass the VPN tunnel.

**A VPN chain (VPN1 -> VPN2) defends against:**

- **A single provider logging** - neither provider sees both the
  client's real IP and the destination. VPN1 sees the client's IP
  and the fact that the client connects to VPN2. VPN2 sees VPN1's
  IP and the destination.
- **A single provider being compromised** - the adversary sees only
  one hop.

**A VPN chain does NOT defend against:**

- **Colluding providers** - if VPN1 and VPN2 share logs, the chain
  collapses to a single provider.
- **A global passive adversary** - correlation still applies.
- **Timing analysis** - the two tunnels may be linkable by timing
  if the adversary observes both ends.

**Tor-over-VPN vs VPN-over-Tor:**

- **VPN -> Tor:** the VPN provider sees that you use Tor, but not
  your destinations. Tor guards see the VPN server's IP, not yours.
  A compromised VPN cannot deanonymize you; a compromised guard
  sees only a VPN IP.
- **Tor -> VPN:** the VPN provider sees your Tor exit traffic and
  your destinations, but not your real IP (only the Tor exit's IP).
  The VPN provider becomes the equivalent of a Tor exit that you
  trust. A compromised VPN can log all your destinations.

**Choice guidance:**

- **Against the local network:** a single VPN is sufficient.
- **Against the VPN provider:** use a chain of two providers that
  do not collude (different jurisdictions, different ownership).
- **Against a global adversary:** VPN alone is not sufficient;
  combine with Tor or accept residual risk.
- **Against the destination:** a VPN hides your IP but not your
  identity if you log in.

---

## 3. How It Works (technical)

**VPN protocols (common):**

- **WireGuard** - modern, minimal, in-kernel on Linux 5.6+. Uses
  Curve25519, ChaCha20, Poly1305, BLAKE2s. Small attack surface,
  high performance.
- **OpenVPN** - mature, userspace or kernel-accelerated. Uses TLS
  for the control channel and a custom data channel. Large
  configuration surface.
- **IPsec/IKEv2** - in-kernel, used by many enterprise VPNs and
  mobile clients. Complex to configure correctly.
- **PPTP** - obsolete and broken. Do not use.
- **L2TP/IPsec** - older, still seen in the wild. Avoid if a modern
  alternative is available.
- **Shadowsocks / V2Ray / Xray** - not VPNs in the strict sense
  (they are proxies), but often used for the same purpose. Designed
  to resist DPI.

**VPN tunnel architecture:**

```text
Client (tun0) --> encrypted UDP/TCP --> VPN server --> Destination
                                           |
                                           +-- NAT: source IP = VPN server IP
```

The client's traffic is captured by a virtual interface (`tun0`,
`wg0`, etc.), encrypted, and sent to the VPN server. The server
decrypts, performs NAT, and forwards to the destination.

**Multi-hop chains:**

**VPN chain (two providers):**

```text
Client -> VPN1 (Provider A) -> VPN2 (Provider B) -> Destination

VPN1 sees: client IP, that the client connects to VPN2.
VPN2 sees: VPN1 IP, the destination.
Neither sees both client IP and destination.
```

**Tor-over-VPN:**

```text
Client -> VPN -> Tor guard -> Tor middle -> Tor exit -> Destination

VPN sees: client IP, that the client uses Tor.
Tor guards see: VPN IP.
Tor exit sees: destination.
No single party sees both client IP and destination.
```

**VPN-over-Tor:**

```text
Client -> Tor guard -> Tor middle -> Tor exit -> VPN -> Destination

Tor sees: client IP (guard), VPN IP (exit).
VPN sees: Tor exit IP, destination.
No single party sees both client IP and destination, BUT the VPN
provider sees all destinations and can log them.
```

**Choosing the order:**

- **VPN -> Tor** is generally preferred: the VPN provider does not
  see your destinations, only that you use Tor. The Tor entry guard
  does not see your real IP.
- **Tor -> VPN** shifts trust to the VPN provider, who sees all
  destinations. Use only if you specifically trust the VPN provider
  more than the Tor exit nodes.

---

## 4. Installation and Setup

**WireGuard (recommended for self-hosted VPN):**

Server (Debian/Ubuntu VPS):

```bash
sudo apt install wireguard
wg genkey | tee privatekey | wg pubkey > publickey
# Create /etc/wireguard/wg0.conf with the server config
sudo systemctl enable --now wg-quick@wg0
```

Client:

```bash
sudo apt install wireguard
# Create /etc/wireguard/wg0.conf with the client config
sudo systemctl enable --now wg-quick@wg0
```

**Commercial VPN (provider-managed):**

Most providers ship a WireGuard or OpenVPN profile. Import into the
client (WireGuard app, NetworkManager, OpenVPN Connect) and connect.
Read the provider's privacy policy and logging claims before trusting.

**Tor Browser + VPN:**

Install Tor Browser normally. Configure the VPN at the OS level so
that all traffic (including Tor Browser's bootstrap) goes through
the VPN. Verify the order with a leak test (see section 6).

**Self-hosted VPN on a VPS:**

Popular choices: Hetzner, DigitalOcean, Linode, Vultr. Choose a
jurisdiction that fits your threat model. Pay with a method that
does not tie the VPS to your identity (crypto, prepaid card) if
anonymity is part of the goal.

**Algo / Streisand / WireGuard-installer:**

Automated deployment scripts that set up a VPN on a cloud provider.
Convenient but larger attack surface than a hand-configured
WireGuard. Review what they install.

---

## 5. Hardening and Configuration

**WireGuard hardening:**

```text
[Interface]
PrivateKey = <server-private-key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

- **Use a modern cipher suite** (WireGuard's defaults are fine).
- **Disable logging** in the provider's configuration where possible.
- **Rotate keys** periodically.
- **Restrict AllowedIPs** to the minimum needed (split tunnel vs
  full tunnel).
- **Firewall the VPN server** - only expose the VPN port, nothing else.

**OpenVPN hardening:**

```text
# Use TLS 1.2+, AEAD ciphers, and tls-auth / tls-crypt
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305
tls-crypt /etc/openvpn/ta.key
auth SHA256
```

**Client-side hardening:**

- **Kill switch.** If the VPN drops, all traffic must be blocked,
  not leaked to the ISP. WireGuard has no built-in kill switch; use
  `wg-quick` with `Table = off` and firewall rules, or use a
  firewall-based kill switch.
- **DNS leak protection.** Set DNS to the VPN provider's resolver,
  or to a resolver reachable only through the tunnel.
- **IPv6 leak protection.** If the VPN is IPv4-only, disable IPv6
  on the client or configure the VPN for IPv6.
- **WebRTC leak protection.** Disable WebRTC in the browser, or
  use a browser that does not leak.
- **Application-level leaks.** Some applications bypass the system
  VPN (e.g. by binding to a specific interface). Test with a leak
  test (section 6).

**Chain hardening:**

- **Use providers in different jurisdictions.** A chain of two
  providers in the same country can be compelled by the same court.
- **Use providers with different ownership.** A chain of two brands
  owned by the same company is effectively one provider.
- **Verify the order.** With VPN -> Tor, verify that the Tor guard
  sees the VPN IP, not your real IP. With Tor -> VPN, verify that
  the VPN sees the Tor exit IP, not your real IP.
- **Do not use free VPNs for anonymity.** Free VPNs monetize by
  logging and selling data. If you are not paying, you are the product.

---

## 6. Operational Usage

**Verifying the VPN is active:**

```bash
# Check the public IP (should be the VPN server's IP)
curl https://ifconfig.me/
curl https://api.ipify.org/

# Check the tunnel interface
ip addr show wg0   # or tun0 for OpenVPN
```

**Leak tests:**

```text
DNS leak:     https://www.dnsleaktest.com/
IP leak:      https://ipleak.net/
WebRTC leak:  https://browserleaks.com/webrtc
Tor check:    https://check.torproject.org/
```

**Verifying VPN -> Tor:**

```bash
# With VPN active, start Tor Browser
# Check the Tor circuit: the guard should see the VPN IP
# In Tor Browser, visit about:tor and check the circuit details
```

**Verifying Tor -> VPN:**

```bash
# With Tor active, route the VPN connection through Tor
# The VPN server should see the Tor exit IP, not your real IP
# Check the VPN server's logs (if you control it) or use a
# test endpoint that echoes the source IP
```

**Chain example (VPN1 -> VPN2 -> Tor):**

```text
1. Connect to VPN1 (Provider A).
2. From VPN1, connect to VPN2 (Provider B) - nested tunnel.
3. From VPN2, start Tor Browser.
4. Verify: Tor guard sees VPN2 IP; VPN2 sees VPN1 IP; VPN1 sees client IP.

No single party sees both client IP and destination.
```

**Self-hosted VPN server:**

```bash
# On the VPS, check active connections
sudo wg show

# On the client, check the handshake
sudo wg show
```

---

## 7. Common Mistakes

- **Assuming a VPN provides anonymity.** A VPN relocates trust to
  the provider; it does not eliminate it.
- **Using a free VPN for anonymity.** Free VPNs monetize by logging.
  If you are not paying, you are the product.
- **Using two VPNs owned by the same company.** A chain of two
  brands under one owner is effectively one provider.
- **Using two VPNs in the same jurisdiction.** A single court order
  can compel both.
- **Forgetting the kill switch.** If the VPN drops, traffic leaks
  to the ISP. Always configure a kill switch.
- **Forgetting DNS leaks.** If DNS queries go to the ISP's resolver,
  the VPN is bypassed for name resolution.
- **Forgetting IPv6 leaks.** If the VPN is IPv4-only and IPv6 is
  enabled, IPv6 traffic bypasses the tunnel.
- **Forgetting WebRTC leaks.** WebRTC can reveal the real IP even
  with a VPN active.
- **Logging into personal accounts over a VPN.** The VPN hides your
  IP, not your identity. The destination still sees your account.
- **Using a VPN to "hide" from the client during a red team
  engagement.** The client must know what infrastructure you use.
  Use dedicated infrastructure, not a commercial VPN.
- **Choosing VPN-over-Tor without understanding the trust shift.**
  VPN-over-Tor gives the VPN provider visibility into all your
  destinations. Use only if you trust the provider more than Tor
  exits.
- **Assuming the VPN provider does not log.** "No-logs" is a policy
  claim, not a technical guarantee. Providers have been compelled
  to log, or have logged despite claims.

---

## 8. Attacks Against It

**Against a single VPN:**

- **Provider logging.** The provider can log your real IP,
  timestamps, and destinations. A court order or a rogue employee
  can expose the logs.
- **Provider compromise.** A compromised VPN server can inject
  content, redirect traffic, or perform MITM on unencrypted
  traffic.
- **Traffic correlation.** A global passive adversary can
  correlate traffic entering and leaving the VPN server.
- **VPN protocol exploits.** Historical vulnerabilities in PPTP,
  L2TP, and older OpenVPN configurations. Use modern protocols.
- **Client-side leaks.** DNS, IPv6, WebRTC, and application-level
  bypasses defeat the VPN entirely.

**Against a VPN chain:**

- **Colluding providers.** If both providers share logs, the chain
  collapses.
- **Same ownership / same jurisdiction.** A chain of two brands
  under one owner or in one country is effectively one provider.
- **Timing correlation.** If the adversary observes both ends of
  the chain, correlation is possible.
- **First-hop compromise.** If VPN1 is compromised, the adversary
  sees the client IP and the fact that the client connects to VPN2.
  This is not full deanonymization but narrows the anonymity set.

**Against VPN-over-Tor:**

- **VPN provider sees all destinations.** The VPN provider is the
  equivalent of a Tor exit that sees your destinations. If the
  provider logs, your browsing history is exposed.
- **VPN provider sees the Tor exit IP.** Not your real IP, but
  the exit IP. If the provider also logs timestamps, correlation
  with Tor exit traffic is possible.

**Against Tor-over-VPN:**

- **VPN provider sees that you use Tor.** In some jurisdictions,
  this alone may be incriminating or draw attention.
- **VPN provider compromise does not deanonymize you.** The
  adversary sees a Tor connection, not the destinations.
- **Tor exit compromise.** A malicious Tor exit can snoop on
  unencrypted traffic, as in plain Tor.

---

## 9. Detection (Blue Team)

**Network-level detection:**

- **Known VPN IP ranges.** Commercial VPN providers publish their
  IP ranges; blocking them is easy but bypassed by self-hosted VPNs.
- **WireGuard handshake fingerprint.** WireGuard's handshake has
  a recognizable pattern (fixed message sizes, no version
  negotiation). DPI boxes can classify it.
- **OpenVPN fingerprint.** The TLS handshake and the OpenVPN
  control channel have recognizable patterns.
- **Traffic volume and timing.** A full-tunnel VPN shows a
  constant, encrypted flow to a single IP (the VPN server).
- **DNS behavior.** If DNS leaks, the resolver sees unexpected
  queries. If DNS is tunneled, the resolver sees only the VPN
  server's resolver.

**Host-level detection:**

- **Tunnel interfaces.** `wg0`, `tun0`, `tap0` are visible to
  endpoint agents.
- **Process names.** `wireguard`, `openvpn`, `wg-quick`,
  `openvpn-gui`, provider-specific client processes.
- **Configuration files.** `/etc/wireguard/`, `/etc/openvpn/`,
  provider-specific directories.
- **Firewall rules.** Kill-switch rules (e.g. `iptables` rules
  blocking non-VPN traffic) are visible to EDR.

**Detection in an enterprise:**

- **Egress filtering.** Blocking outbound to non-approved
  destinations catches naive VPN use, but self-hosted VPNs on
  common ports (443, 80) bypass this.
- **TLS inspection.** A TLS-terminating proxy can see the SNI
  and, if the client trusts the proxy CA, can see the plaintext.
  WireGuard is not TLS and is not inspectable this way.
- **Endpoint agents.** EDR can detect the tunnel interface, the
  process, and the configuration files.
- **Behavioral analytics.** Unusual outbound patterns
  (constant-rate encrypted traffic to a single IP) can be flagged.

**False positives:** remote workers, travelers, and privacy-conscious
users use VPNs legitimately. Detection should inform policy, not
trigger automatic blocking.

---

## 10. Case Studies

**Case 1 - Cryptodome / "The Bull" (2019).** A dark web vendor
known as "The Bull" was identified through a combination of
operational mistakes: reusing a VPN account, logging into a
personal email over the VPN, and correlating the VPN's logs with
other evidence. The VPN provider was not compromised; the vendor's
operational discipline was.

**Case 2 - Ross Ulbricht and VPN logs.** In the Silk Road
investigation, VPN logs (from a provider that had been compelled
to log) contributed to the correlation that identified Ulbricht.
The lesson: a VPN provider is a single point of trust and can be
compelled to log or hand over data.

**Case 3 - "No-logs" VPN providers and court orders.** Several
providers have been served with court orders requiring them to
log. Providers that genuinely do not log cannot comply; providers
that do log may hand over data. The technical architecture (RAM-only
servers, no persistent storage) is a stronger claim than a policy
statement.

**Case 4 - VPN chains in journalism.** Journalists and activists
in high-risk environments use VPN chains (and VPN -> Tor) to
protect sources. The design assumption is that no single provider
sees both the client and the destination. This works only if the
providers do not collude and are in different jurisdictions.

**Common pattern:** In public cases where VPNs were involved,
deanonymization came from provider logging, provider compromise,
or operational mistakes - not from breaking the VPN cryptography.

---

## 11. Legal and Ethical Notes

**Client use:**

- Legal in most jurisdictions. Some countries restrict VPN use
  (China, Iran, Russia, Belarus, Turkmenistan, UAE, Oman, and
  others).
- Using a VPN to access content illegal in your jurisdiction is
  still illegal. A VPN does not legalize the content.

**Running a VPN server:**

- **Self-hosted VPN on a VPS:** legal in most jurisdictions.
  Check the VPS provider's AUP; some forbid VPN servers.
- **Commercial VPN provider:** operates under the laws of its
  jurisdiction. Jurisdictions with mandatory logging (e.g. some
  EU countries under data retention laws) may require logging.
- **Exit to clearnet:** a self-hosted VPN that exits to the
  clearnet behaves like a Tor exit relay for legal purposes. You
  are the visible source of the traffic.

**Ethical considerations:**

- VPNs are used by journalists, activists, remote workers, and
  ordinary users. Do not assume malicious intent.
- Do not use a VPN to evade lawful investigation, commit
  unauthorized access, or harm others.
- See `../../../SECURITY.md` for the repository's authorized-use
  policy.

---

## 12. Production Notes

**For a red team engagement:**

- **Never use a commercial VPN to "hide" from the client.** The
  client must know what infrastructure you use. Document it in
  the engagement plan.
- **Use dedicated infrastructure** (VPS + VPN) provisioned for the
  engagement, not a shared commercial VPN.
- **Log your own activity** for the engagement report. Anonymity
  is not the goal; attribution to the engagement is.
- **Consult the rules of engagement** before using any anonymizing
  infrastructure.

**For personal threat modeling:**

- **Single VPN:** sufficient against the local network and casual
  destination-side IP tracking.
- **VPN chain (two providers):** protects against a single
  provider logging. Use providers in different jurisdictions and
  with different ownership.
- **VPN -> Tor:** best for clearnet browsing where you want to
  hide from the VPN provider that you are using Tor (at the cost
  of the VPN knowing you use Tor).
- **Tor -> VPN:** best if you specifically trust a VPN provider
  more than Tor exits (rare).

**Provider selection criteria:**

- **Jurisdiction.** Different from your own, and different from
  the other provider in the chain.
- **Ownership.** Different company, not a subsidiary of the other.
- **Logging policy.** "No-logs" is a policy claim; look for
  technical guarantees (RAM-only servers, warrant canaries,
  independent audits).
- **Payment method.** Accepts payment that does not tie the
  account to your identity (crypto, cash, prepaid).
- **Protocol support.** WireGuard preferred; OpenVPN acceptable.
- **Reputation.** Public track record of handling court orders.

**Verification checklist after setup:**

```text
[ ] Public IP is the VPN server's IP
[ ] DNS queries go to the VPN's resolver (no leak)
[ ] IPv6 is either tunneled or disabled (no leak)
[ ] WebRTC does not reveal the real IP
[ ] Kill switch blocks traffic when the VPN drops
[ ] (Chain) Each hop sees only the previous hop
[ ] (Chain) No single provider sees both client IP and destination
```

---

## 13. References

- WireGuard - https://www.wireguard.com/
- WireGuard protocol paper - https://www.wireguard.com/papers/wireguard.pdf
- OpenVPN documentation - https://openvpn.net/community-resources/
- EFF Surveillance Self-Defense - VPNs - https://ssd.eff.org/module/choosing-vpn-thats-right-you
- Tor Project - VPNs and Tor - https://support.torproject.org/misc/#vpn
- Tor Project - Tor and VPN - https://support.torproject.org/misc/#tor-vpn
- Whonix Wiki - Combining Tor and VPNs - https://www.whonix.org/wiki/Tunnels/Introduction
- "The effectiveness of VPNs for anonymity" (various academic papers)
- Public reporting on VPN-related deanonymization cases (2013-2024)
