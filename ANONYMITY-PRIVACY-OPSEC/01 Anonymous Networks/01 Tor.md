# 01 Tor

Tor (The Onion Router) is a low-latency anonymity network that routes
traffic through three relays (guard, middle, exit) using layered
encryption. This file covers installation, hardening, operational
usage, common mistakes, attacks against Tor, and detection from a
blue-team perspective.

> [!CAUTION]
> **Authorized Use Only.**
>
> Tor is legal in most jurisdictions but may be restricted in others
> (China, Iran, Russia, Belarus, and others block or criminalize it).
> Running an **exit relay** makes you the visible source of any traffic
> leaving the Tor network through your node - check your local laws
> before doing so. See `../../../SECURITY.md` for the repository's
> authorized-use policy.

---

## 1. Overview

Tor is a circuit-based, low-latency anonymity network. A client builds
a circuit of three relays (guard, middle, exit), negotiates a separate
symmetric key with each relay, and sends data as fixed-size cells. Each
relay peels one layer of encryption and forwards the cell to the next
hop. The exit relay makes the final connection to the destination.

Key properties:

- **Low latency** - suitable for interactive browsing, not for bulk
  transfer (unlike mixnets like Nym or Loopix).
- **No single relay knows both source and destination** - the guard
  knows the client, the exit knows the destination, but neither sees both.
- **Onion services (.onion)** - services reachable only through Tor,
  with no exit relay involved; both client and service stay inside the
  network.

What Tor is **not**:

- Not a mixnet. It provides unlinkability under a specific threat model
  (no global passive adversary), not information-theoretic anonymity.
- Not a VPN. A VPN trusts a single provider; Tor distributes trust
  across three independently-operated relays.
- Not a magic bullet against a global adversary doing traffic
  confirmation. See section 8.

---

## 2. Threat Model

**Defends against:**

- **Local network adversary (ISP, coffee-shop Wi-Fi, corporate proxy)** -
  cannot see the destination IP, only that the client speaks to a Tor
  guard.
- **Destination server** - sees the exit relay's IP, not the client's.
- **Compromised exit relay** - cannot link the client to the destination,
  but can read unencrypted traffic (mitigated by HTTPS end-to-end).
- **Passive observation of a single relay** - cannot deanonymize the
  client on its own.

**Does NOT defend against:**

- **Global passive adversary (GPA)** - an adversary who observes both
  ends of the circuit (guard + exit) can perform traffic correlation
  (timing, volume, packet-size pattern).
- **Traffic confirmation attacks** - an adversary who controls both the
  client's local network and the destination can confirm a visit by
  injecting a unique traffic pattern.
- **Bad Apple attack (misconfigured applications)** - if an application
  leaks the real IP outside Tor (DNS, WebRTC, direct connection), Tor
  is bypassed entirely.
- **Malicious guard + malicious exit (Sybil)** - a sufficiently
  well-resourced adversary running both ends can deanonymize.
- **Endpoint compromise** - malware on the client, keyloggers, or a
  compromised browser undermine every layer of the network.

**Choice guidance:**

- Against an ISP or a local network: Tor is sufficient.
- Against a nation-state with global visibility: Tor alone is not
  sufficient; combine with operational discipline (section 6) and
  accept residual risk.
- Against a destination that you do not trust: use HTTPS inside Tor,
  and prefer onion services when available.

---

## 3. How It Works (technical)

**Circuit construction (simplified):**

```text
Client -> Guard -> Middle -> Exit -> Destination

1. Client picks a guard (long-term, pinned).
2. Client extends the circuit hop by hop using CREATE/CREATED cells.
3. Each hop shares a separate symmetric key with the client (ntor handshake).
4. Data is sent as fixed-size cells (514 bytes), each with one layer of encryption.
5. Each relay decrypts one layer, learns only the next hop.
```

**Relay roles:**

- **Guard (entry)** - the first hop. Long-lived (clients pin a guard for
  months) to resist guard-discovery attacks. Sees the client's IP.
- **Middle** - forwards cells. Knows neither the client nor the
  destination.
- **Exit** - makes the final connection. Sees the destination and, if
  the traffic is unencrypted, the payload.
- **Bridge** - an unlisted guard, used when the client's network blocks
  known Tor relays. Distributed out-of-band or via BridgeDB.
- **Directory authority** - signs the consensus document that lists all
  relays. Nine authorities, hardcoded.

**Onion services (v3):**

```text
Service publishes descriptor to a set of introduction points (via DHT).
Client learns the descriptor, picks an intro point, sends an INTRODUCE.
Service builds a rendezvous circuit to a rendezvous point (RP).
Client builds a circuit to the same RP.
Traffic flows client <-> RP <-> service. No exit relay involved.
```

**Pluggable transports** - obfuscate the Tor traffic so that it does
not look like Tor to a DPI box. Examples: obfs4, meek, snowflake, webtunnel.

---

## 4. Installation and Setup

**Tor Browser (recommended for browsing):**

```bash
# Download from https://www.torproject.org/download/
# Verify the GPG signature against the Tor Project signing key.
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290
gpg --verify tor-browser-linux-x86_64-*.tar.xz.asc tor-browser-linux-x86_64-*.tar.xz
# Extract, run ./start-tor-browser.desktop
```

**Tor daemon (for non-browser use):**

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install tor
# Fedora
sudo dnf install tor
# Arch
sudo pacman -S tor

# Start and enable
sudo systemctl enable --now tor

# Check it is listening on the SOCKS port
ss -tlnp | grep 9050
```

**Tails** - a live operating system that routes everything through Tor
by default. See `../03 Operating Systems and Hygiene/` (planned).

**Whonix** - a two-VM setup (gateway + workstation) that forces all
workstation traffic through Tor. See `../03 Operating Systems and Hygiene/` (planned).

---

## 5. Hardening and Configuration

**torrc - client hardening:**

```text
# Use a specific guard to avoid guard-rotation attacks
UseEntryGuards 1
NumEntryGuards 1

# Enable safe logging
SafeLogging 1

# Isolate by destination (each .onion / domain gets a new circuit)
# Useful for compartmentalization; costs performance.
IsolateDestAddr 1
IsolateDestPort 1

# Stream isolation by SOCKS username/password (per-application isolation)
# Applications pass different SOCKS credentials to get separate circuits.
```

**Browser hardening (Tor Browser):**

- **Security Level: Safer or Safest.** Disables JavaScript on non-HTTPS
  sites (Safer) or all sites (Safest). Breaks many sites; use for
  high-risk browsing.
- **Do not resize the window.** Tor Browser letterboxes the viewport to
  a fixed set of sizes to prevent fingerprinting by window size.
- **Do not install extensions.** Each extension is a fingerprint.
- **Do not log into personal accounts.** Every login ties the Tor
  circuit to your real identity on the destination side.
- **Disable JavaScript when not needed.** NoScript is built into Tor
  Browser; keep it in "Safer" mode by default.

**System hardening:**

- **Do not run Tor alongside a normal browser session.** DNS leaks,
  WebRTC, and application-level direct connections bypass Tor.
- **Use a dedicated OS or VM.** Tails or Whonix prevent leaks by design.
- **Never mix clearnet and Tor identities.** A pseudonym used on Tor
  must never touch a clearnet account.

**Running a relay (optional):**

```text
# torrc for a non-exit relay
ORPort 9001
Nickname MyRelay
ContactInfo 0x<YOUR_PGP_FINGERPRINT>
ExitRelay 0
SocksPort 0
```

Running a **bridge** is a middle ground: it helps blocked users without
making you an exit. Running an **exit** requires accepting legal risk.

---

## 6. Operational Usage

**Per-application isolation (stream isolation):**

Applications that speak SOCKS5 can pass a username/password to Tor.
Tor uses the credentials to derive a separate circuit per unique
credential. This prevents two applications from sharing a circuit.

```bash
# curl through Tor, isolated by SOCKS credentials
curl --socks5-hostname user1:pass1@127.0.0.1:9050 https://check.torproject.org/
```

**Verify Tor is working:**

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Expected: {"IsTor":true,"IP":"<exit-ip>"}
```

**DNS leak check:**

```bash
# All DNS must go through Tor, not the local resolver.
curl --socks5-hostname 127.0.0.1:9050 https://dnsleaktest.com/
```

**Onion service (client side):**

```bash
# .onion addresses resolve inside Tor; no exit relay involved.
curl --socks5-hostname 127.0.0.1:9050 http://<v3-onion-address>.onion/
```

**Running a v3 onion service:**

```text
# torrc
HiddenServiceDir /var/lib/tor/my-service/
HiddenServicePort 80 127.0.0.1:8080
```

```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/my-service/hostname
# <56-char-v3-address>.onion
```

**Bridges (when direct Tor is blocked):**

```text
# torrc
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0
```

Get bridges at https://bridges.torproject.org/ or via the built-in
BridgeDB in Tor Browser.

---

## 7. Common Mistakes

- **Logging into a personal account inside Tor.** A single login ties
  the Tor circuit to your real identity on the destination side.
  Even if the circuit is anonymous, the account is not.
- **Using Tor for BitTorrent.** Tor is not built for bulk transfer;
  it hurts the network and leaks your identity through the BitTorrent
  protocol (peer exchange, DHT, trackers).
- **Mixing Tor and non-Tor in the same browser session.** WebRTC,
  DNS prefetch, or a single direct request leaks the real IP.
- **Maximizing the Tor Browser window.** Window size is a fingerprint.
  Keep the default letterboxed size.
- **Installing extensions in Tor Browser.** Each extension narrows
  the anonymity set.
- **Using a VPN and Tor in the wrong order.** VPN -> Tor protects
  against the local network but trusts the VPN. Tor -> VPN protects
  the exit destination from seeing the exit IP but trusts the VPN
  with the client identity. Neither is universally better; see
  `04 VPN and Multi-hop Chains.md`.
- **Assuming bridges hide you from a global adversary.** Bridges help
  against IP blocklists, not against traffic correlation.
- **Reusing a pseudonym across circuits.** Persistent pseudonyms defeat
  the anonymity of the network.
- **Running an exit relay on a home connection without checking the
  ISP's AUP.** Many ISPs terminate the account on abuse reports.
- **Using the wrong timezone / language in the browser.** These leak
  information about the user's real environment.

---

## 8. Attacks Against It

**Traffic correlation (traffic confirmation):**

- **End-to-end correlation.** An adversary who observes both the
  client's traffic to the guard and the exit's traffic to the
  destination can correlate timing and volume. Requires a global
  passive adversary or control of both ends.
- **Website fingerprinting.** An adversary who observes the client's
  traffic to the guard can guess which site is being visited by
  matching traffic patterns against a trained classifier, even without
  observing the exit. Works best on a small set of candidate sites.

**Relay-level attacks:**

- **Guard discovery.** An adversary who can force a client to rotate
  guards (by DoS-ing the current guard) can eventually become the
  guard. Mitigated by pinning guards and by guard rotation policies.
- **Sybil relays.** An adversary who runs many relays increases the
  chance of being selected as guard or exit. Mitigated by relay
  diversity policies and by the directory authorities.
- **Exit snooping.** A malicious exit sees unencrypted traffic.
  Mitigated by HTTPS end-to-end and by not sending plaintext.
- **Bad Apple attack.** A malicious exit correlates traffic with
  user activity on the destination (e.g. a forum post made at the
  same time as the traffic).

**Onion-service attacks:**

- **Descriptor harvesting.** An adversary who learns the descriptor
  can find the introduction points and attempt to DoS them.
- **Introduction-point DoS.** Forcing the service to rotate intro
  points can eventually place the adversary as an intro point.
- **Rendezvous-point attacks.** Similar to guard discovery, applied
  to the rendezvous point.
- **HSv2 deprecation.** v2 onion services were deprecated in 2021
  due to a practical attack (the "v2 onion address" is only 80 bits
  and can be brute-forced). Use v3 only.

**Client-side attacks:**

- **Browser exploits.** A zero-day in Tor Browser (Firefox ESR)
  compromises the client directly. Mitigated by keeping Tor Browser
  up to date and by disabling JavaScript.
- **Application leaks.** DNS, WebRTC, direct connections, and
  non-proxied applications bypass Tor entirely.
- **Timing side channels in the client.** An adversary who can
  observe the client's local network can infer browsing patterns.

---

## 9. Detection (Blue Team)

**Network-level detection:**

- **Known guard IPs.** Blocking the public Tor relay list is easy but
  bypassed by bridges. This is a policy control, not a security control.
- **Traffic fingerprinting.** Tor traffic has recognizable patterns
  (fixed-size cells, TLS to a small set of ports). DPI boxes can
  classify it with reasonable accuracy. Pluggable transports reduce
  this signal.
- **TLS fingerprint (JA3/JA4).** Tor's TLS handshake differs from
  a standard browser. Some DPI boxes fingerprint it.
- **SNI filtering.** Tor Browser sends SNI in cleartext for HTTPS
  (TLS 1.2 and 1.3 with ECH disabled). Some networks filter on SNI.

**Host-level detection:**

- **Process names.** `tor`, `obfs4proxy`, `snowflake-client` are
  visible to EDR agents.
- **SOCKS port.** A process listening on 9050 (Tor) or 9150
  (Tor Browser) is a strong signal.
- **Tor Browser artifacts.** `~/.tor-browser/`, browser profile
  directories, and known file hashes.
- **DNS behavior.** If DNS leaks, the resolver sees `.onion`
  lookups or unexpected domains.

**Detection in an enterprise:**

- **Egress filtering.** Blocking outbound to non-approved destinations
  catches naive Tor use but not bridges.
- **TLS inspection.** A TLS-terminating proxy can see SNI and, if
  the client trusts the proxy CA, can see the plaintext after
  the proxy re-encrypts. Tor Browser does not trust enterprise CAs
  by default, so this fails for Tor Browser.
- **Endpoint agents.** EDR can detect the Tor process, the SOCKS
  listener, and Tor Browser artifacts.
- **Behavioral analytics.** Unusual outbound patterns (fixed-size
  cells, long-lived connections to unknown IPs) can be flagged.

**False positives:** privacy-conscious users, researchers, and
journalists use Tor legitimately. Detection should inform policy,
not trigger automatic blocking or investigation.

---

## 10. Case Studies

**Case 1 - Harvard bomb threat (2013).** A student used Tor to send
a bomb threat. The FBI identified him not by breaking Tor, but by
correlating the timing of the threat with the timing of the student's
Tor usage on the university network and with the set of people who
had the exam schedule. The Tor network was not broken; operational
security was.

**Case 2 - Silk Road (2013).** The FBI identified Ross Ulbricht not
by breaking Tor, but through operational mistakes: a Gmail address
tied to the original Silk Road announcement, a Stack Overflow
question posted with the real name, and a forum post that reused an
earlier pseudonym. Tor was not the weak point.

**Case 3 - Playpen (2015).** The FBI took over a Tor hidden service
and used a NIT (Network Investigative Technique) delivered through
a browser exploit to identify visitors. The attack targeted the
client, not the network.

**Case 4 - AlphaBay (2017).** Law enforcement identified the
operator through a personal email address in the welcome message
of the site and through correlation with a previous identity.
Again, operational security, not Tor.

**Common pattern:** In every public case where Tor was involved,
the deanonymization came from operational mistakes, endpoint
compromise, or correlation - not from breaking the cryptographic
core of the network.

---

## 11. Legal and Ethical Notes

**Client use:**

- Legal in most jurisdictions. Blocked or restricted in some
  (China, Iran, Russia, Belarus, Turkmenistan, and others).
- Using Tor to access content that is illegal in your jurisdiction
  is still illegal. Tor does not legalize the content.

**Relay operation:**

- **Non-exit relay (middle/guard):** low legal risk in most
  jurisdictions. Some hosting providers forbid it in their AUP.
- **Bridge:** similar to a non-exit relay. Helps blocked users.
- **Exit relay:** you are the visible source of all traffic leaving
  through your node. You may receive abuse reports, DMCA notices,
  and law enforcement inquiries. Check your jurisdiction's laws
  and your ISP's AUP before running an exit.
- **Exit relay and illegal content:** in some jurisdictions,
  running an exit may create liability for what passes through it.
  Running an exit on a home connection is strongly discouraged.

**Ethical considerations:**

- Tor is used by journalists, activists, whistleblowers, and
  ordinary privacy-conscious users. Do not assume that Tor use
  implies malicious intent.
- Do not use Tor to evade lawful investigation, traffic illegal
  material, or harm others.
- See `../../../SECURITY.md` for the repository's authorized-use
  policy.

---

## 12. Production Notes

**For a red team engagement:**

- Tor is usually **not** the right tool for an authorized engagement.
  Corporate networks often block it, and its use may violate the
  engagement's rules of engagement.
- If anonymity is required during an engagement (e.g. for a
  physical-social-engineering pretext), use a dedicated
  infrastructure (VPS + VPN) rather than Tor, and document it in
  the engagement plan.
- Never use Tor to "hide" from the client. The client must know
  what infrastructure you use.

**For personal threat modeling:**

- Use Tor Browser, not a custom Tor setup, unless you have a
  specific reason.
- Keep Tor Browser up to date. Update through the built-in
  updater, not through a package manager (which lags).
- Use Tails or Whonix if your threat model includes endpoint
  compromise.
- Do not mix Tor with personal accounts, personal email, or
  personal browsing.

**For running infrastructure:**

- Monitor your relay for abuse reports.
- Set a valid ContactInfo in torrc (PGP fingerprint).
- Join the tor-relays mailing list for operational updates.
- For an exit: use a dedicated VPS, not a home connection;
  respond to abuse reports promptly; consider a reduced exit
  policy to limit the traffic types.

---

## 13. References

- Tor Project - https://www.torproject.org/
- Tor specifications - https://spec.torproject.org/
- Tor Browser design - https://2019.www.torproject.org/projects/torbrowser/design/
- Tor relay guide - https://community.torproject.org/relay/
- Pluggable transports - https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports
- BridgeDB - https://bridges.torproject.org/
- EFF Surveillance Self-Defense - https://ssd.eff.org/
- "Tor: The Second-Generation Onion Router" (Dingledine et al., 2004) -
  https://www.usenix.org/legacy/events/sec04/tech/full_papers/dingledine/dingledine.pdf
- "Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries"
  (Johnson et al., 2013) - https://www.ohmygoddess.org/papers/users-get-routed.pdf
- "Trawling for Tor Hidden Services" (Birge-Lee et al., 2017) -
  https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/birge-lee
- Harvard bomb threat case analysis (public reporting, 2013).
- Silk Road case analysis (public reporting, 2013-2015).
