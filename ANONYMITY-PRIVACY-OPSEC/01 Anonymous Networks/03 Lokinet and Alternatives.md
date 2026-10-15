# 03 Lokinet and Alternatives

Lokinet is a low-latency onion routing network built on LLARP (Low
Latency Anonymous Routing Protocol) and operated over the Oxen Service
Node network. Unlike Tor and I2P, Lokinet operates at the network layer
(Layer 3), which allows it to route any IP-based protocol - TCP, UDP,
ICMP - not just TCP. This file also covers alternatives to the three
main networks: Nym (a mixnet), Freenet/Hyphanet, GNUnet, and Yggdrasil.

> [!CAUTION]
> **Authorized Use Only.**
>
> Lokinet and the alternatives described here are dual-use anonymity
> technologies. Running a client is legal in most jurisdictions;
> running a service node (relay) involves staking OXEN tokens and may
> have tax or regulatory implications in your jurisdiction. Using any
> of these networks to evade lawful investigation, commit unauthorized
> access, or traffic illegal material is prohibited. See
> `../../../SECURITY.md` for the repository's authorized-use policy.

---

## 1. Overview

Lokinet is the reference implementation of LLARP, a Layer 3 onion
routing protocol. It is designed as a hybrid between Tor
and I2P: it provides low-latency onion routing (like Tor) with
support for in-network services called SNApps (like I2P).

Key architectural differences from Tor and I2P:

- **Network layer (Layer 3)** - Lokinet routes IP packets, not TCP
  streams. This means it can carry UDP, ICMP, and any other IP
  protocol, including real-time voice and video.
- **Staked service nodes** - relays are operated by Oxen Service Nodes
  that stake OXEN tokens and are economically incentivized to provide
  quality service, unlike Tor's volunteer relays.
- **Blockchain coordination** - peer discovery and node registration
  use the Oxen blockchain rather than a central directory or a
  distributed DHT.
- **Packet-switched** - like I2P, Lokinet uses packet switching rather
  than Tor's circuit switching.

**Alternatives covered in this file:**

- **Nym** - a mixnet that provides stronger resistance to global
  passive adversaries at the cost of latency.
- **Freenet/Hyphanet** - a distributed storage and publishing network
  with high latency, optimized for censorship-resistant publishing.
- **GNUnet** - a research-oriented P2P framework with a modular
  architecture and strong adversary-resistance assumptions.
- **Yggdrasil** - a lightweight IPv6 overlay network, not designed
  primarily for anonymity but useful as a fast overlay.

---

## 2. Threat Model

**Lokinet defends against:**

- **Local network adversary** - sees only encrypted LLARP traffic to
  service nodes.
- **Destination server** - sees an exit node's IP, not the client's.
- **Single-node observation** - a compromised service node sees only
  the previous and next hop.

**Lokinet does NOT defend against:**

- **Global passive adversary** - like Tor, Lokinet is vulnerable to
  end-to-end traffic correlation if the adversary observes both ends.
- **Token-based Sybil resistance** - staking raises the cost of
  running many nodes, but a well-funded adversary can still acquire
  a significant share of service nodes.
- **Small anonymity set** - Lokinet has fewer than 1,000 service
  nodes, compared to Tor's millions of daily users and I2P's ~55,000
  routers. A smaller anonymity set means a higher chance
  of a single adversary controlling a relevant fraction of nodes.

**Nym defends against:**

- **Global passive adversary** - Nym's mixnet design (random delays,
  cover traffic, Poisson sending) is specifically built to resist
  traffic correlation.
- **Timing analysis** - packets are reordered and delayed at each
  mix layer, destroying the timing signal.

**Nym does NOT defend against:**

- **Latency-sensitive use cases** - the mixing delay makes Nym
  unsuitable for video calls or interactive browsing.
- **Destination-side observation** - against the destination, Nym
  behaves like a VPN: the destination sees the exit gateway's IP and
  the full content of the connection.

**Yggdrasil does NOT defend against:**

- **Traffic correlation** - Yggdrasil is not designed for anonymity.
  It provides encrypted overlay networking, not onion routing.

---

## 3. How It Works (technical)

**Lokinet (LLARP):**

```text
Client -> Service Node 1 -> Service Node 2 -> Service Node 3 -> Exit Node -> Destination

Each service node removes one layer of encryption.
No single node knows the full path.
```

LLARP is a Layer 3 protocol: it creates a virtual tunnel interface
(`tun0` on Linux) and routes IP packets through the network. Because it
operates at Layer 3, it can carry any IP protocol.

Service nodes are staked Oxen nodes. The Oxen blockchain maintains the
list of active service nodes and their public keys.

**Nym (mixnet):**

```text
Client -> Entry Gateway -> Mix L1 -> Mix L2 -> Mix L3 -> Exit Gateway -> Destination

Each mix node:
1. Decrypts one Sphinx layer.
2. Holds the packet for a random delay (exponential distribution, mean 50 ms).
3. Forwards to the next hop.

Cover traffic flows continuously, independent of real traffic.
```

Nym uses the Loopix design: random delays at each mix layer, constant
cover traffic, and Poisson sending from clients. This breaks the
timing correlation that onion routers are vulnerable to.

The cost is latency: a 5-hop mixnet round-trip is on the order of
1.5-2 seconds, compared to Tor's 200-500 ms.

**Freenet/Hyphanet:**

Freenet is a distributed data store. Content is encrypted and stored
across many nodes; routing is key-based. Latency is high (minutes for
cold requests), but the network is designed for censorship-resistant
publishing rather than interactive browsing.

**GNUnet:**

GNUnet is a modular P2P framework with 45+ subsystems. It provides a
DHT (R5N), a file-sharing layer (ECRS), a name system (GNS), and an
anonymous routing layer with user-controllable anonymity levels. It is
primarily a research platform, and the version packaged in Debian
stable is often too old to connect to the live network.

**Yggdrasil:**

Yggdrasil is an IPv6 overlay network. It assigns each node a public
IPv6 address in a reserved range and routes traffic over encrypted
links. It is fast and easy to set up, but it is **not** an anonymity
network: traffic is encrypted in transit, but the topology is not
designed to hide source-destination relationships.

---

## 4. Installation and Setup

**Lokinet (Linux - official repository):**

```bash
# Add the Oxen APT repository
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install lokinet

# Bootstrap and start
sudo systemctl enable --now lokinet
```

**Lokinet (macOS/Windows):**

Download the installer from https://lokinet.org/.

**Lokinet usage:**

```bash
# On Linux, run as normal user (setcaps are set by make install)
lokinet -g          # generate config
lokinet-bootstrap   # fetch bootstrap seed
lokinet             # start as client

# As a relay (requires staking)
lokinet -r -g
```

**Nym (via NymVPN):**

Download from https://nym.com/ or use the Nym SDK for applications.
Nym requires acquiring and spending NYM tokens for mixnet access.

**Yggdrasil:**

```bash
# Debian/Ubuntu
sudo apt install yggdrasil

# Or download from https://yggdrasil-network.github.io/
sudo systemctl enable --now yggdrasil
```

---

## 5. Hardening and Configuration

**Lokinet client hardening:**

- **Do not run as root on Linux.** The binary uses `setcap` for the
  necessary privileges. Running as root is unnecessary and risky.
- **Run as a normal user.** On Windows, do not run the batch file as
  an elevated user.
- **Use the exit node only when needed.** Like a VPN exit, the exit
  node sees your clearnet traffic.
- **Keep the client updated.** Lokinet is actively developed; security
  fixes are released regularly.

**Nym operational notes:**

- **Use cover traffic.** Nym clients send cover traffic by default;
  do not disable it. Cover traffic is what provides unobservability.
- **Accept the latency.** Nym is not for real-time applications.
  Use it for messaging, file transfers, and API calls where a few
  seconds of latency is acceptable.
- **Do not use Nym for clearnet browsing.** It is too slow. Use Tor
  for browsing.

**GNUnet:**

- **Use a recent version.** The Debian stable package is often too
  old to connect. Build from source or use a recent release.
- **Configure anonymity level.** GNUnet allows user-controllable
  anonymity levels; set them based on your threat model.

**Yggdrasil:**

- **Not an anonymity tool.** Use Yggdrasil for fast overlay
  networking, not for hiding your identity.
- **Firewall the IPv6 range.** Yggdrasil assigns public IPv6
  addresses; ensure your firewall rules account for them.

---

## 6. Operational Usage

**Lokinet - accessing the network:**

```bash
# Check the tunnel interface
ip addr show lokinet0

# Access a SNApp (Lokinet hidden service)
curl --interface lokinet0 http://<snapp-address>.loki/

# Access clearnet through an exit node
curl --interface lokinet0 https://check.torproject.org/
```

**Lokinet - running a SNApp:**

SNApps are services hosted on Lokinet. They are accessed through the
Lokinet tunnel interface, similar to how I2P eepsites are accessed
through the I2P proxy.

**Nym - sending a message (SDK):**

Nym provides SDKs for Rust and other languages. The general flow:

1. Client connects to an Entry Gateway.
2. Client sends Sphinx packets containing the message.
3. Packets traverse three mix layers, each adding delay.
4. Exit Gateway delivers the message to the destination.

For clearnet destinations, the Exit Gateway acts as a proxy.

**Yggdrasil - accessing the network:**

```bash
# Check your Yggdrasil IPv6 address
ip addr show tun0
# or
yggdrasilctl getSelf
```

Other Yggdrasil nodes are reachable via their IPv6 addresses in the
`200::/7` range.

---

## 7. Common Mistakes

- **Assuming Lokinet is as anonymous as Tor.** Lokinet has a much
  smaller anonymity set (<1,000 service nodes vs Tor's millions of
  users).
- **Using Lokinet for high-threat anonymity.** The small network and
  token-based relay model mean a well-funded adversary can acquire a
  significant share of nodes.
- **Using Nym for real-time applications.** The mixnet latency
  (1.5-2 seconds) makes video calls and interactive browsing
  impractical.
- **Disabling cover traffic in Nym.** Cover traffic is what provides
  unobservability; disabling it breaks the threat model.
- **Treating Yggdrasil as an anonymity network.** Yggdrasil is an
  overlay network, not an anonymity network.
- **Running GNUnet from Debian stable.** The packaged version is
  often too old to connect to the live network.
- **Using the wrong network for the threat model.** Tor for clearnet
  browsing, I2P for in-network hosting, Lokinet for UDP/real-time
  over onion routing, Nym for high-latency strong anonymity.

---

## 8. Attacks Against It

**Lokinet attacks:**

- **Traffic correlation** - as with Tor, a global passive adversary
  can correlate entry and exit traffic.
- **Sybil service nodes** - staking raises the cost, but a
  well-funded adversary can still acquire many nodes.
- **Exit node snooping** - a malicious exit sees clearnet traffic.
- **Small anonymity set** - with fewer than 1,000 nodes, the chance
  of an adversary controlling a relevant fraction is higher than
  in Tor.

**Nym attacks:**

- **Mix node compromise** - if multiple mix layers are compromised,
  correlation becomes possible. Nym's design assumes some mix nodes
  may be malicious.
- **Entry gateway compromise** - a user's long-term entry gateway is
  a point of attack. Discovering a user's gateway is consequential
  for deanonymization.
- **Timing analysis with reduced cover traffic** - if cover traffic
  is insufficient, statistical timing attacks become possible over
  many messages.

**General attacks against all networks:**

- **Endpoint compromise** - malware, keyloggers, or a compromised
  browser undermine any network.
- **Operational mistakes** - reusing identities, logging into
  personal accounts, leaking real IP through applications.

---

## 9. Detection (Blue Team)

**Lokinet detection:**

- **Tunnel interface** - `lokinet0` on Linux, visible in `ip addr`.
- **Process name** - `lokinet` on Linux/macOS, `lokinet.exe` on Windows.
- **Network traffic** - LLARP traffic has recognizable patterns;
  DPI boxes can classify it.
- **Service node connections** - connections to known Oxen service
  node IPs.

**Nym detection:**

- **Process** - Nym client processes (SDK-dependent).
- **Traffic pattern** - constant-rate traffic, Sphinx packet sizes
  (fixed 2413 B per packet).
- **Latency** - unusually high round-trip times to destinations,
  consistent with mixnet delays.

**Yggdrasil detection:**

- **Tunnel interface** - `tun0` or a custom interface name.
- **IPv6 range** - traffic to/from `200::/7` addresses.
- **Process** - `yggdrasil` daemon.

**General detection:**

- **Endpoint agents** - EDR can detect the tunnel interface, the
  process, and the unusual network behavior.
- **Egress filtering** - blocking connections to known anonymity
  network infrastructure. Easily bypassed by bridges or alternative
  networks.
- **Behavioral analytics** - constant-rate traffic (Nym), high
  latency (mixnets), or connections to non-standard ports.

---

## 10. Case Studies

**Lokinet and Oxen (now Session) - token economics.** Lokinet's
design ties anonymity to a token economy: service nodes stake OXEN
(now Session Token) and earn rewards for providing service. This
model aims to solve the "volunteer relay" problem of Tor (where
relays are run by volunteers and may be under-resourced), but it
also ties network participation to cryptocurrency ownership and
regulatory considerations.

**Nym and the Loopix design.** Nym implements the Loopix mixnet
design from the academic literature. Loopix showed that a mixnet
with random delays, cover traffic, and Poisson sending could
provide strong resistance to global passive adversaries at the
cost of latency. Nym is one of the few production deployments of
this design.

**Freenet and censorship-resistant publishing.** Freenet (now
Hyphanet) has been used for censorship-resistant publishing for
over two decades. Its high latency and storage requirements make
it unsuitable for interactive use, but it demonstrates that a
network can provide strong anonymity for publishing without
low-latency routing.

**GNUnet and research.** GNUnet is a research platform that has
influenced many subsequent designs. Its modular architecture and
strong adversary-resistance assumptions make it a useful reference
for understanding the design space, even though it is not widely
deployed as a production anonymity network.

---

## 11. Legal and Ethical Notes

**Client use:**

- Legal in most jurisdictions. Lokinet, Nym, and Yggdrasil are
  not as widely blocked as Tor, but the same legal principles
  apply: anonymity does not legalize illegal content.
- Using these networks to access content illegal in your
  jurisdiction is still illegal.

**Service node / relay operation:**

- **Lokinet service nodes** require staking OXEN tokens. This may
  have tax, regulatory, or securities implications depending on
  your jurisdiction. Consult a professional if you are unsure.
- **Lokinet exit nodes** see clearnet traffic, similar to a Tor
  exit relay. Check your jurisdiction's laws and ISP AUP.
- **Nym mix nodes** are operated by node operators who earn NYM
  tokens. Similar considerations apply.

**Ethical considerations:**

- These networks are used by journalists, activists, and ordinary
  users for legitimate privacy. Do not assume malicious intent.
- Do not use any of these networks to evade lawful investigation,
  traffic illegal material, or harm others.
- See `../../../SECURITY.md` for the repository's authorized-use
  policy.

---

## 12. Production Notes

**For a red team engagement:**

- None of these networks are appropriate for an authorized
  engagement. Corporate networks block them, and their use may
  violate the rules of engagement.
- If anonymity is required, use dedicated infrastructure (VPS +
  VPN) and document it in the engagement plan.

**For personal threat modeling:**

- **Clearnet browsing:** use Tor (or Tor Browser).
- **In-network hosting:** use I2P.
- **Real-time UDP over onion routing:** use Lokinet.
- **Strong anonymity for messaging/file transfer (latency acceptable):**
  use Nym.
- **Fast overlay networking (not anonymity):** use Yggdrasil.
- **Censorship-resistant publishing:** use Freenet/Hyphanet.

**Network comparison (2025):**

| Network | Focus | Latency | Anonymity set | Exit to clearnet |
|---------|-------|---------|---------------|------------------|
| Tor | Clearnet anonymity | ~200-500 ms | Millions | Core design |
| I2P | In-network services | 1-3 s | ~55,000 routers | Limited |
| Lokinet | Hybrid VPN + hidden services | Low | <1,000 nodes | Supported |
| Nym | Strong anonymity | 1.5-2 s | Small | Supported (proxy) |
| Yggdrasil | Overlay networking | Low | N/A (not anonymity) | N/A |

---

## 13. References

- Lokinet README - https://github.com/oxen-io/lokinet
- Oxen Docs - Lokinet - https://docs.oxen.io/products-built-on-oxen/lokinet
- I2P vs Other Privacy Networks - https://i2p.net/en/docs/overview/comparison/
- Nym Docs - Packet Mixing - https://nym.com/docs/network/deep-dives/mixing
- Nym Docs - Mixnet Mode - https://nym.com/docs/network/mixnet-mode
- Nym Docs - Traffic Flow - https://nym.com/docs/network/mixnet-mode/traffic-flow
- GNUnet (Whonix Wiki) - https://www.whonix.org/wiki/GNUnet
- Yggdrasil Network - https://yggdrasil-network.github.io/
- Freenet/Hyphanet - https://hyphanet.org/
- Loopix design (academic paper, referenced by Nym)
- "The effectiveness of mixnets - an empirical study" (2013) - https://www.sciencedirect.com/science/article/abs/pii/S1361372313701118
