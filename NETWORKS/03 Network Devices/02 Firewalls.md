# Firewalls (Offensive and Defensive)

> [!CAUTION]
> This reference is for authorized penetration testing and defensive engineering only. Every technique here assumes written authorization and an isolated lab or a production change window approved by the asset owner.

## 1. Overview

A firewall enforces a policy on traffic that crosses a trust boundary: which flows are allowed, which are denied, and what the device does with everything else. The trust boundary can sit between networks (perimeter), between zones inside one network (segmentation), between a host and the network (host firewall), or inside an application (WAF). The core question a firewall answers is always the same: given the packet, the connection state, and the policy, does this flow proceed?

There are five families worth knowing, because each fails in a different way.

- **Stateless packet filter.** Examines each packet in isolation against an ordered list of rules (source, destination, protocol, port, flags). Fast, cheap, and blind to connection state. Bypassed by any attack that lives inside an allowed port, and by fragmentation tricks if the device does not reassemble correctly.
- **Stateful firewall.** Tracks connection state (the five-tuple plus TCP state machine) and allows return traffic for established flows without an explicit rule. The default on almost every modern device. The state table is the attack surface: exhaustion, stale entries, and asymmetric routing all break it.
- **NGFW (Next-Generation Firewall).** Stateful plus application identification (L7), user identity, TLS inspection, and IPS signatures. Palo Alto, Fortinet, Cisco Firepower, Check Point. Powerful and complex: the policy is only as good as the app-ID mapping, and TLS inspection is its own attack surface.
- **WAF (Web Application Firewall).** HTTP-aware. A reverse proxy in front of the web app that parses requests and matches rules (ModSecurity/CRS, vendor rule sets). It sees methods, headers, bodies, and JSON/XML; it can be bypassed by encoding, parsing differentials, and anything the app accepts but the WAF does not understand.
- **Proxy and reverse proxy.** A forward proxy mediates client egress; a reverse proxy terminates TLS and fronts servers. Both are policy points and both are frequently misconfigured as open relays or as TLS-termination weak spots.

The two-track structure below applies to all of them: Offensive (how the policy is tested and bypassed) and Defensive (how the policy is built, verified, and monitored).

## 2. Reconnaissance / Enumeration

Enumeration of a firewall has one goal: map the actual policy, not the intended one. The policy you can read in a diagram and the policy the device enforces diverge constantly.

### Offensive

- **Port scan with timing and fragmentation variation.** A single scan tells you what is open right now; three scans at different rates tell you whether the device rate-limits or shuns. Compare a fast SYN scan with a slow connect scan.
- **Firewall fingerprinting.** nmap -O, TTL behavior, ICMP error quoting, TCP options, and response to malformed packets all hint at the vendor and generation. A device that silently drops is different from one that rejects with RST or ICMP admin-prohibited.
- **Policy probing on filtered ports.** Filtered (not closed) means the firewall dropped the packet. Compare nmap -sA (ACK scan) against -sS: a stateful firewall that drops SYNs may still RST ACKs differently, revealing the rule structure.
- **Egress policy discovery.** From an obtained host, test outbound: DNS to 8.8.8.8, HTTP/HTTPS to arbitrary hosts, non-standard ports. The egress policy is often far looser than ingress and is the path for C2 and exfiltration.
- **Management plane exposure.** Scan for the firewall's own management interface: HTTPS/SSH on the management network, SNMP, and vendor-specific ports. An exposed management plane is a higher-value target than any rule bypass.
- **WAF fingerprinting.** Send a benign request with a known-malicious-looking parameter and watch the response: a WAF block page, a 403, a connection reset, or a challenge. wafw00f automates the common vendors; header order and cookie names confirm.

### Defensive

- **Inventory what should be reachable.** Every firewall rule should map to a documented service. Anything reachable that is not in the inventory is a finding.
- **Test the management plane reachability from untrusted zones.** The management interface must not answer from the internet or from user VLANs. Verify with an external scan and an internal scan from a user segment.
- **Baseline the shun/rate-limit behavior.** Know how the device responds to scans so that a scan in the logs is recognizable as a scan and not as an outage.

## 3. Common Attack Vectors

Firewall attacks split into three groups: bypass the policy, attack the device, and abuse the trust the firewall creates.

**Policy bypass (the traffic gets through when it should not):**

- **Allowed-port tunneling.** SSH, DNS, HTTPS, and any permitted service carry arbitrary payloads. If 443 is open to the internet, a C2 channel over HTTPS is allowed by policy.
- **Protocol confusion.** The firewall identifies traffic by port, the app by content. Running a non-HTTP protocol on 80, or HTTP on a non-standard port, defeats port-based rules and confuses naive app-ID.
- **Fragmentation and overlap.** Overlapping IP fragments, tiny fragments, and TCP segment overlap can slip past stateless devices and some stateful ones if reassembly differs between the firewall and the endpoint.
- **Source routing and loose source route options** on devices that still honor them.
- **Tunneling and encapsulation.** GRE, IP-in-IP, and VPN tunnels hide the inner flow from a device that only inspects the outer header.
- **Asymmetric routing.** Return traffic that takes a different path bypasses a stateful device that never sees the reply, so the state entry is never created or never matched.
- **IPv6 gaps.** A network that is hardened for IPv4 and dual-stack for IPv6 frequently has no IPv6 firewall policy at all. The v6 path is the bypass.

**Device attacks (the firewall itself is the target):**

- **Management plane compromise.** Default credentials, exposed management UI, SNMP with a writable community, and unpatched CVEs in the management interface. This is the highest-impact path: control of the firewall is control of every rule.
- **Known CVEs in the data plane.** Vendor advisories list them constantly: authentication bypass in the web UI, pre-auth RCE in the SSL VPN, path traversal in the management portal. Track the vendor advisory feed and the CISA KEV list.
- **Resource exhaustion.** State-table exhaustion, session limits, and half-open connection floods. A firewall that runs out of state fails open or fails closed depending on vendor and configuration, and either is a denial of service.
- **WAF rule evasion.** Encoding (double URL-encode, Unicode, HTML entity), content-type confusion (JSON parsed as form data), HTTP parameter pollution, chunked transfer-encoding desync, and request smuggling between the WAF and the backend. The WAF and the app must parse the request identically; any differential is a bypass.

**Trust abuse (the firewall's own trust model is exploited):**

- **Trusted-zone pivot.** A compromised host in a trusted zone inherits the zone's access. Flat internal networks make the perimeter firewall irrelevant.
- **VPN as a door.** An exposed SSL VPN is an authentication surface and, when unpatched, a pre-auth RCE surface. Many breaches start at the VPN concentrator, not the perimeter rule set.
- **Split-tunnel leakage.** A VPN client that splits traffic sends corporate DNS and some traffic outside the tunnel, where it is neither inspected nor protected.

The common thread: the firewall is only as strong as its weakest parser and its loosest rule. Bypass usually targets the gap between what the policy says and what the device actually understands.

## 4. Exploitation Recipes

All commands and tests below are run only against systems you own or have written authorization to test.

### Recipe 1 - Map the effective policy

```bash
# Fast SYN scan, then a slow connect scan for comparison
nmap -sS -p- --min-rate 2000 10.10.10.1
nmap -sT -p 22,80,443,3389 10.10.10.1

# ACK scan to see how the device treats non-SYN packets
nmap -sA -p 1-1000 10.10.10.1

# Firewall and OS fingerprint
nmap -O --osscan-guess 10.10.10.1
```

Expected: filtered ports return no response (dropped) while closed ports return RST. The difference between the fast and slow scan reveals rate limiting.

### Recipe 2 - Test egress from an obtained host

```bash
# DNS egress to a public resolver
dig @8.8.8.8 example.com +short

# HTTPS egress to an arbitrary host
curl -s -o /dev/null -w "%{http_code}\n" https://example.com

# Non-standard port egress
nc -vz example.com 4444
```

Expected: if DNS and 443 succeed but 4444 fails, egress is limited to web and DNS, which constrains C2 to those channels.

### Recipe 3 - WAF fingerprint and a first bypass attempt

```bash
# Vendor fingerprint
wafw00f https://target.example

# Benign request with a malicious-looking parameter
curl -s "https://target.example/?q=1'%20OR%20'1'='1"

# Encoding variation of the same payload
curl -s "https://target.example/?q=1%2527%2520OR%25201%253D1"
```

Expected: the first request may return a WAF block page (403, a challenge, or a vendor error). The double-encoded request tests whether the WAF decodes once while the app decodes twice; a different response is a parsing differential worth pursuing.

### Recipe 4 - Check the management plane

```bash
# Is the management UI reachable from an untrusted segment?
nmap -p 443,22,161,8443 10.10.10.1

# Default credential check (authorized only)
curl -sk -o /dev/null -w "%{http_code}\n" -u admin:admin https://10.10.10.1/
```

Expected: a management port answering from an untrusted segment is a finding regardless of the credential result.

### Recipe 5 - Request smuggling probe (WAF vs backend desync)

```bash
# Send both Content-Length and Transfer-Encoding and watch timing/response
printf 'POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | openssl s_client -quiet -connect target.example:443
```

Expected: if the WAF and the backend disagree on which header wins, the response timing or body diverges between a normal request and this one. That divergence is the precondition for a smuggling attack.

### Recipe 6 - State-table stress (lab only)

```bash
# SYN flood from a lab host to a target service behind the firewall
sudo hping3 -S --flood -p 443 10.10.10.1
```

Expected: watch the firewall session table and CPU. A device that fails open under exhaustion is a critical finding; one that fails closed is a denial of service. Never run this outside an isolated lab or an approved test window.

## 5. Post-Exploitation

Once a firewall or its policy is compromised, the post-exploitation options are network-wide.

**Rule and policy manipulation.** Full read of the rule base is the first objective: it maps every trust relationship in the network. Write access allows opening a hole, disabling logging, or widening a rule. On an NGFW this means access to the security policy, NAT, VPN, and routing.

**Configuration exfiltration.** The running config contains every rule, every object, every VPN key, every admin credential (often hashed), and every management endpoint. Treat it as the crown jewel of the network.

**Persistence.** A local admin account on the device, a modified rule that permits the attacker back in, or a scheduled config change. On devices with API access, an API token is durable persistence. All survive a reboot if the config is saved.

**Traffic redirection and interception.** A firewall or proxy under attacker control can mirror, redirect, or drop traffic. SSL forward proxy on an NGFW can decrypt and re-encrypt, which turns the device into a network-wide MITM.

**Logging suppression.** Disabling or redirecting syslog, clearing the local log buffer, and excluding the attacker's source from logging. A compromised firewall that keeps logging is only half compromised; the attacker will try to fix that.

**Pivot into trusted zones.** The firewall is the map of the trusted zones. Once it is understood or controlled, the next hop is the most valuable segment it protects, not the perimeter itself.

## 6. Preventive Controls

Firewall hardening is policy discipline plus device hardening. One without the other is incomplete.

**Policy design:**

```text
! Default deny, explicit allow, deny with logging
! Order: specific allow rules first, default deny last
! Every rule has: owner, ticket, purpose, expiry review
! No "any/any/any" rules, no broad RFC1918-to-RFC1918 allows
! Egress default deny with an allow-list of required destinations
```

- **Default deny in both directions.** Ingress and egress both default to deny. The egress policy is the one most often left open and the one that stops exfiltration.
- **Zone segmentation.** Group assets by trust level, not by convenience. A flat internal network makes the perimeter pointless.
- **Rule hygiene.** Every rule has an owner and a review date. Unused rules are removed; broad rules are narrowed. A rule base that has never been pruned is a finding.
- **IPv6 parity.** If the network runs IPv6, the IPv6 policy is as strict as the IPv4 policy. Dual-stack without v6 rules is a bypass.

**Device hardening:**

```text
! Management plane on a dedicated network, not the data plane
! Strong admin auth (AAA, MFA), no default accounts
! SSH v2 only, no Telnet, no HTTP (HTTPS only if required)
! SNMP v3 auth+priv, no v1/v2c community strings
! NTP authenticated, syslog to a remote collector
! Firmware current, vendor advisory feed monitored
! Config backups encrypted and stored offline
```

- **Management plane isolation.** A dedicated management network with an allow-list. Never expose the management UI to the internet or to user VLANs.
- **AAA and MFA.** Centralized authentication (TACACS+/RADIUS) with per-admin accounts and MFA where the vendor supports it.
- **Least privilege for admins.** Read-only accounts for monitoring, change windows for write access, and command authorization.
- **Patch discipline.** Subscribe to the vendor advisory feed and the CISA KEV list. The SSL VPN and the management UI are the two most-attacked surfaces.
- **TLS inspection hygiene.** If the device decrypts TLS, its CA certificate must be protected and its exclusions documented. A compromised inspection CA is a universal MITM.

**WAF hardening:**

- **Positive security model where possible.** Allow known-good rather than block known-bad for critical endpoints.
- **Parsing parity with the backend.** The WAF and the app must agree on how a request is parsed. Test with the smuggling probe above.
- **Virtual patching is a stopgap.** A WAF rule that blocks an exploit does not fix the code. Track the underlying fix.

## 7. Detection Controls

**Policy and rule changes:**

- Every rule add, delete, or modify is logged and alerted. A change outside a change window is a high-severity alert.
- Config diffing: compare the running config against the last known-good baseline on a schedule.

**Management plane activity:**

- Successful and failed admin logins, especially from new source IPs.
- New admin accounts, privilege changes, and API token creation.
- Management access from unexpected networks.

**Traffic anomalies:**

- New flows to destinations that never appeared before (C2 and exfiltration).
- Volume anomalies per host (data staged and sent).
- DNS tunneling indicators: high-entropy subdomains, long TXT records, unusual volume to one resolver.

**WAF and IPS telemetry:**

- Spike in blocked requests from one source (scan or attack attempt).
- A request that the WAF allowed but the backend logged as malicious (a bypass in progress).
- Signature hits correlated with the same source across multiple devices.

**Example syslog and flow correlation:**

```text
! Firewall: log denies and rule hits
log traffic deny all
! Send to the SIEM
logging host 10.10.10.50
! Flow telemetry to the collector
netflow export destination 10.10.10.50 2055
```

The high-value SIEM alert is a chain: an admin login from a new IP, followed by a rule change, followed by a new flow to an external host. Each event alone is noise; together they are a compromised firewall.

## 8. Verification

How to verify that the firewall is enforcing what it claims.

**Verify the policy matches the intent:**

```text
! Export the rule base and diff against the approved baseline
show running-config | include (access-list|rule|policy)
! Look for any/any rules and rules without owners
```

- Scan from each zone to each zone and compare the result with the documented matrix. Any reachable service that is not in the matrix is a gap.

**Verify the device is hardened:**

```text
! Management access
show run | include (telnet|ssh|http|snmp)
! Expect: SSH v2, no Telnet, no HTTP, SNMP v3 only
! AAA and logging
show aaa servers
show logging
! Expect: AAA reachable, logs going to the collector
```

**Verify egress control:**

- From a test host, attempt DNS, HTTPS, and a non-standard port to the internet. The allowed set must match the policy, and everything else must fail.

**Verify IPv6 parity:**

- Repeat the zone-to-zone scan over IPv6. Any service reachable over IPv6 but not IPv4 is a policy gap.

**The verification habit:** after every rule change, re-run the zone matrix and the egress test. A silent rule change is the most common firewall compromise.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**

- Domain 3: Network Operations - firewalls, ACLs, monitoring.
- Domain 4: Network Security - firewall types, segmentation, IDS/IPS.

**Cisco CCNA (200-301):**

- Domain 4: IP Services - ACLs, NAT.
- Domain 5: Security Fundamentals - firewalls, zone-based firewall, IPS.

**Cisco CCNP Security (350-701 SCOR):**

- Firepower, ISE, WSA/ESA, and the security policy model.
- TLS inspection, VPN, and the management plane.

**CompTIA Security+ (SY0-701):**

- Domain 3: Implementation - firewalls, WAF, proxy, segmentation.

**Cross-references:**

- 01 Network Fundamentals covers the layer 1-3 basics the firewall filters.
- 02 Routing and Switching covers the routing the firewall protects.
- 04 Network Protocols covers the protocols inside the allowed flows.
- 05 Traffic Analysis and Forensics covers how the firewall's telemetry is captured and analyzed.

## 10. Production Notes

**The rule base is the policy, and the policy is the business.** A firewall that enforces a rule nobody can explain is a liability, not a control. Every rule needs an owner, a purpose, and a review date. The most common finding in a firewall assessment is not a missing firewall; it is a firewall full of rules nobody understands.

**Egress is the forgotten direction.** Most teams harden ingress and leave egress wide open. The egress policy is what stops C2 and exfiltration once a host is compromised, and it is the control most often absent.

**The management plane is the real perimeter.** An exposed management UI with default credentials turns the firewall from a control into an entry point. Isolate the management plane first, before any rule tuning.

**App-ID and TLS inspection are not free.** They add power and they add attack surface (parsing bugs, the inspection CA). Enable them where the value is clear and document the exclusions; do not enable them everywhere by default.

**The WAF is a mitigation, not a fix.** A WAF rule that blocks an exploit does not fix the code. Treat virtual patching as a stopgap with an expiry, and track the underlying fix.

**IPv6 is the quiet bypass.** Dual-stack networks frequently have no IPv6 policy. If the network runs IPv6, the IPv6 firewall is as strict as the IPv4 one, or the IPv4 policy is decoration.

## 11. References

- NIST SP 800-41 Rev. 1 (Guidelines on Firewalls and Firewall Policy) - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- NIST SP 800-125B (Secure Virtual Network Configuration for Virtual Machine Hosts) - https://csrc.nist.gov/pubs/sp/800/125/b/final
- NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs) - https://csrc.nist.gov/pubs/sp/800/77/r1/final
- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- OWASP ModSecurity Core Rule Set - https://owasp.org/www-project-modsecurity-core-rule-set/
- CISA Known Exploited Vulnerabilities Catalog - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK - Network Security Appliances - https://attack.mitre.org/techniques/T1556/
- Cisco - Firepower Configuration Guides - https://www.cisco.com/c/en/us/support/security/firepower-ngfw-products/series.html
- Palo Alto Networks - Firewall Best Practices - https://docs.paloaltonetworks.com/
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics
