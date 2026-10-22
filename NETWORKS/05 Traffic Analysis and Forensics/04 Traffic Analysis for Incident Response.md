# Traffic Analysis for Incident Response

How traffic analysis supports an active incident: detection, scoping, containment decisions, and the evidence that drives the post-incident report. Where the previous file covered forensic analysis after the fact, this file covers analysis under time pressure, during an incident that is still unfolding.

## 1. Overview

Incident response has a different tempo from forensic analysis. In an active incident the analyst answers questions in minutes, not days:

- **Is this real?** - triage a detection, decide whether to escalate.
- **How far did it spread?** - scope: which hosts, which accounts, which data.
- **Is it still happening?** - is the adversary still active, and through which channel.
- **Can we contain it?** - which network blocks will stop the activity without breaking the business.
- **What did we lose?** - the data exposure question, asked after containment.

Each question has a traffic-analysis answer, and each answer has a confidence level. The IR analyst's job is to make the confidence explicit, so the incident commander can act on the answer.

The file covers the analysis workflow during an incident, not the forensic workflow after it.

## 2. Triage: From Alert to Decision

Every alert is a question, not a finding. Triage decides whether it is a finding.

The triage loop:

1. **What triggered?** - a signature, a threshold, a heuristic, a report. Know which.
2. **What does the traffic show?** - pull the corresponding PCAP window, check the connection, the payload if decryptable, the peer.
3. **Is it expected?** - a scanner, a backup, a legitimate admin action. Most alerts are expected activity.
4. **If unexpected, what is the blast radius?** - which other hosts talked to the same peer, in the same window.
5. **Escalate or close.** - document the decision and its basis either way.

The common failure: escalating without looking at the PCAP, or closing without documenting why. Both produce noise or missed incidents.

## 3. Offensive

### 3.1 How the attacker shapes the alert stream

An attacker who expects to be detected works on the detection side as much as the payload side.

- **Beacon jitter.** Random intervals between C2 check-ins prevent periodic-signature detection.
- **Volume shaping.** Exfiltration at the baseline rate of the environment, not at line rate.
- **Protocol choice.** Use a protocol the environment already trusts heavily (HTTPS to a CDN, DNS to the corporate resolver) so that the alert, if it fires, is a low-priority one.
- **Blend with business hours.** Activity during the target environment's normal working hours is less anomalous than activity at 3 AM.
- **Clean up detections.** Avoid the noisiest scanners and the noisiest exploits. The quiet TTPs are the goal.

### 3.2 Recipes

- **Living off the land.** Use built-in tools (`certutil`, `bitsadmin`, `powershell`) whose traffic is normal in the environment.
- **Cloud services as C2.** Abuse a legitimate SaaS (a file-sharing API, a messaging API) so the traffic is to a known-good destination.
- **Domain fronting where it still works.** CDN-fronted C2 (see current CDN policies - many CDNs now block SNI/host mismatch).
- **Fast flux.** Rotate the destination IP from a pool, so IP-based blocking rules do not stick.

### 3.3 Detection of analysis during an active IR

An attacker with a foothold can observe the IR analyst's actions: which endpoints are being triaged, which blocks are being deployed. Move faster than the attacker, or act on one channel while watching another. The traffic tells the attacker what the defender is about to do, unless the defender keeps the analysis traffic off the production network.

## 4. Defensive

### 4.1 The IR analysis cycle

For each active alert or reported incident:

1. **Collect the traffic.** Pull the last 24 h of PCAP (or the specific window, if storage is limited).
2. **Identify the flow.** Which host, which peer, which port, which protocol.
3. **Establish the baseline.** Is this connection type normal for that host at that time of day?
4. **Scope.** Query for other hosts with the same peer, the same payload signature, the same beacon pattern.
5. **Decide containment.** What can be blocked, what must not.
6. **Document the decision.** What was seen, what was concluded, what was done.

### 4.2 Scoping queries (fast)

```bash
# All hosts that talked to a given peer IP in the last window
tshark -r last24h.pcap -Y "ip.addr == 203.0.113.5" -T fields -e ip.src -e ip.dst | sort -u

# All DNS queries for a suspicious domain
tshark -r last24h.pcap -Y "dns.qry.name contains \"suspicious\"" -T fields -e frame.time -e ip.src -e dns.qry.name | sort -u

# All TLS connections with a given SNI
tshark -r last24h.pcap -Y "tls.handshake.extensions_server_name == \"malicious.example\"" -T fields -e frame.time -e ip.src -e tcp.dstport

# All SMB connections in the last hour (lateral movement)
tshark -r last1h.pcap -Y "tcp.port == 445 and tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e ip.dst | sort -u
```

Expected output (hosts that talked to a given peer):

```text
10.10.10.10
10.10.10.21
10.10.10.42
10.10.10.55
```

Four hosts. That is the scope of the C2 channel. Everything else is unrelated to this peer.

### 4.3 Containment: traffic-level decisions

Containment is a network decision with network consequences. Each option trades speed for precision:

- **Block the peer IP** - fast, effective, also tips off the attacker (their C2 stops). Attacker may pivot.
- **Block the peer domain at DNS** - slower (TTL), effective against new connections, does not stop an active session.
- **Block the port** - too coarse, breaks legitimate traffic if the port is shared.
- **Sinkhole the C2** - see which hosts keep checking in; high confidence scope after the block.
- **Isolate the host** - most decisive; kills business connectivity too.
- **Monitor, do not block** - continue gathering intelligence, accept the risk of ongoing compromise.

The choice belongs to the incident commander, informed by the analyst's confidence level and the business context.

## 5. Offensive (continued): survive IR

Once an incident is being responded to, the attacker's goal changes: from "do the mission" to "do not be found out entirely".

- **Assume the C2 will be blocked.** Have alternative channels ready. Do not rely on a single domain.
- **Assume the initial host will be isolated.** Have a foothold outside the isolated segment. Persistence that survives host rebuild.
- **Assume the PCAP will be read.** Minimise the signal in the capture: fewer hosts, fewer peers, less volume.
- **Assume timing correlation.** If the defender builds a timeline across multiple sources, the attacker should split activity across hosts so no single timeline shows the full picture.

These are operational decisions, not traffic decisions. The traffic is a consequence.

## 6. Common Mistakes

- **Blocking before scoping.** A fast block stops one host's channel and tips off the rest. Scope first (query, list, confirm), then contain.
- **Scoping from the SIEM alone.** SIEM alerts are summaries. The PCAP has the actual bytes. Confirm every scoping decision against the traffic.
- **Ignoring the DNS.** A block rule for the C2 IP does nothing about the DNS query that resolves to the IP. Block at both layers.
- **Not documenting the confidence.** "It might be C2" and "it is confirmed C2" lead to different decisions. State which.
- **Letting the IR analyst run queries on the compromised network.** If the analyst's workstation is on the same VLAN as the adversary's foothold, the analyst is a target. Segment the analysis tools.

## 7. Attacks and Detection

- **Adversary observes IR response.** If the adversary can see network segments that host the IR tooling, they can see the containment being prepared. Segment.
- **False-positive flood.** A noisy alert stream that buries the real one. Tune detections continuously; have a documented suppression policy.
- **C2 churn.** Blocking one domain/IP is fine if the adversary rotates. Have ready-made queries for scoping by signature, not just by specific destination.
- **Detection of the analyst.** An alerting rule that fires on the analyst's traffic (large tshark queries from one workstation) is background noise but is also visible. Keep analysis queries batched.

## 8. Verification

- **Scope list cross-check.** The hosts in the scope list should match the hosts in the endpoint EDR's list for the same peer. Discrepancies = missed hosts or bad PCAP.
- **Containment effectiveness.** After the block, confirm zero new connections to the peer in the following window. If not zero, the block is ineffective (cached DNS, alternate IP, alternate channel).
- **Timeline sanity.** The IR timeline should have no unexplained gaps. Each event has a cause from the previous event.
- **Evidence preservation.** The PCAP used during IR is the same PCAP preserved for post-IR analysis. Do not delete.

## 9. Production Notes

- Keep 24-72 h of full PCAP accessible to the IR team at all times. Longer retention = a separate archival tier.
- Pre-write the scoping queries. During IR is not when you want to remember tshark syntax.
- Segment the IR analysis workstations. They are the most valuable target on the network during an incident.
- Rotate IR playbooks after every real incident; keep the version history.
- Retain PCAPs used in an incident for the incident's evidence retention period, not the standard PCAP retention.

## 10. References

- NIST SP 800-61 Revision 3, Computer Security Incident Handling Guide - https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA Incident and Vulnerability Response Playbooks - https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
- SANS Incident Handler's Handbook - https://www.sans.org/white-papers/33901/
- tshark manual page - https://www.wireshark.org/docs/man-pages/tshark.html
- RFC 7011, IPFIX Protocol Specification - https://www.rfc-editor.org/rfc/rfc7011

## Certification Alignment

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 4 (Security Operations) - incident response basics |
| CompTIA CySA+ | Domain 3 (Incident Response) - detection, scoping, containment |
| Cisco CyberOps Associate | Domain 4 (Incident Response) - analyst role in IR |
