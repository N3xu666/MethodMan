# Network Forensics and PCAP Analysis

Reconstructing what happened on a network from packet captures and related artefacts. Where "Wireshark and tshark" covered the tooling, this file covers the forensic method: chain of custody, timeline reconstruction, correlation with host artefacts, and the analytical discipline that separates a finding from a guess.

## 1. Overview

Network forensics answers questions of the form: "did host X talk to host Y, when, and what was exchanged". The PCAP is one source; the answer usually requires three:

- **Packet data** - the PCAP, or flow records if packets are not stored.
- **Host artefacts** - process trees, network connection logs, file system timestamps from the endpoint.
- **Infrastructure logs** - DNS, DHCP, proxy, firewall, authentication logs.

A conclusion supported by only one source is a hypothesis. A conclusion supported by correlated timestamps across all three is a finding.

The forensic method is not different from any other evidence discipline: preserve, analyse, document, conclude. Only the artefacts differ.

## 2. Chain of Custody

The PCAP is evidence. Treat it accordingly from the moment of capture.

- **Hash on acquisition.** `sha256sum capture.pcap` immediately after capture stops. Record the hash, the file size, the acquisition time and the capture host identity.
- **Write-once storage.** Store the original on media or a share that is append-only or write-once where possible. If that is not available, restrict write access and record who had it.
- **Work on copies.** Every analysis step uses a copy. The original is re-hashed at the end of the case to confirm it is unchanged.
- **Document every access.** Who opened the PCAP, when, with which tool version. A defence that says "the file was modified after capture" is impossible to answer without this record.
- **Retention and destruction.** Define retention before the case starts. Destruction is documented with the same rigour as acquisition.

Chain of custody is not bureaucracy: it is what makes the analysis admissible and defensible.

## 3. Offensive

### 3.1 Anti-forensics at the network layer

An attacker cannot delete packets already captured, but can make the analysis expensive or misleading.

- **Timestamp manipulation via TTL and timing.** TTLs and inter-packet delays shaped to look like a different OS or a different network distance.
- **Protocol mimicry.** HTTPS to a legitimate CDN, DNS to a legitimate resolver, SMB over admin shares - each looks like business traffic.
- **Decoy traffic.** Generate benign traffic that looks like the real C2, so the analyst's first lead is a false one.
- **Encryption.** Application-layer encryption of the payload means the PCAP shows metadata only.
- **Fragmentation.** Deliberate fragmentation complicates reassembly and analysis tools that do not defragment may silently miss content.

### 3.2 Recipes

- **TLS to a CDN with a legitimate SNI.** The capture shows the SNI; the SNI is a real CDN domain. Unless JA3/JA4 or certificate pinning flags it, the connection is unremarkable.
- **DNS tunnelling via a legitimate resolver.** Queries to a popular resolver (8.8.8.8, 1.1.1.1) to subdomains controlled by the attacker. The resolver is legitimate; the queries are not.
- **ICMP with large payloads.** Many captures filter out ICMP entirely. Large ICMP payloads carry data.

### 3.3 Detection of forensic analysis

Analysis activity that touches external services (WHOIS, online sandboxes, VirusTotal) from a shared IP is observable. Work offline where possible; batch external lookups and source them from infrastructure that is not linked to the case.

## 4. Defensive

### 4.1 Forensic workflow

1. **Preserve.** Hash the PCAP, copy, store the original write-protected.
2. **Triage.** Protocol hierarchy, conversations, endpoints. Identify the interesting flows.
3. **Timeline.** Build a per-packet or per-flow timeline for the incident window. Merge with host and infrastructure logs.
4. **Reconstruct.** For each interesting flow, follow the stream, identify the application protocol, extract payload and metadata.
5. **Correlate.** For every network event, find the host event that produced it and the infrastructure log that recorded it. Note the clock offsets.
6. **Document.** Record the filter, the evidence file, the hash, the conclusion, and the confidence (high, medium, low).
7. **Re-verify.** Re-hash the original at the end. Confirm nothing changed.

### 4.2 Timeline construction

Timelines are the core forensic artefact. A good timeline has four columns:

| Time (UTC) | Source | Event | Confidence |
|------------|--------|-------|------------|
| 14:22:01.123 | PCAP | HTTP POST /admin/login.php from 10.10.10.10 | High |
| 14:22:01.120 | Host (web server) | access.log entry for the same POST | High |
| 14:22:00.000 | DNS server | resolver query for attacker domain | Medium (clock offset) |

Clock offsets are noted explicitly. A finding that depends on a millisecond-level correlation across hosts with unverified clocks is low confidence.

### 4.3 PCAP analysis recipes

```bash
# Extract all unique HTTP hosts seen in the capture
tshark -r capture.pcap -Y "http.request" -T fields -e http.host | sort -u

# Extract DNS queries to a specific domain
tshark -r capture.pcap -Y "dns.flags.response == 0 and dns.qry.name contains \"attacker\"" -T fields -e frame.time -e ip.src -e dns.qry.name

# Find TLS Client Hellos with SNI, list IP, SNI, JA3 if available
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja3

# Export HTTP objects to a directory
mkdir -p http_objects && tshark -r capture.pcap --export-objects http,http_objects
```

Expected output (DNS queries to attacker domain):

```text
2026-10-22 14:25:11.111 10.10.10.10 exfil.attacker.tld
2026-10-22 14:25:12.222 10.10.10.10 exfil.attacker.tld
2026-10-22 14:25:13.333 10.10.10.10 exfil.attacker.tld
```

### 4.4 Correlation with host artefacts

For a suspected exfiltration, the cross-check is:

- PCAP: which host made the outbound connection, when, to which IP/domain, how many bytes.
- Host (network connection log, `netstat` if captured, EDR telemetry): which process held the socket.
- Host (file system): which files were accessed in the minutes before the connection.
- Infrastructure (proxy, firewall): the same connection seen from the perimeter.

When all four agree on a source port, timestamp and byte count, the finding is high confidence.

## 5. Offensive (continued): defeat the timeline

An attacker who knows the forensic method targets the correlation, not just the packets.

- **Time skew.** If the attacker controls a host that produces evidence, skew its clock to make the timeline inconsistent. An analyst who trusts host timestamps without checking clock offset draws the wrong conclusion.
- **Split across hosts.** Perform the attack from one host, stage from a second, exfiltrate from a third. Correlation across three hosts is expensive.
- **Slow-and-low exfiltration.** Bytes per hour well below any volume alert, spread across a full working day. The PCAP has all the evidence; the analyst has to find it.
- **Legitimate infrastructure as a pivot.** Use a proxy or VPN whose IPs are shared with thousands of legitimate users. Attribution becomes nearly impossible.

These do not defeat the PCAP. They defeat sloppy analysis.

## 6. Common Mistakes

- **Trusting host timestamps without clock offset.** A 40 ms offset between PCAP and host log is enough to break millisecond-level correlation. Document the offset for every source.
- **Building a timeline from one source.** A PCAP-only timeline is a hypothesis. A host-only timeline is a hypothesis. Both together with infrastructure logs is a finding.
- **Not hashing exports.** Files exported from the PCAP are evidence. Hash each on export.
- **Analysing the original.** Analysis on the original PCAP risks accidental modification. Always work on copies.
- **Missing DNS.** A capture without DNS forces manual resolution later, often after the records have rotated or the domain has been taken down.
- **Forgetting flow records.** Flow records (NetFlow, IPFIX) are not packets but they answer "did X talk to Y, when, how much" for windows where packets are not stored. Ignoring them wastes the most available evidence class.

## 7. Attacks and Detection

- **Timeline poisoning.** A host that produces false log entries (or an attacker who can write to a log) poisons the timeline. Corroborate across independent sources.
- **Evidence tampering.** PCAPs on write-accessible storage are tamperable. Hash-on-acquisition, write-once storage and re-hash-on-completion are the countermeasures.
- **Tool poisoning.** A compromised analysis tool (custom scripts, unmaintained exporters) can produce false artefacts. Use signed tools, record versions, sanity-check outputs.
- **Over-reliance on one signature.** A single detection (a suspicious JA3, a single DNS query) is not evidence of compromise. Build the case from multiple correlated facts.

## 8. Verification

- **Timeline sanity check.** Walk the timeline end to end. Every event should have a plausible cause. An unexplained gap is a finding.
- **Byte-count reconciliation.** The bytes attributed to an exfiltration in the PCAP should match the bytes reported by flow records for the same flow.
- **Re-hash the original.** At the end of the case, re-hash the original PCAP. It must equal the acquisition hash.
- **Cross-tool reproducibility.** Re-run a key extraction with a different tool (tcpdump/tshark vs Wireshark vs a script) and confirm the same result. A single-tool finding is a single point of failure.

## 9. Production Notes

- Maintain a case template: acquisition record, chain-of-custody log, timeline spreadsheet, evidence index, conclusion document.
- Retain PCAPs, extracted objects, notes and hashes for the retention period defined by policy, not by convenience.
- For recurring incident types, pre-write the query set (tshark filter + host log query + flow query). The analysis is much faster when the queries already exist.
- Store PCAPs encrypted at rest; captures routinely contain credentials and PII.
- Train the IR team on cross-tool reproducibility. One analyst, one tool, one opinion is a single point of failure.

## 10. References

- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response - https://csrc.nist.gov/pubs/sp/800/86/final
- RFC 3227, Guidelines for Evidence Collection and Archiving - https://www.rfc-editor.org/rfc/rfc3227
- pcap-filter (BPF syntax) - https://www.tcpdump.org/manpages/pcap-filter.7.html
- tshark manual page - https://www.wireshark.org/docs/man-pages/tshark.html
- RFC 7011, IPFIX Protocol Specification - https://www.rfc-editor.org/rfc/rfc7011

## Certification Alignment

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 4 (Security Operations) - forensic evidence handling |
| CompTIA CySA+ | Domain 1 (Security Operations), Domain 3 (Incident Response) - timeline reconstruction, evidence correlation |
| Cisco CyberOps Associate | Domain 4 (Incident Response) - network forensic method |
