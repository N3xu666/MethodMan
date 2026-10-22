# Packet Capture Fundamentals

How to capture network traffic correctly before analysing it. A bad capture is worse than no capture: it is incomplete, timestamped unreliably or filtered in a way that silently removes the evidence. This file covers the capture layer that every later forensic step depends on.

## 1. Overview

Packet capture is the act of copying frames or packets from a network interface into a file (a PCAP) for later analysis. It sounds trivial - run tcpdump, press Ctrl+C, open in Wireshark - but the failure modes are subtle and expensive:

- **Dropped packets.** The kernel buffer overflows under load, and the capture silently misses traffic. A forensic conclusion built on an incomplete capture is wrong.
- **Truncated packets.** Snaplen too small: headers are complete, payload is cut off, the exfiltration evidence is gone.
- **Wrong clock.** Timestamps from a host without NTP drift, and cross-correlating with logs from another host becomes guesswork.
- **Filtered capture.** A BPF filter that excludes the interesting traffic. The PCAP looks valid and is useless.

This file establishes the capture methodology that the rest of the subcategory assumes.

## 2. Capture Point Selection

Where you capture determines what you can see. The same incident looks different at each point.

| Capture point | Sees | Misses |
|---------------|------|--------|
| Endpoint NIC | That host's traffic, full payload after decryption | Everything else; encrypted traffic unless TLS keys are available |
| Span port / mirror | All traffic through a switch port | Traffic not forwarded to the mirror; oversubscribed mirrors drop |
| Network TAP | All traffic on the link, including errors | Only that link; requires physical access |
| Firewall / router export | Flows (NetFlow, IPFIX, sFlow), not packets | Payload; sampling may be active |
| Inline proxy | Decrypted HTTP(S) if the proxy terminates TLS | Non-proxied traffic; anything not routed through it |

Rule: capture as close to the source of truth as possible. For an endpoint compromise, capture on the endpoint. For a lateral-movement investigation, capture at the choke point the attacker must traverse.

## 3. Offensive

### 3.1 How the attacker's traffic looks to a capture

An attacker who understands the capture methodology can shape traffic to be hard to capture or hard to interpret after capture.

- **Volume.** High-rate transfers overflow kernel buffers on the defender's capture host. A 10 Gbps exfiltration on a 1 Gbps mirror is invisible in the gaps.
- **Timing.** Slow-and-low exfiltration spreads the traffic across hours, below the threshold of volume-based alerting, but still fully present in a complete PCAP.
- **Encapsulation.** Tunnelling (GRE, IP-in-IP, DNS) means the interesting traffic sits inside a protocol the capture filter may not include.
- **Fragmentation.** Deliberate IP fragmentation complicates reassembly in tools that do not defragment by default.

### 3.2 Evasion recipes

- **Fragment the payload.** Send the exfiltrated data in fragments small enough that per-packet DLP signatures never see a complete pattern.
- **Encapsulate in an allowed protocol.** DNS tunnelling, ICMP tunnelling, HTTPS to a CDN front - the traffic passes any allow-list.
- **Pad to break signatures.** Insert random padding in application protocols where the parser tolerates it (HTTP chunk extensions, DNS EDNS padding) so fixed-offset signatures miss.
- **Vary the rate.** Match the baseline traffic profile of the target network so statistical anomaly detection has no signal.

These are not capture-evasion in the strict sense - they do not prevent capture. They reduce the value of a capture that uses naive filters or signatures.

## 4. Defensive

### 4.1 Capture methodology

A defensible capture has four properties: complete, timestamped, integrity-protected and documented.

- **Complete.** Snaplen 0 (full packets) unless storage forces truncation, and a documented snaplen if truncation is used. Buffer sized to the link rate.
- **Timestamped.** NTP-synchronised clock on the capture host. Record the clock source in the case notes.
- **Integrity.** Hash the PCAP on write (`sha256sum capture.pcap`), store the hash with the case file. Any later analysis works from a copy; the original is read-only.
- **Documented.** Interface, filter, snaplen, buffer size, start/end time, host clock offset.

### 4.2 tcpdump baseline

```bash
# Full-packet capture, interface eth0, all traffic, to a ring of 10 files of 100 MB
tcpdump -i eth0 -s 0 -w capture-%Y%m%d-%H%M%S.pcap -C 100 -W 10

# Same, filtered to a host of interest, with a human-readable live tail
tcpdump -i eth0 -s 0 -w host10.pcap -G 3600 host 10.10.10.10
```

Expected output (live tail, `tcpdump -n -i eth0 host 10.10.10.10`):

```text
14:22:01.123456 IP 10.10.10.10.50412 > 10.10.10.20.445: Flags [S], seq 1234567890, win 64240, length 0
14:22:01.124123 IP 10.10.10.20.445 > 10.10.10.10.50412: Flags [S.], seq 987654321, ack 1234567891, win 65535, length 0
```

### 4.3 BPF filter discipline

Capture filters (BPF, applied in the kernel) and display filters (Wireshark syntax, applied after capture) are different languages. Confusing them is a classic source of empty captures.

- **Capture filter** `host 10.10.10.10 and port 445` - only that traffic is written to disk.
- **Display filter** `ip.addr == 10.10.10.10 && tcp.port == 445` - all traffic is captured, only matching frames are shown.

Rule for forensics: capture broadly (host-level or link-level filter at most), filter during analysis. A capture filter that was too narrow cannot be undone; a display filter can be changed at will.

### 4.4 What to capture for an incident

- All traffic to and from the compromised host, bidirectional.
- All traffic through the suspected C2 destination, even if it looks benign.
- DHCP and DNS for the incident window (they anchor the timeline).
- Authentication traffic (Kerberos, LDAP, RADIUS) for the same window.
- ARP and LLDP for topology reconstruction.

## 5. Offensive (continued): capture-aware tradecraft

An operator who knows the capture is happening can still operate, but must trade speed for stealth.

- **Use the same TLS stack as the target.** New or unusual JA3/JA4 fingerprints stand out in a capture with TLS metadata.
- **Match DNS patterns.** Query volume and timing similar to the host's baseline.
- **Avoid bursty C2.** Jitter and beacon shaping reduce the periodic signature that a simple PCAP review would catch.
- **Do not reuse a channel.** A channel reused across incidents links them in a capture that covers both windows.

## 6. Common Mistakes

- **`-s 0` forgotten.** Default snaplen of 262144 is fine on most modern tcpdump, but older defaults truncate.
- **Buffer too small.** `-B` not raised on a busy link. The kernel drops packets silently; `tcpdump` reports `packets dropped by kernel` only on exit.
- **Wrong interface.** `-i any` on Linux is convenient but uses a pseudo-interface that loses some link-layer metadata.
- **Unfiltered capture on a huge link.** Disk fills in seconds. Use a ring buffer (`-C`/`-W`) and a host-level filter.
- **Trusting capture timestamps to the millisecond.** Clock offset between capture host and log sources easily reaches tens of milliseconds; document it.
- **Forgetting DNS.** A capture without DNS is a capture of IPs you must resolve by hand later, often after the records have rotated.

## 7. Attacks and Detection

- **Capture-host compromise.** The capture host is on the network and often privileged. It is a target. Harden it, restrict access, and verify hashes.
- **Capture tampering.** An attacker with write access to the PCAP store can alter evidence. Append-only storage and hashing-on-write prevent this.
- **Filter-based blind spots.** An attacker who knows the defender's capture filter can route around it. Rotate filters and capture broadly during incidents.
- **Detection of the capture host.** A capture host that performs active resolution or reverse lookups generates its own traffic. Keep the capture host passive.

## 8. Verification

- **Packet count reconciliation.** Compare the PCAP's packet count with the interface counters on the capture host for the same window. A large gap means drops.
- **Filter validation.** Before the incident window, run the intended capture filter against a synthetic flow that matches it. Confirm it captures what you expect.
- **Clock check.** Compare `date -u` on the capture host with an authoritative NTP source immediately before the capture.
- **Hash check.** After capture, `sha256sum` the file and record the hash in the case notes.

## 9. Production Notes

- Keep capture hosts on a dedicated management VLAN, reachable only by the IR team.
- Store PCAPs on append-only or write-once storage where the platform supports it.
- Retain PCAPs per policy; large captures are often the largest storage consumer in an IR case.
- Encrypt the PCAP store at rest; captures routinely contain credentials and PII.
- For high-rate links, a network TAP plus a hardware capture appliance beats a general-purpose host.

## 10. References

- tcpdump manual page - https://www.tcpdump.org/manpages/tcpdump.1.html
- pcap-filter (BPF syntax) - https://www.tcpdump.org/manpages/pcap-filter.7.html
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response - https://csrc.nist.gov/pubs/sp/800/86/final
- RFC 3227, Guidelines for Evidence Collection and Archiving - https://www.rfc-editor.org/rfc/rfc3227
- Wireshark User's Guide, "Capturing Live Network Data" - https://www.wireshark.org/docs/wsug_html_chunked/ChapterCapture.html

## Certification Alignment

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 4 (Security Operations) - logging, monitoring, packet capture basics |
| CompTIA CySA+ | Domain 1 (Security Operations) - capture tooling, traffic analysis |
| Cisco CyberOps Associate | Domain 3 (Host and Network Analysis) - capture on Linux and network devices |
