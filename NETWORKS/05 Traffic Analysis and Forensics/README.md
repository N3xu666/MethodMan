# Traffic Analysis and Forensics

Packet capture, protocol-level inspection and forensic reconstruction of network incidents. This subcategory covers the analyst's side of the wire: how to capture traffic correctly, how to read it efficiently, and how to answer the question "what actually happened on this network" from a PCAP.

The material is written for both sides of the same skill: an offensive operator who needs to understand how their traffic looks on the wire (and how to blend in), and a defensive analyst who needs to detect, triage and reconstruct adversary activity.

## Format

Each file uses the two-track format:

- **Offensive** - how an attacker generates, obfuscates or hides the traffic being analysed.
- **Defensive** - how a defender captures, detects and reconstructs that traffic.

The two tracks are complementary: you cannot reliably detect what you cannot generate, and you cannot evade what you cannot detect.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [Packet Capture Fundamentals](./01%20Packet%20Capture%20Fundamentals.md) | Two-track |
| 02 | [Wireshark and tshark](./02%20Wireshark%20and%20tshark.md) | Two-track |
| 03 | [Network Forensics and PCAP Analysis](./03%20Network%20Forensics%20and%20PCAP%20Analysis.md) | Two-track |
| 04 | [Traffic Analysis for Incident Response](./04%20Traffic%20Analysis%20for%20Incident%20Response.md) | Two-track |
| 05 | [Covert Channels and Traffic Obfuscation](./05%20Covert%20Channels%20and%20Traffic%20Obfuscation.md) | Two-track |

Status: 5 files done.

## Certification Alignment

This subcategory maps to the following certifications:

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 4 (Security Operations), Domain 3 (Security Architecture) |
| CompTIA CySA+ | Domain 1 (Security Operations), Domain 2 (Vulnerability Management), Domain 3 (Incident Response) |
| Cisco CyberOps Associate | Domain 3 (Host and Network Analysis), Domain 4 (Incident Response) |

Traffic analysis and PCAP forensics appear in every blue-team certification at the operational level. The material here focuses on the practical skills those exams test: capture methodology, protocol parsing, timeline reconstruction and evidence handling.

## See Also

- [01 Network Fundamentals](../01%20Network%20Fundamentals/) - protocols and addressing this material assumes.
- [04 Network Protocols](../04%20Network%20Protocols/) - per-protocol reference (ARP, ICMP, TCP/UDP, DNS/DHCP, HTTP/TLS).
- [03 Network Devices](../03%20Network%20Devices/) - IDS/IPS and monitoring appliances that consume the traffic analysed here.
- [INFRASTRUCTURE/05 Network Attacks](../../INFRASTRUCTURE/05%20Network%20Attacks/) - the attacks whose traffic this subcategory analyses.

## References

- Wireshark User's Guide - https://www.wireshark.org/docs/wsug_html_chunked/
- tshark manual page - https://www.wireshark.org/docs/man-pages/tshark.html
- pcap-filter (BPF syntax) - https://www.tcpdump.org/manpages/pcap-filter.7.html
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response - https://csrc.nist.gov/pubs/sp/800/86/final
- RFC 3227, Guidelines for Evidence Collection and Archiving - https://www.rfc-editor.org/rfc/rfc3227
