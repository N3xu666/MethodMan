# Wireshark and tshark

The two primary tools for reading a PCAP: Wireshark (GUI, exploratory analysis) and tshark (CLI, automation and bulk extraction). Both use the same dissectors, so a filter that works in one works in the other - only the syntax context differs (display filter vs command-line filter flag).

## 1. Overview

Wireshark is the reference packet analyser. Its value is not just the GUI: it ships a dissector for nearly every protocol in use, and those dissectors are the same ones tshark uses. Learning the filter language once gives you both tools.

- **Wireshark** - interactive: follow streams, apply filters, colour rules, export objects. Best for exploring an unfamiliar capture.
- **tshark** - scriptable: extract fields, count, filter, convert. Best for bulk processing and repeatable analysis.

The file covers the operational skill: how to get from "here is a PCAP" to "here are the facts" efficiently.

## 2. Reconnaissance (of a capture)

Before filtering, understand what you have.

- **Protocol hierarchy** (`Statistics > Protocol Hierarchy` / `tshark -q -z io,phs`) - what protocols are present and in what proportion. A sudden spike of an unexpected protocol is the first lead.
- **Conversations** (`Statistics > Conversations`) - top talkers by bytes and packets. Exfiltration shows as a conversation far larger than its peers.
- **Endpoints** - which IPs and ports are active. Sort by bytes to find the heavy hitters.
- **Expert information** (`Analyze > Expert Information` / `tshark -q -z expert`) - retransmissions, malformed packets, resets. These are hints, not conclusions.

This triage takes minutes and often points directly at the interesting conversation.

## 3. Offensive

### 3.1 What the attacker controls in the capture

An attacker cannot change how Wireshark parses their packets, but they can change what those packets look like.

- **Protocol obfuscation.** Non-standard ports, encapsulating in allowed protocols, protocol impersonation (HTTP-looking traffic that is not HTTP).
- **Field manipulation.** Set TTLs, sequence numbers and window sizes to mimic a common OS so fingerprinting heuristics mislabel the source.
- **Payload encoding.** Base64, hex, custom encoding inside a well-known protocol, so content signatures miss.
- **Chaff.** Generate benign-looking traffic around the real C2 to dilute the signal-to-noise ratio of a capture.

### 3.2 Recipes

- **DNS-over-HTTPS to a legitimate resolver** blends C2 into traffic that looks like a normal browser.
- **HTTPS to a CDN front** uses a JA3/JA4 that matches the CDN's other clients.
- **ICMP echo with large payloads** hides data in a protocol many captures filter out.
- **SMB named pipes over legitimate admin traffic** hides lateral movement in business-as-usual traffic.

### 3.3 Detection of analysis

An attacker with access to the defender's Wireshark habits (shared notes, screenshots in reports) learns what fields the defender looks at. Rotate the analytical approach: do not always start with the same conversation or the same protocol.

## 4. Defensive

### 4.1 Essential Wireshark workflow

1. Open the PCAP. Sort by time.
2. `Statistics > Protocol Hierarchy` - what is here.
3. `Statistics > Conversations` - sort by bytes, look at the top.
4. Apply a display filter to the top conversation.
5. Follow the TCP/HTTP stream (`Follow > TCP Stream`).
6. Export objects if applicable (`File > Export Objects`).
7. Note facts (IPs, ports, hashes, timestamps) in the case file as you find them.

### 4.2 Essential tshark recipes

```bash
# Protocol hierarchy summary
tshark -r capture.pcap -q -z io,phs

# Top conversations by bytes
tshark -r capture.pcap -q -z conv,tcp

# List HTTP requests (method + host + uri)
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri

# Extract DNS query names
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name

# Follow a TCP stream to stdout
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

Expected output (HTTP request listing):

```text
2026-10-22 14:22:01.123456 10.10.10.10 GET /admin/login.php
2026-10-22 14:22:15.654321 10.10.10.10 POST /admin/login.php
2026-10-22 14:23:00.111222 10.10.10.10 GET /uploads/shell.php?cmd=id
```

### 4.3 Display filter essentials

- `ip.addr == 10.10.10.10` - any packet to or from that IP.
- `tcp.port == 445` - TCP on port 445.
- `http.request` - HTTP requests only.
- `dns.qry.name contains "example"` - DNS queries whose name contains "example".
- `tls.handshake.extensions_server_name contains "example"` - TLS SNI filter.
- `tcp.flags.syn == 1 and tcp.flags.ack == 0` - SYN-only packets.
- `frame contains "password"` - any frame whose bytes contain "password" (case-sensitive).

Display filters are evaluated per-frame; complex filters with many `or` clauses get slow on large captures. Filter incrementally.

## 5. Offensive (continued): shaping traffic for analysis evasion

An operator whose traffic will be read in Wireshark can choose which analysis path is fastest for the defender - and make it the wrong one.

- **Mimic a common client.** Match the User-Agent, TLS version, cipher order and header set of a browser everyone uses in that environment. The defender's "unusual client" heuristic finds nothing.
- **Use a protocol the analyst is likely to skip.** Traffic on port 53 is often assumed to be DNS; a non-DNS payload on port 53 may be dismissed. Verify this against the specific environment, not as a general rule.
- **Spread across many flows.** A single large flow is visible as an outlier. Many small flows to the same destination evade per-flow volume thresholds.
- **Encrypt at the application layer.** TLS to a legitimate CDN means only metadata is visible; if the JA3 matches, the metadata itself is unremarkable.

These are analysis-evasion, not capture-evasion. They do not stop a determined analyst; they cost the analyst time.

## 6. Common Mistakes

- **Confusing capture filter and display filter syntax.** `host 10.10.10.10` is a capture filter, `ip.addr == 10.10.10.10` is a display filter. Mixing them produces an empty result that looks like an empty capture.
- **Using `frame contains` on large captures.** Byte-scan across every frame is slow. Narrow with a protocol filter first (`http contains "password"`, `tcp.port == 445 and frame contains "secret"`).
- **Not resolving MACs at the start.** Without a MAC-to-IP map, ARP-based analysis later is guesswork. Build the map from the capture before any filtering.
- **Trusting "Follow Stream" output as-is.** It shows reassembled payload, not the individual packets. Timing information is lost.
- **Exporting objects without hashing.** Exported HTTP objects are evidence. Hash each one on export.
- **Forgetting TLS keylog.** If the environment captures `SSLKEYLOGFILE`, all TLS traffic in the PCAP is decryptable. If not, that option is gone - confirm the policy before assuming.

## 7. Attacks and Detection

- **Deception in fields.** Wireshark's dissectors trust what is on the wire. A crafted packet with misleading fields (fake User-Agent, spoofed TTL) makes the analyst's notes wrong if the analyst trusts the field value.
- **Malformed packets.** Dissector crashes and infinite loops (Wireshark CVEs) turn the analysis tool into an attack surface. Keep Wireshark updated; open untrusted PCAPs in a sandbox.
- **Export-object decoys.** A decoy file (benign-looking document) alongside the real exfiltration can be exported first and studied for hours. Compare object hashes against known-good before treating any as interesting.
- **Detection of analysis activity.** A PCAP never "knows" it is being read. But if the analyst re-queries external sources (WHOIS, DNS resolution) from a shared IP, that activity is observable. Keep analysis offline where possible.

## 8. Verification

- **Stream reassembly check.** For any TCP stream you cite as evidence, confirm the reassembled bytes hash matches the exported object hash. A mismatch means an export bug or a stream offset error.
- **Filter reproducibility.** Save the exact display filter used. A finding that cannot be reproduced from the filter is anecdotal.
- **Time-sync check.** If the finding depends on a timestamp, confirm the capture host clock against an authoritative source for the incident window.
- **Packet count.** A TCP stream that "ends" cleanly on paper but has RSTs or retransmissions in the capture is a different conclusion. Check `tcp.analysis.flags` on the stream.

## 9. Production Notes

- Keep a library of saved display filters for common pivots (SMB lateral movement, DNS exfil, TLS to rare SNI). Review the library quarterly.
- In an IR case, work on a copy of the PCAP. Keep the original hash recorded and untouched.
- Colour rules in Wireshark are per-user, not per-PCAP. Export the ruleset alongside the analysis notes if the finding depends on colour.
- For automation, prefer tshark to scripting Wireshark. Same dissectors, no GUI race conditions.
- Log the exact tshark/Wireshark version in the analysis notes. Dissectors change between versions, and a field name that worked in 4.0 may be absent in 3.6.

## 10. References

- Wireshark User's Guide - https://www.wireshark.org/docs/wsug_html_chunked/
- Wireshark display filter reference - https://www.wireshark.org/docs/dfref/
- tshark manual page - https://www.wireshark.org/docs/man-pages/tshark.html
- Wireshark Security Advisories - https://www.wireshark.org/security/
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response - https://csrc.nist.gov/pubs/sp/800/86/final

## Certification Alignment

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 4 (Security Operations) - traffic analysis with Wireshark |
| CompTIA CySA+ | Domain 1 (Security Operations) - capture analysis, evidence handling |
| Cisco CyberOps Associate | Domain 3 (Host and Network Analysis) - packet-level forensics |
