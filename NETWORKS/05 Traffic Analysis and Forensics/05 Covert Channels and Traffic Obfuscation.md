# Covert Channels and Traffic Obfuscation

Hiding data inside traffic that looks legitimate. This is the intersection of the previous four files: the offensive operator who needs a channel that survives traffic analysis, and the defensive analyst who needs to detect such a channel. Every technique in this file exists on both sides - if you cannot construct the channel, you cannot build the detection for it.

## 1. Overview

A covert channel is any communication path not intended by the system designers. The classic taxonomy splits them into two families:

- **Storage channels** - data is written into a field that should not carry that data (TCP sequence numbers, IP ID, TTL, unused header bits, DNS labels, ICMP payloads).
- **Timing channels** - data is encoded in the timing of packets, not in their content (inter-packet delays, packet count patterns, ordering).

Network-based covert channels usually combine both: a storage channel for payload, a timing channel for coordination.

Detection is statistical. A channel that carries one bit per packet is invisible in any single packet; the signal is in the aggregate pattern, and it is only detectable if the analyst knows which aggregate to look at.

## 2. Covert Channel Families

Three families account for most real-world covert channel traffic:

| Family | Carrier | Capacity | Detectability |
|--------|---------|----------|---------------|
| DNS tunnelling | DNS queries and responses | High (labels can carry ~200 bytes per query) | Medium (volume and label entropy stand out) |
| ICMP tunnelling | ICMP echo payloads | High (payload up to 1400+ bytes) | Medium (large ICMP and high rate are anomalous) |
| HTTP(S) tunnelling | HTTP headers, paths, bodies; TLS SNI and timing | High | Depends on how well the channel matches legitimate traffic |
| Protocol header fields | IP ID, TCP initial sequence, TTL, TCP timestamp | Low (bits per packet) | High (requires statistical analysis but hard to hide) |

The rule of thumb: the higher the capacity, the easier the detection. Channels designed for durability (low-and-slow, bits per packet) are hard to detect but slow.

## 3. Offensive

### 3.1 DNS tunnelling

Encode data in DNS query labels. The authoritative server for the attacker-controlled domain decodes the labels and responds with data in TXT or A records.

- **Label encoding.** Base32 (DNS-safe, case-insensitive). Base64 with URL-safe alphabet works but is not universal across resolvers.
- **Query types.** TXT (high capacity, often logged), AAAA (high capacity, less logged), NULL (rare, often blocked), CNAME (medium capacity, common).
- **Chunking.** Split payload into 63-byte labels (DNS limit), each query carries one or more labels, sequence numbers in the labels reconstruct the stream.
- **Domain.** Registered by the attacker, often a lookalike or a short random domain. NS delegation to the attacker's authoritative server.
- **Detection evasion.** Query the corporate resolver (not 8.8.8.8 directly) - the traffic looks like normal DNS from the resolver's perspective.

Tools: iodine, dnscat2, dns2tcp, Sliver's DNS listener, Cobalt Strike's DNS beacon.

### 3.2 ICMP tunnelling

Encode data in ICMP echo payloads. The receiving host (or an intermediary) extracts the payload and forwards it.

- **Payload size.** Standard echo is 56 bytes; larger (up to MTU) is possible but anomalous.
- **Frequency.** A steady ping every second is normal; a burst of pings with 1400-byte payloads is not.
- **Type.** Echo request/reply is the common carrier; timestamp and address mask are less common and more anomalous.

Tools: ptunnel, icmptunnel, Hans, icmpsh.

### 3.3 HTTP(S) tunnelling

Encode data in HTTP request/response fields. The channel is a legitimate HTTP session to a domain that looks legitimate.

- **Path encoding.** `/api/v1/status?d=<base64>` - the request looks like a normal API call.
- **Header encoding.** Custom headers (X-Data-1, X-Data-2), User-Agent strings, Accept-Encoding tokens.
- **Cookie encoding.** Session cookie carries the payload, server responds with `Set-Cookie` carrying data back.
- **Body encoding.** POST with base64-encoded payload; the response body carries return data.
- **TLS SNI.** Encode low-bandwidth data (a bit per connection) in the SNI field or the timing of TLS handshakes.
- **WebSocket.** Persistent bidirectional channel inside an HTTPS-looking upgrade. Very hard to distinguish from legitimate WebSocket traffic if the User-Agent and behaviour match.

Tools: chisel (WebSocket), gost (HTTP/2), Sliver (mtls/wireguard over HTTP), Cobalt Strike (HTTPS with malleable profiles).

### 3.4 Protocol header fields (storage channels)

Data in fields that should be fixed or predictable. High effort per bit, but very hard to detect without statistical analysis of the specific field.

- **IP ID.** 16 bits, often sequential. A random or patterned IP ID sequence can carry ~16 bits per packet.
- **TCP ISN.** 32 bits, historically predictable, now randomised. Still usable on hosts with poor ISN generation.
- **TTL.** 8 bits, mostly constant per path. Timing changes are more common than TTL changes.
- **TCP timestamp.** 32 bits per packet, monotonic. Small deviations are visible only with careful analysis.
- **TCP options ordering.** The order of TCP options (MSS, SACK, timestamp, NOP, window scale) is not standardised. Order can carry a few bits per packet.

These channels are used only when the adversary cannot afford a higher-bandwidth channel. They trade throughput for stealth in a way that DNS tunnelling cannot.

## 4. Defensive

### 4.1 Detection principles

Covert channel detection is a statistical problem. The analyst is looking for a pattern that stands out from the environment's normal traffic distribution.

- **Baseline first.** What does DNS look like in this environment? Volume, query types, label length distribution, domain reputation. A channel that differs from the baseline is a signal.
- **Anomalies are weak signals.** A large DNS response is not a channel. A large DNS response to a domain no one has queried before, from a host that usually does not query that domain, at 3 AM, is a channel.
- **Cross-correlation.** The strongest detection is the combination of anomalies: volume + entropy + timing + relationship between source and destination that has no business rationale.
- **Known-bad matching.** Threat intelligence feeds for tunnelling infrastructure (domains used for iodine, dnscat2, CS beacons) catch a subset. Do not rely on them alone.

### 4.2 DNS tunnelling detection

```bash
# Top DNS query volumes per source (last hour)
tshark -r last1h.pcap -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# DNS queries with unusually long labels
tshark -r last1h.pcap -Y "dns.qry.name.len > 100" -T fields -e ip.src -e dns.qry.name

# DNS queries with high entropy labels (entropy per label > 4 bits)
tshark -r last1h.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | awk -F. '{for (i=1; i<=NF; i++) { if (length($i) > 20) print $i } }'
```

Expected output (high-volume DNS sources):

```text
   4201 10.10.10.10
    120 10.10.10.21
     95 10.10.10.35
     42 10.10.10.42
```

10.10.10.10 has 35x the DNS traffic of the next host. Either it is a DNS server, or it is a tunnel.

### 4.3 ICMP tunnelling detection

- Large ICMP payloads (ICMP echo with 500+ bytes is unusual in most environments).
- High ICMP rate to a single external peer.
- ICMP traffic at unusual hours or to unusual destinations.
- ICMP echo request/reply asymmetry (a request without a matching reply, or vice versa).

### 4.4 HTTP(S) tunnelling detection

- Long-lived HTTPS connections to a single peer, with regular bidirectional traffic.
- HTTP requests with structured-looking path/header/body fields that decode to something.
- User-Agent strings that do not match any known browser or tool.
- JA3/JA4 fingerprints that match known C2 frameworks (Sliver, Cobalt Strike, Metasploit).
- DNS resolutions to domains registered recently, with a suspicious WHOIS profile.

### 4.5 Verification

For every suspected channel:

1. Decode the payload if possible. A suspected DNS tunnel that decodes to random noise is either encrypted or a false positive. A suspected channel that decodes to readable data is confirmed.
2. Cross-reference with endpoint telemetry. Which process on the host is making these connections?
3. Cross-reference with threat intelligence. Does the destination match known-bad infrastructure?
4. Build the pattern. A single anomaly is not a channel. A set of correlated anomalies is.

## 5. Offensive (continued): channel design trade-offs

Choosing a channel is a design decision with four axes.

- **Bandwidth.** Bits per second through the channel. DNS is ~1-10 KB/s in practice; HTTPS to a CDN can approach line rate; ICMP is in between. High-bandwidth channels are more detectable.
- **Detectability.** How much does the channel differ from the environment's baseline. DNS to a domain no one uses is highly detectable; DNS to the corporate resolver with a lookalike domain is not.
- **Durability.** How long the channel survives blocking. Domain fronting and CDN fronting are resilient; direct IP connections are not.
- **Cost.** What the operator pays in infrastructure, setup, and ongoing maintenance.

The right channel for an engagement depends on the objective: a data exfiltration channel wants bandwidth; a C2 channel wants durability; a beacon wants low detectability.

## 6. Common Mistakes

- **Assuming "port 53 means DNS".** DNS tunnels frequently use the standard port; a capture filtered to port 53 with the display filter `dns` misses everything that is not valid DNS.
- **Treating high DNS volume as benign.** In an environment where the DNS server handles 10000 queries/second, one host with 4000 is noise. In an environment where the server handles 100, one host with 400 is a channel.
- **Not decoding the payload.** A suspected channel that is "obviously base64" but not decoded is a suspicion, not a finding.
- **Ignoring timing.** A covert channel that transmits one bit per packet is invisible in any single packet. The pattern only appears when plotted over time.
- **Overfitting the detection.** A detection that fires on all large DNS packets catches legitimate CDN traffic and creates noise. Tune to the specific baseline of the environment.

## 7. Attacks and Detection

- **Detection of the detector.** An analyst who runs queries from a shared IP or sends DNS lookups for suspicious domains creates observable traffic. Keep the analysis offline.
- **Channel rotation.** A channel that is detected and blocked is replaced. Have a fresh detection ready.
- **Encrypted covert channels.** A DNS tunnel carrying TLS-encrypted data is a payload that no DLP will decode. Detection must be on the pattern, not the content.
- **The detection paradox.** A detection sensitive enough to catch low-and-slow channels fires on many false positives. Every detection is a trade-off between true positive rate and analyst time.
- **Side-channel leakage.** Timing of channel establishment, or of the response, can leak information (e.g. whether the analyst is blocking).

## 8. Verification

- **Decode before concluding.** No tunnel is confirmed until some of its traffic decodes to readable structure. Encrypted channels confirm by pattern only, not by content.
- **Baseline comparison.** Run the same detection query against a normal-traffic window. If the "channel" pattern is also present in the baseline, it is not a channel.
- **Endpoint corroboration.** Which process on the source host made the connections? A tunnel from a process that has no business making DNS queries is a channel.
- **Threat-intel match.** The destination (domain or IP) matching known-bad infrastructure moves confidence from medium to high.

## 9. Production Notes

- Retain DNS logs at high fidelity for at least 30 days. Most covert channel investigations start with the DNS layer.
- Store PCAPs for the suspected channel window longer than normal retention; the analysis takes days, not hours.
- Maintain a library of decode scripts for common encodings (base32, base64, hex). Half of a tunnel analysis is decoding the payload.
- Train the IR team on at least one tunnel detection exercise per quarter. Detection without practice is theoretical.
- Do not rely on a single tool (Suricata, Zeek, a commercial NDR) for covert channel detection. Each has a bias; cross-check.

## 10. References

- RFC 1035, Domain Names - Implementation and Specification - https://www.rfc-editor.org/rfc/rfc1035
- RFC 792, Internet Control Message Protocol - https://www.rfc-editor.org/rfc/rfc792
- RFC 9293, Transmission Control Protocol (TCP) - https://www.rfc-editor.org/rfc/rfc9293
- SANS, Detecting DNS Tunneling - https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response - https://csrc.nist.gov/pubs/sp/800/86/final

## Certification Alignment

| Certification | Relevant domains |
|---------------|------------------|
| CompTIA Security+ | Domain 3 (Security Architecture) - covert channels and data exfiltration |
| CompTIA CySA+ | Domain 1 (Security Operations) - covert channel detection |
| Cisco CyberOps Associate | Domain 3 (Host and Network Analysis) - tunnelling protocol analysis |
