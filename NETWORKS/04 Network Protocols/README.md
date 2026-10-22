# 04 Network Protocols

Protocol-level reference for network attacks and defenses. Each file covers one protocol family: its role, how it can be abused, and how to detect and prevent that abuse.

Format: two-track (Offensive / Defensive), 11 sections. See the category README for details.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | [ARP and Neighbor Discovery](./01%20ARP-and-Neighbor-Discovery.md) | Layer 2 address resolution, spoofing, poisoning |
| 02 | [ICMP and Traceroute](./02%20ICMP-and-Traceroute.md) | Control messages, tunneling, recon |
| 03 | [TCP and UDP](./03%20TCP-and-UDP.md) | Transport semantics, scanning, floods |
| 04 | [DNS and DHCP](./04%20DNS-and-DHCP.md) | Name resolution, dynamic addressing, poisoning |
| 05 | [HTTP and TLS](./05%20HTTP-and-TLS.md) | Web transport, downgrade, interception |

## Certification Alignment

- CompTIA Network+ (N10-009): network protocols, services, troubleshooting
- Cisco CCNA (200-301): IP services, security fundamentals

## References

- RFC 826 (ARP) - https://www.rfc-editor.org/rfc/rfc826
- RFC 792 (ICMP) - https://www.rfc-editor.org/rfc/rfc792
- RFC 9293 (TCP) - https://www.rfc-editor.org/rfc/rfc9293
- RFC 768 (UDP) - https://www.rfc-editor.org/rfc/rfc768
- RFC 1035 (DNS) - https://www.rfc-editor.org/rfc/rfc1035
- RFC 2131 (DHCP) - https://www.rfc-editor.org/rfc/rfc2131
- RFC 8446 (TLS 1.3) - https://www.rfc-editor.org/rfc/rfc8446
