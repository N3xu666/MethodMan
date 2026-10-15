# Anonymous Networks

Anonymous overlay networks and multi-hop privacy chains. Covers Tor,
I2P, Lokinet, and VPN-based anonymity approaches.

> [!CAUTION]
> **Authorized Use Only.**
>
> Overlay networks described here are dual-use technologies. Running a
> Tor relay, I2P node, or VPN client is legal in most jurisdictions but
> may be restricted or criminalized in others. Using them to evade
> lawful investigation, commit unauthorized access, or traffic illegal
> material is prohibited. See `../../SECURITY.md` before proceeding.

---

## Scope

This subcategory covers:

- **Tor** - onion routing, relay types, hidden services, bridges, pluggable transports.
- **I2P** - garlic routing, eepsites, in-network services, threat model differences from Tor.
- **Lokinet and alternatives** - LLARP-based routing, mixnets, Nym, comparison to Tor/I2P.
- **VPN and multi-hop chains** - commercial VPNs, self-hosted VPNs, VPN-over-Tor,
  Tor-over-VPN, multi-hop chains, common chain mistakes.

This subcategory does **NOT** cover:

- how to configure a specific VPN provider (out of scope, changes often),
- legal advice on using anonymity networks in a specific country,
- attack/deanonymization techniques against these networks (see
  `../08 Attacks and Detection/`).

---

## Files

| # | File | Format | Focus |
|---|------|--------|-------|
| 01 | Tor | Hands-on | Onion routing, relay types, bridges, hidden services |
| 02 | I2P | Hands-on | Garlic routing, eepsites, threat model |
| 03 | Lokinet and Alternatives | Hands-on | LLARP, mixnets, Nym |
| 04 | VPN and Multi-hop Chains | Hands-on | VPN types, Tor+VPN chains, common mistakes |

All files use **Format 4 (Hands-on)** - see `_WORKFLOW.md` section 6.7
for the template.

---

## Threat Model Summary

Anonymous networks provide different guarantees. Choosing the wrong
network for a threat model is a common mistake.

| Network | Primary threat defended against | Known weaknesses |
|---------|--------------------------------|------------------|
| Tor | Local network adversary, IP correlation by destination | Global passive adversary, traffic confirmation, malicious exits |
| I2P | Same as Tor, with a different mix of trade-offs | Smaller network, slower, fewer exits |
| Lokinet | Low-latency onion routing with a different incentive model | Young network, less audited |
| VPN | ISP-level surveillance | Single point of trust (provider), correlation with billing identity |

No single network defends against all adversaries. Read the per-file
`## Threat Model` sections before choosing.

---

## Operational Notes

- **Never mix identity across networks.** A pseudonym used on Tor and
  a pseudonym used on I2P must never be linkable.
- **Assume timing correlation works.** A global passive adversary can
  correlate entry and exit traffic with enough time and traffic volume.
- **Bridges are not a magic solution.** They help against IP blocklists,
  not against a global adversary.
- **VPN-over-Tor and Tor-over-VPN are different.** Each has a specific
  threat model. See `04 VPN and Multi-hop Chains.md`.

---

## Legal and Ethical Notes

Running any of these networks as a client is legal in most countries.
Running a **relay or exit node** has additional considerations:

- Exit nodes see unencrypted traffic; you may be liable for what passes
  through. Read your jurisdiction's laws before running an exit.
- Some hosting providers forbid relays in their AUP; check before deploying.
- Running a bridge is lower-risk than an exit, but still requires care.

See `../../SECURITY.md` for the repository's authorized-use policy.

---

## References

- Tor Project - https://www.torproject.org/
- Tor specifications - https://spec.torproject.org/
- I2P - https://geti2p.net/
- Lokinet - https://lokinet.org/
- Nym - https://nymtech.net/
- EFF Surveillance Self-Defense - https://ssd.eff.org/
