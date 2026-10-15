# 02 Secure Communications

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Practical operator guides for end-to-end encrypted messaging, metadata-resistant communication, and anonymous email. Each file is a self-contained hands-on reference: what the tool protects against, how to install it, how to harden it, and how it fails.

This subcategory is part of the **ANONYMITY-PRIVACY-OPSEC** category. All files follow the **Hands-on** format (13 sections, ending with Legal and Ethical Notes instead of OSCP Notes).

## Scope

This subcategory covers:

- **Session** - decentralized, onion-routed messenger with no phone number or email requirement.
- **SimpleX** - messenger with no persistent user identifiers at all (no phone, no email, no username).
- **XMPP / OMEMO** - federated messaging with double-ratchet end-to-end encryption.
- **Anonymous Email** - Proton Mail, Tutanota, and self-hosted options; PGP integration; metadata pitfalls.
- **PGP** - key management, signing, encryption, and the common operational mistakes that break it.

## Threat Model Summary

| Tool | Protects against | Does NOT protect against | Metadata |
|------|------------------|--------------------------|----------|
| Session | Server compromise, IP correlation | Global passive adversary, endpoint compromise | Onion routing, no phone number |
| SimpleX | Identity correlation, server compromise | Endpoint compromise, traffic analysis | No persistent identifiers at all |
| XMPP / OMEMO | Server-side plaintext, MITM | Metadata (federation logs), endpoint compromise | Server sees who talks to whom |
| Anonymous Email | Identity correlation, provider snooping | Metadata (SMTP relays), legal compulsion | Relays and timestamps are visible |
| PGP | Message content, tampering | Metadata, endpoint compromise, key theft | None (PGP only protects content) |

## Files

| # | File | Focus | Status |
|---|------|-------|--------|
| 01 | [Session](./01%20Session.md) | Onion-routed decentralized messenger | done |
| 02 | [SimpleX](./02%20SimpleX.md) | Identifier-free messenger | done |
| 03 | [XMPP / OMEMO](./03%20XMPP-OMEMO.md) | Federated E2EE messaging | done |
| 04 | [Anonymous Email](./04%20Anonymous%20Email.md) | Privacy-focused email providers | done |
| 05 | [PGP](./05%20PGP.md) | Key management and signing | done |

## Related

- [01 Anonymous Networks](../01%20Anonymous%20Networks/README.md) - Tor, I2P, Lokinet, VPN chains (transport layer).
- Operating Systems and Hygiene - Tails, Qubes, metadata (planned, no dedicated file yet).

## Legal and Ethical Notes

Communication privacy tools are legal in most jurisdictions, but their use can be criminalized in some countries, and using them to plan or commit a crime is illegal everywhere. Before adopting any tool from this subcategory:

- Confirm that encrypted communication is legal in your jurisdiction.
- Confirm that you are not subject to a legal order that restricts the use of encryption.
- Do not use these tools to harass, stalk, defraud, or harm any person.
- Do not use these tools to violate the terms of service of any platform.

If you are a security professional, use these tools only within the scope of an authorized engagement or for your own personal privacy.

## References

- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - Communication - https://www.privacyguides.org/en/real-time-communication/
- Freedom of the Press Foundation - https://freedom.press/
