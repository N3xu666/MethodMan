# 04 Dark Web

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

The dark web is the part of the internet reachable only through anonymity networks like Tor. It hosts both legitimate services (SecureDrop, OnionShare, privacy-focused forums) and illegal marketplaces. This subcategory focuses on the technical and operational aspects of dark web services that a security professional, journalist, or privacy-conscious operator needs to understand.

This subcategory is part of the **ANONYMITY-PRIVACY-OPSEC** category. All files follow the **Hands-on format** (13 sections, ending with Legal and Ethical Notes instead of OSCP Notes).

## Scope

This subcategory covers:

- **Hidden Services** - how Tor onion services work, how to run one, and how to harden it.
- **OnionShare** - anonymous file sharing, hosting, and chat over Tor.
- **SecureDrop** - the journalist-to-source whistleblowing platform.
- **Pastebins and Dead Drops** - anonymous text publishing and covert data retrieval.

This subcategory does NOT cover:

- Illegal marketplaces or the purchase of illegal goods.
- How to buy or sell anything on the dark web.
- Criminal use of hidden services.
- Cryptocurrency tumblers used to hide proceeds of crime (see 06 for legitimate privacy tooling).

Any use of the techniques in this subcategory for illegal activity is prohibited by the disclaimer above and is illegal in most jurisdictions.

## Threat Model Summary

| Tool / Topic | Protects against | Does NOT protect against | Metadata |
|--------------|------------------|--------------------------|----------|
| Hidden Services | Server IP exposure, client IP exposure | Endpoint compromise, targeted deanonymization | Onion address is public; traffic correlation is possible |
| OnionShare | Third-party file hosting, IP leaks | Endpoint compromise, traffic analysis | Tor-protected; no third-party server |
| SecureDrop | Source identification, provider reading submissions | Endpoint compromise, traffic analysis, physical access to the SecureDrop server | Designed for source anonymity; strong |
| Pastebins / Dead Drops | Identity correlation, easy takedown | Endpoint compromise, traffic analysis | Varies by service; read carefully |

## Files

| # | File | Focus | Status |
|---|------|-------|--------|
| 01 | [Hidden Services](./01%20Hidden%20Services.md) | Run and harden a Tor onion service | done |
| 02 | [OnionShare](./02%20OnionShare.md) | Anonymous file sharing, hosting, chat | done |
| 03 | [SecureDrop](./03%20SecureDrop.md) | Whistleblowing platform for journalists | done |
| 04 | [Pastebins and Dead Drops](./04%20Pastebins%20and%20Dead%20Drops.md) | Anonymous text and covert data retrieval | done |

## Related

- [01 Anonymous Networks](../01%20Anonymous%20Networks/README.md) - Tor, I2P, Lokinet, VPN chains (transport layer).
- [02 Secure Communications](../02%20Secure%20Communications/README.md) - Session, SimpleX, XMPP/OMEMO, anonymous email, PGP.
- [03 Operating Systems and Hygiene](../03%20Operating%20Systems%20and%20Hygiene/README.md) - Tails, Qubes, data destruction, metadata.

## Legal and Ethical Notes

Hidden services, OnionShare, and SecureDrop are legal to use in most jurisdictions. However:

- **Some countries restrict or ban Tor and onion services.** Check your local law before hosting or accessing hidden services.
- **Hosting illegal content is a crime everywhere.** Do NOT use these tools to distribute illegal material, including CSAM, malware, or stolen data.
- **Using these tools to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid them.** On a work device, using or hosting hidden services may violate acceptable-use policy.
- **You are responsible for what you host.** If you run a hidden service, you are the publisher.
- **Authorized use only.** In a professional context, use these tools only within the scope of an authorized engagement or for your own personal privacy.

## References

- Tor Project - Onion Services - https://community.torproject.org/onion-services/
- OnionShare - https://onionshare.org/
- SecureDrop - https://securedrop.org/
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - Tor - https://www.privacyguides.org/en/tor/
