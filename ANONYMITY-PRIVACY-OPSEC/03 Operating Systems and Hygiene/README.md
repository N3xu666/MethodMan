# 03 Operating Systems and Hygiene

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Hands-on guides for privacy-focused operating systems and the day-to-day hygiene that keeps them useful. Anonymity networks (Tor, I2P) and messengers (Session, SimpleX) fail if the underlying OS leaks your identity, and no OS can protect you if you leave metadata in every file you touch.

This subcategory is part of the **ANONYMITY-PRIVACY-OPSEC** category. All files follow the **Hands-on format** (13 sections, ending with Legal and Ethical Notes instead of OSCP Notes).

## Scope

This subcategory covers:

- **Tails** - amnesic live OS that routes everything through Tor and leaves no trace on the host.
- **Qubes / Whonix** - compartmentalized OS and Tor gateway VM for separation of identities.
- **Data Destruction** - secure wipe, SSD caveats, and the limits of "delete".
- **Metadata** - what your files reveal, how to strip it, and how to avoid leaking it in the first place.

## Threat Model Summary

| Tool / Topic | Protects against | Does NOT protect against | Persistence |
|--------------|------------------|--------------------------|-------------|
| Tails | Host compromise, disk forensics, IP leaks | Firmware implants, hardware keyloggers, global passive adversary | None (amnesic by design) |
| Qubes / Whonix | Cross-identity contamination, VM escape (mostly) | Firmware implants, physical access, endpoint compromise of the host | Yes (per-VM) |
| Data Destruction | Recovery of deleted files on HDD/SSD | Already-leaked data, cloud copies, backups | N/A |
| Metadata | File-level identity leakage | Network-level metadata, stylometry | N/A |

## Files

| # | File | Focus | Status |
|---|------|-------|--------|
| 01 | [Tails](./01%20Tails.md) | Amnesic live OS with Tor by default | done |
| 02 | [Qubes / Whonix](./02%20Qubes-Whonix.md) | Compartmentalization and Tor gateway | done |
| 03 | [Data Destruction](./03%20Data%20Destruction.md) | Secure wipe and SSD caveats | done |
| 04 | [Metadata](./04%20Metadata.md) | File metadata stripping and hygiene | done |

## Related

- [01 Anonymous Networks](../01%20Anonymous%20Networks/README.md) - Tor, I2P, Lokinet, VPN chains (transport layer).
- [02 Secure Communications](../02%20Secure%20Communications/README.md) - Session, SimpleX, XMPP/OMEMO, anonymous email, PGP.

## Legal and Ethical Notes

Privacy-focused operating systems are legal to use in most jurisdictions. However:

- **Some countries restrict or ban the use of Tor, Tails, and similar tools.** Check your local law before installing or using them.
- **Using these tools to plan or commit a crime is illegal everywhere.** Anonymity is not a defense against the underlying offense.
- **Corporate policy may forbid them.** On a work device, using Tails, Qubes, or Tor may violate acceptable-use policy.
- **Do not use these tools to harass, stalk, defraud, or harm any person.**
- **Authorized use only.** In a professional context, use these tools only within the scope of an authorized engagement or for your own personal privacy.

## References

- [Tails](https://tails.net/)
- [Qubes OS](https://www.qubes-os.org/)
- [Whonix](https://www.whonix.org/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Operating Systems](https://www.privacyguides.org/en/os/)
