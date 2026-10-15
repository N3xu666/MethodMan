# Anonymous Crypto Operations and AML

Practical reference for using cryptocurrency in a privacy-conscious way,
and for understanding the anti-money-laundering (AML) and blockchain
analysis systems that try to de-anonymize it. The focus is on operational
security for authorized red-team engagements and privacy research, not on
evading lawful investigation.

This subcategory is part of **ANONYMITY-PRIVACY-OPSEC**.

> [!CAUTION]
> This material is provided for educational purposes only. Use it only
> for lawful purposes and, where applicable, within an authorized
> engagement or approved research project. Using cryptocurrency to
> launder money, evade sanctions, or finance illegal activity is a
> criminal offense in most jurisdictions. See the category README for
> the full authorized-use policy.

## Scope

| Area | What it covers |
|------|----------------|
| Monero | The dominant privacy-focused cryptocurrency: ring signatures, stealth addresses, RingCT, Dandelion++, and practical wallet hygiene |
| Bitcoin | Bitcoin's transparent ledger, UTXO model, address reuse, and the privacy techniques that partially mitigate it |
| Physical and Prepaid | Cash-to-crypto methods, prepaid cards, ATMs, and the operational-security trade-offs of each |
| Mixers and Tumblers | CoinJoin, Chaumian mixes, and the legal and operational reality after the 2022-2024 enforcement actions |
| Chain-Hopping and DEX | Cross-chain swaps, decentralized exchanges, and the traces that bridges and DEXs leave behind |
| Transaction OpSec | Address hygiene, timing, amounts, fees, and the metadata that survives on-chain |
| AML and Chain Analysis | How Chainalysis, Elliptic, TRM, and law enforcement cluster addresses, and what defeats each heuristic |
| Cashing Out | Converting crypto back to fiat without creating a single identity-linked event |

## Format

All files in this subcategory use the **Hands-on** format:

1. Overview
2. Threat Model
3. How It Works (technical)
4. Installation and Setup
5. Hardening and Configuration
6. Operational Usage
7. Common Mistakes
8. Attacks Against It
9. Detection (Blue Team)
10. Case Studies
11. Legal and Ethical Notes
12. Production Notes
13. References

> [!NOTE]
> "OSCP Notes" is intentionally replaced by "Legal and Ethical Notes".
> OSCP does not cover anonymity, privacy, or anti-forensics topics -
> the exam is scoped to authorized penetration testing.

## Files

| # | File |
|---|---|
| 01 | [Monero](./01%20Monero.md) |
| 02 | [Bitcoin](./02%20Bitcoin.md) |
| 03 | [Physical and Prepaid](./03%20Physical%20and%20Prepaid.md) |
| 04 | [Mixers and Tumblers](./04%20Mixers%20and%20Tumblers.md) |
| 05 | [Chain-Hopping and DEX](./05%20Chain-Hopping%20and%20DEX.md) |
| 06 | [Transaction OpSec](./06%20Transaction%20OpSec.md) |
| 07 | [AML and Chain Analysis](./07%20AML%20and%20Chain%20Analysis.md) |
| 08 | [Cashing Out](./08%20Cashing%20Out.md) |

## Related

- [01 Anonymous Networks](../01%20Anonymous%20Networks/README.md)
- [02 Secure Communications](../02%20Secure%20Communications/README.md)
- [03 Operating Systems and Hygiene](../03%20Operating%20Systems%20and%20Hygiene/README.md)
- [04 Dark Web](../04%20Dark%20Web/README.md)
- [05 Anonymous Hosting](../05%20Anonymous%20Hosting/README.md)
