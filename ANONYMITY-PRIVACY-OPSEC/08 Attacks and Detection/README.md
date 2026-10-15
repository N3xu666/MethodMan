# Attacks and Detection

This subcategory is the adversary's view of anonymity and privacy. The
previous subcategory (07 OpSec and Threat Models) covered how to reason
about your adversary. This one covers what that adversary actually does:
the concrete attacks against anonymity systems, the detection techniques
used by platforms and governments, and the real-world takedowns that
result from both.

This is the second of two conceptual subcategories. There are no tools
to install and no configurations to harden. The material is analytical:
how the attacks work, what they exploit, and what the defender can do.

## Scope

The four files here cover:

- **De-anonymization** - the general techniques: traffic correlation,
  fingerprinting, stylometry, and statistical linking.
- **Hidden Service Attacks** - attacks specific to Tor onion services:
  guard discovery, rendezvous point attacks, and the relay-level
  attacks that have been used against them.
- **Corporate Detection** - how platforms and enterprises detect
  anonymized activity: behavioral analytics, account correlation, and
  abuse detection.
- **LE Takedowns** - how law enforcement dismantles anonymity-based
  operations: legal process, infrastructure seizure, infiltration, and
  operational mistakes.

## Format

All files use the **Conceptual** format (11 sections):

1. Overview
2. Threat Model
3. How It Works (technical)
4. Practical Framework
5. Real-World Examples
6. Common Mistakes
7. Attacks and Detection
8. Risk Context
9. Verification
10. Legal and Ethical Notes
11. References

This is the same format as subcategory 07. There are no installation
steps and no hardening checklists here.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | De-anonymization | Traffic correlation, fingerprinting, stylometry, statistical linking |
| 02 | Hidden Service Attacks | Guard discovery, rendezvous attacks, relay-level attacks |
| 03 | Corporate Detection | Behavioral analytics, account correlation, abuse detection |
| 04 | LE Takedowns | Legal process, infrastructure seizure, infiltration, mistakes |

## Related

- 01 Anonymous Networks - the transport layer these attacks target
- 02 Secure Communications - the messaging layer these attacks target
- 04 Dark Web - hidden services (the target of file 02)
- 07 OpSec and Threat Models - the defensive counterpart to this subcategory

## Warning

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.
