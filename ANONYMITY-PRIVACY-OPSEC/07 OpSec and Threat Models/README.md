# OpSec and Threat Models

Operational security (OpSec) and threat modeling for privacy-focused
operators. This subcategory is conceptual: it covers the reasoning,
frameworks, and mental models behind staying anonymous, not specific
tools to install.

This is the first of two conceptual subcategories in the
ANONYMITY-PRIVACY-OPSEC category. The hands-on subcategories (01-06)
cover tools and configurations; this subcategory covers how to think
about your adversary, your exposure, and your behavior.

## Scope

The four files here cover:

- **Threat Modeling** - how to identify what you are protecting, from
  whom, and what happens if you fail. STRIDE, attack trees, data-flow
  diagrams, and the adversary-capability matrix.
- **Compartmentalization** - how to separate identities, devices, and
  activities so that a compromise of one does not cascade into the
  others. Operational separation, not just technical separation.
- **Attribution** - how adversaries attribute actions to you, and how
  to make that attribution harder. Traffic analysis, stylometry,
  behavioral patterns, and operational mistakes.
- **Case Studies** - real-world failures of anonymity: what went wrong,
  which compartment failed, and what the operator did not model. Read
  these as post-mortems.

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

There are no installation steps and no hardening checklists here -
those live in the hands-on subcategories (01-06). This subcategory is
about reasoning.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | Threat Modeling | Adversary capabilities, STRIDE, attack trees, data-flow analysis |
| 02 | Compartmentalization | Identity, device, and network separation; isolation models |
| 03 | Attribution | Traffic analysis, stylometry, behavioral fingerprinting, mistakes |
| 04 | Case Studies | Real anonymity failures as post-mortems |

## Related

- 01 Anonymous Networks - the transport layer (Tor, I2P, VPN chains)
- 02 Secure Communications - the messaging layer
- 03 Operating Systems and Hygiene - the endpoint layer
- 06 Anonymous Crypto Operations and AML - the financial layer

## Warning

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.
