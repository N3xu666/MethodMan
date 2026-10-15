# Compartmentalization

Compartmentalization is the practice of separating identities, devices,
networks, and activities so that a compromise of one does not cascade
into the others. It is the operational counterpart to threat modeling:
the threat model tells you what you are defending against, and
compartmentalization tells you how to structure your defenses so that a
single failure is survivable.

This file is conceptual. It does not cover tool installation or
configuration. Those live in the hands-on subcategories (01-06). This
file covers how to design compartments and how they fail.

## 1. Overview

A compartment is an isolated unit of operation: one identity, one
device, one network path, one set of behaviors. The goal of
compartmentalization is that the compromise of one compartment does not
imply the compromise of another. In practice this means that no single
piece of evidence - a login, a timing pattern, a writing style, a piece
of infrastructure - should be sufficient to link two compartments
together.

Compartmentalization is the difference between anonymity and
pseudonymity. A single pseudonym is not compartmentalized; it is one
compartment with a long history. Multiple compartments with no linkable
overlap are what make attribution hard.

## 2. Threat Model

The adversary for compartmentalization is a correlation adversary. This
adversary does not need to break cryptography; they need to find a
single feature that two compartments share. The features they look for
are:

- **Infrastructure** - the same IP, the same VPN exit, the same hosting
  provider, the same domain registrar, the same email provider.
- **Timing** - the same login times, the same activity windows, the
  same response latency.
- **Content** - the same writing style, the same vocabulary, the same
  typos, the same references, the same images.
- **Behavior** - the same routines, the same order of operations, the
  same mistakes.
- **Metadata** - the same browser fingerprint, the same screen
  resolution, the same timezone, the same language settings.
- **Financial** - the same payment method, the same crypto address, the
  same exchange account.

The adversary does not need all of these. One shared feature is enough
to link two compartments. The threat model for compartmentalization is
therefore: assume the adversary has one feature, and design so that one
feature is not enough.

## 3. How It Works (technical)

Compartmentalization operates at four layers, and each layer must be
separated independently:

- **Identity layer** - separate names, separate accounts, separate
  email addresses, separate PGP keys. Identities must not share
  recovery mechanisms (phone numbers, backup emails) because those are
  linkable.
- **Device layer** - separate physical devices, or separate virtual
  machines, or separate OS user accounts with separate storage. The
  device layer is where most compartmentalization fails: a shared
  keyboard, a shared camera, a shared clipboard, or a shared browser
  profile links compartments.
- **Network layer** - separate network paths. This means separate Tor
  circuits, separate VPN exits, separate Wi-Fi networks, separate
  physical locations. A shared network path is a shared IP, and a
  shared IP is a link.
- **Temporal layer** - separate activity windows. Two compartments that
  are active at the same time are linkable by timing, even if every
  other layer is separated.

The layers are not independent: a failure at the device layer can leak
information that links the network layer, and a failure at the temporal
layer can link identities that never share infrastructure.

## 4. Practical Framework

A working compartmentalization framework, in six steps:

1. **Define the compartments.** Name each identity and what it is for.
   "Work", "activism", "personal", "research" are compartments.
   Compartments should be few enough to manage and many enough to
   isolate.

2. **Define the isolation rules.** For each pair of compartments, write
   down what must never be shared. This is the compartmentalization
   policy. It is the document that decides whether a proposed action
   is allowed.

3. **Separate the layers.** For each compartment, assign a device, a
   network path, and an activity window. Verify that no two
   compartments share a layer.

4. **Test the isolation.** Attempt to link two compartments using each
   of the adversary's features (infrastructure, timing, content,
   behavior, metadata, financial). If any test succeeds, the isolation
   is incomplete.

5. **Enforce the policy.** The policy is only as strong as its
   enforcement. Enforcement is operational: routines, checklists,
   physical separation, and (where possible) technical controls that
   make the wrong action hard.

6. **Re-evaluate.** Compartments drift. A new tool, a new device, a new
   routine can link two compartments that were previously separate.
   Re-test on a schedule and after any change.

The hardest part is not the design. It is the discipline to follow the
design when it is inconvenient.

## 5. Real-World Examples

**The Silk Road investigation (2013).** Ross Ulbricht's compartments
were not separated at the identity layer: an early forum post used a
personal email address that was later correlated with his operational
identity. The infrastructure compartment was strong; the identity
compartment was not.

**The "Jeremy Hammond" case (2012).** Hammond was linked to the
Stratfor hack through a combination of IRC logs, a cooperating
informant, and a single login from a non-anonymized IP. The network
compartment was separated; the endpoint compartment was not.

**The "Hector Monsegur" case (2011).** Monsegur (Sabu) was linked
through IRC logging and a personal login from a non-anonymized IP. The
compartmentalization was informal; it did not survive a determined
adversary with time.

**The "Dread Pirate Roberts" arrest (2013).** The arrest was not a
cryptographic failure. It was a compartmentalization failure at the
temporal and behavioral layers: the operator's activity patterns,
combined with a single mistake (a personal login), linked the
operational identity to the physical person.

**Corporate insider cases.** Many insider investigations are resolved
not by technical attribution but by compartmentalization failure:
badge logs, parking records, and calendar data link the identity to
the action.

## 6. Common Mistakes

- **Sharing recovery mechanisms.** A shared phone number or backup
  email links two compartments instantly, regardless of how separate
  everything else is.
- **Sharing devices.** A device carries a browser fingerprint, a
  timezone, a keyboard layout, and a clipboard. Device sharing is the
  most common compartmentalization failure.
- **Sharing network paths.** A shared VPN exit or a shared Tor entry
  guard is a shared IP. The adversary does not need to break the
  network; they need to see the IP.
- **Sharing time.** Two compartments active at the same time are
  linkable by timing, even if everything else is separate.
- **Sharing content.** The same writing style, the same typos, the
  same images link compartments. Content is a fingerprint.
- **Assuming that "separate accounts" are separate compartments.** Two
  accounts on the same platform, from the same device, at the same
  time, are one compartment.
- **Over-compartmentalizing.** Too many compartments lead to
  operational errors: the operator forgets which identity is which,
  and a mistake links them. The number of compartments should match
  the number of distinct adversaries.

## 7. Attacks and Detection

An adversary attacks compartmentalization by finding one shared
feature. The attack is correlation, not exploitation:

- **Infrastructure correlation.** Collect IP logs, DNS logs, WHOIS
  records, hosting records. Find a shared value.
- **Timing correlation.** Collect activity timestamps from multiple
  sources. Find an overlap.
- **Content correlation.** Collect text and images from multiple
  sources. Find a stylistic or visual match.
- **Behavioral correlation.** Collect routine data from multiple
  sources. Find a repeated sequence.
- **Metadata correlation.** Collect browser fingerprints, device
  identifiers, and settings. Find a shared value.
- **Financial correlation.** Collect payment records and crypto
  addresses. Find a shared value.

Detection of compartmentalization failure is retrospective: the
operator usually learns about it when the adversary links two
compartments. The defensive move is to red-team the compartments
periodically, using the same features the adversary would use.

## 8. Risk Context

Compartmentalization has a cost: more devices, more identities, more
routines, more friction. The cost must be proportional to the
adversary. For a low-capability adversary (data broker, scraper),
light compartmentalization is enough. For a medium-capability adversary
(ISP, platform), stronger separation is required. For a high-capability
adversary (law enforcement with warrant, national CERT), the cost of
compartmentalization is high, and perfect separation may be
unachievable through consumer tools alone.

The risk of under-compartmentalizing is exposure. The risk of
over-compartmentalizing is operational error. The correct balance is
the one the operator can actually maintain.

## 9. Verification

Compartmentalization is verified by adversarial linking:

- **Infrastructure test.** For each pair of compartments, check
  whether any IP, domain, hosting provider, or registrar is shared.
- **Timing test.** For each pair of compartments, check whether their
  activity windows overlap.
- **Content test.** For each pair of compartments, check whether
  writing style, vocabulary, or images match.
- **Behavior test.** For each pair of compartments, check whether
  routines or sequences match.
- **Metadata test.** For each pair of compartments, check whether
  browser fingerprints, screen resolutions, timezones, or language
  settings match.
- **Financial test.** For each pair of compartments, check whether
  payment methods or crypto addresses are shared.

If any test succeeds, the compartments are linked. Fix the shared
feature, then re-test.

## 10. Legal and Ethical Notes

Compartmentalization is a defensive discipline. It is used by
journalists protecting sources, activists protecting themselves,
researchers protecting participants, and ordinary people protecting
their privacy. It is not illegal.

The legal risk is in the actions the compartments enable. If a
compartment is used for illegal activity, the compartmentalization
itself may be used as evidence of intent (the court may infer that
separate identities were created to evade detection). If it is used to
protect lawful privacy, it is protected speech in most jurisdictions.

Operators in jurisdictions with restrictive speech or privacy laws
should consult a lawyer before documenting compartmentalization
policies that could be seized. The policy is a document; the document
can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- The Tor Project, "Tor: Overview" and "Tor: Metadata" documentation.
- Electronic Frontier Foundation, "Surveillance Self-Defense" guide,
  especially "How to: Use Tor" and "How to: Protect Your Privacy".
- Bruce Schneier, "Data and Goliath" (W. W. Norton, 2015), chapters on
  identity and correlation.
- Citizen Lab, "The Not-So-Secret Life of Anonymity" (2014).
- The Intercept, "The Silk Road Investigation" (2015).
- United States v. Ulbricht, trial record (2015).
- United States v. Hammond, trial record (2013).
- The Guardian, "LulzSec: The Inside Story" (2013).
