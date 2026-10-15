# Threat Modeling

## 1. Overview

Threat modeling is the discipline of reasoning about your adversary before you choose your defenses. For anonymity and privacy work, it answers the questions that determine every later decision: what you are protecting, from whom, and at what cost. A threat model that is not written down is not a threat model - it is an assumption.

Threat modeling is the process of answering four questions before you
act: what am I protecting, from whom, what can go wrong, and what do I
do about it. For a privacy-focused operator, threat modeling is not an
academic exercise - it determines which tools you use, how many
identities you maintain, and where you accept risk.

This file is conceptual. It does not cover tool installation or
configuration. Those live in the hands-on subcategories (01-06). This
file covers how to reason about your adversary before you pick a tool.

## 2. Threat Model

The threat model for anonymity work is defined by three variables:

- **Asset** - what you are protecting. This is rarely just "my
  identity". It is usually a combination: the content of your
  communications, the fact that you communicated at all, the metadata
  (who, when, how often), your location, your social graph, and your
  financial trail.
- **Adversary** - who you are protecting it from. The adversary has a
  capability level, a motivation, and a time horizon. A script kiddie,
  a data broker, a national ISP, and a nation-state signals-intelligence
  agency are four different adversaries requiring four different
  defenses.
- **Failure mode** - what happens if the protection fails. This
  determines how much effort the defense is worth. Losing a burner
  account is different from losing your physical safety.

A threat model that does not name all three is not a threat model - it
is a wish.

## 3. How It Works (technical)

Threat modeling has a formal methodology. The two most common are
STRIDE and attack trees.

**STRIDE** classifies threats into six categories:

- **S**poofing - pretending to be someone else (identity).
- **T**ampering - modifying data in transit or at rest.
- **R**epudiation - denying an action was taken.
- **I**nformation disclosure - leaking data to unauthorized parties.
- **D**enial of service - making a resource unavailable.
- **E**levation of privilege - gaining rights you should not have.

For anonymity work, the relevant STRIDE categories are Spoofing
(adversary impersonates a service to deanonymize you), Information
disclosure (metadata leaks), and Elevation of privilege (adversary
gains access to your compartment).

**Attack trees** are a hierarchical decomposition of an adversary's
goal. The root is the goal ("deanonymize the operator"). The branches
are the ways to achieve it. Each leaf is a concrete technique. Attack
trees are useful because they show that a defense is only as strong as
its weakest leaf.

**Data-flow diagrams** map where data moves: from source, through
transforms, to sink. Each edge is a place where metadata can leak.
Each node is a place where data can be compromised. For anonymity, the
diagram must include the network layer, the endpoint, and the human.

## 4. Practical Framework

A working threat-modeling framework for anonymity, in six steps:

1. **Inventory assets.** List everything you are protecting. Be
   specific: "the fact that I run account X" is an asset. "My location
   during operation Y" is an asset.

2. **Enumerate adversaries.** For each asset, name the adversary. Give
   each adversary a capability tier: low (script kiddie, scraper),
   medium (ISP, platform, data broker), high (law enforcement with
   warrant, national CERT), very high (nation-state SIGINT).

3. **Map failure modes.** For each asset-adversary pair, write down
   what happens if the adversary wins. Rank by severity.

4. **Decompose the goal.** Build an attack tree from the adversary's
   perspective. What are the ways they could achieve their goal? Which
   leaves are cheapest for them?

5. **Select controls.** For each leaf, choose a control. Controls are
   either preventive (stop the attack), detective (detect the attack),
   or corrective (recover from the attack). Anonymity controls are
   mostly preventive, but detective controls (canary accounts, tripwires)
   are underused.

6. **Re-evaluate.** A threat model is a snapshot, not a permanent
   document. Re-run it when your adversary changes, when your assets
   change, or when a new attack class appears.

A common failure is to model the adversary you find interesting rather
than the adversary you actually face. The data broker who scrapes your
public posts is a more likely adversary than the nation-state, for most
operators.

## 5. Real-World Examples

**The Silk Road investigation (2013).** Ross Ulbricht was not
deanonymized by breaking Tor. He was deanonymized by a threat-modeling
failure: he used a personal email address in an early forum post, and
that email was correlatable with his later activity. The transport
layer was strong; the operational layer was not modeled.

**The Harvard bomb threat (2013).** A student sent a bomb threat over
Tor to avoid exam. The FBI did not break Tor. They correlated the
timing of the Tor connection with the campus network, and correlated
the network with the student's schedule. The metadata (who was on the
network when) was the failure mode.

**The "Sabu" deanonymization (2011).** Hector Monsegur (LulzSec) was
deanonymized through a combination of IRC logging, a personal login
from a non-anonymized IP, and cooperation with law enforcement. The
threat model assumed Tor was sufficient; it did not account for the
IRC layer and the endpoint.

**The Ashley Madison breach (2015).** Not an anonymity failure in the
traditional sense, but a threat-modeling failure: the platform stored
data that its users assumed was ephemeral. The adversary (the
breachers) had a different asset inventory than the users.

## 6. Common Mistakes

- **Modeling the tool, not the adversary.** "I use Tor" is not a
  threat model. "I use Tor against a medium-capability adversary who
  can observe my ISP but not my Tor entry guard" is a threat model.
- **Confusing anonymity with pseudonymity.** A persistent pseudonym is
  not anonymous. It is linkable by definition. Model the linking, not
  the hiding.
- **Ignoring metadata.** Content is easy to protect. Metadata (timing,
  size, frequency, social graph) is hard. The threat model must include
  metadata as a first-class asset.
- **Forgetting the endpoint.** Tor protects the transport. The endpoint
  (browser, OS, keyboard, camera, microphone) is not protected. A
  threat model that stops at the network layer is incomplete.
- **Static threat models.** An adversary who was low-capability last
  year may be high-capability this year. Re-evaluate on a schedule.
- **Optimism about compartments.** Assuming that because identity A is
  separate from identity B, they cannot be linked. They can - through
  timing, stylometry, infrastructure, or a single slip.

## 7. Attacks and Detection

Threat modeling is itself a target. An adversary can:

- **Exploit an unmodeled asset.** If you did not list "the timing of
  my connections" as an asset, you did not defend it.
- **Exploit a mis-ranked adversary.** If you ranked the adversary as
  low-capability and they are actually high-capability, your controls
  are insufficient.
- **Exploit a mis-mapped failure mode.** If you assumed the failure
  mode was "burner account lost" and it is actually "physical safety",
  the effort allocation is wrong.

Detection of a threat-modeling failure is retrospective: you usually
learn about it when the adversary wins. The defensive move is to
red-team your own threat model periodically: assume the adversary has
already won, and work backward to find which leaf failed.

## 8. Risk Context

Threat modeling has a cost. A very high-capability adversary (nation-state)
requires controls that are expensive in time, money, and operational
friction. A medium-capability adversary (ISP, platform) requires much
less. The threat model determines the budget.

For most operators, the correct adversary tier is medium. Nation-state
defense is a specialist discipline and is not achievable through
consumer tools alone. The threat model should be honest about this.

The risk of over-modeling is operational paralysis: so many controls
that the operator cannot act. The risk of under-modeling is exposure.
The correct balance is the one where the controls are proportional to
the adversary.

## 9. Verification

A threat model is verified by adversarial review:

- **Red-team the model.** Assume the adversary has your model. What
  would they exploit? Which leaf is weakest?
- **Test the controls.** For each preventive control, attempt to
  bypass it in a controlled environment. For each detective control,
  verify it actually fires.
- **Review on a schedule.** Quarterly for most operators; after any
  significant change (new identity, new adversary, new tool) for all.
- **Document the model.** A threat model in your head is not a threat
  model. Write it down. The act of writing exposes the gaps.

## 10. Legal and Ethical Notes

Threat modeling is a defensive discipline. It is used by security
professionals, journalists, activists, and ordinary people protecting
their privacy. It is not illegal in any jurisdiction.

The legal risk is in the actions the model enables, not the modeling.
If the threat model is used to plan illegal activity, the modeling
itself may be used as evidence of intent. If it is used to protect
lawful privacy, it is protected speech in most jurisdictions.

Operators in jurisdictions with restrictive speech or privacy laws
should consult a lawyer before documenting a threat model that could
be seized. The model is a document; the document can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- NIST SP 800-154, "Guide to Data-Centric System Threat Modeling".
- Adam Shostack, "Threat Modeling: Designing for Security" (Wiley, 2014).
- OWASP Threat Modeling Cheat Sheet.
- The Tor Project, "Tor: Overview" and "Tor: Metadata" documentation.
- Electronic Frontier Foundation, "Threat Modeling" (Surveillance
  Self-Defense guide).
- Bruce Schneier, "Attack Trees" (Dr. Dobb's Journal, 1999).
- The Intercept, "The Silk Road Investigation" (2015).
- United States v. Ulbricht, trial record (2015).
