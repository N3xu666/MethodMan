# Case Studies

This file is a set of post-mortems. Each case is a real anonymity or
attribution failure, analyzed through the lens of the previous three
files: threat modeling, compartmentalization, and attribution. The goal
is not to admire the failures but to extract the lessons that apply to
current operations.

This file is conceptual. It does not cover tool installation or
configuration. Those live in the hands-on subcategories (01-06). This
file covers what went wrong and why.

## 1. Overview

Anonymity failures are rarely cryptographic. In almost every public
case, the transport layer held: Tor was not broken, the encryption was
not cracked, the password was not guessed. The failure was one layer
up: a threat model that did not include an asset, a compartment that
shared a feature, or an attribution vector that was not considered.

The cases in this file are grouped by failure type:

- **Identity-layer failures** - a personal identity leaked into an
  operational compartment.
- **Temporal and behavioral failures** - activity patterns linked
  compartments that were otherwise separate.
- **Endpoint failures** - the device or the human was the weak link.
- **Social failures** - relationships or informants linked identities.
- **Financial failures** - payment methods or crypto transactions
  linked identities.

Each case follows the same structure: what the operator did, what the
adversary did, which compartment failed, and what the operator did not
model.

## 2. Threat Model

The adversary in these cases is not a single entity. It is usually a
combination:

- **Law enforcement** with legal authority to compel records from
  ISPs, platforms, and payment processors.
- **Platform trust-and-safety** teams with access to account metadata
  and behavioral logs.
- **Investigative journalists** with public-records access and the
  ability to correlate public data.
- **Civil litigants** with subpoena power in civil discovery.
- **Informants** with social access to the operator.

The common thread is that the adversary had time, legal authority, and
access to at least one data source the operator did not model. The
threat model for reading these cases is therefore: assume the adversary
has one data source you forgot, and ask which of your compartments it
would compromise.

## 3. How It Works (technical)

Each case is analyzed with the same method:

1. **Reconstruct the operation.** What was the operator trying to do,
   and what compartments did they use?
2. **Identify the failure.** Which compartment was compromised, and
   how?
3. **Trace the link.** What feature linked the compromised compartment
   to the operator's real identity?
4. **Extract the lesson.** What would have prevented the link, and at
   what cost?

The method is deliberately backward: start from the failure, work
backward to the missing control. This is the same method an adversary
would use if they had already attributed the action and wanted to
document how.

## 4. Practical Framework

Reading these cases as a framework:

- **For each case, ask: which of my compartments has the same
  failure?** The cases are not historical curiosities; they are
  patterns. If the pattern applies to a current compartment, the
  compartment needs to change.
- **For each case, ask: what did the operator not model?** The missing
  asset is the lesson. Write it into your own threat model.
- **For each case, ask: what would the control have cost?** Some
  failures were preventable at low cost (not reusing a personal email);
  some were preventable only at high cost (never using a personal
  device). The cost determines whether the control is worth applying.
- **For each case, ask: is the failure still possible today?** Some
  failures are historical (a platform that no longer exists); some are
  evergreen (reusing an email). Focus on the evergreen ones.

A case study is useful only if it changes a current behavior. If
reading it does not change anything you do, it was entertainment, not
education.

## 5. Real-World Examples

**Case 1: Silk Road (2013) - identity-layer failure.**
Ross Ulbricht ran the Silk Road marketplace under the pseudonym "Dread
Pirate Roberts". The transport compartment (Tor) held. The
identity compartment did not: an early forum post used a personal email
address (`rossulbricht@gmail.com`), and a Stack Overflow question about
Tor hidden services was posted from the same identity. Investigators
linked the two. **Lesson:** a single historical identity leak can
compromise an otherwise strong operational compartment. The threat
model did not include "past personal activity".

**Case 2: Harvard bomb threat (2013) - temporal failure.**
A Harvard student sent a bomb threat over Tor to avoid an exam. The FBI
did not break Tor. They correlated the timing of the Tor connection
with the campus network, then correlated the network with the student's
exam schedule and physical location. **Lesson:** timing is a feature.
Even when the transport is anonymous, the timing of the connection can
link the action to a physical actor. The threat model did not include
"timing correlation with physical presence".

**Case 3: Jeremy Hammond (2012) - social and endpoint failure.**
Hammond was linked to the Stratfor hack through IRC logs, a cooperating
informant (Hector Monsegur), and a single login from a non-anonymized
IP. The transport compartment held. The social compartment
(informant) and the endpoint compartment (non-anonymized login) did
not. **Lesson:** the social layer is part of the threat model. An
informant inside the compartment can compromise everything the
technical controls protect.

**Case 4: Hector Monsegur / Sabu (2011) - endpoint failure.**
Monsegur was linked through IRC logging and a personal login from a
non-anonymized IP. The IRC layer was not compartmentalized: it ran on
the same endpoint as other activity. **Lesson:** the endpoint is the
weak link. A single non-anonymized connection from the operational
device can link the entire compartment.

**Case 5: BTK (2005) - metadata failure.**
Dennis Rader sent a floppy disk to the police. The disk metadata
(an embedded document property) linked the file to a computer at his
church, which linked to him. The physical compartment held (he was not
followed); the metadata compartment did not. **Lesson:** metadata is a
feature. File metadata, document properties, and embedded identifiers
can link a physical actor to an anonymous action.

**Case 6: Unabomber (1995) - linguistic failure.**
Ted Kaczynski was attributed through linguistic analysis: his brother
recognized the writing style in the published manifesto. The physical
compartment held for years; the linguistic compartment did not.
**Lesson:** writing style is a fingerprint. Stylometry can link texts
that share no technical infrastructure.

**Case 7: Golden State Killer (2018) - genetic failure.**
Joseph DeAngelo was attributed through genetic genealogy: a distant
relative's DNA upload to a genealogy site allowed investigators to
build a family tree and narrow it to him. The physical compartment held
for decades; the genetic compartment did not exist in his threat model
(the technology did not exist when the crimes were committed).
**Lesson:** new attribution methods can retroactively compromise old
operations. A threat model is a snapshot, not a permanent guarantee.

**Case 8: Ashley Madison (2015) - platform failure.**
The platform stored data that its users assumed was ephemeral. The
breach did not attribute the users technically; it revealed their
account data. Subsequent investigations attributed specific users
through payment records and email addresses. **Lesson:** the platform
is part of the compartment. If the platform stores linkable data, the
compartment is only as strong as the platform's data retention policy.

**Case 9: Dread Pirate Roberts arrest (2013) - behavioral failure.**
The arrest was not a cryptographic failure. It was a behavioral
failure: the operator's activity patterns, combined with a single
mistake (a personal login), linked the operational identity to the
physical person. **Lesson:** behavior is a feature. Activity hours,
response latency, and order of operations persist across technical
changes.

**Case 10: LulzSec IRC logs (2011) - logging failure.**
Multiple LulzSec members were attributed through IRC logs that they
themselves had not modeled as evidence. The logs were collected by
third parties, by informants, and by law enforcement. **Lesson:**
anything you say on a channel can be logged by anyone in the channel.
The threat model must include "the other participants".

## 6. Common Mistakes

The cases share a small set of recurring mistakes:

- **Modeling the transport, not the operator.** Tor protects the
  network; it does not protect the human, the endpoint, or the social
  layer.
- **Forgetting historical activity.** A personal email from five years
  ago can link a current operational identity.
- **Underestimating timing.** Connection times, activity windows, and
  response latency are features.
- **Ignoring the endpoint.** The device, the browser, the keyboard, and
  the clipboard are all part of the threat model.
- **Trusting the platform.** Platforms store data. If the platform can
  be breached or subpoenaed, the compartment is only as strong as the
  platform's data policy.
- **Ignoring the social layer.** Informants, colleagues, and family
  are part of the threat model. They can link identities without any
  technical compromise.
- **Assuming static attribution methods.** New methods (genetic
  genealogy, blockchain clustering, stylometry) can retroactively
  compromise old operations.
- **Believing that "they cannot prove it" is protection.** Attribution
  does not require proof in a court. It requires enough probability for
  the adversary to act.

## 7. Attacks and Detection

The attack patterns in these cases generalize to:

- **Historical correlation.** Collect public records from the past.
  Find a shared identity.
- **Timing correlation.** Collect activity timestamps from multiple
  sources. Find an overlap.
- **Metadata correlation.** Collect file metadata, document
  properties, and embedded identifiers. Find a link.
- **Linguistic correlation.** Collect text from multiple sources. Find
  a stylistic match.
- **Genetic correlation.** Collect genetic data from relatives. Build
  a family tree.
- **Platform correlation.** Collect platform data (account metadata,
  payment records). Find a shared value.
- **Social correlation.** Collect relationship data from informants
  and public sources. Find a shared contact.
- **Behavioral correlation.** Collect routine data. Find a repeated
  pattern.

Detection of these risks is proactive: for each pattern, ask whether
your current compartments could be linked by it. The defensive move is
to reduce the number of features the pattern can use.

## 8. Risk Context

The cases show a consistent pattern: the cost of prevention is usually
much lower than the cost of the failure. Reusing a personal email costs
nothing to avoid; the Silk Road investigation cost decades of prison.
Posting from a non-anonymized IP costs nothing to avoid; the Hammond
and Monsegur cases cost years of prison.

The risk of not studying these cases is repeating them. The risk of
over-studying them is paralysis: so many possible failures that the
operator cannot act. The correct balance is to extract the patterns
that apply to the current threat model, apply the controls that are
proportional to the current adversary, and re-evaluate on a schedule.

## 9. Verification

Case-study learning is verified by applying each pattern to the current
operation:

- **Historical test.** Search public records for any personal identity
  that could be linked to a current compartment. If found, sever the
  link.
- **Timing test.** Compare activity windows across compartments. If
  they overlap, adjust the schedule.
- **Metadata test.** Inspect files, documents, and images for
  metadata. If it links to a personal identity, strip it.
- **Linguistic test.** Compare writing style across compartments. If a
  machine-learning model can link them, change the style or the
  compartment.
- **Platform test.** Review the data each platform stores. If the data
  is linkable and the platform can be breached or subpoenaed, change
  the platform or the data.
- **Social test.** Assume an informant in each compartment. What would
  the informant reveal? If the answer links compartments, change the
  social layer.

If any test succeeds, the risk is real. Fix the exposed feature, then
re-test.

## 10. Legal and Ethical Notes

This file analyzes publicly documented cases for educational purposes.
The cases are matters of public record; the analysis is commentary. No
confidential or non-public information is used.

The lessons are defensive: they help operators protect lawful privacy.
They do not help anyone commit crimes, and they do not provide
operational instructions for illegal activity. The legal risk is in the
actions an operator takes, not in studying the cases.

Operators in jurisdictions with restrictive speech or privacy laws
should consult a lawyer before documenting a case-study analysis that
could be seized. The analysis is a document; the document can be
evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- The Intercept, "The Silk Road Investigation" (2015).
- United States v. Ulbricht, trial record (2015).
- The Harvard Crimson, "Harvard Bomb Threat Investigation" (2013).
- United States v. Hammond, trial record (2013).
- The Guardian, "LulzSec: The Inside Story" (2013).
- Wichita Eagle, "BTK Investigation" (2005).
- The New York Times, "Unabomber Investigation" (1995).
- The Sacramento Bee, "Golden State Killer Investigation" (2018).
- Wired, "Ashley Madison Breach" (2015).
- Arvind Narayanan et al., "On the Feasibility of Internet-Scale
  Author Identification" (2008).
