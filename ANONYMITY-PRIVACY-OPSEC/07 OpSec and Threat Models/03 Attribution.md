# Attribution

Attribution is the process of linking an action to an actor. For a
privacy-focused operator, attribution is the adversary's goal: they do
not need to stop the action, they need to prove who did it. This file
covers how attribution works, what features adversaries use, and how to
make attribution harder.

This file is conceptual. It does not cover tool installation or
configuration. Those live in the hands-on subcategories (01-06). This
file covers the reasoning behind attribution resistance.

## 1. Overview

Attribution answers the question "who did this?". It is distinct from
deanonymization: deanonymization reveals an identity, attribution links
that identity to an action. An adversary can attribute an action
without ever knowing the actor's real name - a persistent pseudonym is
enough for legal, financial, or social consequences.

Attribution is probabilistic, not binary. Adversaries build a case from
multiple independent features. A single feature is rarely enough; a
pattern of features is. Attribution resistance is therefore the
practice of minimizing the number of independent features an adversary
can collect.

## 2. Threat Model

The adversary for attribution is an investigator with time and
resources. This adversary is not necessarily a nation-state; it can be
a platform trust-and-safety team, a civil litigant, a journalist, or a
competitor. The features they collect fall into six categories:

- **Technical** - IP addresses, device fingerprints, browser
  fingerprints, TLS fingerprints, timing patterns.
- **Linguistic** - vocabulary, syntax, punctuation, typos, code style,
  formatting habits.
- **Behavioral** - activity hours, response latency, order of
  operations, tool choices.
- **Social** - relationships, references, shared interests, common
  contacts.
- **Financial** - payment methods, crypto addresses, purchase patterns.
- **Physical** - location, movement, access to specific infrastructure.

The adversary does not need all six. Two or three independent features
are often enough to build a case that survives legal or public scrutiny.
The threat model for attribution resistance is therefore: assume the
adversary collects all six, and design so that no two can be linked.

## 3. How It Works (technical)

Attribution works by correlation across independent data sources. The
adversary collects features from each source, then looks for
intersections. The sources are:

- **Network logs** - ISP records, VPN provider records, Tor relay
  logs, CDN logs, platform access logs.
- **Platform data** - account metadata, login history, device
  identifiers, content history.
- **Public data** - forum posts, social media, code repositories,
  domain registrations, certificate transparency logs.
- **Financial data** - bank records, exchange records, blockchain
  analysis.
- **Physical data** - CCTV, badge logs, travel records, purchase
  records.
- **Human data** - informants, colleagues, family, social engineering.

The adversary's method is Bayesian: each feature updates a probability.
A feature that is rare in the population is more informative than a
feature that is common. The adversary's goal is to reach a probability
high enough to act (legally, financially, or socially).

Attribution resistance is therefore not about being invisible. It is
about being one of many plausible actors, so that the adversary's
probability never reaches the action threshold.

## 4. Practical Framework

A working attribution-resistance framework, in six steps:

1. **Identify the features.** For each action, list the features the
   adversary could collect. Be exhaustive: technical, linguistic,
   behavioral, social, financial, physical.

2. **Classify by rarity.** For each feature, estimate how rare it is in
   the relevant population. A rare feature is a strong signal; a common
   feature is weak. Prioritize the rare features.

3. **Separate the features.** For each rare feature, decide how to
   separate it from the action. This is the compartmentalization
   policy (see 02 Compartmentalization).

4. **Introduce noise.** Where separation is not possible, introduce
   noise: vary timing, vary phrasing, vary tools, vary routines. Noise
   reduces the signal-to-noise ratio the adversary sees.

5. **Test the case.** Assume the adversary has collected every feature
   you could not separate or noise. Build the strongest case they could
   build. If the case is strong, the resistance is insufficient.

6. **Re-evaluate.** Attribution techniques evolve. New correlation
   methods (machine learning on writing style, blockchain clustering)
   appear regularly. Re-evaluate on a schedule.

The hardest part is honesty: the operator must assume the adversary is
competent and patient, not lucky.

## 5. Real-World Examples

**The Unabomber case (1995).** Ted Kaczynski was attributed through
linguistic analysis: his brother recognized the writing style in the
published manifesto. The technical compartment was strong; the
linguistic compartment was not.

**The "BTK" case (2005).** Dennis Rader was attributed through a
floppy disk he sent to the police. The disk metadata linked the file to
a computer at his church, which linked to him. The physical compartment
was strong; the metadata compartment was not.

**The "Golden State Killer" case (2018).** Joseph DeAngelo was
attributed through genetic genealogy: a distant relative's DNA upload
to a genealogy site allowed investigators to build a family tree and
narrow it to him. The physical compartment was strong; the genetic
compartment was not.

**The "Silk Road" case (2013).** Ross Ulbricht was attributed through a
combination of a personal email in an early forum post, a Stack
Overflow question, and a login from a non-anonymized IP. The technical
compartment was strong; the historical and behavioral compartments were
not.

**The "LulzSec" cases (2011-2013).** Multiple members were attributed
through IRC logging, informants, and a single login from a
non-anonymized IP. The technical compartment was strong; the social and
endpoint compartments were not.

**The "Ashley Madison" investigation (2015).** The breach did not
attribute the users; it revealed them. But the subsequent
investigations attributed specific users through payment records and
email addresses. The platform compartment was strong; the financial and
identity compartments were not.

## 6. Common Mistakes

- **Assuming technical anonymity is enough.** Attribution is
  multi-feature. Technical anonymity protects one feature, not all.
- **Ignoring linguistic features.** Writing style is a fingerprint.
  Machine-learning stylometry can link texts that share no technical
  infrastructure.
- **Ignoring behavioral features.** Activity hours, response latency,
  and order of operations are fingerprints. They persist across
  technical changes.
- **Ignoring social features.** The people you talk to, the topics you
  discuss, and the references you make are fingerprints. They persist
  across identity changes.
- **Ignoring financial features.** Payment methods and crypto addresses
  are fingerprints. Blockchain analysis is increasingly effective.
- **Underestimating the adversary's patience.** Attribution cases are
  built over years. A single slip in year five can link everything
  from year one.
- **Assuming that "they cannot prove it" is protection.** Attribution
  does not require proof in a court. It requires enough probability for
  the adversary to act: a platform ban, a civil suit, a public
  accusation, a financial restriction.

## 7. Attacks and Detection

An adversary attacks attribution resistance by collecting more features
from more sources. The attacks are:

- **Stylometry.** Machine-learning analysis of writing style. Links
  texts by vocabulary, syntax, punctuation, and formatting.
- **Timing analysis.** Correlation of activity timestamps across
  sources. Links identities by shared activity windows.
- **Fingerprinting.** Browser, device, and TLS fingerprinting. Links
  sessions by shared technical features.
- **Blockchain analysis.** Clustering of crypto addresses by shared
  transaction patterns. Links wallets by shared behavior.
- **Social network analysis.** Mapping of relationships and references.
  Links identities by shared contacts and interests.
- **Human intelligence.** Informants, social engineering, and physical
  surveillance. Links identities through people.

Detection of attribution risk is proactive: the operator should assume
the adversary is collecting features continuously, and periodically
audit which features have been exposed. The defensive move is to
minimize the number of exposed features, not to hide the exposed ones.

## 8. Risk Context

Attribution resistance has a cost: more compartmentalization, more
noise, more discipline. The cost must be proportional to the adversary.
For a low-capability adversary (platform trust-and-safety, scraper),
basic hygiene is enough. For a medium-capability adversary (civil
litigant, investigative journalist), stronger separation is required.
For a high-capability adversary (law enforcement with warrant,
national CERT), the cost is high, and perfect resistance may be
unachievable through consumer tools alone.

The risk of under-resisting is exposure. The risk of over-resisting is
operational error: too much noise makes the operator's own work
inconsistent, and inconsistency is itself a signal. The correct balance
is the one the operator can maintain without breaking their own
routines.

## 9. Verification

Attribution resistance is verified by adversarial reconstruction:

- **Stylometry test.** Compare the writing style of the protected
  identity to the writing style of any other identity the operator
  maintains. If a machine-learning model can link them, the resistance
  is insufficient.
- **Timing test.** Compare activity windows across identities. If they
  overlap, the resistance is insufficient.
- **Fingerprint test.** Compare browser, device, and TLS fingerprints
  across sessions. If they match, the resistance is insufficient.
- **Blockchain test.** Compare crypto addresses and transaction
  patterns. If they cluster, the resistance is insufficient.
- **Social test.** Compare contacts, references, and interests. If
  they overlap, the resistance is insufficient.
- **Human test.** Assume the adversary has an informant in the
  operator's social circle. What would the informant reveal? If the
  answer links identities, the resistance is insufficient.

If any test succeeds, the resistance is incomplete. Fix the exposed
feature, then re-test.

## 10. Legal and Ethical Notes

Attribution resistance is a defensive discipline. It is used by
journalists protecting sources, activists protecting themselves,
researchers protecting participants, and ordinary people protecting
their privacy. It is not illegal.

The legal risk is in the actions the resistance enables. If the
resistance is used to evade legitimate law enforcement, the resistance
itself may be used as evidence of intent. If it is used to protect
lawful privacy, it is protected speech in most jurisdictions.

Operators in jurisdictions with restrictive speech or privacy laws
should consult a lawyer before documenting attribution-resistance
policies that could be seized. The policy is a document; the document
can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- The Tor Project, "Tor: Overview" and "Tor: Metadata" documentation.
- Electronic Frontier Foundation, "Surveillance Self-Defense" guide.
- Citizen Lab, "The Not-So-Secret Life of Anonymity" (2014).
- Arvind Narayanan et al., "On the Feasibility of Internet-Scale
  Author Identification" (2008).
- Sadia Afroz et al., "Detecting Hoaxes, Frauds, and Deception in
  Writing Style" (2012).
- Sarah Zhang, "The Golden State Killer Case and the Future of Genetic
  Privacy" (The Atlantic, 2018).
- The Intercept, "The Silk Road Investigation" (2015).
- United States v. Ulbricht, trial record (2015).
- The Guardian, "LulzSec: The Inside Story" (2013).
