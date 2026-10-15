# De-anonymization

De-anonymization is the process of linking an anonymous action to an
identifiable actor. It is the general class of attack that the other
three files in this subcategory specialize: hidden service attacks,
corporate detection, and LE takedowns are all de-anonymization
techniques applied to specific contexts. This file covers the general
methods.

This file is conceptual. It covers how the attacks work and how to
reason about them, not what tools to install. Those live in the
hands-on subcategories (01-06).

## 1. Overview

De-anonymization is a correlation problem. The adversary does not break
the anonymity system itself; they find a feature that the anonymous
actor shares with an identified actor, and then infer that the two are
the same. The feature can be technical (an IP address), behavioral (a
writing style), temporal (an activity window), or social (a shared
contact).

No single feature is usually enough. De-anonymization is a Bayesian
process: each feature updates a probability, and the adversary acts
when the probability is high enough. The threshold for action depends
on the adversary: a platform needs only enough to ban an account, a
civil litigant needs enough to file a suit, a prosecutor needs enough
to charge, and a nation-state needs enough to justify an operation.

The defender's goal is not to be invisible. It is to keep the
adversary's probability below the action threshold for every adversary
that matters.

## 2. Threat Model

The adversary for de-anonymization is any actor with at least one
independent data source that touches the anonymous activity. The
sources are:

- **Network** - ISP logs, VPN provider logs, Tor relay observations,
  CDN logs, BGP data, timing measurements.
- **Platform** - account metadata, login history, device fingerprints,
  browser fingerprints, behavioral logs.
- **Public** - forum posts, social media, code repositories, domain
  registrations, certificate transparency.
- **Financial** - bank records, exchange records, blockchain analysis,
  payment processor data.
- **Physical** - CCTV, badge logs, travel records, purchase records.
- **Human** - informants, colleagues, family, social engineering.

The adversary does not need access to all sources. Two or three
independent sources are usually enough to reach a high probability.
The threat model for de-anonymization resistance is therefore: assume
the adversary has more sources than you can enumerate, and design so
that no two sources can be correlated.

## 3. How It Works (technical)

The technical methods fall into five families:

**1. Traffic correlation.** The adversary observes the timing and volume
of traffic at two points in the network (e.g. the client's ISP and the
destination server) and correlates them. If the patterns match, the two
flows are linked. This is the fundamental attack against low-latency
anonymity networks (Tor, VPNs). It requires observation at both ends;
a single relay or a single ISP is not enough.

**2. Fingerprinting.** The adversary collects technical features that
identify a specific client, browser, or device: TCP/IP stack
fingerprint, TLS fingerprint (JA3/JA4), browser fingerprint (canvas,
fonts, extensions), screen resolution, timezone, language. If the same
fingerprint appears in an anonymous session and in an identified
session, the two are linked. Fingerprinting defeats anonymity when the
client uses the same device or browser for both sessions.

**3. Stylometry.** The adversary analyzes the writing style of
anonymous text and compares it to known text from an identified actor.
Features include vocabulary, syntax, punctuation, typos, formatting,
and code style. Machine learning has made stylometry practical at
scale. Stylometry defeats anonymity when the actor writes the same way
in both contexts.

**4. Timing and behavioral analysis.** The adversary collects activity
timestamps and patterns from multiple sources and looks for overlaps.
If an anonymous actor is active only when an identified actor is known
to be at a keyboard, the two are linked. Behavioral analysis extends
this to routines, order of operations, and tool choices.

**5. Statistical linking.** The adversary uses graph analysis and
record linkage to connect datasets. Given two datasets with
overlapping quasi-identifiers (age, ZIP, purchase history), the
adversary can often re-identify individuals even when direct
identifiers have been removed. This is the classic
"anonymized-dataset" attack.

These families combine. A real investigation uses traffic correlation
to narrow a set of suspects, fingerprinting to eliminate some, and
stylometry to confirm the remainder.

## 4. Practical Framework

A framework for reasoning about de-anonymization risk, in six steps:

1. **Enumerate the features.** For each anonymous action, list every
   feature the adversary could collect. Be exhaustive across the five
   families.

2. **Classify by independence.** Two features are independent if
   knowing one tells you nothing about the other. Correlated features
   are worth less to the adversary than independent ones. The
   defender's goal is to make the features as independent as possible.

3. **Estimate the population.** A feature that is rare in the relevant
   population is a strong signal; a feature that is common is weak.
   The defender's goal is to look like the common case, not the rare
   one.

4. **Assume the worst.** Assume the adversary has access to every data
   source you cannot rule out. Design so that even with those sources,
   no two features can be linked.

5. **Test with an adversarial review.** Construct the strongest
   possible case against yourself using only public sources. If the
   case is strong, the resistance is insufficient.

6. **Re-evaluate.** De-anonymization techniques evolve. New
   correlation methods (machine learning on style, blockchain
   clustering, genetic genealogy) appear regularly. Re-evaluate on a
   schedule.

The hardest part is honesty: the defender must assume the adversary is
competent and patient, not lucky.

## 5. Real-World Examples

**AOL search data release (2006).** AOL released "anonymized" search
logs for 650,000 users. Within days, journalists re-identified several
users from their search queries alone. The data had no names, but the
queries contained enough quasi-identifiers (locations, names of
relatives, medical conditions) to re-identify.

**Netflix Prize dataset (2007-2009).** Netflix released "anonymized"
movie rating data for a recommendation contest. Researchers showed that
cross-referencing with IMDb ratings re-identified users. Netflix
cancelled the follow-up contest.

**Massachusetts GIC health data (1997).** Latanya Sweeney re-identified
the medical records of the Governor of Massachusetts from a "anonymized"
dataset by cross-referencing with voter rolls. The quasi-identifiers
were ZIP code, birth date, and sex.

**Harvard bomb threat (2013).** The FBI did not break Tor. They
correlated the timing of the Tor connection with the campus network,
then correlated the network with the student's schedule and location.

**Silk Road (2013).** Ross Ulbricht was de-anonymized through a
combination of a personal email in an early forum post, a Stack
Overflow question, and a login from a non-anonymized IP. The
correlation was across public sources, not network traffic.

**Golden State Killer (2018).** Joseph DeAngelo was de-anonymized
through genetic genealogy. A distant relative's DNA upload allowed
investigators to build a family tree and narrow it to him. The attack
used a data source (consumer genetic databases) that did not exist in
the original threat model.

## 6. Common Mistakes

- **Treating anonymization as binary.** A dataset is not "anonymous" or
  "not anonymous". It is re-identifiable to a degree, against a
  particular adversary. The correct question is "how much effort does
  the adversary need?".
- **Removing direct identifiers only.** Names, addresses, and phone
  numbers are easy to remove. Quasi-identifiers (ZIP, birth date, sex,
  purchase history) are what enable re-identification.
- **Underestimating auxiliary data.** The adversary almost always has
  auxiliary data: voter rolls, public records, social media, purchase
  history. The attack is the join between the "anonymous" dataset and
  the auxiliary data.
- **Assuming low-latency networks are safe.** Tor and VPNs are
  vulnerable to traffic correlation when the adversary observes both
  ends. The defense is to assume the adversary can observe at least one
  end, and design accordingly.
- **Ignoring stylometry.** Writing style is a fingerprint. Machine
  learning has made it practical at scale. The defense is to vary
  style, or to never write in the same style under two identities.
- **Ignoring timing.** Activity windows are fingerprints. Two
  identities active at the same times are linkable by timing alone.
- **Assuming that "they cannot prove it" is protection.**
  De-anonymization does not require proof in a court. It requires
  enough probability for the adversary to act.

## 7. Attacks and Detection

The attack families are described in section 3. Here is how to detect
each:

- **Traffic correlation.** Assume any adversary who can observe both
  ends can correlate. Detection is not reliable from the client side;
  the defense is to use a high-latency mixnet (when available) or to
  accept the risk.
- **Fingerprinting.** Test your own fingerprint at
  `coveryourtracks.eff.org` and `amiunique.org`. If your fingerprint is
  unique, you are linkable. The defense is a hardened browser (Tor
  Browser, Brave with strict settings) or a browser per identity.
- **Stylometry.** Compare your own writing across identities. If a
  machine-learning model can link them, the resistance is insufficient.
  The defense is to vary style intentionally, or to avoid writing
  under multiple identities on the same topics.
- **Timing and behavioral analysis.** Compare activity windows across
  identities. If they overlap, the resistance is insufficient. The
  defense is to schedule activity in non-overlapping windows.
- **Statistical linking.** Test whether your "anonymized" data can be
  re-identified by joining with public data. The defense is to remove
  or generalize quasi-identifiers before release.

## 8. Risk Context

De-anonymization resistance has a cost: more compartmentalization, more
noise, more discipline. The cost must be proportional to the adversary.
For a low-capability adversary (data broker, scraper), basic hygiene is
enough. For a medium-capability adversary (ISP, platform, civil
litigant), stronger separation is required. For a high-capability
adversary (law enforcement with warrant, national CERT, nation-state
SIGINT), the cost is high, and perfect resistance may be unachievable
through consumer tools alone.

The risk of under-resisting is exposure. The risk of over-resisting is
operational paralysis: so many controls that the operator cannot act.
The correct balance is the one where the controls are proportional to
the adversary.

## 9. Verification

De-anonymization resistance is verified by adversarial reconstruction:

- **Traffic test.** Simulate a traffic correlation attack against your
  own anonymization setup. If the two ends can be correlated, the
  resistance is insufficient.
- **Fingerprint test.** Compare your fingerprint across sessions. If
  it is the same, the resistance is insufficient.
- **Stylometry test.** Compare your writing across identities. If a
  model can link them, the resistance is insufficient.
- **Timing test.** Compare activity windows. If they overlap, the
  resistance is insufficient.
- **Statistical test.** Attempt to re-identify your "anonymized" data
  by joining with public data. If it works, the resistance is
  insufficient.

If any test succeeds, the resistance is incomplete. Fix the exposed
feature, then re-test.

## 10. Legal and Ethical Notes

This file describes attack techniques for educational purposes. The
techniques are documented in the public literature; the analysis is
commentary. No confidential or non-public information is used.

The material is defensive: it helps operators understand what they are
defending against. It does not provide operational instructions for
attacking specific systems or individuals.

The legal risk is in the actions an operator takes, not in studying the
techniques. Operators in jurisdictions with restrictive speech or
privacy laws should consult a lawyer before documenting a
de-anonymization analysis that could be seized. The analysis is a
document; the document can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- Arvind Narayanan and Vitaly Shmatikov, "Robust De-anonymization of
  Large Sparse Datasets" (IEEE S&P, 2008).
- Latanya Sweeney, "k-anonymity: a model for protecting privacy"
  (2002).
- Arvind Narayanan, "The AOL Search Data: A Case Study" (2006).
- Netflix Prize dataset re-identification: Narayanan and Shmatikov
  (2008).
- The Tor Project, "Tor: Overview" and "Traffic Correlation" docs.
- Electronic Frontier Foundation, "Surveillance Self-Defense".
- Citizen Lab, "The Not-So-Secret Life of Anonymity" (2014).
- United States v. Ulbricht, trial record (2015).
- The Harvard Crimson, "Harvard Bomb Threat Investigation" (2013).
- Sarah Zhang, "The Golden State Killer Case and the Future of Genetic
  Privacy" (The Atlantic, 2018).
