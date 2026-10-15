# Hidden Service Attacks

Hidden services (onion services) are the part of Tor that lets a server
be reachable without revealing its IP address. They are the foundation
of dark web marketplaces, whistleblower platforms, and anonymous
publishing. They are also a specific target: the attacks against them
are different from the general de-anonymization techniques, and they
have been used in several real-world takedowns.

This file is conceptual. It covers how the attacks work and how to
reason about them, not what tools to install.

## 1. Overview

A hidden service has two halves: the server side (the onion service
itself, which publishes an introduction point and a descriptor) and the
client side (the user, who connects to a rendezvous point through the
Tor network). The anonymity of the service depends on the server's
location remaining hidden; the anonymity of the client depends on the
client's location remaining hidden.

The attacks in this file target the server side, the client side, or
the rendezvous mechanism. They fall into three families:

- **Guard discovery** - finding the entry guard that the server uses,
  which is the first step toward locating the server.
- **Rendezvous attacks** - attacking the rendezvous point or the
  introduction point to learn the server's IP.
- **Relay-level attacks** - running malicious relays to observe or
  manipulate traffic.

The common thread is that the adversary does not break Tor's
cryptography. They exploit the operational reality: the server is a
process on a machine, the machine has an IP, and the IP can be found if
the adversary can observe the right traffic.

## 2. Threat Model

The adversary for hidden service attacks is typically a
high-capability actor: a nation-state, a law enforcement agency with
legal authority, or a well-resourced research group. The adversary has:

- **Time** - the attacks take weeks to months.
- **Infrastructure** - the ability to run many Tor relays, or to
  observe traffic at many points.
- **Legal authority** - the ability to subpoena hosting providers and
  ISPs.
- **Technical skill** - the ability to perform traffic correlation and
  timing analysis.

The threat model for hidden service defense is therefore: assume the
adversary can run relays, observe traffic, and serve legal process.
Design so that no single observation is enough.

## 3. How It Works (technical)

**Guard discovery.** A Tor client (including a hidden service) uses a
small set of entry guards. If the adversary can identify the guards,
they can observe the traffic between the client and the guard, which is
the first step toward traffic correlation. The classic attack is to
force the client to rotate guards repeatedly (by attacking the guards
or by making the client restart) until the adversary controls the new
guard. With a controlled guard, the adversary can observe the client's
traffic pattern and correlate it with the server's traffic.

**Rendezvous attacks.** A hidden service connection is built through a
rendezvous point (RP). The client picks the RP, the service connects to
it, and the two communicate through it. If the adversary can identify
the RP and observe the traffic between the service and the RP, they can
correlate the service's traffic with the client's traffic. The classic
attack is to force the service to use a rendezvous point that the
adversary controls or observes.

**Relay-level attacks.** The adversary runs many Tor relays, hoping
that the client or service will choose them for a circuit. With enough
relays, the adversary can observe both ends of a circuit (entry and
exit, or entry and rendezvous). This is the "Sybil" attack against Tor.
The Tor network mitigates this with guard pinning and relay diversity
requirements, but a sufficiently large adversary can still run enough
relays to be statistically likely to be chosen.

**Introduction point attacks.** The service publishes introduction
points (IPs) in its descriptor. If the adversary can enumerate the IPs
(e.g. by running a relay that the service chooses as an IP), they can
observe connections to the IPs and correlate them with the service.

**Descriptor correlation.** The service descriptor is published to a
distributed hash table (HSDir). If the adversary can observe the
descriptor and correlate it with a specific server, they can link the
onion address to the server's IP.

## 4. Practical Framework

A framework for hidden service defense, in six steps:

1. **Assume guard discovery.** Design the service so that even if the
   adversary identifies the guard, they cannot correlate the traffic
   with the server. This typically means using a high-latency
   communication pattern (no real-time interaction) or accepting the
   risk.

2. **Assume rendezvous attacks.** Design the service so that even if
   the adversary identifies the rendezvous point, they cannot correlate
   the traffic. This typically means not using the service for
   latency-sensitive operations.

3. **Assume relay-level attacks.** Design the service so that the
   adversary needs to control more than one relay in the circuit to
   succeed. This is inherent in Tor's design; the defense is to avoid
   attracting a high-capability adversary.

4. **Minimize the descriptor.** The descriptor is public. Do not put
   information in it that can be correlated with a specific server.

5. **Separate the service from the operator.** The service process
   should run on infrastructure that is not linkable to the operator's
   identity, location, or other activities.

6. **Test the assumptions.** Periodically re-evaluate whether the
   adversary could identify the guard, the rendezvous point, or the
   relays. If any assumption fails, the service is compromised.

The hardest part is accepting that a high-capability adversary can
almost always defeat a consumer-grade hidden service. The defense is
proportional to the adversary, not absolute.

## 5. Real-World Examples

**Freedom Hosting (2013).** The hosting provider for many Tor hidden
services was compromised through a Firefox exploit (CVE-2013-1690)
delivered via a hidden service. The FBI used the exploit to identify
users of the services. This was not a Tor break; it was an endpoint
compromise.

**Silk Road (2013).** The Silk Road server was located through a
combination of operational mistakes and traffic analysis. The Tor
network itself was not broken; the server's IP was found through
correlation and legal process.

**Playpen (2015).** The FBI seized the Playpen hidden service and ran
it for two weeks, using a network investigative technique (NIT) to
identify visitors. The Tor network was not broken; the clients'
browsers were compromised.

**AlphaBay (2017).** The AlphaBay server was located through a
combination of operational mistakes (a personal email in the welcome
message) and legal process. Tor itself held.

**Hans a/Freedom Hosting (2014).** The operator of Freedom Hosting was
arrested in Ireland after the US requested extradition. The arrest was
based on evidence from the 2013 compromise, not a new Tor break.

**Tor relay attacks (2014-2020).** Researchers have demonstrated
relay-level attacks against Tor that can de-anonymize hidden services
under specific conditions (e.g. the "Sniper Attack" against the
introduction point, the "CellFlood" attack). These are research
demonstrations, not mass-deployment attacks, but they show that the
attack class is real.

## 6. Common Mistakes

- **Assuming Tor is enough.** Tor protects the network layer. It does
  not protect the endpoint, the operator, or the operational mistakes.
  Most real-world hidden service takedowns were endpoint or operational
  compromises, not Tor breaks.
- **Using the service for real-time interaction.** Real-time interaction
  creates timing patterns that are easy to correlate. The defense is to
  avoid it, or to accept the risk.
- **Reusing the same guard across services.** If two services use the
  same guard, the adversary who identifies the guard can link the
  services. The defense is to use separate Tor instances.
- **Publishing descriptors with too much information.** The descriptor
  is public. Anything in it can be correlated. The defense is to keep
  it minimal.
- **Running the service on infrastructure linked to the operator.**
  Hosting provider, domain registrar, payment method, and IP history
  are all linkable. The defense is compartmentalization (see 07 OpSec
  and Threat Models).
- **Underestimating the adversary's patience.** Hidden service attacks
  take weeks to months. A single slip in month three can compromise the
  entire operation.
- **Believing that "they cannot break Tor" is protection.** The
  adversary does not need to break Tor. They need one operational
  mistake, one endpoint compromise, or one legal subpoena.

## 7. Attacks and Detection

The attack families are described in section 3. Detection from the
service side is limited; the defense is preventive:

- **Guard discovery.** Monitor for repeated guard rotation. If the
  guard changes more often than expected, the adversary may be forcing
  rotation. The defense is to use a stable guard and monitor for
  changes.
- **Rendezvous attacks.** Monitor for rendezvous points that the
  service did not choose. The defense is to verify the rendezvous point
  and to use a stable set of points.
- **Relay-level attacks.** Monitor for relays that appear in your
  circuits more often than expected. The defense is to use the Tor
  network's relay diversity features and to avoid attracting a
  high-capability adversary.
- **Introduction point attacks.** Monitor for introduction points that
  change unexpectedly. The defense is to use a stable set of points.
- **Descriptor correlation.** Monitor the descriptor for information
  that could be correlated. The defense is to keep the descriptor
  minimal.

## 8. Risk Context

Hidden service defense has a cost. The defensive measures (separate
Tor instances, high-latency communication, minimal descriptors) reduce
usability. The cost must be proportional to the adversary. For a
low-capability adversary (scraper, curious user), Tor alone is enough.
For a medium-capability adversary (platform, civil litigant), stronger
operational discipline is required. For a high-capability adversary
(nation-state, law enforcement with legal authority), the cost is
high, and perfect defense may be unachievable through consumer tools
alone.

The risk of under-defending is compromise. The risk of over-defending
is operational paralysis. The correct balance is the one where the
defenses are proportional to the adversary.

## 9. Verification

Hidden service defense is verified by adversarial review:

- **Guard test.** Simulate a guard-discovery attack. If the adversary
  can identify your guard and correlate traffic, the defense is
  insufficient.
- **Rendezvous test.** Simulate a rendezvous attack. If the adversary
  can identify the rendezvous point and correlate traffic, the defense
  is insufficient.
- **Relay test.** Simulate a relay-level attack. If the adversary can
  control enough relays to observe your circuit, the defense is
  insufficient.
- **Descriptor test.** Review your descriptor for information that
  could be correlated. If anything is correlatable, remove it.
- **Operational test.** Review your operational discipline
  (hosting, payment, communication, compartmentalization). If any
  operational detail links the service to the operator, the defense is
  insufficient.

If any test succeeds, the defense is incomplete. Fix the exposed
feature, then re-test.

## 10. Legal and Ethical Notes

This file describes attack techniques for educational purposes. The
techniques are documented in the public literature; the analysis is
commentary. No confidential or non-public information is used.

The material is defensive: it helps operators understand what they are
defending against. It does not provide operational instructions for
attacking specific services.

The legal risk is in the actions an operator takes, not in studying the
techniques. Operators in jurisdictions with restrictive speech or
privacy laws should consult a lawyer before documenting a hidden
service analysis that could be seized. The analysis is a document; the
document can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- The Tor Project, "Tor: Overview" and "Tor: Hidden Service Protocol"
  documentation.
- Roger Dingledine, Nick Mathewson, Paul Syverson, "Tor: The
  Second-Generation Onion Router" (USENIX Security, 2004).
- "Sniper Attack: Anonymously Deanonymizing and Disabling the Tor
  Network" (NDSS, 2014).
- "CellFlood: Attacking Tor Onion Routers on the Cheap" (2013).
- "Trawling for Tor Hidden Services: Detection, Measurement,
  Deanonymization" (IEEE S&P, 2013).
- United States v. Ulbricht, trial record (2015).
- FBI, "Playpen Investigation" (2015).
- Europol, "AlphaBay Takedown" (2017).
- The Tor Project blog, "Thoughts on the Freedom Hosting Exploit"
  (2013).
