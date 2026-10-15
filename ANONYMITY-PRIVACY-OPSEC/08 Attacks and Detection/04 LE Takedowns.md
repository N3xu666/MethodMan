# LE Takedowns

Law enforcement (LE) takedowns are the end state of many anonymity
investigations. They combine the technical attacks from the previous
three files (de-anonymization, hidden service attacks, corporate
detection) with legal process, infrastructure seizure, and human
intelligence. This file covers how LE takedowns work, what they exploit,
and what the defender can learn from them.

This file is conceptual. It covers the legal and operational reality of
LE investigations, not what tools to install.

## 1. Overview

An LE takedown is not a single event. It is the final step of an
investigation that may have started months or years earlier. The
investigation has three phases:

- **Identification** - figuring out that a crime is being committed and
  who might be involved. This uses the techniques from the previous
  three files.
- **Attribution** - building enough evidence to identify a specific
  person. This uses legal process (subpoenas, warrants, MLATs) and
  human intelligence (informants, undercover agents).
- **Action** - arrest, seizure, or disruption. This uses physical
  presence (arrest teams, search warrants) and infrastructure control
  (seizure of servers, domains, or funds).

The defender's goal is not to prevent identification (which is often
impossible against a high-capability adversary). It is to prevent
attribution - to ensure that even if the activity is identified, the
person behind it cannot be linked.

## 2. Threat Model

The adversary for LE takedowns is a state actor with:

- **Legal authority** - the ability to subpoena records, obtain
  warrants, and compel testimony.
- **International cooperation** - MLATs (Mutual Legal Assistance
  Treaties) allow cross-border evidence gathering, though the process
  is slow.
- **Technical capability** - the ability to run relays, exploit
  endpoints, and perform traffic analysis (often via contractors or
  partner agencies).
- **Human intelligence** - informants, undercover agents, and
  cooperating witnesses.
- **Patience** - investigations take years. The adversary is not in a
  hurry.

The threat model is therefore: assume the adversary has legal process,
technical capability, and human intelligence, and that they are
patient. Design so that even with all three, no single point of failure
compromises the whole operation.

## 3. How It Works (technical)

The technical and legal methods fall into six families:

**1. Legal process.** Subpoenas to ISPs, hosting providers, email
providers, and payment processors. The process is usually the first
step: it is cheap, quiet, and often yields the identifying data
without the target's knowledge.

**2. Infrastructure seizure.** Seizure of servers, domains, or funds.
The seizure can be physical (a raid on a data center) or legal (a
court order to a domain registrar). The seizure often yields logs,
keys, and user data.

**3. Endpoint exploitation.** Exploitation of the target's device,
often via a browser exploit or a malware implant. This is the
technique used in the Freedom Hosting and Playpen cases. The
exploitation bypasses the anonymity network entirely by compromising
the endpoint.

**4. Traffic analysis.** Correlation of traffic at two points, as
described in the De-anonymization file. This is used to identify the
server's IP or the client's location.

**5. Human intelligence.** Informants, undercover agents, and
cooperating witnesses. The human element is often the decisive one:
people make mistakes, and people talk.

**6. Operational mistakes.** The target's own errors: reusing a
password, logging in from a non-anonymized IP, using a personal email,
telling a friend. These are the most common cause of takedowns, and
the hardest to defend against.

## 4. Practical Framework

A framework for reasoning about LE takedown risk, in six steps:

1. **Assume legal process.** Assume the adversary can subpoena your
   ISP, hosting provider, email provider, and payment processor.
   Design so that no single subpoena yields identifying data.

2. **Assume infrastructure seizure.** Assume the adversary can seize
   your servers, domains, and funds. Design so that the seizure does
   not compromise the operator's identity.

3. **Assume endpoint exploitation.** Assume the adversary can exploit
   your device. Design so that the endpoint does not contain
   identifying data, or that the endpoint is compartmentalized from the
   operator's identity.

4. **Assume traffic analysis.** Assume the adversary can observe
   traffic at both ends. Design so that the timing and volume of the
   traffic does not correlate.

5. **Assume human intelligence.** Assume the adversary has an informant
   in your social circle. Design so that no single person knows enough
   to compromise the operation.

6. **Assume operational mistakes.** Assume you will make a mistake.
   Design so that no single mistake compromises the whole operation.
   This is the principle of defense in depth: multiple independent
   layers, so that one failure is survivable.

The hardest part is accepting that a high-capability adversary will
eventually identify the activity. The defense is not to prevent
identification; it is to prevent attribution.

## 5. Real-World Examples

**Silk Road (2013).** Ross Ulbricht was arrested after an investigation
that combined legal process (subpoenas to Google, which yielded the
personal email in an early forum post), traffic analysis, and
operational mistakes. The Tor network was not broken.

**Freedom Hosting (2013).** The hosting provider was compromised
through a Firefox exploit (CVE-2013-1690) delivered via a hidden
service. The FBI used the exploit to identify users. The Tor network
was not broken.

**Playpen (2015).** The FBI seized the Playpen hidden service and ran
it for two weeks, using a network investigative technique (NIT) to
identify visitors. The Tor network was not broken; the clients'
browsers were compromised.

**AlphaBay (2017).** The AlphaBay server was located through a
combination of operational mistakes (a personal email in the welcome
message) and legal process. The takedown involved cooperation between
US, Canadian, and Thai authorities.

**Hansa (2017).** The Hansa marketplace was seized by Dutch
authorities, who ran it for a month to collect evidence on users and
vendors. The operation was coordinated with the AlphaBay takedown.

**Welcome to Video (2018).** The operator was identified through a
combination of blockchain analysis (following Bitcoin transactions)
and legal process. The takedown involved cooperation between US, UK,
and South Korean authorities.

**Wall Street Market (2019).** The operators were identified through a
combination of operational mistakes, traffic analysis, and legal
process. The takedown involved cooperation between German, Dutch, and
US authorities.

**DarkMarket (2021).** The operator was identified through a
combination of operational mistakes and legal process. The takedown
was led by German authorities with Europol coordination.

**Hydra Market (2022).** The marketplace was seized by German
authorities, who also seized 543 Bitcoin. The takedown involved
long-term investigation and international cooperation.

The pattern is consistent: the anonymity network itself is rarely
broken. The failures are legal process, operational mistakes, endpoint
exploitation, and human intelligence.

## 6. Common Mistakes

- **Assuming the anonymity network is the only risk.** The network is
  one layer. Legal process, endpoint exploitation, and human
  intelligence are often the decisive ones.
- **Reusing a personal identifier.** An email, username, password, or
  payment method that appears in both the anonymous and identified
  contexts is a link. This is the most common failure.
- **Assuming legal process does not apply.** Subpoenas to ISPs,
  hosting providers, and payment processors are the first step in most
  investigations. The process is quiet and often yields the data
  without the target's knowledge.
- **Assuming the endpoint is safe.** Browser exploits, malware
  implants, and seized devices are common. The endpoint must be
  compartmentalized from the operator's identity.
- **Assuming the informant problem is solvable.** People talk.
  Informants, cooperating witnesses, and undercover agents are often
  the decisive factor. The defense is to minimize the number of people
  who know the operation.
- **Assuming patience is not part of the adversary's model.**
  Investigations take years. A single slip in year five can compromise
  an operation that was clean for four.
- **Assuming that "they cannot prove it" is protection.** LE does not
  need to prove it in court to act. They need enough evidence to
  charge, and often enough to seize assets and disrupt the operation
  before trial.
- **Underestimating international cooperation.** MLATs are slow but
  effective. Authorities in one country can request evidence from
  another, and the process is increasingly streamlined.

## 7. Attacks and Detection

The attack families are described in section 3. Detection from the
operator side is limited; the defense is preventive:

- **Legal process.** Monitor for subpoenas and court orders. The
  defense is to design so that no single subpoena yields identifying
  data.
- **Infrastructure seizure.** Monitor for domain transfers, server
  seizures, and fund freezes. The defense is to distribute
  infrastructure across jurisdictions and providers.
- **Endpoint exploitation.** Monitor for unusual device behavior,
  unexpected processes, and known browser exploits. The defense is a
  hardened, compartmentalized endpoint.
- **Traffic analysis.** Monitor for unusual network activity. The
  defense is to assume the adversary can observe at least one end, and
  to design so that the timing does not correlate.
- **Human intelligence.** Monitor your social circle for unusual
  interest or behavior. The defense is to minimize the number of people
  who know the operation.
- **Operational mistakes.** Review your own operational discipline.
  The defense is defense in depth and regular adversarial review.

## 8. Risk Context

LE takedown resistance has a cost: more compartmentalization, more
infrastructure, more discipline, more people to manage. The cost must
be proportional to the adversary. For a low-capability adversary
(local police, small agency), basic hygiene is enough. For a
medium-capability adversary (national agency, coordinated
international operation), stronger separation and infrastructure
distribution are required. For a high-capability adversary (nation-state
SIGINT, Five Eyes cooperation), the cost is high, and perfect
resistance may be unachievable through consumer tools alone.

The risk of under-resisting is arrest, asset seizure, and prosecution.
The risk of over-resisting is operational paralysis: so many controls
that the operation cannot function. The correct balance is the one
where the controls are proportional to the adversary.

## 9. Verification

LE takedown resistance is verified by adversarial review:

- **Legal test.** Assume the adversary can subpoena your ISP, hosting
  provider, email provider, and payment processor. What would each
  subpoena yield? If any subpoena yields identifying data, the
  resistance is insufficient.
- **Infrastructure test.** Assume the adversary can seize your
  servers, domains, and funds. What would each seizure yield? If any
  seizure compromises the operator, the resistance is insufficient.
- **Endpoint test.** Assume the adversary can exploit your device.
  What would the exploit yield? If the endpoint contains identifying
  data, the resistance is insufficient.
- **Traffic test.** Assume the adversary can observe traffic at both
  ends. Can the timing and volume be correlated? If yes, the
  resistance is insufficient.
- **Human test.** Assume the adversary has an informant in your social
  circle. What would the informant reveal? If the informant can
  compromise the operation, the resistance is insufficient.
- **Mistake test.** Assume you will make a mistake. What is the
  worst-case impact? If a single mistake compromises the operation, the
  resistance is insufficient.

If any test succeeds, the resistance is incomplete. Fix the exposed
feature, then re-test.

## 10. Legal and Ethical Notes

This file describes LE techniques for educational purposes. The
techniques are documented in the public record (indictments, court
records, press releases) and in the investigative journalism that
covered the cases. No confidential or non-public information is used.

The material is defensive: it helps operators understand what LE
looks for. It does not provide operational instructions for evading
lawful investigation, and it does not condone illegal activity.

The legal risk is in the actions an operator takes, not in studying the
cases. Operators in jurisdictions with restrictive speech or privacy
laws should consult a lawyer before documenting an analysis that could
be seized. The analysis is a document; the document can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- United States v. Ulbricht, trial record (2015).
- FBI, "Playpen Investigation" (2015).
- Europol, "AlphaBay and Hansa Takedown" (2017).
- US DOJ, "Welcome to Video Takedown" (2019).
- Europol, "Wall Street Market Takedown" (2019).
- Europol, "DarkMarket Takedown" (2021).
- German BKA, "Hydra Market Takedown" (2022).
- The Intercept, "The Silk Road Investigation" (2015).
- Wired, "The Untold Story of Silk Road" (2015).
- Joseph Cox, "The Dark Web Marketplace Takedowns" (various, 2017-2022).
- Sarah Jeong, "The Dark Web and the Law" (2017).
- Electronic Frontier Foundation, "Surveillance Self-Defense".
