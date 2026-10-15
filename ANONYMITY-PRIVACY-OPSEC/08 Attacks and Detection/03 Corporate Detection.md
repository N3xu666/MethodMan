# Corporate Detection

Corporate detection is the set of techniques that platforms, employers,
and service providers use to identify anonymized activity on their
systems. It is the adversary that most operators actually face: not a
nation-state, but the company whose terms of service they are using.
The detection is often automated, always logged, and increasingly
effective.

This file is conceptual. It covers how the detection works and how to
reason about it, not what tools to install.

## 1. Overview

A platform's goal is not to de-anonymize users in the abstract. It is
to enforce its terms of service, prevent abuse, protect its brand, and
comply with legal obligations. The detection techniques are a means to
those ends, and they are optimized for scale: a platform with millions
of users cannot investigate each one manually.

The detection is therefore statistical and automated. It looks for
patterns that deviate from the norm: new accounts with unusual
behavior, accounts that share technical features, activity that matches
known abuse patterns. The output is a risk score, and the score drives
an action (warning, rate limit, ban, report to law enforcement).

For an operator, the relevant question is: what does my activity look
like to the platform's detection system, and how do I keep the risk
score below the action threshold?

## 2. Threat Model

The adversary for corporate detection is the platform itself. The
platform has:

- **Full visibility** into its own systems: account metadata, login
  history, device identifiers, behavioral logs, content history.
- **Legal authority** to act on its own terms of service: warning,
  rate-limiting, banning, and (in some jurisdictions) reporting to law
  enforcement.
- **Auxiliary data**: public records, social media, data brokers, and
  (for some platforms) cross-platform data-sharing agreements.
- **Automated systems**: machine learning models that score accounts
  for abuse risk at scale.

The platform does not need to prove anything in a court. It needs
enough confidence to act. The threat model is therefore: assume the
platform logs everything, scores everything, and acts on scores, and
design so that your activity does not look like abuse.

## 3. How It Works (technical)

The detection techniques fall into five families:

**1. Account correlation.** The platform links accounts that share
technical features: the same device fingerprint, the same browser
fingerprint, the same IP, the same email pattern, the same recovery
phone. The linking does not require proof that the same person owns
the accounts; it only requires enough shared features to raise the
score.

**2. Behavioral analytics.** The platform models normal behavior for
an account (login times, activity patterns, content style) and flags
deviations. A new account that behaves like an established account, or
an account that changes behavior abruptly, is flagged.

**3. Content analysis.** The platform analyzes content for patterns:
known abuse keywords, stylistic features, links to known-bad
infrastructure, images that match known content. The analysis is
automated and increasingly uses machine learning.

**4. Network analysis.** The platform analyzes the network of
interactions: who talks to whom, who shares content with whom, who
follows whom. Accounts that cluster together are scored together; if
one is flagged, the cluster is flagged.

**5. Velocity and anomaly detection.** The platform flags accounts that
act too fast (mass registration, mass posting, mass messaging) or in
patterns that match known abuse. The detection is based on rate, not
content.

These families combine. A real detection system uses a weighted score
across all five, and the action threshold is set by the platform's
risk tolerance.

## 4. Practical Framework

A framework for reasoning about corporate detection risk, in six steps:

1. **Enumerate the platform's data.** Read the terms of service and
   privacy policy. What does the platform log? What does it share with
   third parties? What does it retain? The answers determine the
   detection surface.

2. **Model the platform's adversary.** The platform's goal is not to
   catch you specifically; it is to catch abuse at scale. Your risk is
   proportional to how much your activity looks like abuse, not to how
   interesting you are.

3. **Minimize shared features.** Use separate devices, browsers,
   email addresses, phone numbers, and payment methods for each
   account. Do not let two accounts share any technical feature.

4. **Match normal behavior.** Do not behave like an outlier. Log in at
   normal times, use the platform normally, and do not act faster than
   a human would.

5. **Avoid known-bad patterns.** Do not use the platform for the
   activities it explicitly flags: mass messaging, mass registration,
   coordinated posting, links to known-bad infrastructure.

6. **Assume logging.** Assume the platform logs everything you do, and
   that the logs are retained and shareable. Design so that even with
   the logs, no two accounts can be linked.

The hardest part is not the technical controls. It is the discipline to
behave normally under an account that exists for a non-normal purpose.

## 5. Real-World Examples

**Facebook's "real name" policy enforcement.** Facebook has used a
combination of account correlation, behavioral analysis, and user
reports to identify accounts that violate its real-name policy. The
detection is not about proving the user's identity; it is about
confidence that the account is not a real name.

**Twitter/X's coordinated inauthentic behavior (CIB) takedowns.**
Twitter has published regular reports on CIB takedowns, often based on
network analysis and behavioral patterns. The takedowns are of clusters
of accounts, not individuals.

**Google's account correlation for abuse.** Google links accounts
across its services (Gmail, YouTube, Drive, etc.) and uses the linking
to score abuse risk. An account that is flagged in one service affects
the risk score in the others.

**Reddit's shadowban and ban evasion detection.** Reddit uses
behavioral and network analysis to detect ban evasion. The detection
is not perfect, but it is automated and continuous.

**Cloud provider abuse detection (AWS, Azure, GCP).** Cloud providers
detect abuse (crypto mining, phishing, malware hosting) through a
combination of network analysis, content analysis, and behavioral
analytics. Accounts flagged for abuse are suspended, often without
appeal.

**Email provider spam detection.** Email providers (Gmail, Outlook,
etc.) detect spam through content analysis, sender reputation, and
network analysis. Anonymized email services are often blocked by
default because their traffic looks like spam.

**Data broker aggregation.** Data brokers (Acxiom, Experian, etc.)
aggregate data from multiple sources and sell it to platforms,
employers, and law enforcement. The aggregation itself is a detection
technique: it links accounts that the platform could not link on its
own.

## 6. Common Mistakes

- **Reading the terms of service as a contract.** The terms of service
  are the platform's rules, not a negotiated agreement. The platform
  can change them at any time, and enforcement is at the platform's
  discretion.
- **Assuming the platform does not log.** Most platforms log
  extensively, retain logs for months to years, and share logs with
  third parties. The assumption that "they don't really look" is
  usually wrong.
- **Sharing any technical feature between accounts.** A shared device,
  browser, IP, email pattern, or recovery phone is enough to link two
  accounts. The platform does not need more.
- **Behaving like an outlier.** A new account that behaves like an
  established one, or an account that changes behavior abruptly, is
  flagged. The defense is to match normal behavior.
- **Acting too fast.** Mass registration, mass posting, and mass
  messaging are flagged by velocity detection. The defense is to act
  at human speed.
- **Using the same payment method across accounts.** Payment methods
  (credit cards, PayPal, crypto exchanges) are linkable. The defense is
  separate payment methods for each account.
- **Underestimating data brokers.** The platform may not link your
  accounts, but a data broker might. The defense is to minimize the
  data that the broker can aggregate.
- **Assuming that "they cannot prove it" is protection.** The platform
  does not need to prove anything. It needs a risk score above the
  action threshold.

## 7. Attacks and Detection

The attack families are described in section 3. Detection from the
user side is limited; the defense is preventive:

- **Account correlation.** Test whether your accounts share any
  technical feature. The defense is to use separate devices, browsers,
  emails, and payment methods.
- **Behavioral analytics.** Compare your activity to the platform's
  normal patterns. The defense is to match normal behavior.
- **Content analysis.** Review your content for patterns that the
  platform flags. The defense is to avoid known-bad patterns.
- **Network analysis.** Review your interactions for clusters that the
  platform might flag. The defense is to avoid coordinated behavior.
- **Velocity detection.** Review your activity rate. The defense is to
  act at human speed.

## 8. Risk Context

Corporate detection resistance has a cost: more accounts, more devices,
more discipline. The cost must be proportional to the adversary. For a
low-capability platform (small forum, niche service), basic hygiene is
enough. For a medium-capability platform (large social network, email
provider), stronger separation is required. For a high-capability
platform (Google, Meta, AWS), the cost is high, and perfect resistance
may be unachievable through consumer tools alone.

The risk of under-resisting is account loss and potential reporting to
law enforcement. The risk of over-resisting is operational paralysis:
so many accounts and devices that the operator cannot manage them. The
correct balance is the one where the controls are proportional to the
platform's detection capability.

## 9. Verification

Corporate detection resistance is verified by adversarial review:

- **Correlation test.** For each pair of accounts, check whether any
  technical feature is shared. If shared, the resistance is
  insufficient.
- **Behavioral test.** Compare your activity patterns to the platform's
  normal patterns. If your activity is an outlier, the resistance is
  insufficient.
- **Content test.** Review your content for patterns the platform
  flags. If flagged patterns are present, the resistance is
  insufficient.
- **Network test.** Review your interactions for clusters. If your
  accounts cluster together, the resistance is insufficient.
- **Velocity test.** Review your activity rate. If it is above human
  speed, the resistance is insufficient.
- **Broker test.** Search for your accounts in data broker databases.
  If the broker links them, the resistance is insufficient.

If any test succeeds, the resistance is incomplete. Fix the exposed
feature, then re-test.

## 10. Legal and Ethical Notes

This file describes detection techniques for educational purposes. The
techniques are documented in the public literature and in the
platforms' own transparency reports; the analysis is commentary.

The material is defensive: it helps operators understand what the
platform sees. It does not provide operational instructions for
evading the platform's legitimate enforcement of its terms of service.

The legal risk is in the actions an operator takes, not in studying the
techniques. Operators in jurisdictions with restrictive speech or
privacy laws should consult a lawyer before documenting a detection
analysis that could be seized. The analysis is a document; the document
can be evidence.

> [!CAUTION]
> This material is for educational purposes and for authorized,
> lawful privacy protection only. It does not constitute legal advice.
> Laws differ by jurisdiction. You are responsible for understanding
> and following the laws that apply to you.

## 11. References

- Facebook, "Community Standards Enforcement Report" (regular).
- Twitter/X, "Coordinated Inauthentic Behavior" transparency reports.
- Google, "How Google Fights Spam" and "Account Security" docs.
- Reddit, "Content Policy" and "Ban Evasion" docs.
- AWS, "Acceptable Use Policy" and "Abuse Report" docs.
- Electronic Frontier Foundation, "Surveillance Self-Defense".
- Wolfie Christl and Sarah Spiekermann, "Networks of Control"
  (2016), on data brokers and platform analytics.
- Shoshana Zuboff, "The Age of Surveillance Capitalism" (2019).
- Bruce Schneier, "Data and Goliath" (2015).
- Privacy International, "Data Brokers" reports.
