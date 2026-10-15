# Bulletproof Hosting

## 1. Overview

Bulletproof hosting (BPH) is a class of hosting provider that deliberately
ignores abuse complaints, tolerates content and traffic that mainstream
providers prohibit, and resists takedown requests from law enforcement
and rights holders. The term does not describe a technical architecture -
it describes a business and legal posture.

BPH providers are used by botnet operators, malware distributors, phishing
kits, spam infrastructure, and - in authorized red-team and research
contexts - by operators who need an origin that will survive aggressive
takedown attempts during an engagement.

This file covers:

- What BPH is and how it differs from ordinary offshore hosting.
- The threat model: who is trying to take the infrastructure down and how.
- How BPH providers actually operate (ASNs, resellers, payment rails).
- Practical selection and setup for authorized work.
- Hardening, operational mistakes, and how defenders and researchers
  detect and attribute BPH infrastructure.
- Legal and ethical boundaries.

## 2. Threat Model

When you host infrastructure that someone else wants offline, the adversary
is not only a network attacker. The realistic threats are:

| Threat | Actor | Method |
|--------|-------|--------|
| Abuse complaint | Any downstream victim | Email to the provider's abuse desk, upstream transit, or registrar |
| Takedown notice | Rights holders, brand protection | DMCA, court order, letter to the datacenter |
| Law-enforcement seizure | National LE, international MLAT | Physical seizure of servers, domain seizure order |
| Upstream termination | Transit provider, IXP | Null-route, BGP withdrawal, peering cut |
| Payment freeze | Payment processor, bank | Chargeback, account freeze, de-anonymization via KYC |
| DDoS | Competitors, vigilantes | Volumetric or application-layer attack |
| Legal pressure on provider | Any of the above | Civil suit against the hosting company |

The BPH business model exists because a provider that absorbs these threats
can charge a premium. The provider is not "anonymous" in a technical sense -
it is jurisdictionally and contractually resistant.

**What BPH does NOT protect against:**

- Your own operational security failures (reusing identities, leaking a
  real IP in a payload, logging into a personal account from the server).
- A determined state-level adversary with physical access to the datacenter.
- Payment de-anonymization if you pay with a traceable method.
- Correlation of your infrastructure with your real identity through
  timing, content, or shared indicators.

## 3. How It Works (technical)

BPH providers operate on a spectrum. At one end are ordinary offshore
hosting companies in permissive jurisdictions that simply have a slow or
lax abuse process. At the other end are purpose-built networks with
front companies, reseller chains, and bulletproof transit.

**Common technical characteristics:**

- **Own ASN or a small number of leased ASNs.** The provider controls its
  own routing and can move IP space between upstreams quickly.
- **Multiple upstream transit providers.** If one upstream terminates for
  abuse, the provider re-routes through another within hours.
- **IP space that is not clean.** Ranges may be pre-listed on Spamhaus,
  AbuseIPDB, and similar blocklists. This is normal for BPH and is not
  necessarily a problem for the use case.
- **Datacenters in permissive jurisdictions.** Common regions include
  parts of Eastern Europe, Southeast Asia, Latin America, and specific
  Middle Eastern countries. The choice depends on the legal regime and
  the provider's relationships.
- **Reseller chains.** The company you pay is often a reseller of a
  reseller. This complicates attribution and also means the actual
  datacenter operator may never see an abuse complaint.
- **Crypto or semi-anonymous payment.** Bitcoin, Monero, Perfect Money,
  WebMoney, or regional payment systems. Card payments are usually
  accepted only from low-risk jurisdictions.

**What it is not:**

- It is not Tor. BPH is a normal hosting service with a specific
  business posture. The traffic is clearnet.
- It is not a CDN. There is no fronting or origin hiding by default.
- It is not automatically "anonymous" - the provider still knows who
  pays, even if it does not act on that knowledge.

## 4. Installation and Setup

This section describes the setup for an **authorized red-team engagement
or research project** where the rules of engagement explicitly permit
third-party hosting for infrastructure. Do not use this procedure for
any other purpose.

**Step 1. Define the requirement.**

Before choosing a provider, write down:

- Expected lifetime of the infrastructure (days, weeks, months).
- Jurisdiction constraints from the engagement (e.g. "no US-owned
  infrastructure" or "EU-only").
- Whether the origin IP must survive a public disclosure (e.g. a
  phishing landing page that will be reported).
- Payment constraints (the engagement's finance team may refuse
  crypto; a personal research project may require it).
- Whether the client needs to be able to take over the infrastructure
  at the end (some engagements require handover).

**Step 2. Shortlist providers.**

Sources:

- Public BPH tracking lists maintained by security researchers.
- Recommendations from other red-team operators (private channels).
- Providers that appear repeatedly in threat-intel reports as
  "hosting used by" a given actor - these have a known posture.

For each candidate, record: ASN, upstreams, datacenter location,
payment methods, published abuse policy, and known takedown history.

**Step 3. Provision a test instance first.**

Never move production engagement infrastructure to a new provider
without a test. Provision a small VPS, run a canary service (an HTTP
endpoint that logs requests), and observe:

- Uptime over 72 hours.
- Whether the IP is already listed on major blocklists.
- Whether the provider's abuse desk responds to a benign complaint.
- Whether the network path is stable.

**Step 4. Pay in a way that matches the engagement.**

For an authorized engagement, the client's finance team usually pays
through a normal channel and the BPH is only used for its posture, not
for anonymity. For a research project, use a payment method that does
not link to your real identity if that is part of the threat model.

**Step 5. Provision the actual infrastructure.**

Standard hardening applies (see section 5). BPH does not replace
basic system security.

## 5. Hardening and Configuration

BPH gives you jurisdictional resistance, not technical security. Assume
the provider, the datacenter, and any reseller in the chain can read
your disk and your traffic.

**Baseline hardening:**

- Full-disk encryption (LUKS on Linux, BitLocker on Windows). The
  provider cannot read what it cannot decrypt.
- SSH key-only authentication. No passwords. No root login.
- Firewall: allow only the ports the service needs. Default-deny.
- No personal accounts, no personal SSH keys, no browser logins to
  personal services from the server.
- Separate identities for every piece of infrastructure. Do not reuse
  usernames, email addresses, or SSH keys across providers.
- Log to a remote location you control, not to the BPH server itself.
- Automatic security updates.

**Operational hardening:**

- Rotate the infrastructure on a schedule, not only after a complaint.
- Keep a second provider warm so you can move within hours.
- Monitor the origin IP from the outside (a third-party uptime check
  from a different network).
- Do not put all engagement infrastructure behind a single BPH.

**What BPH hardening does NOT cover:**

- A compromised operator workstation.
- Leaked credentials in a payload or a public repository.
- A client-side mistake (e.g. logging into the BPH control panel
  from a personal device without isolation).

## 6. Operational Usage

Day-to-day operation of BPH-hosted infrastructure for an authorized
engagement:

- **Separate the control plane from the data plane.** Manage the
  server through a jump host or a VPN, not directly from your
  workstation.
- **Treat the BPH as hostile.** Assume the provider can log, inspect,
  and modify anything on the box.
- **Keep an offline record.** Store engagement notes, credentials,
  and infrastructure state on your own systems, not on the BPH.
- **Have a migration plan.** Document the steps to move the service
  to the backup provider, including DNS changes and certificate
  re-issuance.
- **Monitor for abuse complaints.** If the client or a third party
  reports the infrastructure, know before the provider acts.

**Engagement-specific considerations:**

- If the rules of engagement require the client to own the
  infrastructure at the end, plan the handover from day one.
- If the engagement is time-boxed, schedule the teardown and the
  proof-of-destruction before the engagement starts.
- If the infrastructure is used for phishing simulation, the
  provider may receive complaints from the simulation targets.
  Brief the client's legal team in advance.

## 7. Common Mistakes

- **Confusing BPH with anonymity.** BPH is a legal posture, not an
  anonymity network. The provider still knows who pays.
- **Assuming the provider will not cooperate with law enforcement.**
  Some will, quietly, especially for serious crimes.
- **Reusing infrastructure across engagements.** Indicators persist.
- **Paying with a traceable method for a use case that requires
  anonymity.** The payment rail is often the weakest link.
- **Not testing the provider before relying on it.**
- **Putting all infrastructure behind one BPH.** A single upstream
  termination takes everything offline.
- **Forgetting the domain layer.** A BPH-hosted IP is useless if the
  domain is seized or the registrar suspends it.
- **Leaking the origin IP through DNS, email headers, or a
  misconfigured CDN.** See the CDN Fronting file in this subcategory.
- **Ignoring the client's legal constraints.** Some clients forbid
  certain jurisdictions entirely.

## 8. Attacks Against It

BPH infrastructure is attacked by:

- **Takedown requests.** Rights holders, brand protection firms, and
  law enforcement send notices to the provider, the upstream transit,
  the datacenter, and the registrar simultaneously.
- **BGP hijacks.** A state actor or a competing network can announce
  the provider's prefix and blackhole traffic.
- **Upstream pressure.** A large transit provider can terminate the
  BPH's connectivity with little notice.
- **Payment de-anonymization.** Chain analysis, KYC leaks, or a
  compromised payment processor.
- **Insider access.** A BPH employee with access to the hypervisor
  can read any unencrypted disk.
- **Legal seizure.** Physical seizure of servers in a datacenter that
  cooperates with law enforcement.
- **DDoS.** BPH providers are frequent DDoS targets themselves.
- **Reputation blocklisting.** The IP range is listed, which breaks
  email deliverability and some legitimate services.

## 9. Detection (Blue Team)

Defenders, researchers, and threat-intel analysts identify BPH
infrastructure through:

- **ASN and IP reputation.** AbuseIPDB, Spamhaus, GreyNoise, and
  commercial IP reputation feeds.
- **Passive DNS.** Historical domain-to-IP mappings showing rapid
  changes or shared infrastructure with known malicious actors.
- **Certificate transparency.** TLS certificates issued for domains
  on the BPH range.
- **Favicon and JARM hashes.** Fingerprints of the default control
  panels and services.
- **BGP and routing data.** Routeviews, RIPE RIS, and commercial BGP
  feeds show prefix announcements and upstream changes.
- **Payment and registration correlation.** Domain WHOIS history,
  registrar patterns, and payment-processor leaks.
- **Honeypot interaction.** Logging connections from the BPH range
  to decoy services.
- **Threat-intel reports.** BPH providers are named in reports from
  vendors tracking botnets, phishing, and ransomware.

For a defender, the practical output is a blocklist entry and, if the
engagement is authorized, a notification to the provider's upstream.

## 10. Case Studies

**Case 1 - Botnet C2 on a BPH.** A well-known banking trojan used a
BPH provider in Eastern Europe for its command-and-control servers.
Takedown attempts over 18 months failed because the provider moved
the C2 between three upstreams and re-issued the domains through a
registrar in a different jurisdiction. The botnet was eventually
disrupted through sinkholing, not through hosting takedown.

**Case 2 - Phishing infrastructure.** A phishing campaign used a BPH
provider in Southeast Asia. The brand-protection team sent DMCA
notices and abuse complaints to the provider, the upstream, and the
registrar. The provider ignored the notices; the upstream terminated
the route after 72 hours; the campaign moved to a second BPH within
a day. The campaign was disrupted only when the payment processor
froze the account.

**Case 3 - Authorized red-team engagement.** A red team used a BPH
provider for a long-running C2 during a client engagement. The
client's rules of engagement explicitly permitted third-party
hosting. The team kept a warm backup at a second provider and a
migration runbook. When the primary provider's upstream terminated
the route mid-engagement, the team moved the C2 in four hours and
the engagement continued without loss of access.

**Case 4 - Research honeypot.** A research group hosted a honeypot
on a BPH provider to observe scanning and exploitation attempts
against a deliberately vulnerable service. The provider's posture
meant the honeypot was not taken down despite complaints from
third parties who saw scanning traffic. The research output was
published with the provider's IP range redacted.

## 11. Legal and Ethical Notes

Bulletproof hosting sits at the intersection of several legal regimes:

- **Jurisdiction.** The legality of the content and traffic depends
  on the laws of the datacenter's country, the provider's country
  of incorporation, and the operator's country of residence. These
  can conflict.
- **Authorization.** For red-team and research use, the engagement
  contract or research ethics approval must explicitly cover
  third-party hosting. Do not assume that "the client asked for a
  red team" includes permission to host C2 on a BPH provider.
- **Export controls.** Some jurisdictions restrict the export of
  certain security tooling and infrastructure services. Check
  before provisioning.
- **Payment regulations.** Anti-money-laundering rules apply to
  payment processors. Using a BPH provider for authorized work
  through a corporate payment rail is normally fine; using it for
  other purposes may create legal exposure for the operator.
- **Ethical boundary.** BPH providers are used by criminal actors.
  Using the same providers for authorized work is not itself
  unethical, but it can create the appearance of association. Be
  transparent with the client and document the choice.

**Do not use BPH for:**

- Hosting content that is illegal in your jurisdiction or the
  provider's.
- Any activity outside an authorized engagement or approved
  research project.
- Storing data you are not authorized to store.
- Anything that would expose the client to legal risk they did
  not agree to.

## 12. Production Notes

- **Cost.** BPH is more expensive than mainstream hosting. Budget
  for a premium of 2x to 10x, plus the cost of a warm backup.
- **SLA.** Do not expect a meaningful SLA. Uptime is best-effort.
- **Support.** Support is often minimal and slow. Plan for
  self-sufficiency.
- **Migration.** Keep a tested migration runbook. The provider's
  posture may change without notice.
- **Teardown.** At the end of an engagement, destroy the
  infrastructure and document the destruction. Do not leave
  abandoned hosts on a BPH provider.
- **Record-keeping.** Keep an offline log of every action taken on
  the infrastructure, for the client's report and for your own
  legal protection.

## 13. References

- ENISA threat landscape reports on hosting infrastructure.
- Spamhaus and AbuseIPDB for IP reputation data.
- Routeviews and RIPE RIS for BGP data.
- Academic papers on bulletproof hosting economics and takedown
  resistance.
- Vendor threat-intel reports naming BPH providers (e.g. reports
  on botnet C2 hosting).
- The client's rules of engagement document (for authorized
  engagements).
