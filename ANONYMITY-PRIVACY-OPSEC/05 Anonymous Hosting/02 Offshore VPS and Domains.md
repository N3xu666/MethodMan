# Offshore VPS and Domains

## 1. Overview

An offshore VPS is a virtual private server hosted in a jurisdiction
that is different from the operator's own, usually chosen because the
hosting country has weaker cooperation with the operator's home country,
lax data-retention rules, or privacy-friendly corporate law. An offshore
domain is a domain registered through a registrar and a TLD that do not
require real-identity disclosure and do not act quickly on foreign
takedown requests.

This file covers the practical selection and setup of offshore VPS
providers and domain registration for authorized red-team engagements
and privacy-focused research projects. It is the second file in the
**Anonymous Hosting** subcategory, after Bulletproof Hosting. It focuses
on ordinary offshore hosting - not the purpose-built bulletproof
providers described in the first file.

The two layers (VPS and domain) are independent. You can host on an
offshore VPS with a domain registered anywhere, and vice versa. The
weakest layer determines the overall resistance to takedown and
attribution.

## 2. Threat Model

The threat model for offshore VPS and domains is similar to bulletproof
hosting, but the actors and methods differ slightly:

| Threat | Actor | Method |
|--------|-------|--------|
| Takedown request | Rights holder, brand protection | DMCA notice, abuse email to the provider or registrar |
| Registrar suspension | Registrar, registry | Suspension of the domain for abuse or non-payment |
| WHOIS disclosure | Registrar, registry | Forced disclosure of registrant data in response to a legal order |
| Jurisdictional cooperation | Foreign government | MLAT request, diplomatic pressure on the host country |
| Payment trace | Payment processor, bank | KYC records, transaction correlation |
| DNS hijack | State actor, attacker | Registrar account takeover, DNS provider compromise |
| Server seizure | Local law enforcement | Physical raid on the datacenter |
| Data retention | Provider | Logs kept for longer than the operator expects |
| Cross-border data flow | Provider's parent company | Data replicated to a jurisdiction with stronger disclosure laws |

**What offshore hosting does NOT protect against:**

- A provider whose parent company is in a cooperating jurisdiction.
- A TLD whose registry is subject to the operator's home-country law
  (e.g. a ccTLD that participates in international cooperation).
- Payment de-anonymization (credit card, bank transfer, PayPal).
- Your own operational-security mistakes.
- A registrar that suspends on a single abuse complaint without
  evidence.

## 3. How It Works (technical)

**VPS layer:**

- A VPS is a virtual machine on a shared hypervisor. The provider
  controls the hypervisor and can read anything that is not encrypted.
- Offshore VPS providers differ in: jurisdiction, upstream transit,
  abuse policy, payment methods, and whether they allow outbound
  traffic patterns that mainstream providers consider abusive.
- Popular jurisdictions include Iceland, Switzerland, Romania,
  Moldova, Panama, Seychelles, and parts of Southeast Asia. Each has
  a different legal regime and a different history of cooperation
  with foreign law enforcement.
- The provider's own jurisdiction matters more than the datacenter's
  physical location for legal process. A provider incorporated in
  Panama with a datacenter in Germany is still a Panamanian company.

**Domain layer:**

- A domain has three independent components: the registrar (who you
  pay), the registry (who operates the TLD), and the DNS provider
  (who answers queries).
- Privacy protection at the registrar hides WHOIS data from public
  view, but the registrar still has the real data and can be forced
  to disclose it.
- Some TLDs have strict identity requirements (most ccTLDs, some
  gTLDs). Others allow anonymous registration (.com via a privacy
  proxy, some new gTLDs).
- DNS resolution can be hosted separately from the registrar. This
  adds a layer but also adds a provider that can be pressured.
- DNSSEC, CAA records, and registry lock are operational controls
  that reduce the risk of hijack but do not affect legal process.

**The relationship between the layers:**

- If the domain is seized, the VPS IP is still reachable directly.
- If the VPS is seized, the domain can be pointed elsewhere.
- If the DNS provider is compromised, both are effectively lost.
- The strongest setup separates all three: registrar in jurisdiction A,
  DNS in jurisdiction B, VPS in jurisdiction C, with different
  payment methods and different identities.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or approved
research project**. The procedure assumes you have a documented
requirement for offshore infrastructure.

**Step 1. Choose the jurisdiction.**

Before choosing a provider, define the constraints:

- Which jurisdictions are acceptable to the client or the research
  ethics board?
- Which jurisdictions are known to cooperate with your home country?
- Which jurisdictions have data-retention laws that match your
  expected infrastructure lifetime?
- Which jurisdictions have a stable legal environment (rule of law,
  no sudden expropriation)?

**Step 2. Choose the VPS provider.**

Sources for candidates:

- Privacy-focused hosting directories and review sites.
- Recommendations from other operators in the same field.
- Providers that appear in academic papers on offshore hosting.

For each candidate, record: jurisdiction of incorporation, upstream
transit, abuse policy, payment methods, whether the provider allows
outbound SMTP (many block it by default), and whether the provider
supports full-disk encryption at the hypervisor level (most do not -
you must do it inside the VM).

**Step 3. Choose the domain registrar and TLD.**

- Registrar: pick one in a jurisdiction that matches your threat
  model. Some registrars are known for resisting broad disclosure
  requests; others comply quickly.
- TLD: prefer a gTLD or a ccTLD that does not require real-identity
  disclosure. Avoid ccTLDs whose registry is subject to your home
  country's law.
- Privacy protection: enable it if the registrar offers it. Note
  that it hides WHOIS, not the registrar's own records.

**Step 4. Choose the DNS provider.**

- Separate the DNS provider from the registrar when possible.
- Prefer providers with a strong privacy policy and a track record
  of resisting disclosure requests.
- Enable DNSSEC and registry lock if the TLD supports them.

**Step 5. Pay in a way that matches the engagement.**

- For an authorized engagement, the client's finance team usually
  pays through a normal corporate channel.
- For a research project, use a payment method that does not link
  to your real identity if that is required by the threat model.
- Never mix payment methods across the layers (registrar, DNS, VPS)
  if you want to avoid correlation.

**Step 6. Provision and harden.**

- Follow the hardening baseline in section 5.
- Set up monitoring from a network outside the provider.
- Document the setup in your offline engagement notes.

## 5. Hardening and Configuration

Offshore hosting gives you jurisdictional distance, not technical
security. Assume every provider in the chain can read your metadata
and, unless you encrypt, your data.

**VPS hardening:**

- Full-disk encryption inside the VM (LUKS on Linux, BitLocker on
  Windows). The provider's hypervisor cannot read what it cannot
  decrypt. Note: the provider can still see the VM is running, its
  network traffic, and its resource usage.
- SSH key-only authentication. No passwords. No root login. Use a
  non-default port only if it helps against opportunistic scanning
  (it does not help against targeted attacks).
- Firewall: default-deny inbound. Allow only the ports the service
  needs.
- Automatic security updates.
- Log to a remote location you control. Local logs are readable by
  the provider.
- No personal accounts, no browser logins, no SSH keys reused from
  other infrastructure.

**Domain hardening:**

- Registrar account: strong password, hardware-token 2FA, no
  password recovery via email. Use a dedicated email address that
  is not your personal one.
- Registry lock: enable it if the TLD supports it. It prevents
  unauthorized transfers and changes.
- DNSSEC: enable it. It prevents DNS spoofing and cache poisoning.
- CAA records: restrict which CAs can issue certificates for the
  domain.
- Transfer lock: enable it. It prevents unauthorized transfers to
  another registrar.
- Monitoring: set up alerts for any change to the domain's DNS,
  registrar records, or WHOIS data.

**DNS hardening:**

- Use a provider with a strong privacy policy.
- Enable DNSSEC at the DNS provider as well as at the registry.
- Use a short TTL only if you need fast changes; a longer TTL
  reduces the window for cache poisoning.
- Do not use the DNS provider's web interface from an untrusted
  network.

**Identity separation:**

- Use a different email address, username, and payment method for
  each provider.
- Do not reuse SSH keys, passwords, or recovery phrases.
- Document the identities in your offline notes, not in a cloud
  password manager that is itself a single point of failure.

## 6. Operational Usage

Day-to-day operation of offshore VPS and domains for an authorized
engagement:

- **Separate the control plane from the data plane.** Manage the VPS
  and the domain through a jump host or a VPN, not directly from
  your workstation.
- **Treat every provider as potentially hostile.** Assume they log,
  inspect, and may disclose.
- **Keep an offline record.** Store credentials, DNS records, and
  engagement notes on your own systems.
- **Monitor externally.** Use a third-party uptime and DNS monitoring
  service from a different network to detect changes.
- **Have a migration plan.** Document the steps to move the VPS to a
  backup provider, the domain to a backup registrar, and the DNS to
  a backup provider.
- **Rotate on a schedule.** Do not wait for an incident to move.

**Engagement-specific considerations:**

- If the client requires the domain to be transferred at the end of
  the engagement, plan the transfer process and the identity
  handover from day one.
- If the engagement is time-boxed, schedule the teardown of the VPS
  and the release of the domain before the engagement starts.
- If the engagement uses the domain for phishing simulation, brief
  the client's legal team and the registrar in advance.

## 7. Common Mistakes

- **Assuming offshore equals anonymous.** The provider still knows
  who pays, and a registrar still has the registrant data.
- **Choosing a provider whose parent company is in a cooperating
  jurisdiction.** The subsidiary is not independent of the parent.
- **Using the same identity across layers.** The same email address
  at the registrar, DNS, and VPS provider links the three.
- **Using a payment method that is traceable.** Credit card, bank
  transfer, and PayPal are all traceable.
- **Forgetting the DNS layer.** A strong registrar is useless if
  the DNS provider complies with disclosure requests.
- **Not testing the provider before relying on it.**
- **Not enabling registry lock, transfer lock, and DNSSEC.**
- **Using a free DNS provider with no privacy policy.**
- **Reusing infrastructure across engagements.** Indicators persist.
- **Leaving the domain registered after the engagement ends.**
  Abandoned domains are a common source of attribution.

## 8. Attacks Against It

Offshore VPS and domains are attacked by:

- **Takedown requests.** Rights holders, brand protection, and law
  enforcement send notices to the registrar, the registry, the DNS
  provider, and the VPS provider simultaneously.
- **Registrar account takeover.** Phishing, credential stuffing, or
  social engineering against the registrar's support team.
- **DNS hijack.** Compromise of the DNS provider or the registrar
  account, followed by changing the domain's nameservers.
- **BGP hijack.** A state actor or a competing network announces the
  VPS provider's prefix and blackholes traffic.
- **Server seizure.** Physical seizure in a datacenter that cooperates
  with law enforcement.
- **Payment de-anonymization.** Chain analysis, KYC leaks, or a
  compromised payment processor.
- **Data retention.** The provider keeps logs longer than expected
  and discloses them later.
- **Cross-border data flow.** The provider's parent company
  replicates data to a jurisdiction with stronger disclosure laws.
- **Certificate transparency correlation.** TLS certificates issued
  for the domain reveal its existence and can be correlated with
  other infrastructure.

## 9. Detection (Blue Team)

Defenders, researchers, and threat-intel analysts identify offshore
VPS and domain infrastructure through:

- **WHOIS history.** DomainTools, WhoisXML, and similar services
  show the history of registrant data, even when privacy protection
  is enabled at the time of observation.
- **Passive DNS.** Historical domain-to-IP mappings showing rapid
  changes or shared infrastructure with known malicious actors.
- **Certificate transparency.** Every publicly trusted TLS
  certificate is logged. CT logs are a primary source for finding
  domains that share infrastructure or certificate patterns.
- **ASN and IP reputation.** AbuseIPDB, Spamhaus, GreyNoise, and
  commercial feeds.
- **BGP and routing data.** Routeviews, RIPE RIS, and commercial
  BGP feeds show prefix announcements and upstream changes.
- **Payment and registration correlation.** Registrar patterns,
  shared privacy-proxy services, and payment-processor leaks.
- **Honeypot interaction.** Logging connections from the provider's
  IP range to decoy services.
- **Threat-intel reports.** Offshore providers are named in reports
  from vendors tracking botnets, phishing, and ransomware.

For a defender, the practical output is a blocklist entry and, if
the engagement is authorized, a notification to the provider's
upstream or the registrar's abuse desk.

## 10. Case Studies

**Case 1 - Ransomware affiliate infrastructure.** A ransomware
affiliate used an offshore VPS provider in Eastern Europe for
staging and a domain registered through a privacy-focused registrar
in a different jurisdiction. The domain was suspended after 11 days
in response to an abuse complaint; the affiliate had a backup
domain ready and switched DNS within hours. The VPS remained
reachable directly by IP throughout. The campaign was disrupted
when the affiliate's payment processor froze the account.

**Case 2 - Phishing domain takedown.** A phishing campaign used a
domain registered through a registrar in a permissive jurisdiction.
A brand-protection team sent a takedown notice to the registrar
with evidence of trademark infringement. The registrar suspended
the domain within 48 hours. The campaign moved to a second domain
at a different registrar within a day. The campaign was disrupted
only when the hosting provider terminated the VPS after receiving
a separate abuse complaint.

**Case 3 - Authorized red-team engagement.** A red team used an
offshore VPS provider in Iceland for a long-running C2 during a
client engagement. The domain was registered through a registrar
in Switzerland with privacy protection, and DNS was hosted by a
third provider in a different jurisdiction. The team enabled
registry lock, transfer lock, and DNSSEC. When the primary VPS
provider's upstream terminated the route mid-engagement, the team
moved the C2 to a backup VPS in a different jurisdiction in six
hours and updated the DNS records. The engagement continued without
loss of access.

**Case 4 - Research honeypot.** A research group hosted a honeypot
on an offshore VPS provider in Romania to observe scanning and
exploitation attempts against a deliberately vulnerable service.
The domain was registered through a privacy-focused registrar.
After three months, the provider disclosed access logs in response
to a legal order from a foreign jurisdiction, which the researchers
had not anticipated. The research output was published with the
provider's IP range and the domain redacted.

## 11. Legal and Ethical Notes

Offshore VPS and domain registration sit at the intersection of
several legal regimes:

- **Jurisdiction.** The legality of the content and traffic depends
  on the laws of the VPS provider's country, the registrar's
  country, the DNS provider's country, and the operator's country
  of residence. These can conflict.
- **Authorization.** For red-team and research use, the engagement
  contract or research ethics approval must explicitly cover
  offshore hosting and domain registration. Do not assume that
  "the client asked for a red team" includes permission to
  register domains in the operator's own name.
- **Export controls.** Some jurisdictions restrict the export of
  certain security tooling and infrastructure services. Check
  before provisioning.
- **Payment regulations.** Anti-money-laundering rules apply to
  payment processors. Using an offshore provider for authorized
  work through a corporate payment rail is normally fine; using
  it for other purposes may create legal exposure for the operator.
- **Domain law.** Some TLDs have specific rules about who can
  register a domain and for what purpose. Violating those rules
  can result in suspension regardless of the hosting provider's
  posture.
- **Ethical boundary.** Offshore hosting is used by criminal
  actors. Using the same providers for authorized work is not
  itself unethical, but it can create the appearance of
  association. Be transparent with the client and document the
  choice.

**Do not use offshore VPS or domains for:**

- Hosting content that is illegal in your jurisdiction or the
  provider's.
- Any activity outside an authorized engagement or approved
  research project.
- Storing data you are not authorized to store.
- Anything that would expose the client to legal risk they did
  not agree to.

## 12. Production Notes

- **Cost.** Offshore VPS is usually 1.5x to 4x the cost of
  mainstream hosting. Domain registration is similar to mainstream
  registrars, but privacy protection and registry lock may add
  cost.
- **SLA.** Do not expect a meaningful SLA. Uptime is best-effort.
- **Support.** Support is often minimal and slow. Plan for
  self-sufficiency.
- **Migration.** Keep a tested migration runbook for the VPS, the
  registrar, and the DNS provider. Any of the three may change
  posture without notice.
- **Teardown.** At the end of an engagement, destroy the VPS,
  release the domain, and document the destruction. Do not leave
  abandoned domains registered.
- **Record-keeping.** Keep an offline log of every action taken on
  the infrastructure, for the client's report and for your own
  legal protection.

## 13. References

- ENISA threat landscape reports on hosting infrastructure.
- Spamhaus and AbuseIPDB for IP reputation data.
- Routeviews and RIPE RIS for BGP data.
- DomainTools, WhoisXML, and similar services for WHOIS history.
- Certificate transparency logs (crt.sh and similar).
- Academic papers on offshore hosting economics and takedown
  resistance.
- Vendor threat-intel reports naming offshore hosting providers
  (e.g. reports on botnet C2 hosting).
- The client's rules of engagement document (for authorized
  engagements).
