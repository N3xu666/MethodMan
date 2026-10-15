# CDN Fronting

## 1. Overview

CDN fronting is a technique for hiding the origin IP address of a
service behind the infrastructure of a legitimate content delivery
network (CDN). The domain resolves to a CDN edge node, not to the
origin server. Clients connect to the CDN, and the CDN forwards
traffic to the origin. Anyone observing the client sees only the
CDN's IP, not the origin's.

Two related but distinct techniques are often grouped under this
term:

- **Origin IP hiding.** The origin server is placed behind a CDN
  (Cloudflare, Fastly, Akamai, AWS CloudFront, Azure Front Door,
  Google Cloud CDN). The DNS record for the service points to the
  CDN. The origin's real IP is not published.
- **Domain fronting.** A client connects to a CDN edge node using
  one domain in the TLS SNI field and a different domain in the
  HTTP Host header. The CDN routes the request based on the Host
  header, so the observable SNI (the "front") does not reveal the
  actual destination.

Both techniques are used by legitimate services (any site behind a
CDN), by privacy tools (Tor pluggable transports, some VPN
protocols), and by malicious actors (C2 channels, phishing pages).
This file covers the technique, its limitations, and how it is
detected.

This is the third file in the **Anonymous Hosting** subcategory,
after Bulletproof Hosting and Offshore VPS and Domains. CDN fronting
is often combined with those layers: the origin lives on a
bulletproof or offshore VPS, and the CDN hides it from casual
observation.

## 2. Threat Model

CDN fronting changes the threat model in two ways: it hides the
origin IP from direct observation, and it moves the visible
infrastructure into a large, reputable provider that is harder to
block without collateral damage.

| Threat | Effect of CDN fronting |
|--------|------------------------|
| Origin IP discovery via DNS | Mitigated - DNS points to the CDN, not the origin |
| Origin IP discovery via certificate transparency | Mitigated if the origin does not have a public certificate; not mitigated if it does |
| Origin IP discovery via email headers | Not mitigated - email sent from the origin reveals its IP unless sent through a relay |
| Origin IP discovery via misconfigured subdomain | Not mitigated - a subdomain that points directly to the origin reveals it |
| Direct DDoS on the origin | Mitigated if the origin only accepts traffic from the CDN |
| Takedown of the origin | Harder - the CDN provider must be convinced to act, and it may not see the malicious content |
| Takedown of the front domain | Depends on the CDN's abuse policy and the front domain's registrar |
| Traffic analysis | Partially mitigated - the observer sees the CDN, not the origin, but traffic volume and timing still leak information |
| Legal process against the CDN | The CDN provider may comply and reveal the origin's IP and account data |

**What CDN fronting does NOT protect against:**

- An origin IP leaked through a non-CDN subdomain, an email header,
  a historical DNS record, or a certificate.
- A CDN provider that complies with a legal order to disclose the
  origin's IP and the account holder's identity.
- Traffic analysis that correlates the CDN connection with the
  origin's activity.
- Your own operational-security mistakes (reusing identities,
  logging into a personal account from the origin).
- The CDN terminating the account for abuse.

## 3. How It Works (technical)

**Origin IP hiding (the common case):**

- The origin server has a public IP. The CDN provider is configured
  with the origin's IP as the "origin" or "upstream".
- The DNS record for the service points to the CDN's anycast IPs,
  not to the origin.
- The CDN's edge nodes accept client connections, terminate TLS,
  and forward the request to the origin over a separate connection.
- The origin is typically configured to accept traffic only from
  the CDN's IP ranges, so a direct connection to the origin's IP is
  refused or ignored. This is the critical configuration step: if
  the origin still accepts direct connections, the hiding is
  cosmetic.
- The origin's IP may still be discoverable through: historical DNS
  records, certificate transparency logs for a certificate issued
  directly to the origin, email sent from the origin, a misconfigured
  subdomain, or a scan of the provider's IP ranges for a service
  that matches the origin's fingerprint.

**Domain fronting (the more specific technique):**

- The client establishes a TLS connection to the CDN's edge node
  using a "front" domain in the SNI field. The front domain is a
  legitimate domain hosted on the same CDN.
- The client then sends an HTTP request with a different "real"
  domain in the Host header. The CDN routes the request based on
  the Host header, so the request reaches the real domain's origin.
- An observer on the network sees the TLS SNI (the front domain)
  and the CDN's IP. The Host header is inside the TLS tunnel and
  is not visible to a passive observer.
- Domain fronting depends on the CDN not enforcing a match between
  the SNI and the Host header. Many major CDNs disabled domain
  fronting between 2018 and 2020 in response to abuse. Cloudflare,
  AWS CloudFront, Google Cloud CDN, and Azure Front Door all
  enforce SNI/Host matching by default today. Some smaller CDNs
  and some providers in permissive jurisdictions still allow it.
- Domain fronting is used by Tor pluggable transports (meek,
  Snowflake), by some VPN protocols, and historically by C2
  frameworks. Its effectiveness today is limited by the CDN
  enforcements above.

**The relationship between the two techniques:**

- Origin IP hiding is a normal, widely supported feature of every
  major CDN. It is not controversial.
- Domain fronting is a specific abuse of CDN routing that most
  major providers now block.
- Origin IP hiding can be combined with domain fronting, but the
  fronting layer is often unnecessary if the goal is only to hide
  the origin.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**. The procedure assumes you have a
documented requirement for origin hiding.

**Step 1. Provision the origin.**

- Host the origin on a VPS (offshore or bulletproof, depending on
  the threat model - see the earlier files in this subcategory).
- Install the service (web server, C2, API, etc.).
- Configure the service to accept traffic only from the CDN's IP
  ranges. This is the single most important step. Without it, the
  hiding is cosmetic.
- If the CDN supports it, configure a shared secret header that the
  CDN adds to every request and the origin checks. This prevents
  anyone who discovers the origin IP from connecting directly.
- Do not issue a public TLS certificate for the origin's real
  hostname. Use the CDN's certificate for the public domain, and a
  self-signed or CDN-issued certificate between the CDN and the
  origin.

**Step 2. Choose the CDN.**

- Major CDNs (Cloudflare, Fastly, Akamai, AWS CloudFront, Azure
  Front Door, Google Cloud CDN) are the most reliable for origin
  hiding. They have global anycast networks and mature abuse
  processes.
- Smaller CDNs may be more permissive but less reliable and more
  likely to terminate an account under pressure.
- For an authorized engagement, use a CDN the client has approved.
  Some clients forbid certain providers for compliance reasons.

**Step 3. Configure the CDN.**

- Add the public domain to the CDN.
- Point the domain's DNS to the CDN (or use the CDN's nameservers).
- Configure the origin's IP as the upstream.
- Enable "Full (strict)" TLS mode or equivalent: the CDN validates
  the origin's certificate. Use a CDN-issued origin certificate or
  a self-signed certificate pinned to the CDN.
- Enable "Authenticated Origin Pulls" or equivalent: the CDN
  presents a client certificate to the origin, and the origin
  rejects connections without it.
- Restrict the origin's firewall to the CDN's published IP ranges.
- If the CDN supports it, enable a WAF, rate limiting, and bot
  protection. These are useful for the engagement and also reduce
  the chance of abuse complaints.

**Step 4. Verify the hiding.**

- From an external network, resolve the domain. It should return
  the CDN's IPs, not the origin's.
- Attempt to connect directly to the origin's IP. The connection
  should be refused or return an error, not the service.
- Check certificate transparency logs for certificates issued to
  the origin's real hostname. If any exist, the origin is
  discoverable.
- Check historical DNS records (SecurityTrails, DNSDumpster,
  VirusTotal) for the domain. If the origin IP appears in the
  history, the hiding is only effective against casual observers,
  not against a determined analyst.
- Check for subdomains that point directly to the origin. A single
  misconfigured subdomain (e.g. `direct.example.com`, `origin.example.com`,
  `dev.example.com`) can reveal the origin.

**Step 5. Domain fronting (only if required and only where it works).**

- Domain fronting requires a CDN that does not enforce SNI/Host
  matching. Most major CDNs do enforce it today.
- If the engagement requires domain fronting, test it explicitly
  before relying on it. The behavior can change without notice.
- For most authorized engagements, origin IP hiding is sufficient.
  Domain fronting adds complexity and is often unnecessary.

## 5. Hardening and Configuration

CDN fronting shifts the security boundary: the CDN is now the
public face of the service, and the origin is a private backend.

**CDN-side hardening:**

- Enable "Full (strict)" TLS between the CDN and the origin. Never
  use "Flexible" mode - it sends traffic from the CDN to the origin
  in plaintext.
- Enable authenticated origin pulls (client certificate) so the
  origin accepts only connections from the CDN.
- Enable a WAF and rate limiting. These reduce abuse complaints and
  improve the engagement's stability.
- Restrict the CDN's origin connection to a specific port and
  protocol.
- Enable logging and forward logs to a location you control. CDN
  logs are useful for the engagement report and for detecting
  attempts to discover the origin.

**Origin-side hardening:**

- Firewall: allow only the CDN's published IP ranges. Update the
  ranges when the CDN publishes changes.
- Shared secret header: the CDN adds a header with a secret value,
  and the origin rejects requests without it. This is a second
  layer after the IP restriction.
- No public TLS certificate for the origin's real hostname. Use
  the CDN's certificate for the public domain.
- No email sending directly from the origin. If the service sends
  email, route it through a relay. Email headers reveal the
  origin's IP.
- No DNS records that point directly to the origin. Audit all
  subdomains.
- No outbound connections from the origin to the public internet
  unless required. An outbound connection reveals the origin's IP
  to the destination.

**Identity separation:**

- Use a different account, email address, and payment method for
  the CDN and the origin provider.
- Do not reuse SSH keys, passwords, or recovery phrases.
- Document the identities in your offline notes.

**Operational hardening:**

- Monitor certificate transparency logs for new certificates
  issued to the origin's real hostname. A new certificate is a
  signal that the origin has been discovered.
- Monitor historical DNS services for the origin IP appearing in
  new records.
- Monitor the CDN's abuse notifications.
- Have a migration plan: if the CDN terminates the account, the
  origin is exposed. Document the steps to move to a backup CDN.

## 6. Operational Usage

Day-to-day operation of CDN-fronted infrastructure for an
authorized engagement:

- **Separate the control plane from the data plane.** Manage the
  CDN and the origin through a jump host or a VPN, not directly
  from your workstation.
- **Treat the CDN as a semi-trusted party.** The CDN terminates
  TLS and can see the plaintext of every request unless the
  application uses end-to-end encryption inside the TLS tunnel.
- **Treat the origin as hostile.** Assume the origin provider can
  log, inspect, and modify anything on the box.
- **Keep an offline record.** Store credentials, DNS records, CDN
  configuration, and engagement notes on your own systems.
- **Monitor externally.** Use a third-party uptime service from a
  different network to detect changes in the CDN's behavior.
- **Have a migration plan.** Document the steps to move the CDN
  and the origin to backup providers.

**Engagement-specific considerations:**

- If the client requires the CDN account to be transferred at the
  end of the engagement, plan the transfer process and the
  identity handover from day one.
- If the engagement is time-boxed, schedule the teardown of the
  CDN configuration and the origin before the engagement starts.
- If the engagement uses the CDN for phishing simulation, brief
  the client's legal team and the CDN's abuse team in advance if
  the CDN has a pre-notification process.

## 7. Common Mistakes

- **Not restricting the origin's firewall to the CDN's IP ranges.**
  The most common and most damaging mistake. The origin is
  reachable directly, and the hiding is cosmetic.
- **Using "Flexible" TLS mode.** Traffic between the CDN and the
  origin is plaintext. Anyone on the path can read it.
- **Issuing a public TLS certificate for the origin's real
  hostname.** The certificate appears in certificate transparency
  logs and reveals the origin.
- **Sending email directly from the origin.** Email headers
  reveal the origin's IP.
- **Leaving a subdomain pointed directly at the origin.** A
  single misconfigured subdomain defeats the entire setup.
- **Reusing the origin's IP in another service.** Any service on
  the same IP reveals the origin.
- **Assuming domain fronting still works on major CDNs.** Most
  major CDNs disabled it between 2018 and 2020.
- **Not monitoring certificate transparency logs.** New
  certificates for the origin's hostname are a warning sign.
- **Not having a migration plan.** If the CDN terminates the
  account, the origin is exposed.
- **Using the same identity for the CDN and the origin provider.**
  A single account compromise links the two.

## 8. Attacks Against It

CDN-fronted infrastructure is attacked by:

- **Origin IP discovery.** The primary attack. Methods: historical
  DNS records, certificate transparency logs, email headers,
  misconfigured subdomains, scans of the hosting provider's IP
  ranges, and correlation of the service's fingerprint with a
  scan result.
- **CDN account takeover.** Phishing, credential stuffing, or
  social engineering against the CDN's support team.
- **Takedown of the front domain.** A rights holder or brand
  protection team sends a takedown notice to the front domain's
  registrar.
- **Takedown of the CDN account.** The CDN terminates the account
  in response to an abuse complaint. The origin is then exposed
  unless a backup CDN is ready.
- **Legal process against the CDN.** The CDN discloses the
  origin's IP and the account holder's identity in response to a
  legal order.
- **Traffic analysis.** An observer correlates the CDN connection
  with the origin's activity through timing, volume, or other
  side channels.
- **DDoS on the CDN.** Large volumetric attacks can saturate the
  CDN's edge for the specific domain, though the CDN's overall
  capacity usually absorbs them.
- **Abuse complaint from the CDN's other customers.** A
  legitimate customer on the same CDN may report the malicious
  domain, triggering the CDN's abuse process.

## 9. Detection (Blue Team)

Defenders, researchers, and threat-intel analysts identify
CDN-fronted infrastructure through:

- **Historical DNS records.** SecurityTrails, DNSDumpster,
  VirusTotal, and similar services show the history of DNS
  records for a domain, including the origin IP before it was
  moved behind the CDN.
- **Certificate transparency.** Every publicly trusted TLS
  certificate is logged. A certificate issued to the origin's
  real hostname appears in CT logs even if the domain is now
  behind a CDN.
- **Email header analysis.** Email sent from the origin reveals
  the origin's IP in the `Received:` headers.
- **Subdomain enumeration.** A subdomain that points directly
  to the origin is a common finding. Tools: `amass`, `subfinder`,
  `dnsx`, `massdns`.
- **Favicon and JARM hashes.** Fingerprints of the service on
  the origin. A scan of the hosting provider's IP ranges for a
  service with the same fingerprint as the CDN-fronted service
  reveals the origin.
- **Passive DNS.** Historical domain-to-IP mappings.
- **ASN and IP reputation.** The origin's hosting provider is
  often a smaller, less reputable ASN than the CDN.
- **BGP and routing data.** The origin's prefix may be
  announced by a different upstream than the CDN's.
- **Threat-intel reports.** CDN-fronted infrastructure is named
  in reports from vendors tracking C2, phishing, and botnets.
- **Traffic analysis.** Correlation of the CDN connection with
  the origin's activity through timing or volume.

For a defender, the practical output is a blocklist entry for
the front domain, a notification to the CDN's abuse desk with
the origin IP if discovered, and, if the engagement is
authorized, a notification to the origin's hosting provider.

## 10. Case Studies

**Case 1 - C2 behind Cloudflare.** A C2 framework used a
Cloudflare-fronted domain for its command-and-control channel.
The origin was an offshore VPS. The operator configured the
origin's firewall to accept only Cloudflare's IP ranges and
enabled authenticated origin pulls. A defender attempted to
discover the origin through historical DNS records and
certificate transparency, but the operator had never issued a
public certificate for the origin's hostname and had not used
the domain before moving it behind Cloudflare. The origin was
eventually discovered through a misconfigured subdomain
(`direct.example.com`) that pointed to the origin's IP. The
defender notified the VPS provider, which terminated the
account.

**Case 2 - Phishing behind AWS CloudFront.** A phishing campaign
used AWS CloudFront to hide the origin. The origin was an EC2
instance in a different AWS region. The operator used the
default CloudFront certificate, so no certificate transparency
entry revealed the origin. The campaign was disrupted when the
phishing domain's registrar suspended it in response to a
takedown notice. The origin remained reachable directly by IP,
but without the domain the campaign lost its lures.

**Case 3 - Domain fronting with Tor.** A Tor pluggable transport
(meek) used domain fronting through a major CDN to allow users
in a censored country to reach the Tor network. The front domain
was a legitimate website hosted on the same CDN. When the CDN
disabled domain fronting in 2018, the transport stopped working
and the Tor Project migrated to Snowflake, which uses a
different technique (WebRTC peer-to-peer). This case shows that
domain fronting is fragile: a policy change at the CDN can
break it overnight.

**Case 4 - Authorized red-team engagement.** A red team used
Cloudflare to hide the origin of a long-running C2 during a
client engagement. The origin was an offshore VPS in Iceland.
The team enabled Full (strict) TLS, authenticated origin pulls,
and a WAF. They monitored certificate transparency logs for new
certificates issued to the origin's real hostname. Mid-engagement,
a new certificate appeared in CT logs, indicating the origin had
been discovered. The team migrated the origin to a backup VPS in
a different jurisdiction within four hours and updated the
Cloudflare origin configuration. The engagement continued without
loss of access.

## 11. Legal and Ethical Notes

CDN fronting sits at the intersection of several legal regimes
and provider policies:

- **Jurisdiction.** The CDN provider's terms of service and the
  laws of its jurisdiction apply to the account. Using a CDN for
  a purpose the CDN prohibits (e.g. C2 for unauthorized activity)
  is a terms-of-service violation and may be a criminal offense
  in the CDN's jurisdiction.
- **Authorization.** For red-team and research use, the
  engagement contract or research ethics approval must
  explicitly cover the use of a CDN and the origin hosting. Do
  not assume that "the client asked for a red team" includes
  permission to use a CDN for infrastructure.
- **Export controls.** Some jurisdictions restrict the export of
  certain security tooling and infrastructure services. Check
  before provisioning.
- **Payment regulations.** Anti-money-laundering rules apply to
  payment processors. Using a CDN for authorized work through a
  corporate payment rail is normally fine; using it for other
  purposes may create legal exposure for the operator.
- **CDN terms of service.** Every CDN prohibits certain uses
  (spam, phishing, malware, C2). Violating the terms of service
  is a civil matter, not a criminal one, but it can result in
  account termination and, in serious cases, referral to law
  enforcement.
- **Ethical boundary.** CDN fronting is used by criminal actors.
  Using the same technique for authorized work is not itself
  unethical, but it can create the appearance of association. Be
  transparent with the client and document the choice.

**Do not use CDN fronting for:**

- Hosting content that is illegal in your jurisdiction or the
  CDN's.
- Any activity outside an authorized engagement or approved
  research project.
- Storing data you are not authorized to store.
- Anything that would expose the client to legal risk they did
  not agree to.
- Bypassing a CDN's terms of service for unauthorized purposes.

## 12. Production Notes

- **Cost.** CDN pricing is usage-based. For a small engagement,
  the cost is negligible (often free tier). For a high-traffic
  engagement, budget for bandwidth and requests.
- **SLA.** Major CDNs have meaningful SLAs. Smaller CDNs may
  not. Read the SLA before relying on the CDN.
- **Support.** Major CDNs have 24/7 support. Smaller CDNs may
  not. Plan for self-sufficiency on the smaller providers.
- **Migration.** Keep a tested migration runbook for the CDN
  and the origin. Any of the two may change posture without
  notice.
- **Teardown.** At the end of an engagement, destroy the CDN
  configuration, destroy the origin, and document the
  destruction. Do not leave abandoned CDN accounts with
  configured origins.
- **Record-keeping.** Keep an offline log of every action taken
  on the infrastructure, for the client's report and for your
  own legal protection.
- **Monitoring.** Set up certificate transparency monitoring
  and historical DNS monitoring for the origin's real hostname.
  Early detection of origin discovery gives you time to
  migrate.

## 13. References

- Cloudflare documentation on origin protection and
  authenticated origin pulls.
- AWS CloudFront documentation on origin access control and
  origin access identity.
- Azure Front Door documentation on origin protection.
- Google Cloud CDN documentation on origin protection.
- Tor Project documentation on pluggable transports (meek,
  Snowflake) and the history of domain fronting.
- Academic papers on domain fronting, CDN abuse, and
  decoy routing.
- Certificate transparency logs (crt.sh and similar).
- SecurityTrails, DNSDumpster, VirusTotal for historical DNS
  and subdomain enumeration.
- Vendor threat-intel reports on CDN-fronted infrastructure
  (e.g. reports on C2 hosting behind Cloudflare).
- The client's rules of engagement document (for authorized
  engagements).
