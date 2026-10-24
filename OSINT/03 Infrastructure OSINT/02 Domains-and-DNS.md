# Domains and DNS

## 1. Overview

The Domain Name System is the map of the internet: it translates human-readable names into IP addresses and stores operational metadata (mail servers, service records, ownership delegation). For an OSINT analyst or a red teamer, DNS is one of the highest-signal sources available, because it is public by design and it is updated continuously by the target organization itself.

This file covers passive and semi-passive collection of domain and DNS data: what records exist, what they reveal, and how to turn them into a coherent picture of an organization's infrastructure. The focus is on public sources (registry records, passive DNS, zone data) rather than active scanning.

Relevance: red teams use this to map the external attack surface before touching a target; blue teams use the same data to discover shadow IT and unmonitored assets; OSINT analysts use it for attribution and infrastructure clustering.

## 2. Reconnaissance and Collection

Domain and DNS collection has three layers, ordered by how much contact they require with the target.

**Layer 1 - Registration data (fully passive).** WHOIS and RDAP records for the domain itself, the registrant organization, and the registrar. Modern privacy services hide registrant identity, but the creation date, name servers, and registrar still provide useful pivots.

**Layer 2 - Passive DNS (fully passive).** Historical resolution records collected by third parties. Reveals subdomains, IP churn, and past infrastructure. Sources include SecurityTrails, VirusTotal, PassiveTotal, and DNSDB.

**Layer 3 - Zone data (semi-passive to active).** Certificate Transparency logs, DNSSEC records, AXFR attempts where misconfigured, and brute-force of common subdomain names. CT logs are fully passive; brute-force sends DNS queries to the target's resolver.

Key record types and what they reveal:

- A / AAAA - current IP addresses; pivots to hosting provider and ASN.
- MX - mail infrastructure; often reveals the mail security vendor (e.g. Proofpoint, Mimecast).
- NS - authoritative name servers; usually the DNS provider (Cloudflare, Route 53, Azure DNS).
- TXT - verification tokens (Google, Microsoft, Atlassian), SPF, DKIM, DMARC; strong indicator of which SaaS services the organization uses.
- CNAME - aliases; frequently exposes third-party services (Shopify, Zendesk, status pages).
- SRV - service records; exposes directory and communication services (LDAP, SIP, XMPP).
- SOA - authoritative server and zone metadata; useful for zone transfer attempts.

```bash
# Passive enumeration with common public tools
whois example.com
dig +short MX example.com
dig +short TXT example.com
dig +short NS example.com
dig +short CNAME www.example.com
```

Expected output (trimmed):

```text
$ dig +short MX example.com
10 mail1.example.com.
20 mail2.example.com.

$ dig +short TXT example.com
"v=spf1 include:_spf.google.com ~all"
"google-site-verification=abc..."
```

The SPF record above immediately reveals that the organization uses Google Workspace for mail, which narrows the search space for credential-based attacks and for phishing infrastructure analysis.

## 3. Common Attack Vectors

From an OSINT perspective, "attack vectors" are not exploits but collection paths that adversaries (and defenders) use to extract information from DNS.

- **Subdomain enumeration.** Subdomains frequently expose development, staging, and legacy systems that are less protected than the primary site. Common sources: Certificate Transparency, passive DNS, wordlists.
- **Zone transfer misconfiguration.** A name server that allows AXFR exposes the entire zone in a single query. Rare on major providers, still common on self-hosted or legacy infrastructure.
- **DNS cache snooping.** Querying a recursive resolver with the RD (recursion desired) bit cleared to determine whether a name was recently resolved by other users. Can reveal which internal services are actively used.
- **Wildcard and dangling records.** A CNAME pointing to a deprovisioned cloud resource (S3 bucket, GitHub Pages, Heroku app) creates a subdomain takeover opportunity. Detected by resolving all subdomains and checking whether the target of the CNAME still exists.
- **Certificate Transparency as an oracle.** Every publicly trusted certificate is logged. Searching CT logs by organization name reveals hosts the organization never intended to publish.
- **MX and SPF analysis.** Misconfigured SPF and missing DMARC can indicate weak mail security, which affects phishing simulation and infrastructure analysis.

```bash
# Subdomain collection from Certificate Transparency (fully passive)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Zone transfer attempt (semi-active; try each NS)
dig AXFR example.com @ns1.example.com
```

Expected output for crt.sh (trimmed):

```text
$ curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
api.example.com
dev.example.com
mail.example.com
staging.example.com
www.example.com
```

## 4. Exploitation Recipes

In OSINT, "exploitation" means converting raw collection into a confirmed, useful fact. Recipes below are ordered by confidence.

**Recipe 1 - Confirm ownership via TXT.** Many SaaS providers require a TXT record to verify domain ownership. Finding `google-site-verification=...` or `MS=ms...` proves the domain is registered with that provider.

**Recipe 2 - Cluster infrastructure by ASN.** Group all discovered IPs by Autonomous System Number. IPs in the same ASN and the same /24 are usually owned by the same hosting account, which means a single takeover compromises all of them.

**Recipe 3 - Detect subdomain takeover.** For each subdomain, resolve the CNAME target. If the target returns NXDOMAIN or a provider-specific "no such app" page, the subdomain is potentially claimable.

**Recipe 4 - Reconstruct deleted records from CT logs.** Certificate Transparency includes certificates for hosts that no longer resolve. A historical timeline of CT entries shows when hosts appeared and disappeared, which is useful for infrastructure change analysis.

**Recipe 5 - Mail infrastructure fingerprinting.** Combine MX, SPF, DMARC, and DKIM selectors to identify the mail security stack. Example: `_dmarc.example.com` returning `v=DMARC1; p=reject; rua=mailto:dmarc@proofpoint.com` indicates Proofpoint as the mail gateway.

```bash
# Subdomain takeover check (simplified)
for sub in $(cat subs.txt); do
  cname=$(dig +short CNAME "$sub")
  if [ -n "$cname" ]; then
    printf "%-40s -> %s\n" "$sub" "$cname"
  fi
done
```

## 5. Post-Exploitation

Once domain and DNS data is collected, the next step is enrichment and graph building.

- **Enrich each IP with geolocation, ASN, and hosting provider.** Use MaxMind, ipinfo, or Team Cymru whois.
- **Cross-reference with certificate data.** A certificate's Subject Alternative Name (SAN) list often contains hosts not present in DNS enumeration.
- **Build a service graph.** Nodes are domains, IPs, ASNs, and certificates; edges are "resolves to", "issued for", "belongs to". The graph reveals shared infrastructure and ownership patterns.
- **Timeline analysis.** Track when each host first appeared in CT logs and when it stopped resolving. Gaps indicate temporary infrastructure, which is often the most interesting (staging, red team, investigation).

```bash
# Enrich IPs with ASN and organization (Team Cymru whois)
for ip in $(cat ips.txt); do
  whois -h whois.cymru.com " -v $ip"
done
```

Expected output (trimmed):

```text
$ whois -h whois.cymru.com " -v 104.16.0.1"
AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
13335   | 104.16.0.1       | 104.16.0.0/12       | US | arin     | 2014-03-28 | CLOUDFLARENET, US
```

## 6. Preventive Controls

For defenders, the goal is to reduce unintended exposure and to detect changes quickly.

- **Register all subdomains intentionally.** Unknown subdomains that resolve to the target's infrastructure are a common source of shadow IT.
- **Lock CNAME targets.** Never point a CNAME to a third-party resource that can be released (e.g. a personal GitHub Pages site or an expiring S3 bucket).
- **Monitor Certificate Transparency.** Subscribe to CT log streams for the organization's domains; new certificates indicate new hosts, including rogue ones.
- **Audit TXT records quarterly.** TXT records accumulate verification tokens for services that were later decommissioned. Each stale token is a potential pivot.
- **Enforce DMARC p=reject.** DMARC enforcement detects and prevents mail spoofing of the organization's domain.
- **DNSSEC for critical zones.** DNSSEC reduces the risk of cache poisoning for authoritative names.

## 7. Detection Controls

Blue teams detect DNS-based OSINT activity primarily through resolver logs, CT monitoring, and DNS anomaly detection.

- **Resolver log analysis.** A single client issuing thousands of NXDOMAIN queries in a short window is either a subdomain brute-force or a malware DGA. Alert on high NXDOMAIN rate per client.
- **CT log monitoring.** Alerts on any new certificate for `*.org-domain` outside the change window.
- **DNS tunneling detection.** Long labels, high entropy, unusual TXT queries. Many SIEMs have built-in rules; verify coverage.
- **AXFR attempts.** Authoritative servers should log zone transfer attempts as security events.
- **Honeypot subdomains.** A deliberately unused subdomain (e.g. `admin-old.example.com`) that suddenly resolves indicates enumeration; alert on any DNS query to it.

```text
# Example: DNS anomaly thresholds (tune per environment)
- NXDOMAIN rate > 100/min from a single client: high signal
- Label length > 40 characters: possible tunneling
- Query volume to random-looking labels: possible DGA
```

## 8. Verification

Verification confirms that collected facts are accurate and current, not artifacts of caching or misconfiguration.

- **Triangulate between sources.** A subdomain found in CT logs should also be confirmed by passive DNS or by direct resolution before being reported.
- **Check resolution date.** A host that no longer resolves may be an artifact of an old CT entry. Confirm with a fresh resolution or a passive DNS record with a recent timestamp.
- **Confirm ASN ownership.** IPs can be reassigned; always use current whois data, not cached copies.
- **Verify the target is authorized.** Before any active DNS query against a target, confirm written authorization is in scope. Passive collection (CT, passive DNS) does not require authorization but should still respect terms of service of the data provider.

## 9. Pentest and Red Team Application

In a real engagement, domain and DNS collection produces the initial external attack surface map.

- **Phase 1 - Passive collection (day 0).** Gather all public sources before touching the target. Output: candidate hosts, ASNs, mail infrastructure.
- **Phase 2 - Active confirmation (day 1).** Resolve candidates, confirm which are alive, and fingerprint the technology stack (covered in the Infrastructure OSINT files for cloud and certificates).
- **Phase 3 - Prioritization.** Rank hosts by exposure: hosts with public CVEs, dev environments, admin panels, VPN gateways.
- **Phase 4 - Phishing infrastructure analysis.** MX, SPF, and DMARC analysis feeds directly into phishing campaign planning and defense.

Red team note: passive DNS and CT logs are usually sufficient to build a complete external map without sending any packet to the target. This is the preferred approach when operational security matters.

## 10. Legal and Ethical Notes

- **Passive collection is generally lawful.** Certificate Transparency and passive DNS are public sources. Their use for security research is widely accepted, though terms of service of the data provider still apply.
- **Active DNS queries against a target require authorization.** This includes brute-force subdomain enumeration, which generates traffic against the target's resolver.
- **WHOIS data is subject to privacy regulation.** GDPR and similar laws restrict how registrant data can be processed. Do not store personal data beyond what is necessary for the task.
- **Do not collect data on individuals unless it is in scope.** Infrastructure data is one thing; identifying the people behind the infrastructure is a separate activity with its own legal constraints.

## 11. Production Notes

- **Store collection results in a structured format** (JSON or CSV with columns: host, record type, value, source, timestamp). Flat text lists lose provenance.
- **Timestamp every record.** DNS answers change; a fact without a date is a guess.
- **Rate-limit active queries.** Aggressive brute-force can trip WAFs, IDS, or the target's monitoring. If the engagement allows active enumeration, still use a modest query rate.
- **Cache the passive data locally.** Passive DNS APIs have rate limits and cost money. A local cache prevents redundant lookups.
- **Reproducibility.** For each fact, store the exact query and the exact response. An OSINT report without provenance is not defensible in a review.

## 12. References

- RFC 1034 - Domain Names: Concepts and Facilities - https://datatracker.ietf.org/doc/html/rfc1034
- RFC 1035 - Domain Names: Implementation and Specification - https://datatracker.ietf.org/doc/html/rfc1035
- RFC 7208 - Sender Policy Framework (SPF) - https://datatracker.ietf.org/doc/html/rfc7208
- RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance (DMARC) - https://datatracker.ietf.org/doc/html/rfc7489
- RFC 4033 - DNS Security Introduction and Requirements (DNSSEC) - https://datatracker.ietf.org/doc/html/rfc4033
- Certificate Transparency - https://certificate.transparency.dev/
- crt.sh Certificate Search - https://crt.sh/
- Team Cymru IP to ASN Mapping - https://team-cymru.com/community-services/ip-asn-mapping/
- SecurityTrails - https://securitytrails.com/
- VirusTotal - https://www.virustotal.com/