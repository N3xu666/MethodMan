# Infrastructure OSINT Fundamentals

Infrastructure OSINT is the discipline of mapping an organization's
technical estate from public sources. Unlike people search, it deals
with domains, IP addresses, certificates, and cloud assets - artifacts
that are designed to be publicly resolvable but not necessarily public
in intent.

This file covers the fundamentals: what infrastructure OSINT is, the
main source categories, the difference between passive and active
collection, and the scope boundaries that apply.

## 1. Overview

The goal of infrastructure OSINT is to answer:

- Which domains and subdomains does the organization own?
- Which IP ranges and ASNs are associated with it?
- Which cloud providers and services does it use?
- Which services are exposed to the internet?
- Which third parties are connected (CDNs, SaaS, partners)?

The output is an attack surface map. Every node is a hypothesis; every
edge needs a source. The map is only as good as the evidence behind it.

## 2. Reconnaissance / Collection

### Source categories

- **DNS and WHOIS** - domain registrations, nameservers, historical
  records (SecurityTrails, ViewDNS).
- **Certificate Transparency** - every TLS certificate issued for a
  domain is logged publicly (crt.sh, Censys, Cert Spotter).
- **Search engines for devices** - Shodan, Censys, FOFA, ZoomEye index
  internet-connected services.
- **Cloud storage** - public S3, Azure Blob, GCP Storage buckets,
  discoverable via search engines and naming conventions.
- **BGP and ASN** - routing data reveals which ASN announces which
  prefixes (bgp.he.net, RIPEstat).
- **Code and CI** - GitHub, GitLab, CI logs sometimes reveal internal
  hostnames, cloud accounts, and API keys.

### Passive vs active

```text
Passive collection (no packets to the target):
  - DNS queries to public resolvers
  - WHOIS lookups
  - Certificate Transparency search
  - Shodan/Censys queries
  - BGP looking glasses

Active collection (packets to the target):
  - Port scanning
  - HTTP requests
  - Subdomain brute forcing with DNS resolution
  - Vulnerability scanning
```

Passive collection is legal in most jurisdictions. Active collection
requires authorization from the target. This subcategory covers passive
collection; active techniques live in INFRASTRUCTURE/.

## 3. Common Attack Vectors

Infrastructure OSINT is the first phase of an external attack:

- **Subdomain takeover** - a dangling DNS record points to a cloud
  service the organization no longer controls. An attacker can claim
  the service and serve content under the organization's domain.
- **Shadow IT discovery** - teams deploy services outside the central
  inventory. OSINT finds them before the security team does.
- **Cloud storage exposure** - public S3, Blob, or GCS buckets leak
  data, backups, and credentials.
- **Exposed admin panels** - forgotten Jenkins, Grafana, Kubernetes
  dashboards, and admin UIs.
- **Third-party mapping** - CDNs, SaaS providers, and partners widen
  the attack surface beyond the organization's own assets.

The attacker's advantage is that the internet is a public map; the
defender's counter is asset inventory and continuous monitoring.

## 4. Exploitation Recipes

### Recipe 1 - Subdomain enumeration (passive)

```text
$ curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
$ subfinder -d example.com -silent
$ amass enum -passive -d example.com
```

All three are passive: no packets to the target, only to public
data sources.

### Recipe 2 - ASN and IP range mapping

```text
$ curl -s "https://bgp.he.net/dns/example.com" | grep -i "AS"
$ whois -h whois.radb.net -- '-i origin AS12345' | grep '^route'
$ curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=AS12345" | jq
```

### Recipe 3 - Cloud bucket discovery

```text
Candidate names for example.com:
  example, example-backup, example-prod, example-dev, example-logs

Check with:
  curl -s "https://example.s3.amazonaws.com/" -o /dev/null -w "%{http_code}\n"
  curl -s "https://storage.googleapis.com/example/" -o /dev/null -w "%{http_code}\n"
  curl -s "https://example.blob.core.windows.net/" -o /dev/null -w "%{http_code}\n"

Codes: 200 = public, 403 = exists but private, 404 = does not exist
```

### Recipe 4 - Shodan query for the organization

```text
$ shodan search "org:\"Example Corp\""
$ shodan search "ssl:\"example.com\""
$ shodan stats --facets port "org:\"Example Corp\""
```

## 5. Post-Exploitation

After the attack surface is mapped, the operator has a target list:

- **Subdomain takeover** - dangling records become live attacks.
- **Credential discovery** - leaked keys in code or CI, exposed
  configuration files, default credentials on admin panels.
- **Lateral movement** - third-party relationships (CDN, SaaS) become
  pivots into the organization.
- **Social engineering** - infrastructure details (helpdesk portal,
  VPN vendor) make pretexts more believable.

**Warning:** every step past "mapping" is active engagement and
requires explicit authorization. See section 10.

## 6. Preventive Controls

Defenders reduce infrastructure exposure by:

- **Asset inventory** - maintain a complete, current inventory of
  domains, subdomains, and cloud assets.
- **Continuous monitoring** - certificate transparency alerts for new
  subdomains; Shodan alerts for the organization's IP ranges.
- **Dangling record hygiene** - remove DNS records that point to
  services no longer in use.
- **Cloud storage defaults** - make buckets private by default;
  audit for public exposure.
- **Shadow IT policy** - a documented process for teams to register
  new services.

## 7. Detection Controls

Detection of infrastructure OSINT is difficult because the queries are
public. Signals:

- **Certificate transparency monitoring** - alert on new subdomains;
  some of these will be legitimate, some will be attackers or shadow IT.
- **DNS query logs** - if the organization runs its own DNS, bulk
  lookups from a single source are a signal.
- **Honeytokens** - fake subdomains, fake buckets, fake records that
  only a collector would query.
- **Search engine alerts** - alerts when the organization's name appears
  in Shodan or Censys with new results.

## 8. Verification

Verification of an infrastructure finding:

- **Two independent sources** - a subdomain found via crt.sh should
  also resolve via DNS (or be confirmed as historical).
- **Timestamp** - infrastructure changes; a 2019 record may be stale.
- **Ownership** - verify that the asset actually belongs to the target,
  not to a third party with a similar name.
- **Scope** - verify the asset is in the engagement scope (some
  subdomains belong to subsidiaries, not the parent).

## 9. Pentest and Red Team Application

In an authorized engagement:

- **Passive first** - map the external footprint with passive sources
  before any active scanning. This protects the engagement and the
  target.
- **Scope validation** - the client's asset inventory is often
  incomplete. OSINT findings expand the scope, which needs client
  approval.
- **Attack surface input** - the map feeds active scanning, web
  enumeration, and cloud assessment.
- **Reporting** - the map is a deliverable: it shows the client what
  the internet already knows about them.

Rules:

- Passive collection is allowed only against in-scope assets.
- Active scanning requires a separate authorization in the SOW.
- Findings about out-of-scope assets are reported privately, not
  exploited.

## 10. Legal and Ethical Notes

- **Passive vs active** - passive collection from public sources is
  generally legal. Active scanning without authorization may be a crime.
- **Cloud ToS** - querying cloud storage endpoints may violate the
  provider's ToS even when the bucket is public.
- **Certificate transparency** - the data is public and intended for
  consumption; using it is fine.
- **Third-party assets** - CDNs, SaaS providers, and partners are
  third parties. Do not attack them without their own authorization.
- **Data minimization** - collect only what the engagement requires.
- **Reporting** - findings about out-of-scope assets are reported
  privately to the target, not published.

## 11. Production Notes

- **Templates** - asset inventory template, subdomain log, cloud
  bucket check log.
- **Tooling** - subfinder, amass (passive), crt.sh, Shodan, Censys,
  bgp.he.net, SecurityTrails.
- **Automation limits** - passive tools are fast but noisy. Deduplicate
  and verify before acting.
- **Retention** - scan results are kept for the engagement and deleted
  on schedule.
- **Review** - a second analyst reviews the attack surface map before
  it is used in active phases.

## 12. References

- OSINT Framework - https://osintframework.com/
- crt.sh Certificate Search - https://crt.sh/
- Shodan - https://www.shodan.io/
- Censys - https://search.censys.io/
- BGP Toolkit (Hurricane Electric) - https://bgp.he.net/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
