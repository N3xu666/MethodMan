# Shodan and Censys

## 1. Overview

Shodan and Censys are specialized search engines that index internet-connected devices and services, rather than web pages. They continuously scan the public IPv4 and IPv6 address space and record the banners returned by services on open ports. For OSINT and red teaming, they are the fastest way to answer: "What is this organization exposing to the internet right now?"

This file covers the practical use of Shodan and Censys for infrastructure mapping: searching by organization, finding specific technologies, identifying exposed databases and management interfaces, and correlating results with other OSINT sources.

Relevance: these engines reveal misconfigurations (open Elasticsearch, exposed RDP, default credentials on IoT) that are invisible to DNS and certificate collection. They are fully passive from the perspective of the target, because the search engine performed the scanning, not the analyst.

## 2. Reconnaissance and Collection

Both Shodan and Censys provide web interfaces and APIs. The free tiers limit the number of results and the number of queries per month; the paid tiers remove these limits and add historical data.

Key search dimensions:

- **Organization / ASN.** Shodan has an `org:` filter and Censys has `autonomous_system.name`. This returns all hosts in the organization's IP ranges.
- **Product / technology.** Shodan has `product:` and `version:` filters; Censys has `services.software.product`.
- **Port / protocol.** Shodan has `port:`; Censys has `services.port`.
- **Geographic.** Both have country and city filters.
- **Certificate fields.** Both allow searching by certificate subject, issuer, and SAN.

```bash
# Shodan CLI examples (requires API key)
shodan search "org:\"Example Corp\""
shodan search "org:\"Example Corp\" port:3389"
shodan search "ssl.cert.subject.CN:\"example.com\""

# Censys CLI examples (requires API key)
censys search "services.tls.certificates.leaf_data.subject.common_name: example.com"
censys search "autonomous_system.name: \"EXAMPLE-AS\" and services.port: 22"
```

Expected output (Shodan search snippet):

```text
$ shodan search "org:\"Example Corp\" port:3389"
203.0.113.10    3389    microsoft-rdp  Microsoft Terminal Services
203.0.113.22    3389    microsoft-rdp  Microsoft Terminal Services
```

The two RDP hosts above are exposed to the internet and accept external connections. This is a common finding that DNS enumeration would miss, because the hosts may not have public DNS records.

## 3. Common Attack Vectors

In the context of internet-exposed services, attack vectors are the classes of exposure that an attacker can exploit.

- **Exposed management interfaces.** RDP, SSH, WinRM, Jenkins, Kubernetes API, Docker API, and vSphere. Each has known attack patterns (password spraying, CVE exploitation, unauthenticated API).
- **Exposed databases.** MongoDB, Elasticsearch, Redis, Cassandra, Memcached. Many have no authentication by default; exposed instances frequently leak data.
- **Default credentials on IoT and network devices.** Cameras, routers, printers, and industrial controllers often ship with default credentials. Shodan has a `has_screenshot:true` filter for visual confirmation.
- **Exposed CI/CD and secrets.** Jenkins servers, GitLab instances, and HashiCorp Vault are frequently exposed without MFA. These can leak credentials for the entire cloud environment.
- **Unpatched web frameworks.** Search by product and version to find hosts running known-vulnerable versions (e.g. `product:Apache version:2.4.49` for CVE-2021-42013).
- **Cloud storage endpoints.** S3, GCS, and Azure Blob endpoints are indexed; combined with bucket enumeration (see previous file), this reveals public data stores.

```text
# Shodan dorks for common exposures
"product:MongoDB" -authentication          # Open MongoDB instances
"port:9200" "You Know, for Search"         # Open Elasticsearch
"port:6379" "redis_version"                # Open Redis
"product:Apache-Coyote" "port:8080"        # Tomcat admin
"X-Jenkins" country:US                     # Jenkins instances
```

## 4. Exploitation Recipes

Shodan and Censys are passive tools, so "exploitation" here means confirming and acting on a finding in an authorized engagement.

**Recipe 1 - Confirm a target IP belongs to the organization.** Use `org:` filter, then check ASN registration and reverse DNS. False positives are common when IPs are reassigned.

**Recipe 2 - Find exposed admin panels.** Search by product name and port. Confirm the panel is accessible by attempting a benign HTTP request. Do not attempt authentication without written authorization.

**Recipe 3 - Identify version and CVE.** Shodan exposes the banner returned by the service; parse it for product and version. Cross-reference with NVD for CVEs.

**Recipe 4 - Screenshots as evidence.** Shodan's `has_screenshot:true` filter combined with visual inspection confirms that the service is running. Screenshots are acceptable evidence in an OSCP report but not a substitute for direct access.

**Recipe 5 - Correlate with other OSINT.** A host seen in Shodan should be cross-checked against CT logs (was there a certificate?) and DNS (does it resolve?). The combination of three sources is much stronger evidence than any one alone.

```bash
# Confirm exposed service without authentication
curl -s -o /dev/null -w "%{http_code}\n" "http://203.0.113.22:8080/"
```

## 5. Post-Exploitation

Post-collection steps: enrichment, prioritization, and building the attack surface graph.

- **Enrich with geolocation and ASN.** Same as for DNS-based hosts.
- **Categorize by service type.** Group exposures by class (management, database, web, ICS). Each class has its own set of controls and detection signals.
- **Prioritize by exploitability.** A host running an unpatched web framework with a public RCE is more critical than an exposed database that requires authentication.
- **Build an asset inventory.** For each host: IP, port, product, version, org, ASN, certificate, and last-seen timestamp. This becomes the external attack surface map for the engagement.
- **Track changes over time.** New hosts appearing in Shodan between two collection dates may indicate new deployments or attackers using the target's IP space.

## 6. Preventive Controls

Defenders should treat internet exposure as a first-class risk.

- **Inventory internet-facing assets.** Use the same tools (Shodan, Censys) to monitor the organization's IP ranges. If a host appears in the index and is not in the inventory, it is either unknown or unauthorized.
- **Restrict management interfaces.** RDP, SSH, WinRM should never be exposed to the internet. Use VPN or bastion hosts.
- **Harden databases.** Require authentication; bind to localhost or a private network; use cloud security groups.
- **Enforce MFA on all admin panels.** Jenkins, GitLab, Kubernetes API.
- **Rotate credentials and API keys.** Any exposed endpoint is a potential credential leak.
- **Disable Shodan/Censys indexing for sensitive services.** Both engines respect `robots.txt` only for web crawling, not for banner grabbing. The only real fix is not exposing the service.

## 7. Detection Controls

Detection focuses on tracking the organization's footprint and responding to unauthorized exposure.

- **Regular exposure scanning.** Run automated Shodan/Censys queries for the organization's IP ranges on a schedule (weekly or daily). Diff against the previous inventory.
- **Alerting on new exposures.** A new open port or a new product version on a known IP range is a change signal.
- **Cloud provider IP monitoring.** Cloud IPs can change; a host can appear in the index without the organization's knowledge if a cloud account is misconfigured.
- **DNS and CT cross-check.** A host in Shodan with no corresponding DNS or CT record may be unauthorized or transient.
- **Threat intelligence feeds.** Many feeds include Shodan-indexed hosts; integrating them with the SIEM closes the loop.

## 8. Verification

- **Confirm the host is currently live.** Shodan results can be stale (last scan weeks ago). Use a benign HTTP request to confirm.
- **Confirm the IP belongs to the target.** ASN and reverse DNS are strong signals but not proof. Written scope should list specific IP ranges.
- **Confirm the service is the claimed product.** Banners can be spoofed; version numbers can be fake. Use at least one other fingerprint (TLS certificate, HTTP headers, error page).
- **Do not attempt authentication without authorization.** Even confirming that a login page exists is technically an interaction with the target; ensure the engagement covers it.

## 9. Pentest and Red Team Application

- **Phase 1 - Passive collection.** Query Shodan/Censys for the organization's IP ranges; collect all exposed services.
- **Phase 2 - Categorization.** Group by service type (web, admin, database, IoT).
- **Phase 3 - Vulnerability correlation.** For each product-version pair, check NVD for known CVEs.
- **Phase 4 - Exploitability assessment.** Prioritize hosts with public exploit code and low complexity.
- **Phase 5 - Report.** Include the Shodan/Censys evidence (timestamped queries and screenshots) in the report.

Red team note: Shodan and Censys are a "second opinion" on the external footprint. A host seen in these engines is by definition internet-reachable. A host not seen is either firewalled or scanned after the last index update.

## 10. Legal and Ethical Notes

- **Shodan and Censys are public search engines.** Using them for security research is lawful and expected.
- **Do not scan back without authorization.** A Shodan result gives you the target IP and port; a direct scan or exploit attempt is an active action that requires written scope.
- **Respect API terms of service.** Both services have rate limits and acceptable use policies. Do not scrape aggressively.
- **Screenshots and metadata are evidence.** Store the exact query, the timestamp, and the result set. This is what makes an OSINT finding defensible.

## 11. Production Notes

- **Schedule regular scans.** Daily or weekly scanning of the organization's IP ranges catches new exposures before attackers do.
- **Use multiple IP range sources.** ASN, cloud provider IP ranges (AWS, GCP, Azure JSON feeds), and manual inventories. No single source is complete.
- **Store results in a structured database.** Shodan CLI supports JSON output; import into a local database for diffing.
- **Combine with certificate data.** A host with a certificate is more likely to be a legitimate deployment than a transient scan artifact.
- **Do not assume that "not in Shodan" means "not exposed".** New hosts may not be indexed yet; internal services may be exposed to a specific peer network.

## 12. References

- Shodan - https://www.shodan.io/
- Shodan CLI - https://cli.shodan.io/
- Censys Search - https://search.censys.io/
- Censys API - https://search.censys.io/api
- Shodan Search Filters - https://www.shodan.io/search/filters
- NVD - https://nvd.nist.gov/
- AWS IP Ranges - https://ip-ranges.amazonaws.com/ip-ranges.json
- Google Cloud IP Ranges - https://cloud.google.com/compute/docs/faq#find_ip_range
- Azure IP Ranges - https://www.microsoft.com/en-us/download/details.aspx?id=56519