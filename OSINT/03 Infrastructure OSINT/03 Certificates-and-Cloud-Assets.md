# Certificates and Cloud Assets

## 1. Overview

X.509 certificates are cryptographic bindings between a public key and an identity. For OSINT, they are one of the most reliable public data sources, because every certificate issued by a publicly trusted Certificate Authority (CA) is written to a Certificate Transparency (CT) log. The log is append-only, publicly auditable, and cannot be retroactively edited.

This file covers how to use certificates and cloud asset data for infrastructure mapping: discovering subdomains via CT logs, inferring ownership from certificate metadata, identifying cloud providers from DNS and certificate patterns, and enumerating exposed cloud storage.

Relevance: CT logs reveal hosts the organization may have forgotten; cloud asset enumeration reveals storage buckets and serverless endpoints that are frequently misconfigured; both are fully or mostly passive.

## 2. Reconnaissance and Collection

Certificate-based collection is fully passive. Cloud asset collection is mostly passive but sometimes requires light probing (e.g. checking if a bucket name is claimable).

Key collection paths:

- **Certificate Transparency logs.** Every public certificate is logged by at least two CT logs. The dominant public search interface is crt.sh. Alternative sources include Censys, Shodan, and CT log stream APIs.
- **Certificate fields.** Subject Common Name (CN), Subject Alternative Names (SAN), Issuer, Validity dates, and sometimes email addresses (legacy).
- **TLS handshake metadata.** For a live host, the certificate served during a TLS handshake can differ from what is in CT logs, indicating short-lived certificates or reverse-proxy termination.
- **Cloud provider fingerprints.** DNS records and certificate issuers often indicate the cloud provider. Example: certificates issued by Amazon indicate that the endpoint is fronted by AWS (CloudFront or ALB); Google Trust Services indicates GCP.
- **Cloud storage enumeration.** Cloud buckets are often named after the organization. Enumerating well-known naming patterns reveals both public and protected buckets.

```bash
# Certificate Transparency search by organization name
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u

# Certificate transparency search by organization string (e.g., "Example Corp")
curl -s "https://crt.sh/?q=Example%20Corp&output=json" | jq -r '.[].name_value' | sort -u

# Inspect a live TLS certificate
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text
```

Expected output (trimmed):

```text
$ openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text | head -20
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ...
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Apr  1 00:00:00 2025 GMT
        Subject: CN = example.com
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:example.com, DNS:www.example.com, DNS:api.example.com
```

## 3. Common Attack Vectors

In infrastructure OSINT, "attack vectors" are the ways an adversary uses certificates and cloud assets to expand the target's footprint.

- **Certificate SAN pivot.** A single certificate often covers many hostnames (SAN). A SAN of `*.example.com` tells you the wildcard scope, but individual SANs can reveal hosts that do not resolve publicly, indicating internal or staging environments.
- **Issuer pivot.** Certificates issued by a specific CA or ACME account can group assets by the same team or project. A team that consistently uses a specific CA for staging may also use it for production.
- **Certificate expiration monitoring.** New certificates for the target domain indicate new deployments. An expired certificate on a production endpoint is an operational weakness.
- **Cloud bucket takeover.** S3, GCS, and Azure Blob Storage buckets that are referenced (via DNS CNAME or application links) but not claimed can be registered by an attacker. This is the classic "dangling bucket" takeover.
- **Serverless endpoint enumeration.** Lambda function URLs, Google Cloud Functions, and Azure Functions often have predictable names or are listed in CT logs (via CloudFront/API Gateway domains).
- **Cloud provider service discovery.** CloudFront, Fastly, Cloudflare, and Akamai edge IPs can be mapped to origin services via DNS or by examining response headers.

```bash
# Check if an S3 bucket name is globally claimable (returns 403 if taken, 404 if claimable)
curl -s -o /dev/null -w "%{http_code}\n" "https://s3.amazonaws.com/example-backup"

# Check GCS bucket (returns 401/403 if taken, 404 if claimable)
curl -s -o /dev/null -w "%{http_code}\n" "https://storage.googleapis.com/example-backup"
```

## 4. Exploitation Recipes

For OSINT, exploitation is confirmation: turning a candidate finding into a verified fact.

**Recipe 1 - Map all hosts from a single CT log entry.** A single certificate entry on crt.sh can contain dozens of SANs. Extract all SANs and resolve them to identify live hosts.

**Recipe 2 - Ownership verification via certificate issuer.** If a certificate for `dev.example.com` is issued by an ACME account that also issued certificates for `example.com`, the same organization controls both. This is strong evidence for ownership.

**Recipe 3 - Cloud provider attribution.** If a host's certificate is issued by Amazon and served from a CloudFront IP range, the host is fronted by AWS. This narrows the attack surface to AWS-specific controls.

**Recipe 4 - Dangling CNAME to cloud resource.** If `old.example.com` CNAMEs to `example-2023.s3-website-us-east-1.amazonaws.com` and the bucket no longer exists, an attacker can claim it. Verification: attempt to register the bucket with a benign name and see if the registration succeeds (only in an authorized engagement).

**Recipe 5 - Subdomain takeover via third-party SaaS.** Many SaaS providers allow custom domains. When the SaaS subscription lapses, the custom domain can be claimed by another user. Detect by checking for provider-specific error pages.

```text
# Provider error page fingerprints for subdomain takeover
GitHub Pages: "There isn't a GitHub Pages site here."
Heroku: "No such app"
Shopify: "Sorry, this shop is currently unavailable."
AWS S3: "NoSuchBucket"
Azure: "404 Web Site not found"
```

## 5. Post-Exploitation

Once certificates and cloud assets are mapped, the next step is enrichment and correlation.

- **Build a certificate timeline.** For each host, record the first and last appearance in CT logs. New hosts are likely recent deployments; disappeared hosts are candidates for takeover.
- **Cross-reference with DNS data.** A certificate can exist for a host that no longer resolves. The mismatch is a strong signal for infrastructure changes.
- **Correlate cloud IPs with ASN.** Cloud providers have public IP ranges. ASN mapping (from Domains and DNS file) refines this.
- **Enumerate cloud regions.** A certificate for `api.eu-west-1.example.com` implies an EU region deployment. This helps scope the enumeration.
- **Storage bucket graph.** Map all discovered buckets to their owners (via HTTP response metadata or bucket policies). Shared buckets may indicate shared services.

```bash
# Enrich with CT log timeline (using crt.sh JSON)
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[] | [.not_before, .name_value] | @tsv' | sort
```

## 6. Preventive Controls

Defenders can reduce certificate and cloud exposure.

- **Inventory all certificates.** Use a CT monitoring service (e.g. Cert Spotter, Facebook CT Monitor) to alert on new certificates for organization domains.
- **Limit wildcard certificates.** Wildcard certificates reduce operational overhead but broaden the impact of a leaked key. Split wildcards by environment.
- **Name buckets intentionally.** Avoid using the organization's name in bucket names unless the bucket is meant to be public. Use opaque names for private data.
- **Enforce bucket policies.** Even for private buckets, set explicit policies that deny anonymous access. AWS Block Public Access is a baseline.
- **Rotate certificates on schedule.** Short-lived certificates (Let's Encrypt) reduce the window of compromise. Automate renewal.
- **Audit cloud asset inventories.** Tag all cloud resources; regularly review the inventory for orphaned or unmanaged assets.

## 7. Detection Controls

Detection focuses on unauthorized certificate issuance, bucket takeover, and unusual cloud access patterns.

- **CT log monitoring.** Alert on any new certificate for organization domains from an unexpected issuer or for an unexpected host.
- **Bucket access logs.** Cloud storage services provide access logs; monitor for requests from unexpected IPs or user agents.
- **CNAME target monitoring.** Alert if a CNAME record points to a provider endpoint that returns a "no such resource" error.
- **CloudTrail / GCP Audit Logs / Azure Activity Log.** Monitor for unauthorized IAM changes, bucket policy changes, and function invocations.
- **DNS anomaly detection.** A sudden surge of queries to a specific subdomain can indicate enumeration or targeted attack.

## 8. Verification

- **Confirm CT log entry with live resolution.** A CT entry proves a certificate was issued; it does not prove the host is currently serving. Always verify with a fresh DNS lookup or TLS handshake.
- **Confirm bucket ownership before claiming.** In an authorized engagement, verify that the bucket reference is real and unowned. In some cases, the reference is stale from a deleted application and no live service depends on it.
- **Check issuer legitimacy.** CT logs can contain certificates issued by compromised CAs; in rare cases, a rogue certificate appears. Cross-check with CA reputation.
- **Verify cloud region.** A host may resolve to any region depending on load balancer rules. Do not assume the region from the hostname alone.

## 9. Pentest and Red Team Application

- **Phase 1 - Certificate harvest.** Collect all certificates for the organization via crt.sh and Censys.
- **Phase 2 - Host mapping.** Extract all unique SANs and resolve them to live hosts.
- **Phase 3 - Cloud asset enumeration.** Check for dangling buckets, function URLs, and origin services behind CDNs.
- **Phase 4 - Prioritization.** Rank hosts by exposure and by the sensitivity of the data they serve.

Red team note: certificate transparency is a two-edged tool. It gives defenders the same visibility as attackers. If a red team uses a new domain or certificate for C2 infrastructure, that certificate will be logged publicly; do not use CT-visible certificates for covert infrastructure.

## 10. Legal and Ethical Notes

- **Certificate Transparency is public by design.** Using CT logs for security research is lawful and expected.
- **Cloud bucket probing requires care.** Attempting to register a bucket is an active action that may violate the cloud provider's terms of service. Only do it in an authorized engagement and with written scope.
- **Do not perform bucket takeovers outside an engagement.** Claiming a bucket that belongs to another organization, even one that appears abandoned, can be a legal violation.
- **Respect rate limits.** crt.sh and Censys have rate limits. Use batch queries and caching.

## 11. Production Notes

- **Automate certificate inventory.** Use an API-driven CT log monitor rather than manual crt.sh queries; this scales and provides timestamps.
- **Use separate CT log monitors for production and staging.** Staging hosts often appear in CT logs and confuse inventory.
- **Cache CT log results.** CT logs are append-only; a local cache of host -> certificate mapping is cheap and makes future queries instant.
- **Tag cloud resources with owner and environment.** This is essential for attribution during incident response.
- **Do not assume a cloud resource is safe because it is private.** Many cloud misconfigurations involve private buckets that inadvertently allow access via public endpoints.

## 12. References

- Certificate Transparency - https://certificate.transparency.dev/
- crt.sh - https://crt.sh/
- Censys - https://censys.io/
- Shodan - https://www.shodan.io/
- RFC 6962 - Certificate Transparency - https://datatracker.ietf.org/doc/html/rfc6962
- AWS IP Ranges - https://ip-ranges.amazonaws.com/ip-ranges.json
- Google Cloud IP Ranges - https://cloud.google.com/compute/docs/faq#find_ip_range
- Azure IP Ranges - https://www.microsoft.com/en-us/download/details.aspx?id=56519
- Let's Encrypt - https://letsencrypt.org/