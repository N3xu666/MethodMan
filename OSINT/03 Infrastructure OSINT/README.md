# 03 Infrastructure OSINT

Infrastructure OSINT maps an organization's technical estate from public
sources: domains, subdomains, certificates, DNS records, cloud assets,
and exposed services. It is the technical counterpart to people search
and the primary input to external attack surface discovery.

This subcategory covers the sources, the techniques, and the legal
boundaries that apply when mapping someone else's infrastructure.

## Scope

- Domain and subdomain enumeration (passive).
- DNS records: A, AAAA, MX, TXT, CNAME, NS, SOA.
- Certificate Transparency logs (crt.sh, Censys).
- Cloud asset discovery (S3, Azure Blob, GCP Storage).
- Search engines for internet-connected devices (Shodan, Censys, FOFA).
- BGP and ASN mapping.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [Infrastructure OSINT Fundamentals](./01%20Infrastructure-OSINT-Fundamentals.md) | Two-track |
| 02 | [Domains and DNS](./02%20Domains-and-DNS.md) | Two-track |
| 03 | [Certificates and Cloud Assets](./03%20Certificates-and-Cloud-Assets.md) | Two-track |
| 04 | [Shodan and Censys](./04%20Shodan-and-Censys.md) | Two-track |

Files are added one at a time. A row appears here only when the file exists.

## Format

Two-track (Offensive / Defensive) plus a `## Pentest and Red Team
Application` section. See the category [README](../README.md) for the
full skeleton and the legal notes.

## Related

- 01 OSINT Methodology - collection planning and source evaluation.
- 02 People Search - identity resolution and public records.
- 04 Social Media and Content - platform-specific collection.
- 05 Corporate and Business OSINT - registries and org mapping.

## References

- OSINT Framework - https://osintframework.com/
- crt.sh Certificate Search - https://crt.sh/
- Shodan - https://www.shodan.io/
- Censys - https://search.censys.io/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
