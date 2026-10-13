# APPLICATIONS

Application security reference - pentest and AppSec tracks for web,
API, mobile, desktop, and embedded applications. Each file covers both
the offensive (detection, exploitation) and defensive (controls,
verification) sides.

---

## Categories

| # | Category | Description | Status |
|---|----------|-------------|--------|
| 1 | [Web](./01%20Web/) | Web application security reference (recon, frameworks, languages, servers, CMS, technologies, vulnerabilities, OWASP Top 10) | active |
| 2 | [API](./05%20API/) | REST, GraphQL, gRPC, WebSocket, SOAP, OAuth2, rate limiting, API gateways, OWASP API Top 10 | planned |

## Format

Two-track format (see `_WORKFLOW.md` section 6.7):

- **Pentest track** - detection, enumeration, exploitation recipes, OSCP notes.
- **AppSec track** - risk context, root causes, preventive controls,
  detection controls, verification, ASVS mapping.

Section headers use the `(AppSec)` suffix (e.g. `Risk Context (AppSec)`).

## Structure

```
APPLICATIONS/
+-- 01 Web/
|   +-- 01 Recon/
|   +-- 02 Frameworks/
|   +-- 03 Languages/
|   +-- 04 Servers/
|   +-- 05 CMS/
|   +-- 06 Technologies/
|   +-- 07 Vulnerabilities/
|   +-- 08 OWASP Top 10/
+-- 05 API/                      (planned)
    +-- 01 OWASP-API-Top-10.md
    +-- 02 REST.md
    +-- 03 GraphQL.md
    +-- 04 gRPC.md
    +-- 05 WebSocket.md
    +-- 06 SOAP.md
    +-- 07 Authentication.md
    +-- 08 Rate-Limiting.md
    +-- 09 API-Gateway.md
```

## Roadmap

- `02 Mobile/` - Android, iOS (planned).
- `03 Desktop/` - Windows, macOS, Linux desktop apps (planned).
- `04 Embedded/` - firmware, IoT (planned).

## Related

- [Methodology](../METHODOLOGY.md) - engagement phases and checklists.
- [Cheatsheet](../CHEATSHEET.md) - quick command reference.
- [OSCP Reporting](../methodology/OSCP-Reporting.md) - exam reporting rules.

