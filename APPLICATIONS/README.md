# APPLICATIONS

Application security reference - pentest and AppSec tracks for web,
API, mobile, desktop, and embedded applications. Each file covers both
the offensive (detection, exploitation) and defensive (controls,
verification) sides.

---

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.<br>`n> See [../SECURITY.md](../SECURITY.md) for the full policy.
## Categories

| # | Category | Description |
|---|---|---|
| 1 | [Web](./01%20Web/) | Web application security reference (recon, frameworks, languages, servers, CMS, technologies, databases, vulnerabilities, OWASP Top 10) |
| 2 | [Mobile](./02%20Mobile/) | Mobile application security reference (Android, iOS, MASVS, OWASP Mobile Top 10) |
| 3 | [API](./03%20API/) | API security reference (REST, GraphQL, gRPC, WebSocket, SOAP, authentication, rate limiting, API gateways, OWASP API Top 10) |

## Format

Two-track format:

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
|   +-- 07 Databases/
|   +-- 08 Vulnerabilities/
|   +-- 09 OWASP Top 10/
+-- 02 Mobile/
|   +-- README.md
+-- 03 API/
|   +-- 01 OWASP-API-Top-10.md
|   +-- 02 REST.md
|   +-- 03 GraphQL.md
|   +-- 04 gRPC.md
|   +-- 05 WebSocket.md
|   +-- 06 SOAP.md
|   +-- 07 Authentication.md
|   +-- 08 Rate-Limiting.md
|   +-- 09 API-Gateway.md
```
