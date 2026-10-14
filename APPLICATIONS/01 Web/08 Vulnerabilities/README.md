# Vulnerabilities

> Part of [01 Web](../README.md) in the [Web Application Testing Cheatsheet](../README.md).

Web application vulnerability classes, ordered roughly by how often they
appear on OSCP/HTB and in real engagements. Each file covers detection,
manual exploitation, tooling (sqlmap, Burp, custom payloads), and the
context tags [LAB]/[PROD]/[PROD-RISK]/[PROD-NO].

---

## Files

| File | Class | Description |
|------|-------|-------------|
| [SQLi.md](./SQLi.md) | Injection | SQL injection - in-band, blind, out-of-band; DB-specific quirks. |
| [Command-Injection.md](./Command-Injection.md) | Injection | OS command injection - shell metacharacters, blind timing, OOB. |
| [SSTI.md](./SSTI.md) | Injection | Server-Side Template Injection - engine fingerprinting, sandbox escape, RCE. |
| [LFI-RFI.md](./LFI-RFI.md) | File inclusion | Local/Remote File Inclusion - wrappers, log poisoning, RFI to RCE. |
| [File-Upload.md](./File-Upload.md) | File upload | Unrestricted file upload - extension bypass, content-type tricks, webshells. |
| [XXE.md](./XXE.md) | XML | XML External Entity - file read, SSRF, blind OOB exfiltration. |
| [SSRF.md](./SSRF.md) | Request forgery | Server-Side Request Forgery - internal services, cloud metadata, gopher. |
| [CSRF.md](./CSRF.md) | Request forgery | Cross-Site Request Forgery - token bypass, SameSite, state-changing GETs. |
| [XSS.md](./XSS.md) | Client-side | Cross-Site Scripting - reflected, stored, DOM; CSP and WAF bypass. |
| [IDOR.md](./IDOR.md) | Access control | Insecure Direct Object Reference - horizontal and vertical privilege abuse. |
| [Open-Redirect.md](./Open-Redirect.md) | Access control | Open redirect - phishing, OAuth token theft, SSRF chaining. |
| [Deserialization.md](./Deserialization.md) | Deserialization | Insecure deserialization - Java, PHP, Python, .NET, Node.js, Ruby gadget chains. |

---

> See [01 Web README](../README.md) for the full subcategory map.