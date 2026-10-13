# OWASP Top 10 - Web Application Security Risks



> **Version note:** This section uses **OWASP Top 10:2021** as the practical

> baseline for OSCP-oriented techniques (SSRF, Injection, XXE). For the

> production-oriented 2025 revision (Supply Chain, Exceptional Conditions),

> see [2021-vs-2025.md](./2021-vs-2025.md).

> Official source: https://owasp.org/Top10/



---



## Purpose



This section maps the OWASP Top 10:2021 categories to the existing

`02 Web/` content. It is a **navigational layer**, not a replacement for

the technical files under `01 Recon/`, `02 Frameworks/`, `03 Languages/`,

`04 Servers/`, `05 CMS/`, `06 Technologies/`, and `07 Vulnerabilities/`.



Each category below lists:



- a one-sentence description of the risk;

- the files in `02 Web/` that cover it;

- a coverage status: `Covered`, `Partial`, or `Missing`.



---



## Coverage map (2021)



| # | Category | Coverage | Where |

|---|----------|----------|-------|

| A01 | Broken Access Control | Partial | `07 Vulnerabilities/IDOR.md`, `SSRF.md`, `Open-Redirect.md`, `CSRF.md` |

| A02 | Cryptographic Failures | Partial | `06 Technologies/JWT.md`, `OAuth.md` |

| A03 | Injection | Covered | `07 Vulnerabilities/SQLi.md`, `Command-Injection.md`, `SSTI.md`, `XXE.md`, `LFI-RFI.md`, `Deserialization.md` |

| A04 | Insecure Design | Missing | - |

| A05 | Security Misconfiguration | Partial | `04 Servers/` (Apache, Nginx, IIS, Tomcat, Jetty), `06 Technologies/Databases/README.md` |

| A06 | Vulnerable and Outdated Components | Partial | `05 CMS/` (WordPress, Joomla, Drupal, Magento, PrestaShop) |

| A07 | Identification and Authentication Failures | Partial | `06 Technologies/JWT.md`, `OAuth.md` |

| A08 | Software and Data Integrity Failures | Partial | `06 Technologies/Deserialization.md`, `JWT.md` |

| A09 | Security Logging and Monitoring Failures | Missing | - |

| A10 | Server-Side Request Forgery (SSRF) | Covered | `07 Vulnerabilities/SSRF.md` |



---



## A01:2021 - Broken Access Control



Access control enforces policy such that users cannot act outside of

their intended permissions. Failures typically lead to unauthorized

information disclosure, modification, or destruction of data.



**Covered in:**



- [IDOR](../07%20Vulnerabilities/IDOR.md) - insecure direct object references.

- [SSRF](../07%20Vulnerabilities/SSRF.md) - server-side request forgery (also A10:2021, merged into A01 in 2025).

- [Open-Redirect](../07%20Vulnerabilities/Open-Redirect.md) - unvalidated redirects.

- [CSRF](../07%20Vulnerabilities/CSRF.md) - cross-site request forgery.



**Gaps:** path traversal, privilege escalation, CORS misconfiguration,

forced browsing. See `A01-Broken-Access-Control.md` (planned).



---



## A02:2021 - Cryptographic Failures



Failures related to cryptography (or its absence) that lead to exposure

of sensitive data: weak algorithms, missing TLS, hardcoded keys, improper

key management.



**Covered in:**



- [JWT](../06%20Technologies/JWT.md) - JWT signing, alg confusion, weak secrets.

- [OAuth](../06%20Technologies/OAuth.md) - token handling, redirect URI validation.



**Gaps:** TLS misconfiguration, weak hashing, hardcoded secrets,

padding oracle. See `A02-Cryptographic-Failures.md` (planned).



---



## A03:2021 - Injection



User-supplied data is not validated, filtered, or sanitized, allowing

the attacker to inject code or commands into the application.



**Covered in:**



- [SQLi](../07%20Vulnerabilities/SQLi.md)

- [Command-Injection](../07%20Vulnerabilities/Command-Injection.md)

- [SSTI](../07%20Vulnerabilities/SSTI.md)

- [XXE](../07%20Vulnerabilities/XXE.md)

- [LFI-RFI](../07%20Vulnerabilities/LFI-RFI.md)

- [Deserialization](../07%20Vulnerabilities/Deserialization.md)



**Status:** fully covered. Best-covered category in the repo.



---



## A04:2021 - Insecure Design



Risks related to design and architectural flaws. Different from

implementation bugs: a secure implementation of an insecure design

is still insecure. Includes threat modeling gaps, missing rate limiting,

business logic flaws, race conditions.



**Covered in:** nothing yet.



**Gaps:** all of it. See `A04-Insecure-Design.md` (planned).



---



## A05:2021 - Security Misconfiguration



Missing hardening, unnecessary features enabled, default accounts,

verbose errors, open cloud storage, misconfigured HTTP headers.



**Covered in:**



- [Apache](../04%20Servers/Apache.md)

- [Nginx](../04%20Servers/Nginx.md)

- [IIS](../04%20Servers/IIS.md)

- [Tomcat](../04%20Servers/Tomcat.md)

- [Jetty](../04%20Servers/Jetty.md)

- [Databases overview](../06%20Technologies/Databases/README.md)



**Gaps:** a single cross-server file covering misconfig as a class

(HTTP headers, default creds, directory listing, verbose errors).

See `A05-Security-Misconfiguration.md` (planned).



---



## A06:2021 - Vulnerable and Outdated Components



Using components (libraries, frameworks, CMS) with known vulnerabilities.

Detection and exploitation of known CVEs.



**Covered in:**



- [WordPress](../05%20CMS/WordPress.md)

- [Joomla](../05%20CMS/Joomla.md)

- [Drupal](../05%20CMS/Drupal.md)

- [Magento](../05%20CMS/Magento.md)

- [PrestaShop](../05%20CMS/PrestaShop.md)

- [phpMyAdmin](../05%20CMS/phpMyAdmin.md)

- [Adminer](../05%20CMS/Adminer.md)



**Gaps:** a general file on CVE discovery workflow (WPScan, Nuclei,

exploit-db, version fingerprinting). See `A06-Vulnerable-Components.md`

(planned).



---



## A07:2021 - Identification and Authentication Failures



Weaknesses in authentication and session management: credential

stuffing, weak passwords, missing MFA, session fixation, improper

session invalidation.



**Covered in:**



- [JWT](../06%20Technologies/JWT.md)

- [OAuth](../06%20Technologies/OAuth.md)



**Gaps:** session management, credential stuffing, MFA bypass,

password reset flaws. See `A07-Auth-Failures.md` (planned).



---



## A08:2021 - Software and Data Integrity Failures



Code and infrastructure that does not protect against integrity

violations: insecure deserialization, unsigned updates, CI/CD

supply chain, untrusted data sources.



**Covered in:**



- [Deserialization](../06%20Technologies/Deserialization.md)

- [JWT](../06%20Technologies/JWT.md)



**Gaps:** supply chain attacks, CI/CD pipeline risks, unsigned

artifacts, dependency confusion. See `A08-Integrity-Failures.md`

(planned).



---



## A09:2021 - Security Logging and Monitoring Failures



Insufficient logging, detection, monitoring, and active response.

Helps attackers stay undetected, escalate, and persist.



**Covered in:** nothing yet.



**Gaps:** all of it. Note: this is the category most relevant to

defensive/blue-team work, but still relevant for pentesters (blind

vulnerabilities, evidence collection, avoiding detection in

authorized tests). See `A09-Logging-Failures.md` (planned).



---



## A10:2021 - Server-Side Request Forgery (SSRF)



The application fetches a remote resource without validating the

user-supplied URL. Allows the attacker to coerce the server into

making requests to unintended destinations.



**Covered in:**



- [SSRF](../07%20Vulnerabilities/SSRF.md)



**Status:** fully covered. In OWASP 2025, SSRF is merged into

A01 Broken Access Control.



---



## See also



- [2021-vs-2025.md](./2021-vs-2025.md) - what changed between the two revisions.

- [02 Web/README.md](../README.md) - top-level navigation for the whole section.

- [METHODOLOGY.md](../../METHODOLOGY.md) - methodology reference.

- [CHEATSHEET.md](../../CHEATSHEET.md) - command cheat sheet.

