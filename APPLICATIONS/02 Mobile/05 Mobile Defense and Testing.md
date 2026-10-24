# Mobile Defense and Testing

> [!NOTE]
> This document is for authorized security testing, educational purposes, and defensive engineering only. Do not use these techniques against applications you do not own or have explicit permission to test.

## 1. Overview

This file covers what is not platform-specific: the testing methodology, the supply chain (M2), privacy controls (M6), and the defensive/CI side.

The OWASP Mobile Application Security (MAS) project provides two complementary resources:

- **MASVS** (Mobile Application Security Verification Standard) - what to verify, organized into 8 categories and 3 assurance levels (L1, L2, R).
- **MASTG** (Mobile Application Security Testing Guide) - how to verify it, with concrete test cases per platform.

**MASVS assurance levels:**

| Level | Meaning | When to use |
|-------|---------|-------------|
| L1 | Baseline | All mobile apps |
| L2 | Defense-in-depth | Apps handling sensitive data (finance, health, enterprise) |
| R | Resilience | Apps that need anti-tampering / anti-reverse-engineering (DRM, banking, government) |

L1 + L2 are about correctness; R is about resilience and is optional (only if the threat model requires it).

## 2. Reconnaissance / Enumeration

### 2.1 Test environment

| Component | Android | iOS |
|-----------|---------|-----|
| Device | Rooted (Magisk) or emulator with writable system | Jailbroken (checkra1n, palera1n, Dopamine) or Corellium |
| Runtime hooking | Frida server | Frida server (from Cydia/Sileo) |
| Traffic interception | mitmproxy / Burp with user CA | mitmproxy / Burp with user CA (trusted in Settings) |
| Static analysis | jadx, apktool, Ghidra | class-dump, Hopper, Ghidra, otool |
| Automated | MobSF | MobSF |
| Dynamic instrumentation | Objection, Frida scripts | Objection, Frida scripts |

### 2.2 Test plan

1. **Scope** - list the apps, versions, and backend APIs.
2. **Static** - manifest/plist, permissions, exported components, hardcoded secrets, pinning, ATS/cleartext, debuggable flag.
3. **Dynamic** - install, launch, browse all screens, capture traffic, exercise deep links and IPC.
4. **Abuse** - try exported components, content providers, WebView bridges, deep links, jailbreak/root detection bypass, pinning bypass.
5. **Backend** - test the API directly (auth, IDOR, rate limiting, token lifetime).
6. **Report** - per MASVS category, with severity and evidence.

### 2.3 Automated scan with MobSF

```bash
# Docker (recommended for isolation)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Upload APK/IPA via the web UI at http://localhost:8000
# Or use the REST API:
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: <API_KEY>"
```

**Expected output:** JSON with `scan_type`, `hash`, `file_name`; then `POST /api/v1/scan` with the hash triggers static analysis.

### 2.4 CI integration

MobSF can run as a CI step (GitHub Actions, GitLab CI). Minimal pattern:

```yaml
- name: MobSF scan
  run: |
    curl -F "file=@app-release.apk" $MOBSF_URL/api/v1/upload -H "Authorization: $MOBSF_API_KEY" -o upload.json
    HASH=$(jq -r '.hash' upload.json)
    curl -X POST $MOBSF_URL/api/v1/scan -H "Authorization: $MOBSF_API_KEY" -d "hash=$HASH"
    curl -X POST $MOBSF_URL/api/v1/report_json -H "Authorization: $MOBSF_API_KEY" -d "hash=$HASH" -o report.json
```

**Expected output:** `report.json` with findings; fail the build if high-severity issues are present.

## 3. Common Attack Vectors

### 3.1 Supply chain (M2)

Mobile apps bundle third-party SDKs (analytics, ads, crash reporting, payments). Each SDK is code that runs with the app's permissions.

Risks:

- Vulnerable SDK version (e.g. old OkHttp, old WebView bridge).
- Malicious SDK (data exfiltration, hidden tracking).
- Dependency confusion in the build pipeline.
- Repackaged app distributed outside official stores.

**Pentest angle:** enumerate embedded frameworks (`Frameworks/` in IPA, `lib/<abi>/` and `classes.dex` in APK), check versions against known CVEs, look for unexpected network calls.

**AppSec angle:** maintain a Software Bill of Materials (SBOM), scan dependencies (OWASP Dependency-Check, `snyk`, `trivy`), pin SDK versions, review SDK permissions, use Play Integrity / App Attest to detect repackaging.

### 3.2 Privacy controls (M6)

Risks:

- Excessive data collection (contacts, location, clipboard, device identifiers).
- Data shared with third parties without consent.
- Analytics containing PII.
- Clipboard snooping (iOS 14+ shows a banner; Android 10+ restricts background clipboard access).

**Pentest angle:** capture traffic, look for PII in analytics, check clipboard access, check permission requests vs. actual use.

**AppSec angle:** data minimization, consent flows, privacy manifest (iOS `PrivacyInfo.xcprivacy`, required since 2024), Google Play Data Safety declaration, no PII in logs.

### 3.3 Backend API testing

The mobile app is a client. The backend must not trust it.

Common backend issues:

- Broken object-level authorization (BOLA/IDOR) - the #1 API risk (OWASP API Top 10).
- Weak token lifetime / no revocation.
- No rate limiting (credential stuffing, enumeration).
- Verbose error messages leaking stack traces.

**Pentest angle:** extract tokens from the app, replay them with `curl`/Burp, mutate IDs, test role boundaries.

**AppSec angle:** server-side authorization on every request, short-lived tokens with refresh, rate limiting per user/IP, generic error messages.## 4. Exploitation Recipes

### 4.1 Automated static analysis (MobSF)

```bash
# Upload and scan
curl -s -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: $MOBSF_API_KEY" -o upload.json
HASH=$(jq -r '.hash' upload.json)
curl -s -X POST http://localhost:8000/api/v1/scan -H "Authorization: $MOBSF_API_KEY" -d "hash=$HASH"
curl -s -X POST http://localhost:8000/api/v1/report_json -H "Authorization: $MOBSF_API_KEY" -d "hash=$HASH" -o report.json
jq '.appsec | to_entries[] | select(.value.severity == "high")' report.json
```

**Expected output:** JSON list of high-severity findings (hardcoded secrets, exported components, cleartext, weak crypto).

### 4.2 Dynamic analysis (MobSF dynamic + Frida)

```bash
# Start MobSF dynamic analyzer (requires a rooted Android emulator or Genymotion)
# In the MobSF UI: Dynamic Analysis -> select the device -> Start
# MobSF injects Frida and captures traffic, logs, API calls
```

**Expected output:** MobSF dynamic report with API calls, file accesses, and Frida logs.

### 4.3 Frida script library (universal bypasses)

Combine the platform-specific bypasses into one script per test:

```javascript
// Android: root + SSL pinning bypass (see 03 Android Security.md for the full version)
Java.perform(function() {
    // ... RootBeer + File.exists + TrustManager hooks ...
});
```

```javascript
// iOS: jailbreak + SSL pinning bypass (see 04 iOS Security.md for the full version)
if (ObjC.available) {
    // ... NSFileManager + NSURLSession hooks ...
}
```

**Expected output:** App starts without warnings; `mitmproxy` shows decrypted traffic.

### 4.4 Backend API testing (from the app's token)

```bash
# Extract the token from the app (shared_prefs on Android, keychain/NSUserDefaults on iOS)
TOKEN="<extracted_token>"

# Replay against the API
curl -s -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/1234

# IDOR check: mutate the ID
curl -s -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/users/1235
```

**Expected output:** `200 OK` with user 1234's data; if 1235 also returns `200 OK` with another user's data, that is BOLA/IDOR.

### 4.5 SBOM generation (supply chain)

```bash
# Android: list native libraries and DEX files
unzip -l app.apk | grep -E "lib/|classes.*dex"

# iOS: list embedded frameworks
unzip -l app.ipa | grep -E "Frameworks/|\.dylib"

# Dependency scan (Android Gradle project)
./gradlew app:dependencies > deps.txt
# Or use syft for a CycloneDX SBOM
syft app.apk -o cyclonedx-json > sbom.json
```

**Expected output:** `sbom.json` (CycloneDX) with all components and versions; cross-reference against CVE databases.

### 4.6 Privacy manifest check (iOS)

Since 2024, apps that use certain APIs must declare them in `PrivacyInfo.xcprivacy`. Missing declarations are rejected by App Store review and are a privacy finding.

```bash
# Check for the privacy manifest in the IPA
unzip -l app.ipa | grep PrivacyInfo.xcprivacy
# Inspect the declared API categories
plutil -p app-decoded/Payload/App.app/PrivacyInfo.xcprivacy
```

**Expected output:** `PrivacyInfo.xcprivacy` present with `NSPrivacyAccessedAPITypes` declared; missing file = finding.

## 5. Post-Exploitation

- **Report per MASVS category:** STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY. Each finding: title, severity, MASVS ID, MASTG test ID, evidence (screenshot/log), remediation.
- **Evidence:** screenshots (device), Frida console output, `mitmproxy` flows (export as HAR), MobSF report JSON.
- **Severity:** use CVSS 3.1 or the MASVS severity model; align with the client's risk appetite.
- **Retest:** after fixes, re-run the same MASTG test cases; do not accept "fixed" without evidence.
- **SBOM handover:** provide the SBOM and the list of SDK versions to the client's AppSec team.

## 6. Preventive Controls (AppSec)

| Area | Control |
|------|---------|
| SDLC | Threat model per app; security requirements in the backlog (MASVS L1/L2); security review before release |
| CI/CD | MobSF scan on every build; dependency scan (`snyk`, `trivy`, OWASP Dependency-Check); SBOM generation (CycloneDX); signed builds |
| Supply chain | Pin SDK versions; review SDK permissions and network calls; vendor security questionnaires; monitor CVEs for embedded SDKs |
| Privacy | Data minimization; consent flows; privacy manifest (iOS); Data Safety declaration (Google Play); no PII in logs or analytics |
| Secrets | No hardcoded secrets; use Keystore/Keychain; rotate on leak; secret scanning in CI (gitleaks, trufflehog) |
| Release | Play Integrity / App Attest configured server-side; RASP if the threat model requires it; certificate pinning |
| Monitoring | Backend anomaly detection; pinning failure telemetry; crash reports without PII |

## 7. Detection Controls (AppSec)

- **Integrity attestation:** Play Integrity API (Android), App Attest (iOS). Server rejects requests with invalid attestation (with a grace path for legitimate edge cases).
- **RASP telemetry:** if the app detects Frida/Xposed/jailbreak, send a signal to the backend (rate-limited). Do not hard-block on the client alone.
- **Anomaly detection:** impossible travel, unusual API call patterns, device fingerprint changes.
- **Certificate transparency monitoring:** detect unauthorized certificates for the app's domains.
- **Store monitoring:** detect repackaged apps on third-party stores (Google Play Protect, manual review).

## 8. Verification (AppSec)

- **MASTG checklist:** run the test cases per MASVS category for the target level (L1 or L2; add R if required).
- **MobSF score:** track the MobSF security score over releases (regression detection).
- **SBOM diff:** compare SBOMs between releases; any new dependency is reviewed.
- **Privacy manifest:** verify `PrivacyInfo.xcprivacy` is present and correct for iOS; verify Data Safety for Android.
- **Retest:** after remediation, rerun the exact MASTG test cases and capture evidence.

**Minimum gate for release (L2):**

- 0 high-severity findings in MobSF.
- 0 hardcoded secrets (verified by gitleaks/trufflehog).
- All exported components justified and permission-protected.
- Certificate pinning + ATS strict (iOS) / Network Security Config (Android).
- Play Integrity / App Attest configured server-side.
- Privacy manifest present (iOS) and Data Safety declared (Android).
- SBOM generated and reviewed.

## 9. References

- OWASP MASVS - https://mas.owasp.org/MASVS/
- OWASP MASTG - https://mas.owasp.org/MASTG/
- OWASP Mobile Top 10 - https://owasp.org/www-project-mobile-top-10/
- MobSF - https://github.com/MobSF/Mobile-Security-Framework-MobSF
- MobSF REST API - https://mobsf.github.io/docs/#/rest_api
- Frida - https://frida.re/docs/home/
- Objection - https://github.com/sensepost/objection
- OWASP Dependency-Check - https://owasp.org/www-project-dependency-check/
- Syft (SBOM) - https://github.com/anchore/syft
- CycloneDX - https://cyclonedx.org/
- Apple Privacy Manifest - https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
- Google Play Data Safety - https://support.google.com/googleplay/android-developer/answer/10787469
- Play Integrity API - https://developer.android.com/google/play/integrity
- App Attest - https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity