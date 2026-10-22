# Mobile Sandbox Security

> [!CAUTION]
> Educational reference only. Escape techniques must be used exclusively in
> authorized testing, CTF environments, or your own isolated lab. Running them
> against systems you do not own is illegal.

## 1. Overview

Mobile platforms (iOS and Android) run third-party code that the user
downloaded from an app store or side-loaded from the internet. The platform
must contain that code so a malicious app cannot read another app's data,
access the user's photos without permission, or compromise the OS.

The mobile sandbox is stricter than a desktop OS-level sandbox. Each app
runs as its own user (UID) on Android, in its own container on iOS, with a
per-app data directory that no other app can read. Privileged APIs are
reachable only through mediated interfaces that check the app's declared
permissions or entitlements.

This file covers how the mobile sandbox works, where it has broken, and how
to test and harden it.

## 2. Threat Model

The mobile sandbox defends against:

- A malicious app installed by the user (from a store, a side-load, or a
  malicious MDM profile).
- A compromised legitimate app (supply-chain compromise of an SDK).
- A web page rendered inside an in-app WebView (partially - WebView has its
  own sandbox).
- Malicious content that exploits a media parser or a system service.

What it does NOT defend against:

- A user who grants a dangerous permission (camera, contacts, location).
- A jailbroken or rooted device, where the OS-level guarantees are removed.
- A malicious app that uses an accessibility service to read other apps'
  screens (an intentional capability, not a sandbox escape).
- A baseband or bootloader compromise (out of scope for the app sandbox).

## 3. How the Mobile Sandbox Works

### 3.1 Android

Android sandbox primitives:

- **Per-app UID**: each app gets a unique Linux UID; two apps cannot read
  each other's files by default.
- **SELinux**: mandatory access control; the app runs in an untrusted domain
  (`untrusted_app`) with a narrow policy.
- **App data directory**: `/data/data/<package>/` is owned by the app's UID
  and mode `0700`.
- **Permissions**: declared in the manifest, granted at install or at
  runtime; enforced by the system server.
- **Scoped storage**: apps access shared storage through a mediated API
  (`MediaStore`, SAF) rather than raw filesystem paths.
- **Isolated processes**: some components (WebView renderer, certain media
  codecs) run in isolated processes with no permissions.
- **Verified boot + dm-verity**: protects the system partition from tampering.

Android 10+ strengthened the sandbox with scoped storage; Android 11+
added per-app storage and one-time permissions. Android 12+ added the
`android:exported` requirement for components.

### 3.2 iOS

iOS sandbox primitives:

- **Per-app container**: each app gets a private container under
  `/var/mobile/Containers/Data/Application/<UUID>/`; no other app can read it.
- **Seatbelt profile**: a per-app sandbox profile limits file, network, and
  IPC access.
- **Entitlements**: privileged capabilities (keychain groups, app groups,
  push, background modes) are code-signed entitlements checked by the kernel.
- **Code signing**: every executable page must be signed; the kernel refuses
  unsigned code.
- **Pointer authentication (PAC)**: on ARM64e, protects return addresses and
  function pointers.
- **Data Protection**: files are encrypted with a key derived from the
  device passcode and the app's class key.

App Store review is a policy control, not a technical sandbox; it is not
part of the isolation boundary.

### 3.3 Inter-Process Communication

Both platforms mediate IPC:

- Android: Intents, Binder, ContentProviders, bound services. Each has an
  exported flag and a permission check.
- iOS: XPC (system services), URL schemes, app extensions, shared
  containers (app groups).

An exported component without a permission check is the most common
mobile-app security defect.

## 4. Common Attack Vectors

### 4.1 Exported Components

An Android component (Activity, Service, Receiver, Provider) declared
`android:exported="true"` without a permission is reachable by any app on
the device.

The classic issue: an exported ContentProvider with a path traversal in its
`openFile` implementation, reachable by any installed app.

### 4.2 Intent Redirection

An exported Activity that forwards an Intent to a private component without
validating the caller lets a malicious app reach a component it should not.

### 4.3 Deep Link and URL Scheme Hijacking

A custom URL scheme (`myapp://`) can be registered by any app, so a
malicious app can intercept the callback. Universal Links (iOS) and App
Links (Android) with domain verification are the mitigation.

### 4.4 WebView Misconfiguration

A WebView with JavaScript enabled, a permissive `WebViewClient`, and a
JavaScript bridge can expose native functionality to web content. If the
app loads untrusted URLs in that WebView, the web content reaches native code.

### 4.5 Insecure Data Storage

App data written to external storage, world-readable files, or unencrypted
databases. Not a sandbox escape, but a data-exposure defect that defeats the
confidentiality the sandbox is meant to provide.

### 4.6 Kernel and Driver Bugs

The mobile kernel is reachable from the app through system calls and device
drivers (GPU, media, Wi-Fi). A memory-safety bug in a driver is a
kernel-level escape.

Android's `binder` driver and the media codecs (`Stagefright` class) are
historically the largest attack surfaces.

### 4.7 Jailbreak and Root Detection Bypass

On a jailbroken or rooted device, the OS-level guarantees are removed. An
app that handles sensitive data should detect the compromise, but the
detection is a mitigation, not a sandbox.

### 4.8 Accessibility Service Abuse

An app with the Accessibility permission can read the screen content of
other apps. This is an intentional capability, not a sandbox escape, but it
is abused by banking trojans. The permission should be treated as highly
privileged.

## 5. Exploitation Recipes

### 5.1 Android: Enumerate Exported Components

From a connected device with `adb` and an authorized test build:

```bash
# list packages
adb shell pm list packages | grep <target>

# dump the manifest (requires the APK)
adb shell pm path <package>
adb pull <apk_path> target.apk

# use a manifest viewer (apktool, aapt, jadx) to list exported components
aapt dump xmltree target.apk AndroidManifest.xml | grep -E 'exported|name='
```

Expected: a list of components with their `exported` value and any
`permission` attribute. An exported component with no permission is
reachable by any app.

### 5.2 Android: Test an Exported Provider

```bash
# query an exported content provider
adb shell content query --uri content://<authority>/<path>

# insert (write) to an exported provider
adb shell content insert --uri content://<authority>/<path> \
  --bind <column>:s:<value>

# call a method on an exported service
adb shell am startservice -n <package>/<service> --es key value
```

If the provider responds without a permission error, the component is
insecure.

### 5.3 Android: Intent Redirection Probe

```bash
# send an Intent to an exported Activity that forwards its extras
adb shell am start -n <package>/<activity> \
  --es forwarded_intent "intent:#Intent;component=<package>/<private_component>;end"
```

The private component should reject the request; if it runs, the redirect
is exploitable.

### 5.4 iOS: Inspect Entitlements

From an authorized test build with a decrypted IPA:

```bash
# extract entitlements from a signed binary
codesign -d --entitlements :- Payload/<App>.app/<App>

# list URL schemes and app groups
plutil -p Payload/<App>.app/Info.plist | grep -E 'URLSchemes|AppGroup'
```

Expected: a list of entitlements and declared URL schemes. Any privileged
entitlement the app does not need is a hardening gap.

### 5.5 iOS: URL Scheme Reachability

```bash
# trigger a registered URL scheme from another app or Safari
xcrun simctl openurl booted "myapp://callback?token=test"
```

If the app accepts the URL without validating the source, the scheme is
hijackable.

## 6. Post-Exploitation

Mobile post-exploitation depends on what was reached.

App data compromise (no sandbox escape):

- Read the app's own container (tokens, cached data, local databases).
- Access the app's keychain items (iOS) or keystore entries (Android).
- Call the app's private components through the exported one.

OS-level compromise (root/jailbreak or kernel bug):

- Read every app's data.
- Install a persistent implant.
- Bypass platform code signing and integrity checks.

Most mobile bug-bounty reports stop at the first level. OS-level compromise
on a modern device requires a chain of kernel and hardware mitigations
bypasses.

## 7. Preventive Controls

- Declare `android:exported="false"` for every component that does not need
  to be reachable by other apps; add a signature-level permission to the
  ones that do.
- Validate every Intent and URL before acting on it; do not blindly
  forward Intents.
- Use Android App Links / iOS Universal Links with domain verification
  instead of custom URL schemes for authentication callbacks.
- Disable JavaScript in WebViews that display untrusted content; never expose
  a `@JavascriptInterface` to untrusted pages.
- Store secrets in the platform keystore (Android Keystore, iOS Keychain),
  not in shared preferences or user defaults.
- Enable scoped storage (Android 10+) and avoid external storage for app data.
- Detect rooted/jailbroken devices for high-value apps (mitigation, not a
  sandbox).
- Treat the Accessibility permission as highly privileged; require explicit
  user consent with context.
- Keep the OS and apps patched; kernel and media-codec bugs are the primary
  escape vectors.

## 8. Detection Controls

- Monitor for apps requesting Accessibility or Device Admin permissions.
- Alert on exported components being invoked by an unexpected app.
- Detect rooted/jailbroken state and integrity-check failures at runtime.
- Monitor unusual Binder/XPC traffic from third-party apps.
- For enterprise, use MDM to enforce OS version, patch level, and app
  allow-listing.
- On-device: Play Protect (Android) and notarization (iOS) provide some
  malware detection, but they are not part of the sandbox.

## 9. Verification

To verify a mobile app's sandbox posture:

1. Enumerate all exported components and confirm each one is intentional
   (section 5.1).
2. Test each exported component for missing permission checks.
3. Confirm no WebView loads untrusted URLs with JavaScript and a bridge.
4. Confirm secrets are in the platform keystore, not plain files.
5. Confirm URL schemes/Universal Links validate the caller.
6. For the platform: confirm the OS is patched and not rooted/jailbroken.

## 10. References

- Android security overview - https://source.android.com/docs/security
- Android app sandbox - https://source.android.com/docs/security/app-sandbox
- Android scoped storage - https://developer.android.com/training/data-storage
- iOS App Sandbox - https://developer.apple.com/documentation/security/app_sandbox
- iOS Security Guide - https://support.apple.com/guide/security/welcome/web
- OWASP Mobile Application Security - https://mas.owasp.org/
- OWASP MASVS - https://mas.owasp.org/MASVS/
- NIST SP 800-163 Rev. 1, Vetting the Security of Mobile Applications - https://csrc.nist.gov/pubs/sp/800/163/r1/final