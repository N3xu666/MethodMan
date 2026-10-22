# Sandbox Evasion and Detection

This file covers techniques used by malware and attackers to detect, evade, and escape application sandboxes and isolated execution environments (browsers, PDF readers, document viewers, and OS-level sandboxes). It also covers defensive controls to detect evasion attempts.

## 1. Overview

A sandbox is an isolated execution environment designed to run untrusted code safely. Examples include browser renderer sandboxes, PDF reader sandboxes, OS-level sandboxes (macOS App Sandbox, Windows AppContainer), and mobile app sandboxes (iOS, Android).

Attackers use sandbox evasion to:

- Prevent analysis by security researchers.
- Detect if the code is running in a sandbox and change behavior.
- Escape the sandbox to compromise the host.

This file focuses on detection and evasion techniques, with a brief look at actual escapes.

## 2. Sandbox Types

- **Browser sandboxes:** Chromium (renderer sandbox), Firefox (content process sandbox). Escape often involves a browser bug plus a kernel bug.
- **Document sandboxes:** Adobe Reader Protected Mode, Microsoft Office Protected View.
- **OS sandboxes:** macOS App Sandbox, Windows AppContainer, Linux Flatpak/Snap confinement.
- **Mobile sandboxes:** iOS app sandbox, Android app sandbox.
- **Analysis sandboxes:** Cuckoo, Any.run, Joe Sandbox, CAPE.

## 3. Evasion Techniques

### 3.1 Environment Fingerprinting

Malware checks for signs of a sandbox:

- Usernames like `sandbox`, `malware`, `virus`, `cuckoo`.
- Computer names with `SANDBOX`, `MALWARE`, `VIRUS`.
- Low disk size or low RAM.
- Missing user activity (no recent documents, no mouse movement).
- Running in a VM (check for `VBox`, `VMware`, `QEMU` artifacts in hardware IDs).

### 3.2 Timing Attacks

Malware measures execution time. Sandboxes often use accelerated time or fast-forwarding. If the elapsed time is too short or too predictable, the code may refuse to run.

### 3.3 API Hooking Detection

Malware checks if critical APIs are hooked (e.g., by a sandbox monitoring tool). It can compare in-memory function bytes with the on-disk version of the DLL.

### 3.4 Human Interaction Checks

Malware waits for mouse movement or keyboard input. Automated sandboxes often provide no such input.

### 3.5 Network Checks

Malware checks for internet connectivity, DNS resolution, or specific domains. Sandboxes may block or simulate network access.

## 4. Sandbox Escape Techniques

### 4.1 Browser Sandbox Escape

A browser exploit chain usually involves:

1. A renderer bug (e.g., V8 type confusion) to get code execution in the renderer process.
2. A sandbox escape bug (e.g., a Windows kernel bug or a bug in the broker process) to escape the sandbox and run code on the host.

### 4.2 Document Sandbox Escape

PDF readers and Office applications run in a sandbox. An escape requires a bug in the sandbox implementation (e.g., a Windows AppContainer escape or a macOS sandbox profile bug).

### 4.3 OS Sandbox Escape

OS-level sandboxes (AppContainer, App Sandbox) can be escaped via kernel bugs or misconfigurations (e.g., overly permissive entitlements).

## 5. Exploitation Recipes

### 5.1 Checking for a Sandbox Environment

```powershell
# Check for common sandbox artifacts.
$username = whoami
$computername = hostname
$ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
$disk = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").Size

Write-Host "User: $username"
Write-Host "Host: $computername"
Write-Host "RAM: $ram"
Write-Host "Disk: $disk"
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
User: sandbox\user
Host: SANDBOX-PC
RAM: 2147483648
Disk: 32212254720
```

### 5.2 Detecting a VM

```bash
# Check for VM artifacts on Linux.
$ dmesg | grep -i "virtual"
$ systemd-detect-virt
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-1 04/01/2014
kvm
```

## 6. Defensive Controls

- **Harden sandbox configurations:** use the strongest sandbox profile available (e.g., Chromium's `--enable-sandbox`, macOS App Sandbox).
- **Keep sandboxes patched:** browser sandbox escapes are often fixed quickly.
- **Use hardware-assisted isolation:** Windows Defender Application Guard (WDAG), macOS System Integrity Protection (SIP).
- **Monitor for evasion:** endpoint detection and response (EDR) can detect timing checks, API hooking checks, and VM detection.

## 7. Detection Controls

- **Behavioral analysis:** detect timing anomalies, API hooking checks, and environment fingerprinting.
- **EDR telemetry:** monitor for processes that check hardware IDs, RAM size, or disk size.
- **Sandbox hardening:** use a sandbox that hides its artifacts (e.g., spoof MAC addresses, hardware IDs).
- **Threat intelligence:** track known evasion techniques and update detection rules.

## 8. Verification

To verify sandbox isolation:

- Run a known sandbox-evading sample in a lab sandbox and confirm that the sandbox detects the evasion attempt.
- Check that the sandbox hides common artifacts (e.g., VM strings, low RAM).
- Use a tool like `pafish` to test sandbox detection capabilities.

## 9. Production Notes

- In malware analysis, assume that sophisticated samples will detect and evade the sandbox.
- Use multiple sandbox types (emulation, full virtualization, bare-metal) to increase coverage.
- Monitor for sandbox escapes as a high-severity event.

## 10. References

- MITRE ATT&CK: Virtualization/Sandbox Evasion (T1497) - https://attack.mitre.org/techniques/T1497/
- Chromium Sandbox documentation - https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- pafish (sandbox detection tool) - https://github.com/a0rtega/pafish
- Windows Defender Application Guard - https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-defender-application-guard/
- macOS App Sandbox documentation - https://developer.apple.com/documentation/security/app_sandbox
- Cuckoo Sandbox - https://cuckoosandbox.org/