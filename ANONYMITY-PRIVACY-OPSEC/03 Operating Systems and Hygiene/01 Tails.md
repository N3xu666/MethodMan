# Tails

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Tails (The Amnesic Incognito Live System) is a Debian-based live operating system that routes all network traffic through Tor and leaves no trace on the host machine by default. It is designed for users who need a trusted, disposable environment on an untrusted computer.

This file is a hands-on operator guide: what Tails protects against, how to install it, how to harden it, and where it still fails.

## 1. Overview

Tails is a live OS: you boot it from a USB stick, it runs entirely in RAM, and when you shut down, everything is wiped. All network traffic is forced through Tor (any direct connection is blocked by firewall rules), and the system includes Tor Browser, Thunderbird with Enigmail/OpenPGP, KeePassXC, Electrum (Bitcoin), and a persistent storage option for selected files.

Key properties:

- **Amnesic.** Nothing persists after shutdown unless you enable Persistent Storage.
- **Tor by default.** All traffic is routed through Tor; non-Tor connections are blocked by iptables.
- **Live USB.** Runs from a USB stick on almost any x86-64 computer.
- **No installation on the host.** Does not touch the host's disk unless you explicitly ask it to.
- **Signed releases.** Tails releases are signed by the Tails signing key; you verify the ISO before use.
- **Persistent Storage (optional).** Encrypted volume for selected files and settings.
- **Tor bridges and pluggable transports.** Supports obfs4 and Snowflake to bypass censorship.

Tails is the reference tool for the "I need a trusted environment on an untrusted machine" scenario. It is widely recommended by journalists, activists, and human rights organizations.

## 2. Threat Model

What Tails protects against:

- **Host compromise (software-level).** Tails does not use the host OS; it boots its own kernel and userspace.
- **Disk forensics.** The host's disk is not touched. RAM is wiped on shutdown.
- **IP leaks.** All traffic is routed through Tor; non-Tor connections are blocked.
- **DNS leaks.** DNS is resolved through Tor.
- **Traces on the host.** No files, no history, no browser cache on the host disk.
- **Malware in the host OS.** Tails runs independently of the host OS.
- **Cold boot attacks (partially).** Tails wipes RAM on shutdown.

What Tails does NOT protect against:

- **Firmware implants.** A compromised BIOS/UEFI can compromise Tails before it starts.
- **Hardware implants.** A hardware keylogger between the keyboard and the machine will capture everything.
- **Physical surveillance.** Cameras, guards, and physical access to the machine.
- **Global passive adversary.** Tor does not protect against a global adversary that observes the entire network.
- **Compromised hardware.** A machine with a hardware backdoor (e.g. Intel ME, AMD PSP) is not fully trusted even under Tails.
- **Endpoint compromise within Tails.** Malware inside the Tails session can still act.
- **User error.** Logging into a personal account, using a personal email, or writing in your usual style defeats Tails.
- **Persistent Storage leaks.** If you enable Persistent Storage, the data persists (encrypted, but present).
- **Cold boot attacks (fully).** A sophisticated attacker with physical access and specialized equipment may recover RAM contents.

Threat model summary:

| Adversary | Tails |
|-----------|-------|
| Host OS compromise | Strong |
| Disk forensics | Strong |
| Network-level IP correlation | Strong (Tor) |
| Firmware implant | None |
| Hardware keylogger | None |
| Global passive adversary | Weak (Tor limits) |
| Physical coercion | None |

## 3. How It Works (technical)

Tails boots from a USB stick and runs as a live system. On startup:

1. **Bootloader** loads the Tails kernel. The boot process can be verified with a checksum (Tails provides a verification method for the USB).
2. **Tor bootstrap.** Tails starts Tor before any user application. If Tor cannot connect, network is blocked.
3. **Firewall.** iptables rules block all traffic except Tor's SOCKS port and the Tor control port. Applications cannot bypass Tor without breaking.
4. **User session.** A GNOME desktop starts. All apps (Tor Browser, Thunderbird, KeePassXC, etc.) are pre-configured to use Tor.
5. **Shutdown.** Tails wipes RAM (kernel memory wiping via `sdmem`), unmounts the USB, and powers off.

**Persistent Storage:**

- Optional encrypted volume on the USB.
- Can store: personal files, GPG keys, SSH keys, browser bookmarks, network connections, additional software.
- Unlocked with a passphrase at boot.
- Encrypted with LUKS.

**Tor bridges and pluggable transports:**

- Tails can use obfs4 or Snowflake to bypass censorship.
- Configured at boot if direct Tor is blocked.

**Verification of the ISO:**

- Download Tails ISO and the signature.
- Verify with the Tails signing key (fetched independently).
- Verify the USB after installation with the Tails Installer's verification feature.

## 4. Installation and Setup

**Requirements:**

- A USB stick (8 GB minimum; 16 GB recommended for Persistent Storage).
- A computer that can boot from USB.
- The Tails ISO and its OpenPGP signature.

**Step 1: Download and verify the ISO (on a trusted machine):**

```bash
# Download the ISO and signature
wget https://tails.net/torrents/files/tails-amd64-x.y.z.img
wget https://tails.net/torrents/files/tails-amd64-x.y.z.img.sig

# Fetch the Tails signing key
gpg --auto-key-locate keyserver --locate-keys tails@boum.org

# Verify
gpg --verify tails-amd64-x.y.z.img.sig tails-amd64-x.y.z.img
```

Verify the fingerprint of the Tails signing key against the one published on tails.net (and other trusted sources).

**Step 2: Write the ISO to USB.**

**From Linux:**

```bash
# Identify the USB device
lsblk

# Write the ISO (assume /dev/sdX is the USB stick)
sudo dd if=tails-amd64-x.y.z.img of=/dev/sdX bs=16M status=progress oflag=sync
```

**From Windows:** use balenaEtcher or the official Tails Installer for Windows.

**From macOS:** use balenaEtcher.

**Step 3: Boot from the USB.**

- Reboot the machine and enter the boot menu (F12, F10, Esc, or Del, depending on the firmware).
- Select the USB stick.
- Tails boots. The first screen offers to configure language, region, and Tor bridges.

**Step 4 (optional): Enable Persistent Storage.**

- On the first Tails boot, choose "Persistent Storage" in the welcome screen.
- Set a strong passphrase.
- On subsequent boots, unlock Persistent Storage at the welcome screen.

**Step 5: Verify your Tails USB (recommended).**

- After booting Tails, open the "Tails" application and run "Tails Installer" - it can verify the USB.

## 5. Hardening and Configuration

**Boot hardening:**

- **Verify the ISO every time you update.** Do not skip this step.
- **Use a hardware-verified USB.** A USB stick with a physical write-protect switch (rare) is better.
- **Boot from the USB with the host disk disabled** (if the BIOS allows it).
- **Set a BIOS password** on the host to prevent unauthorized boot-order changes (physical threat model only).

**Session hardening:**

- **Do not enable Persistent Storage unless you need it.** Amnesic is the default for a reason.
- **If you do enable it, store only what you must.**
- **Use a strong passphrase for Persistent Storage.** A weak passphrase on a LUKS volume is not much better than no encryption.
- **Never unlock Persistent Storage on a machine you do not trust.** A hardware keylogger can capture the passphrase.
- **Disable Wi-Fi auto-connect.** Let Tails use its default random MAC address.
- **Do not install additional software unless you need it.** Every package is attack surface.
- **Do not use your real name, email, or social accounts.** Tails is for anonymous work.
- **Do not log in to a personal account.** This is the single most common mistake.

**Network hardening:**

- **Use Tor bridges if direct Tor is blocked.** Configure at boot.
- **Do not use a VPN with Tails.** Tails is designed for Tor, not for VPNs. Adding a VPN can break the Tor design and create new leaks.
- **Do not use a public Wi-Fi without checking the captive portal behavior.** Some captive portals leak data before authentication.

**Operational hardening:**

- **Use Tails only for activities that require it.** Do not mix.
- **Do not write in your usual style.** Stylometry is a real threat.
- **Do not check email at the same time every day.**
- **Do not reuse usernames across services.**
- **Do not print from Tails.** Printers can leak metadata.
- **Do not use the microphone or webcam unless you must.** Physical covers.

## 6. Operational Usage

**Booting:**

1. Insert the USB.
2. Reboot the machine. Enter the boot menu.
3. Select the USB.
4. Welcome screen: choose language, keyboard, region.
5. Optional: configure Tor bridges.
6. Optional: unlock Persistent Storage.
7. Click "Start Tails".

**Using Tor Browser:**

- Tails includes Tor Browser pre-configured.
- Use it as you would any Tor Browser, but remember: your traffic is Tor-only.
- Do not change security levels casually; "Safest" disables JavaScript, which is often necessary.

**Using Thunderbird (email):**

- Configure a PGP key.
- Use an anonymous email provider (see 02 Secure Communications).
- Do not configure a personal email account.

**Using KeePassXC:**

- Store passwords in KeePassXC, not in the browser.
- The database can be saved in Persistent Storage.
- Use a strong master password.

**File handling:**

- Files created during a session are wiped on shutdown unless saved to Persistent Storage.
- To transfer files in/out, use an encrypted USB (LUKS) or an onion service.
- Do not use cloud storage.

**Shutdown:**

- Tails wipes RAM on shutdown (may take a few seconds).
- Wait for the machine to power off completely before removing the USB.

**Updating Tails:**

- Tails prompts to update when an update is available.
- Verify the new ISO before use (same procedure as the initial install).
- Use "Tails Installer" to upgrade an existing USB.

## 7. Common Mistakes

Real mistakes that break Tails' protections:

1. **Logging into a personal account.** This defeats the entire purpose of Tails.
2. **Enabling Persistent Storage without a need.** Amnesia is the default for a reason.
3. **Using a weak passphrase for Persistent Storage.** LUKS with a weak passphrase is not much better than no encryption.
4. **Not verifying the ISO.** A compromised ISO compromises everything.
5. **Installing additional software.** Every package is attack surface.
6. **Using a VPN with Tails.** Tails is Tor-only by design; VPNs break the model.
7. **Writing in your usual style.** Stylometry.
8. **Using the same writing time every day.** Timing correlation.
9. **Reusing usernames or emails across services.**
10. **Printing from Tails.** Printers store metadata.
11. **Using the microphone or webcam without covers.**
12. **Trusting the host hardware.** Firmware and hardware implants are out of scope for Tails.
13. **Assuming Tails protects against physical coercion.** It does not.
14. **Using Tails on a machine with a keylogger.** A hardware keylogger captures everything.

## 8. Attacks Against It

Known attacks and limitations:

- **Firmware implants.** A compromised BIOS/UEFI or a hardware implant (e.g. Intel ME, AMD PSP) can compromise Tails before it starts.
- **Hardware keyloggers.** A physical keylogger captures all keystrokes, including Persistent Storage passphrases.
- **Cold boot attacks.** RAM contents may survive a short power-off; a sophisticated attacker with physical access can attempt recovery.
- **Evil maid attacks.** An attacker with physical access can modify the bootloader or the USB. Tails mitigates this with a signed boot process (Secure Boot compatibility varies), but a determined attacker can still tamper.
- **Global passive adversary.** Tor does not protect against a global adversary.
- **Endpoint compromise within the session.** Malware inside Tails can still act.
- **User error.** The most common failure mode is the user, not the tool.
- **Malicious Tor exit nodes.** Tor exit nodes can observe unencrypted traffic. Use HTTPS everywhere.
- **Side channels.** Timing, power, and electromagnetic side channels can leak information in extreme threat models.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Tor traffic.** Tails traffic looks like Tor traffic to the network. Tor entry guards are known.
- **Tor bridges.** obfs4 and Snowflake look like random traffic, but obfs4 has a recognizable pattern in some deployments.
- **USB boot events.** On a managed machine with BIOS logging, booting from USB is logged.
- **Physical presence.** A user booting from a USB stick on a managed machine is physically detectable in most corporate environments.
- **On a managed device:** Tails cannot be detected by endpoint agents because it does not use the host OS. But the fact that the machine booted from USB may be logged by the firmware.
- **Network-level:** Tor traffic is the primary signature.

Blocking Tails at the network level means blocking Tor, which is a broader policy question. Many corporate networks block Tor entirely.

## 10. Case Studies

- **Tails and Edward Snowden (2013).** Snowden used Tails to communicate with journalists. The Tails documentation and Laura Poitras's work are well-documented and demonstrate Tails in a real high-risk scenario.
- **Tails and the Snowden leaks.** Tails was recommended in the Snowden documents as a standard tool for high-risk communication.
- **Tails in journalism.** Many newsrooms recommend Tails to sources for initial contact. The SecureDrop project integrates with Tails as the recommended client OS.
- **Tails and censorship circumvention.** Tails supports obfs4 and Snowflake, making it usable in countries where Tor is blocked.
- **Tails and reproducible builds.** Tails uses reproducible builds so that anyone can verify that the published ISO matches the source code. This is a significant supply chain hardening step.
- **Criticism.** Some researchers argue that Tails' amnesic model is too restrictive for real-world use and that users often enable Persistent Storage, which reduces the amnesic guarantee. The trade-off is real.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Tails is legal to use in most jurisdictions. However:

- **Some countries restrict or ban Tor and Tails.** Check your local law before installing or using Tails.
- **Using Tails to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid booting from USB.** On a managed machine, booting from a USB stick may violate acceptable-use policy.
- **You are responsible for your contacts' safety.**
- **No tool replaces operational discipline.**
- **Authorized use only.** In a professional context, use Tails only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying Tails for a small group (journalists, activists, a security team):

- **Standardize the Tails version.** Pin a specific release and verify signatures.
- **Standardize the Persistent Storage policy.** Decide whether Persistent Storage is allowed; document the passphrase policy.
- **Standardize the Tor bridge policy.** If bridges are needed, agree on obfs4 vs. Snowflake.
- **Define a compromise procedure.** If a device is lost or seized, define who is notified and how to rotate keys.
- **Train users.** Tails is easy to misuse. A 1-hour training session prevents most mistakes.
- **Do not distribute the Tails USB with Persistent Storage pre-configured.** Each user should set up their own.
- **Test the workflow** before relying on it.
- **Monitor the threat model.** Tails' design and Tor's adversary model evolve. Re-evaluate periodically.

## 13. References

- [Tails official site](https://tails.net/)
- [Tails documentation](https://tails.net/doc/)
- [Tails signing key](https://tails.net/torrents/files/tails-signing.key)
- [SecureDrop](https://securedrop.org/)
- [Tor Project](https://www.torproject.org/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Operating Systems](https://www.privacyguides.org/en/os/)
