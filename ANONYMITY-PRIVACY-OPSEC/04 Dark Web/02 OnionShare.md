# OnionShare

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

OnionShare is an open-source tool that lets you share files, host a temporary website, and chat anonymously over Tor. It turns your own machine into a temporary onion service for the duration of a single operation, with no third-party server involved. When the operation ends, the .onion address is gone.

This file is a hands-on operator guide: what OnionShare protects against, how to install it, how to use it safely, and where it fails.

## 1. Overview

OnionShare was created by Micah Lee and released in 2014. It is maintained by the Freedom of the Press Foundation and is available for Linux, macOS, Windows, and Qubes OS. OnionShare uses the Tor network to expose a local server as an onion service, on demand, for a single operation.

Key modes:

- **Share Files.** Send files to a recipient anonymously. The recipient downloads via Tor Browser. Can be one-time or multi-use.
- **Receive Files.** Receive files from anonymous senders (added in 2.3). The sender uploads via Tor Browser.
- **Host a Website.** Serve a static website as an onion service, temporarily.
- **Chat.** End-to-end encrypted chat between two people over an onion service (added in 2.3).
- **CLI mode.** OnionShare has a command-line interface for scripting.

Key properties:

- **No third-party server.** Your machine is the server. There is no cloud provider to subpoena.
- **Temporary onion service.** The .onion address exists only for the duration of the operation.
- **Tor-only.** Clients must use Tor Browser (or a Tor SOCKS proxy) to reach the service.
- **Client authentication (optional).** Private mode requires a password.
- **No accounts.** No signup, no email, no identity.
- **Cross-platform.** Linux, macOS, Windows, Qubes OS.
- **Open source.** Reproducible builds are provided for some platforms.

OnionShare is widely used by journalists, activists, and privacy-conscious users. It is one of the simplest ways to move a file anonymously.

## 2. Threat Model

What OnionShare protects against:

- **Server-side plaintext.** No third-party server holds your data.
- **IP correlation (both sides).** Neither the sender nor the recipient reveals its IP (Tor).
- **Account correlation.** No accounts, no emails, no identities.
- **Provider subpoena.** There is no provider.
- **Cloud retention.** Files are not stored anywhere except on your machine and the recipient's.
- **Long-lived metadata.** The .onion address exists only during the operation.
- **Man-in-the-middle on file transfer.** The .onion address is self-authenticating (v3).

What OnionShare does NOT protect against:

- **Endpoint compromise.** If your machine or the recipient's is compromised, OnionShare cannot help.
- **Traffic correlation.** A global passive adversary can correlate traffic entering and leaving the Tor network.
- **Recipient behavior.** The recipient can leak the file after receiving it.
- **Long-term exposure.** While the operation is running, the service is reachable; the address is only secret if you keep it secret.
- **Weak passwords in private mode.** A weak password can be brute-forced.
- **Malicious files.** OnionShare does not scan files for malware; the recipient is responsible.
- **Tor limitations.** Tor's limitations (exit node attacks for clearnet, global passive adversary, etc.) apply.
- **Legal compulsion on you.** If you are legally compelled to reveal the file or the address, OnionShare cannot help.
- **Metadata in the file itself.** OnionShare does not strip file metadata (see 03 Operating Systems and Hygiene / Metadata).
- **Screen recording on your machine.** If your screen is recorded, the .onion address and the operation are visible.

Threat model summary:

| Adversary | OnionShare |
|-----------|------------|
| Passive network observer | Strong (Tor) |
| Malicious third-party server | N/A (no third-party server) |
| Subpoena to a provider | N/A (no provider) |
| Global passive adversary | Weak (traffic correlation) |
| Endpoint compromise | None |
| Recipient leak | None |
| Physical access to your machine | None |

## 3. How It Works (technical)

OnionShare runs a local web server (or a small application server) on your machine and exposes it as a Tor onion service.

**File Share flow:**

1. You select files or a folder in OnionShare.
2. OnionShare starts a local HTTP server (random port) on 127.0.0.1.
3. OnionShare asks Tor to create an onion service pointing to that local port.
4. OnionShare shows the .onion address (or a URL with a slug) for the recipient.
5. The recipient opens the .onion address in Tor Browser, sees the file list, and downloads.
6. When you stop the share, Tor tears down the onion service; the .onion address is gone.

**Receive Files flow:**

1. You start Receive mode in OnionShare.
2. OnionShare creates an onion service and a one-time slug.
3. The sender opens the .onion address in Tor Browser and uploads files.
4. Files land in a folder you chose.
5. When you stop the receive, the onion service is torn down.

**Host a Website flow:**

1. You select a folder containing a static site.
2. OnionShare serves it as an onion service.
3. You share the .onion address.
4. When you stop the site, the onion service is torn down.

**Chat flow:**

1. Two users run OnionShare Chat and exchange .onion addresses out-of-band.
2. Each connects to the other's onion service.
3. Messages are encrypted end-to-end between the two clients.
4. Neither user's IP is revealed.

**Tor integration:**

- OnionShare uses the system Tor or a bundled Tor (depending on the platform).
- On Tails, OnionShare uses the system Tor.
- On Qubes, OnionShare can run in a dedicated qube with `sys-whonix` as the gateway.

**Client authentication (private mode):**

- When enabled, OnionShare requires a password. The client must know the password to access.
- The password is sent out-of-band (e.g. via Signal, PGP, or in person).

**Self-authenticating address:**

- The .onion address is derived from the onion service's public key.
- A client connecting to the address is cryptographically guaranteed to reach the correct service.

## 4. Installation and Setup

**Official site:** https://onionshare.org/

**Linux:**

- Download the AppImage from https://onionshare.org/ (recommended).
- Or use the distribution package: `sudo apt install onionshare` (Debian/Ubuntu), `sudo dnf install onionshare` (Fedora), `sudo pacman -S onionshare` (Arch). Distribution packages may lag.

**macOS:**

- Download the .dmg from https://onionshare.org/.

**Windows:**

- Download the .exe from https://onionshare.org/.

**Qubes OS:**

- Install OnionShare in an AppVM (e.g. `anon-whonix`) with `sys-whonix` as the gateway.
- The official Qubes documentation covers the recommended setup.

**Tails:**

- OnionShare is pre-installed on Tails.

**Verify the download:**

```bash
# Linux: verify the AppImage signature (if provided)
gpg --verify onionshare-x.y.z.AppImage.asc onionshare-x.y.z.AppImage

# Check the SHA-256 hash against the value published on onionshare.org
sha256sum onionshare-x.y.z.AppImage
```

**First-run checklist:**

1. Launch OnionShare.
2. Select the mode (Share Files, Receive Files, Host a Website, Chat).
3. For Share Files: drag files or select a folder.
4. Optional: enable private mode (password).
5. Optional: set an auto-stop timer (seconds after the first download).
6. Click "Start sharing". OnionShare connects to Tor and produces the .onion address.
7. Copy the .onion address and share it with the recipient out-of-band.
8. When the transfer is complete (or when the timer expires), click "Stop sharing".

## 5. Hardening and Configuration

**Private mode (password):**

- Enable private mode for any file share that contains sensitive content.
- Use a strong password; share it out-of-band (not in the same channel as the .onion address).
- Combine the .onion address and the password in two separate channels: e.g. .onion via Signal, password via PGP.

**Auto-stop timer:**

- Set a timer (e.g. stop after 1 download, or stop after 1 hour).
- The shorter the window, the smaller the exposure.
- OnionShare can also stop after the first download automatically.

**File hygiene:**

- Strip file metadata before sharing (see 03 Operating Systems and Hygiene / Metadata).
- Do not share files that contain personal information unless necessary.
- Do not share a whole home directory; share only the specific files.

**Operational hygiene:**

- Do not use the same machine for OnionShare and your personal identity at the same time.
- Do not leave OnionShare running unattended.
- Do not share the .onion address in a public channel.
- Do not reuse the same .onion address across sessions (OnionShare creates a new one each time).
- On Tails, OnionShare is already isolated; on Qubes, use a dedicated qube.

**Tor hardening:**

- On Tails and Whonix, Tor is already hardened.
- On Linux, use the bundled Tor or the system Tor with default settings; do not override Tor configuration.
- Do not use OnionShare with a VPN; use Tor directly.

**Chat hardening:**

- Verify the .onion address out-of-band.
- Treat chat as ephemeral; do not use it for long-term storage.
- If the content is sensitive, both parties should be on hardened systems.

## 6. Operational Usage

**Share a file (GUI):**

1. Open OnionShare.
2. Select "Share Files".
3. Add files.
4. Optional: enable "Private" (password).
5. Optional: set "Auto-stop timer".
6. Click "Start sharing".
7. Copy the .onion address and share it out-of-band.
8. Wait for the download.
9. Click "Stop sharing" (or wait for the timer).

**Receive a file (GUI):**

1. Open OnionShare.
2. Select "Receive Files".
3. Choose the folder where received files will be saved.
4. Optional: enable private mode.
5. Optional: set an auto-stop timer.
6. Click "Start receiving".
7. Copy the .onion address and share it out-of-band.
8. Wait for the upload.
9. Click "Stop receiving".

**Host a website (GUI):**

1. Prepare a static site in a folder.
2. Open OnionShare, select "Host a Website".
3. Choose the folder.
4. Optional: enable private mode.
5. Click "Start sharing".
6. Share the .onion address.

**Chat (GUI):**

1. Both users open OnionShare and select "Chat".
2. One user starts chat and gets a .onion address.
3. The other user joins via the .onion address.
4. Messages are exchanged over the onion service.

**Command-line (CLI):**

```bash
# Share a file
onionshare-cli --share file1.txt file2.txt

# Share with a password
onionshare-cli --share --password <PASSWORD> file.txt

# Receive files to a folder
onionshare-cli --receive --receive-dir ~/Downloads/onionshare

# Host a website
onionshare-cli --website --website-dir ./site

# Chat
onionshare-cli --chat
```

**Stop sharing:**

- In GUI: click "Stop sharing".
- In CLI: press Ctrl+C.

The onion service is torn down and the .onion address is no longer reachable.

## 7. Common Mistakes

Real mistakes that break OnionShare's protections:

1. **Sharing the .onion address and the password in the same channel.** Compartmentalize.
2. **Leaving OnionShare running after the transfer.** Stop sharing as soon as the recipient confirms.
3. **Not stripping file metadata.** The file itself may reveal identity.
4. **Using OnionShare on a machine that also runs a clearnet browser.** Endpoint compromise risk.
5. **Sharing a whole directory.** Share only the specific files.
6. **Using a weak password in private mode.**
7. **Sharing the .onion address publicly** (e.g. Twitter). It is meant to be shared privately.
8. **Assuming OnionShare strips metadata.** It does not.
9. **Using OnionShare over a VPN instead of Tor.** OnionShare depends on Tor.
10. **Not verifying the recipient's ability to reach Tor.** The recipient must have Tor Browser (or a Tor SOCKS proxy).
11. **Reusing the same .onion address across sessions.** OnionShare creates a new one each time; do not copy it.
12. **Forgetting that the recipient can leak the file.** Once the file is received, OnionShare's role ends.
13. **Not setting an auto-stop timer.** A timer reduces the window of exposure.
14. **Using OnionShare on a compromised OS.** OnionShare cannot protect a compromised machine.
15. **Assuming the .onion address is a security measure by itself.** It is not; the password and the out-of-band channel are.

## 8. Attacks Against It

Known attacks and limitations:

- **Traffic correlation.** A global passive adversary can correlate traffic entering and leaving the Tor network. This is the same limitation as all Tor traffic.
- **Endpoint compromise.** Malware on your machine or the recipient's can read files before encryption or after decryption.
- **Weak password brute-force.** In private mode, a weak password can be brute-forced (though Tor slows this).
- **Public .onion address exposure.** If the .onion address is shared publicly, an attacker can attempt to connect (subject to password and Tor).
- **Denial of service.** While the share is running, an attacker can attempt to saturate the onion service. Tor-level DoS is possible.
- **Recipient leak.** The recipient can leak the file after receiving it; OnionShare cannot prevent this.
- **Legal compulsion on you.** If you are legally compelled to reveal the file, OnionShare cannot help.
- **Screen recording.** If your screen is recorded (malware, shoulder surfing), the .onion address and the operation are visible.
- **OnionShare bugs.** OnionShare is open source but not immune to bugs. Keep it updated.
- **Tor bugs.** Tor has had CVEs. Keep Tor updated.
- **The recipient's operational security.** If the recipient is compromised, the file is compromised.
- **Metadata in the file.** OnionShare does not strip metadata; the file may reveal identity.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Tor traffic.** OnionShare traffic is Tor traffic. Tor entry guards are known and can be blocked.
- **Local process.** On a managed device, the OnionShare process is visible. MDM can block or uninstall it.
- **Listening ports.** OnionShare starts a local HTTP server; local firewall logs may show it.
- **Tor bootstrap events.** Tor connects to known entry guards; the timing and volume are visible.
- **Physical presence.** A user running OnionShare on a corporate machine is physically detectable.

Blocking OnionShare at the network level means blocking Tor. This is a broad policy decision.

## 10. Case Studies

- **OnionShare and the Freedom of the Press Foundation.** OnionShare is maintained by the FPF, the same organization that maintains SecureDrop. It is widely recommended for journalists and sources.
- **OnionShare in protests.** OnionShare has been recommended for distributing files during protests (e.g. protest materials, leaked documents) because it requires no third-party server and no accounts.
- **OnionShare and SecureDrop.** OnionShare and SecureDrop are complementary: SecureDrop for structured whistleblowing workflows, OnionShare for ad-hoc file transfer.
- **OnionShare in Qubes.** OnionShare is a recommended tool in Qubes-Whonix setups, used for anonymous file sharing inside an `anon-whonix` qube.
- **OnionShare and Tails.** OnionShare is pre-installed on Tails and is part of the standard Tails workflow for anonymous file sharing.
- **Criticism.** OnionShare's threat model depends heavily on operational hygiene; users who do not strip metadata or who share the .onion address carelessly can leak identity despite the tool's protections.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

OnionShare is legal to use in most jurisdictions. However:

- **Some countries restrict or ban Tor.** Check your local law before using OnionShare.
- **Using OnionShare to distribute illegal content is a crime everywhere.**
- **Corporate policy may forbid Tor.** On a work device, using OnionShare may violate acceptable-use policy.
- **You are responsible for what you share.** OnionShare is a publishing tool.
- **Do not use OnionShare to harass, stalk, defraud, or harm any person.**
- **Authorized use only.** In a professional context, use OnionShare only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying OnionShare for a small group (journalists, activists, a security team):

- **Standardize the OS.** Tails or Qubes-Whonix is recommended.
- **Standardize the OnionShare version.** Pin a specific release and verify signatures.
- **Define a channel policy.** .onion address in one channel, password in another.
- **Define a time policy.** Short auto-stop timers (minutes, not hours).
- **Define a metadata policy.** Strip metadata before sharing.
- **Define a recipient verification protocol.** Verify the recipient can reach Tor and knows the password.
- **Train users.** OnionShare is simple but easy to misuse.
- **Test the workflow** before relying on it.
- **Monitor the threat model.** OnionShare and Tor evolve; re-evaluate periodically.

## 13. References

- [OnionShare official site](https://onionshare.org/)
- [OnionShare documentation](https://docs.onionshare.org/)
- [OnionShare source code (GitHub)](https://github.com/onionshare/onionshare)
- [Freedom of the Press Foundation](https://freedom.press/)
- [Tor Project - Onion Services](https://community.torproject.org/onion-services/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - File Sharing](https://www.privacyguides.org/en/file-sharing/)
