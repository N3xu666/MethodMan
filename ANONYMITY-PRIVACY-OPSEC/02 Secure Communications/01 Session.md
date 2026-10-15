# Session

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Session is a decentralized, end-to-end encrypted messenger built on top of an onion routing network (Oxen Service Nodes). It requires no phone number, no email address, and no personal identifier to register. Unlike Signal or WhatsApp, there is no central server that stores your messages or your contact graph.

This file is a hands-on operator guide: what Session protects against, how to install it, how to harden it, and how it fails.

## 1. Overview

Session was created by the Oxen Project (formerly Loki Network) and released in 2020. The design goal is simple: a messenger that cannot be shut down, cannot be coerced into handing over user data, and does not require any personal information to use.

Key properties:

- **Decentralized.** No central server. Messages are routed through a network of Oxen Service Nodes (thousands of them, operated by independent parties).
- **Onion routing.** Multi-hop routing hides the sender's IP from the recipient's node and from the recipient themselves.
- **No phone number.** Registration generates a random Session ID (66-character base32 string). No SIM, no email.
- **End-to-end encryption.** Signal Protocol (X3DH + Double Ratchet) for message content.
- **Attachments and voice messages.** Supported, encrypted like text.
- **Closed groups.** Up to 100 members, E2E encrypted.
- **Open groups.** Public chat rooms; messages are stored on the network and are NOT E2E encrypted (see section 8).

Session is not a drop-in replacement for Signal. It trades some usability (no phone-number-based contact discovery, smaller network) for stronger metadata resistance and decentralization.

## 2. Threat Model

What Session protects against:

- **Server-side plaintext.** No server holds your messages in readable form.
- **IP correlation with the recipient.** Onion routing hides your IP from the recipient and from the recipient's Service Node.
- **Account takeover via SIM swap.** No phone number, so SIM swap is irrelevant.
- **Subpoena to a central provider.** There is no central provider to subpoena.
- **Contact graph exposure to a provider.** The Service Node network does not store your contact list.

What Session does NOT protect against:

- **Global passive adversary.** A nation-state that can observe the entire network can correlate traffic by timing and volume.
- **Endpoint compromise.** If your device is infected, Session cannot help.
- **Screenshots or manual exfiltration by the recipient.**
- **Metadata from the OS.** Notification content, keyboard caches, clipboard, and backups may leak.
- **Open groups.** Messages in open groups are not E2E encrypted in the same way as 1:1 and closed groups.
- **Registration node linking.** At first registration, the Service Node that assigns your Session ID sees your IP. Mitigate with Tor or a VPN (see section 6).

Threat model summary:

| Adversary | 1:1 / closed group | Open group |
|-----------|-------------------|------------|
| Passive network observer | Partial (traffic analysis) | Weak |
| Malicious Service Node | No (onion routing) | No |
| Compromised recipient device | No | No |
| Legal subpoena to provider | No (no provider) | No |
| Global passive adversary | No | No |

## 3. How It Works (technical)

Session has three layers:

1. **Onion routing layer (Oxen Service Nodes).** Similar to Tor: a message is wrapped in multiple encryption layers and routed through 3+ Service Nodes. Each node removes one layer and learns only the next hop. The last node delivers the message to the recipient's storage.

2. **Storage layer.** Session messages are stored temporarily on the Service Node network (not on a central server). If the recipient is offline, the message waits in an encrypted queue. The queue is deleted after delivery or after a timeout.

3. **Encryption layer (Signal Protocol).** Once the message reaches the recipient, the content is decrypted with the Signal Protocol (X3DH for the initial key agreement, Double Ratchet for forward secrecy and post-compromise security).

Session ID generation:

- On first launch, the client generates a random Ed25519 keypair.
- The public key is encoded as a 66-character base32 string - this is your Session ID.
- There is no directory. To message someone, you must obtain their Session ID out-of-band (in person, via another secure channel, or via a QR code).

This is fundamentally different from Signal: no phone-number-based discovery, no central directory. This is why Session does not leak your social graph to a provider.

## 4. Installation and Setup

Session is available for Android, iOS, Windows, macOS, and Linux.

**Android:**

- Download from the official site: https://getsession.org/
- Or from F-Droid (recommended for reproducible builds): search for "Session".
- Do NOT install from unofficial APK mirrors.

**iOS:**

- App Store: search for "Session Private Messenger".
- Verify the developer is "Oxen Privacy Tech Foundation".

**Desktop (Linux / macOS / Windows):**

- Download the official desktop build from https://getsession.org/
- Linux: AppImage or .deb, depending on your distribution.
- macOS: .dmg (signed and notarized).
- Windows: .exe (signed).

**First-run checklist:**

1. Open the app. Do NOT enter any personal information (Session does not ask for any).
2. Wait for the Session ID to be generated. Copy it to a safe place.
3. Optional: set a display name (visible to your contacts only).
4. Optional: enable a PIN or biometric lock for the app.
5. Note the 24-word recovery phrase if offered. Store it offline.

**Verify the download:**

```bash
# Linux: verify the AppImage signature
gpg --verify session-desktop-x.y.z.AppImage.asc session-desktop-x.y.z.AppImage

# Or check the SHA-256 hash against the one published on getsession.org
sha256sum session-desktop-x.y.z.AppImage
```

## 5. Hardening and Configuration

Default Session settings are reasonable, but several can be tightened.

**In-app settings:**

- **Screen lock:** enable PIN or biometric. Prevents casual physical access.
- **Read receipts:** disable if you do not want the recipient to know when you read a message.
- **Typing indicators:** disable (same reason).
- **Link previews:** disable. Link previews fetch the URL from your device, which leaks your IP to the target site and confirms you received the message.
- **Auto-download media:** disable. Media auto-download can leak metadata and consume storage.
- **Notification content:** set to "Name only" or "No content". Notification previews are visible on the lock screen and stored in the OS notification log.

**Device hardening:**

- **Full-disk encryption:** enable (LUKS on Linux, FileVault on macOS, BitLocker on Windows, default on modern Android/iOS).
- **OS updates:** keep the OS and Session up to date. E2E encryption does not help if the client has a memory-safety bug.
- **App permissions:** Session needs only network access and (optionally) camera for QR codes. Revoke anything else.
- **No rooted / jailbroken devices.** Root compromises the app sandbox and defeats most protections.

**Network hardening:**

- **Route Session through Tor.** Session does not use Tor by default. On desktop, run Tor and route Session traffic through a SOCKS5 proxy (127.0.0.1:9050). On Android, use Orbot in VPN mode.
- **Or use a trusted VPN.** A VPN is weaker than Tor against a global passive adversary, but it hides your IP from the first Service Node.
- **Do not use both Tor and a commercial VPN from the same provider.** This can correlate.

**Key and account hardening:**

- **Back up your Session ID and recovery phrase offline.** If you lose your device and the recovery phrase, you lose the account permanently.
- **Do not share your Session ID publicly.** Anyone with your Session ID can send you messages; it is the only identifier you have.
- **Verify contacts out-of-band.** Session does not have a central directory, so verify the Session ID via a second channel (in person, via Signal, via PGP-signed message).

## 6. Operational Usage

Daily-use practices for a paranoid operator:

**Sending a message:**

1. Open Session.
2. Tap "New message" -> enter the recipient's Session ID.
3. Type, attach, or record. Send.
4. The message is routed through Service Nodes and delivered.

**Verifying a contact:**

- Compare Session IDs in person or via a second channel.
- Session does not (currently) have a built-in safety-number verification like Signal. Verification is manual.

**Group chats:**

- **Closed groups:** up to 100 members, E2E encrypted. Use these for sensitive coordination.
- **Open groups:** public, NOT E2E encrypted in the same way. Treat as public. Never share secrets in an open group.

**Disappearing messages:**

- Enable per-conversation. Set a timer appropriate to the sensitivity (1 hour to 1 day).
- Disappearing messages delete the message from your device and the recipient's device after the timer, but not from any screenshots or backups taken before the timer expired.

**Account migration:**

- Session supports restoring from a recovery phrase.
- Restore on a new device ONLY on a trusted network.

**Compartmentalization:**

- Use a separate device or a separate OS profile for high-risk communication.
- Do not link your Session identity to your real identity on any public platform.

## 7. Common Mistakes

Real mistakes that break Session's protections:

1. **Registering without Tor/VPN.** The first Service Node that assigns your Session ID sees your real IP. Always register over Tor or a VPN.
2. **Posting your Session ID publicly.** Anyone can then message you, and your ID becomes a pivot point.
3. **Using open groups for sensitive topics.** Open groups are not E2E encrypted the same way as closed groups.
4. **Enabling link previews.** Link previews fetch the URL from your device, leaking your IP to the target site.
5. **Enabling notifications with content.** Lock-screen previews leak message text to anyone with physical access and to the OS notification log.
6. **Not verifying contacts.** Session has no central directory; a wrong Session ID means a wrong recipient.
7. **Using the same device for real identity and anonymous activity.** Compartmentalization is not optional for high-risk use.
8. **Backing up the recovery phrase to cloud storage.** Cloud backups can be subpoenaed or hacked.
9. **Rooted or jailbroken device.** Root defeats the app sandbox.
10. **Assuming Session is a drop-in replacement for Signal.** It is not: it trades contact discovery and some usability for metadata resistance.

## 8. Attacks Against It

Known attacks and limitations:

- **Traffic analysis.** A global passive adversary can correlate message timing and volume between sender and recipient, even with onion routing. Session does not add cover traffic by default.
- **Endpoint compromise.** Malware on the device can read messages before encryption or after decryption. Session cannot help.
- **Malicious Service Node.** A single malicious Service Node sees only one hop of the onion. It cannot read the message or identify both endpoints without controlling a large fraction of the network.
- **Sybil Service Nodes.** If an adversary controls enough Service Nodes, they can improve traffic correlation. This is a theoretical attack against the current network size.
- **Open group plaintext exposure.** Messages in open groups are stored on the network and are not E2E encrypted in the same way as closed groups. Assume they are public.
- **Registration node correlation.** The first Service Node that assigns your Session ID sees your IP. Register over Tor/VPN to mitigate.
- **Metadata in OS.** Notification logs, keyboard caches, and clipboard can leak message content even with E2E encryption.
- **Compromised update channel.** If the update server is compromised, a malicious update could be delivered. Verify signed releases and use reproducible builds (F-Droid) where possible.
- **Legal compulsion on the recipient.** If the recipient is legally compelled to hand over the device, Session cannot help.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **DNS queries.** Session resolves a small set of seed nodes and Service Node addresses. DNS queries to Session-related domains (e.g. `*.oxen.io`, `*.session.foundation`) are visible to a DNS resolver.
- **TLS SNI.** Session uses TLS to Service Nodes. The SNI field may reveal Session-related hostnames unless ECH is used.
- **Connection patterns.** Persistent connections to many IP addresses (Service Nodes) look like a mesh/VPN pattern, not normal HTTPS.
- **Traffic volume.** Large sustained uploads/downloads over these connections can indicate file transfer, not just chat.
- **On a managed device:** the app itself is visible in the installed-apps list. MDM can block or uninstall it.
- **Network flow analysis.** Even without decryption, timing and volume can suggest that a user is communicating with a specific other user.

Detection is limited: Session traffic is designed to blend with general encrypted traffic. Network-level blocking is possible only by blocking the Service Node IP ranges or the seed DNS names, both of which change.

## 10. Case Studies

- **Session in protests (2022-2024).** Session has been recommended by privacy advocates for protest coordination because it does not require a phone number and cannot be shut down by blocking a single server.
- **Session vs. Signal metadata.** In 2021, Signal's use of phone numbers and its reliance on AWS was criticized by privacy researchers; Session was positioned as an alternative. The trade-off is a smaller network and no central directory.
- **Law enforcement interest.** There is no public record of a successful legal compulsion against Session to hand over user messages, because there is no central provider to compel. This does not mean Session is immune: endpoint compromise and metadata analysis remain possible.
- **Oxen Service Node economics.** Service Nodes are incentivized by OXEN token rewards, which creates a different trust model than Tor's volunteer relays. The security of the network depends on the distribution and honesty of Service Node operators.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Session is legal to use in most jurisdictions. However:

- **Some countries restrict or ban encrypted messengers.** Check your local law before installing or using Session.
- **Using Session to plan or commit a crime is illegal everywhere.** Encryption is a tool, not a shield.
- **Corporate policy may forbid it.** On a work device, using Session may violate acceptable-use policy even if it is legal.
- **You are responsible for your contacts' safety.** If you introduce someone to Session, explain the threat model and the metadata limitations honestly.
- **No tool replaces operational discipline.** Session protects the transport; it does not protect against a compromised endpoint, a careless screenshot, or a coerced disclosure.
- **Authorized use only.** In a professional context, use Session only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying Session for a small group (journalists, activists, a security team):

- **Standardize the client version.** Different versions may have different defaults. Pin the version and verify signatures.
- **Standardize the network path.** If using Tor, use the same Tor configuration for all members (bridge vs. direct, etc.).
- **Provide a verification protocol.** Session has no built-in safety numbers, so define an out-of-band verification procedure for your group.
- **Define a compromise procedure.** If a device is lost or seized, define who must be notified, how keys are rotated, and how the group is informed.
- **Test the recovery process.** Practice restoring an account from a recovery phrase on a spare device before you need it.
- **Do not store the recovery phrase in the same place as the device.**
- **Monitor the threat model.** Session's design and network size change. Re-evaluate periodically.

## 13. References

- [Session official site](https://getsession.org/)
- [Session documentation](https://docs.getsession.org/)
- [Oxen Privacy Tech Foundation](https://oxen.io/)
- [Session source code (GitHub)](https://github.com/oxen-io/session-desktop)
- [Signal Protocol specification](https://signal.org/docs/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Real-Time Communication](https://www.privacyguides.org/en/real-time-communication/)
