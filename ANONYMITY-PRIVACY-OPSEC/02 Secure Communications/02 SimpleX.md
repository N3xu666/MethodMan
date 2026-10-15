# SimpleX

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

SimpleX is a messaging protocol and client that eliminates user identifiers entirely. There is no phone number, no email, no username, and no persistent account ID. Each conversation uses a separate pair of unidirectional message queues, and each queue is identified by a random address that can be rotated.

This file is a hands-on operator guide: what SimpleX protects against, how to install it, how to harden it, and where it still fails.

## 1. Overview

SimpleX was created by Evgeny Poberezkin and released in 2021. The design goal is to remove the last remaining metadata leak in modern messengers: the persistent user identifier. Signal has phone numbers, Session has Session IDs, Cwtch has onion addresses. SimpleX has none of these - only per-conversation queue addresses.

Key properties:

- **No user identifiers.** No phone, no email, no username, no persistent ID.
- **Unidirectional queues.** Each conversation direction uses a separate queue on a separate relay. The relay never sees both directions.
- **No central servers.** SimpleX uses a network of independent relays (SMP servers) and a separate set of XFTP servers for file transfer.
- **End-to-end encryption.** Double ratchet with Curve25519, XSalsa20, and Poly1305.
- **Post-quantum resistance (optional).** SimpleX supports a hybrid X25519 + sntrup761 key exchange for the initial handshake.
- **Contact via invitation.** To message someone, you scan a QR code or open an invitation link. No directory lookup.
- **Groups and channels.** Supported, encrypted with a group ratchet.
- **Tor integration.** Built-in support for routing through Tor (via SOCKS5).

SimpleX is arguably the most metadata-resistant mainstream messenger available today. The cost is usability: contact discovery is manual, and losing the device means losing all conversations unless you back up.

## 2. Threat Model

What SimpleX protects against:

- **Identity correlation.** There is no persistent identifier to correlate.
- **Server-side plaintext.** Relays see only encrypted blobs.
- **Server-side direction correlation.** Each direction uses a different relay, so no single relay sees both sides.
- **Contact graph exposure.** No provider stores your contacts.
- **SIM swap.** No phone number is required.
- **Central provider subpoena.** There is no central provider to subpoena.
- **Traffic analysis (partial).** Per-queue rotation and optional Tor routing reduce correlation.
- **Quantum adversaries (partial).** Hybrid post-quantum key exchange protects the initial handshake.

What SimpleX does NOT protect against:

- **Endpoint compromise.** Malware on the device can read messages before encryption or after decryption.
- **Global passive adversary.** A nation-state that observes the entire network can still correlate timing and volume across relays.
- **Screenshots or manual disclosure by the recipient.**
- **Metadata in the OS.** Notification logs, keyboard caches, and clipboard.
- **Relay-level denial of service.** If your relay is taken down or blocked, your queue is unavailable until you switch to another relay.
- **Compromised update channel.** Verify signed releases.
- **Legal compulsion on the recipient.**

Threat model summary:

| Adversary | SimpleX |
|-----------|---------|
| Passive network observer | Strong (per-queue rotation, Tor optional) |
| Malicious relay | No (relay sees only encrypted blob) |
| Compromised recipient device | No |
| Legal subpoena to provider | No (no provider) |
| Global passive adversary | Partial (traffic analysis remains possible) |
| Quantum adversary (handshake only) | Partial (hybrid PQ) |

## 3. How It Works (technical)

SimpleX has three components:

1. **SMP (Simple Message Protocol) servers.** These are the relays that store and forward messages. Each queue lives on one SMP server. The server sees only an encrypted blob addressed to a queue ID.

2. **XFTP servers.** These handle file transfer. A file is uploaded to an XFTP server, and the recipient downloads it separately, so file transfer does not block the message queue.

3. **Clients.** The SimpleX app (or CLI) on your device. The client generates all keys, performs the double ratchet, and manages queue rotation.

**Connection flow:**

1. Alice creates an invitation (one-time or reusable) containing her address and public keys.
2. Bob scans or opens the invitation.
3. Bob sends his address and public keys back through Alice's queue.
4. Both sides create a separate unidirectional queue for each direction.
5. Messages flow through these queues, each with its own encryption layer.

**Queue rotation:**

- SimpleX can rotate queue addresses periodically (either manually or automatically).
- After rotation, the old queue is abandoned and the new one takes over. This limits the value of long-term traffic correlation.
- Rotation is the primary mechanism that distinguishes SimpleX from other messengers at the metadata level.

**Post-quantum handshake:**

- SimpleX supports a hybrid key exchange combining X25519 (classical) and sntrup761 (post-quantum).
- This protects the initial handshake against a future quantum adversary who recorded the traffic today (harvest-now-decrypt-later).

**No user identifier:**

- SimpleX does not generate a stable ID. The only identifier is the per-queue address, which is random and rotatable.
- Even the recipient cannot see your queue address unless they are part of the conversation.

## 4. Installation and Setup

SimpleX is available for Android, iOS, Windows, macOS, and Linux (desktop and CLI).

**Android:**

- Official site: https://simplex.chat/
- Google Play: search for "SimpleX Chat".
- F-Droid: recommended for reproducible builds.
- Do NOT install from unofficial APK mirrors.

**iOS:**

- App Store: search for "SimpleX Chat".
- Verify the developer is "SimpleX Chat".

**Desktop:**

- Download from https://simplex.chat/ (Linux AppImage, macOS .dmg, Windows .exe).
- The desktop app is a Flutter client; it can route through Tor (see section 5).

**CLI (Linux):**

```bash
# Download the latest simplex-chat CLI release for your architecture
wget https://github.com/simplex-chat/simplex-chat/releases/latest/download/simplex-chat-ubuntu-22_04-x86-64

chmod +x simplex-chat-ubuntu-22_04-x86-64
./simplex-chat-ubuntu-22_04-x86-64
```

**First-run checklist:**

1. Open the app. No personal information is requested.
2. Create a new profile. Choose a display name (local only, visible to contacts).
3. Note that there is no account recovery by default. Back up if the app supports it (or keep the profile file secure).
4. Enable a PIN or biometric lock for the app.
5. If you want to route through Tor, enable it in settings (see section 5).

**Verify the download:**

```bash
# Linux: verify the AppImage or CLI signature
gpg --verify simplex-chat-x.y.z.AppImage.asc simplex-chat-x.y.z.AppImage

# Or check the SHA-256 hash published on simplex.chat
sha256sum simplex-chat-x.y.z.AppImage
```

## 5. Hardening and Configuration

Default SimpleX settings are already privacy-focused, but several can be tightened.

**In-app settings:**

- **Screen lock:** enable PIN or biometric.
- **Notification content:** set to "Name only" or "No content" to avoid leaking message text to the lock screen and OS notification log.
- **Link previews:** disable. Link previews fetch the URL from your device, leaking your IP to the target site and confirming receipt of the message.
- **Auto-download media:** disable.
- **Transport:** enable Tor (built-in SOCKS5 support) or route the app through Orbot on Android.
- **Automatic queue rotation:** enable if available. It reduces long-term correlation.
- **Disappearing messages:** enable per-conversation if appropriate.

**Device hardening:**

- **Full-disk encryption:** enable (LUKS, FileVault, BitLocker, or default on modern mobile OSes).
- **OS updates:** keep current.
- **App permissions:** SimpleX needs network access and (optionally) camera for QR codes.
- **No rooted / jailbroken devices.**

**Network hardening:**

- **Tor (recommended).** SimpleX has built-in Tor support. On desktop, enable it in settings; on Android, use Orbot in VPN mode and set SimpleX to use SOCKS5 at 127.0.0.1:9050.
- **Bridges if Tor is blocked.** Use obfs4 or Snowflake bridges.
- **Do not mix Tor and a commercial VPN.** This can correlate your traffic.

**Key and account hardening:**

- **Back up the profile file.** SimpleX stores all keys locally. Losing the profile means losing all conversations and contacts permanently.
- **Keep the backup offline.** Do not store it in cloud storage.
- **Verify contacts out-of-band.** Use a second channel (in person, or a PGP-signed message) to confirm the invitation source.

## 6. Operational Usage

Daily-use practices for a paranoid operator:

**Starting a new conversation:**

1. Open SimpleX.
2. Tap "New contact" and share the one-time invitation (QR code or link) through a secure channel.
3. The recipient opens the invitation. Both sides now have a pair of queues.
4. Verify the contact out-of-band.

**Sending a message:**

1. Type or attach. Send.
2. The message is encrypted with the double ratchet and routed through the appropriate SMP server.

**Groups and channels:**

- **Groups:** small, E2E encrypted. Use the group ratchet.
- **Channels:** one-to-many, useful for announcements. Secure but still metadata-leaky at the group level (members know each other).
- **Large public groups:** treat as public.

**Queue rotation:**

- Rotate queues periodically (weekly or monthly) for high-risk use.
- Some clients support automatic rotation. Enable it.
- After rotation, verify the contact is still reachable through the new queue.

**File transfer:**

- Files are uploaded to XFTP servers, which are separate from SMP servers.
- Large files may take longer because the recipient has to fetch them separately.
- Assume any XFTP server sees the file size, time, and (if not using Tor) the IP.

**Disappearing messages:**

- Enable per-conversation for sensitive discussions.
- Remember that screenshots and backups are not affected.

**Compartmentalization:**

- Use separate devices or OS profiles for high-risk communication.
- Do not reuse a SimpleX profile across different identities.

## 7. Common Mistakes

Real mistakes that break SimpleX's protections:

1. **Not enabling Tor.** SimpleX without Tor leaks your IP to the SMP relay you use.
2. **Reusing the same invitation link.** One-time invitations are single-use for a reason. Reusing a reusable invitation links conversations.
3. **Sharing screenshots of conversations.** Screenshots leak the entire conversation, including the other party.
4. **Enabling link previews.** Link previews fetch URLs from your device, leaking your IP.
5. **Not backing up the profile.** Losing the device means losing all conversations permanently.
6. **Storing the profile backup in cloud storage.** Cloud backups can be subpoenaed or hacked.
7. **Assuming SimpleX replaces Tor.** SimpleX is not a general-purpose anonymity network. It is a messenger with strong metadata resistance.
8. **Using the same device for real identity and anonymous activity.**
9. **Not rotating queues.** Long-lived queues are easier to correlate.
10. **Assuming endpoint security is out of scope.** SimpleX cannot protect a compromised device.

## 8. Attacks Against It

Known attacks and limitations:

- **Traffic analysis.** A global passive adversary can correlate timing and volume between relays. Queue rotation and Tor reduce this but do not eliminate it.
- **Relay correlation.** If the same adversary controls the SMP relays on both sides of a conversation, they can improve correlation. Mitigation: rotate queues and use Tor.
- **Endpoint compromise.** Malware on the device can read messages before encryption or after decryption.
- **Relay-level denial of service.** If your relay goes down or is blocked, your queue is unavailable until you switch.
- **Invitation interception.** If an invitation link is intercepted in transit, the attacker can join the conversation. Use a secure channel to share invitations.
- **Group metadata leakage.** Group members see each other. If you do not want that, use 1:1 conversations.
- **Compromised update channel.** Verify signed releases.
- **Legal compulsion on the recipient.**
- **Post-quantum gap (long-term).** The hybrid PQ handshake protects the initial exchange, but the ratchet still relies on classical primitives for ongoing messages. This is a transitional design; full PQ ratchets are an active research area.
- **UI-level fingerprinting.** The SimpleX desktop client is a Flutter app; its traffic profile may be distinguishable from other apps if the network observer knows what to look for.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **DNS queries.** SimpleX resolves SMP server hostnames. The set is dynamic and distributed, but queries are visible to a DNS resolver.
- **TLS SNI.** The SNI field may reveal SimpleX-related hostnames unless ECH is in use.
- **Connection pattern.** Persistent connections to multiple SMP servers look like a distributed mesh, not normal HTTPS.
- **Tor usage.** If the user routes SimpleX through Tor, the network sees Tor traffic (which may itself be flagged or blocked).
- **On a managed device:** the app is visible in the installed-apps list. MDM can block or uninstall it.
- **Traffic volume.** Large sustained transfers (XFTP) are visible as distinct flows.
- **Flow analysis.** Even without decryption, timing and volume can suggest that two users are in the same conversation.

Detection is limited. SimpleX is designed to blend with general encrypted traffic, and its distributed relay model makes IP-based blocking ineffective (blocking one SMP server does not affect the others).

## 10. Case Studies

- **SimpleX in journalism.** Privacy-focused journalists have adopted SimpleX for source communication because it eliminates the need for a phone number, which is often a barrier for sources in hostile environments.
- **SimpleX vs. Signal metadata.** Signal has phone numbers and central servers. SimpleX was designed to remove both, at the cost of a smaller network and more complex UX.
- **Relay operators.** SimpleX relays are operated by a mix of volunteers and organizations. The trust model is similar to Tor: the more independent operators, the stronger the metadata resistance.
- **Post-quantum roadmap.** SimpleX's hybrid PQ handshake (X25519 + sntrup761) is one of the first production deployments of PQ-resistant messaging. It signals the direction the field is moving.
- **Criticism.** Some researchers argue that SimpleX's per-queue model has non-trivial usability costs and that its metadata resistance depends on the honesty of relay operators, which is not guaranteed.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

SimpleX is legal to use in most jurisdictions. However:

- **Some countries restrict or ban encrypted messengers.** Check your local law.
- **Using SimpleX to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid it.** On a work device, using SimpleX may violate acceptable-use policy.
- **You are responsible for your contacts' safety.** Explain the threat model honestly.
- **No tool replaces operational discipline.** SimpleX protects the transport; it does not protect against a compromised endpoint, a careless screenshot, or a coerced disclosure.
- **Authorized use only.** In a professional context, use SimpleX only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying SimpleX for a small group:

- **Standardize the client version.** Pin the version and verify signatures.
- **Standardize the transport.** If using Tor, use the same Tor configuration for all members.
- **Define an invitation protocol.** How invitations are shared (in person, via a secure channel) must be standardized.
- **Define a queue rotation cadence.** Weekly or monthly for high-risk use.
- **Define a compromise procedure.** If a device is lost or seized, who is notified, how the group is informed, and how queues are rotated.
- **Test the backup and restore process.** Practice before you need it.
- **Do not store the profile backup in cloud storage.**
- **Monitor the threat model.** SimpleX's design and network change. Re-evaluate periodically.

## 13. References

- [SimpleX official site](https://simplex.chat/)
- [SimpleX documentation](https://github.com/simplex-chat/simplex-chat/tree/stable/docs)
- [SimpleX whitepaper](https://github.com/simplex-chat/simplex-chat/blob/stable/docs/SIMPLEX.md)
- [SimpleX source code (GitHub)](https://github.com/simplex-chat/simplex-chat)
- [Signal Protocol specification](https://signal.org/docs/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Real-Time Communication](https://www.privacyguides.org/en/real-time-communication/)
