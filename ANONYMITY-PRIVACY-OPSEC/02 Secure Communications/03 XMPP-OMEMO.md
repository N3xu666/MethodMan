# XMPP / OMEMO

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

XMPP (Extensible Messaging and Presence Protocol) is an open, federated messaging protocol. OMEMO is the de-facto end-to-end encryption extension for XMPP, based on the Signal Protocol (Double Ratchet). Together they provide a federated, E2E-encrypted messenger that no single provider can shut down or read.

This file is a hands-on operator guide: what XMPP/OMEMO protects against, how to install a client and pick a server, how to harden the setup, and where it fails.

## 1. Overview

XMPP has existed since 1999 (originally as Jabber). It is a federated protocol: anyone can run a server, and servers talk to each other. OMEMO was designed in 2016 as a replacement for OTR and OpenPGP-based XMPP encryption, and it is now supported by most modern XMPP clients (Conversations, Gajim, Dino, Monal).

Key properties:

- **Federated.** No central server. Any user can run their own XMPP server (Prosody, ejabberd, Openfire).
- **Decentralized identity.** Your address is `user@server.tld`, similar to email.
- **End-to-end encryption via OMEMO.** Signal Protocol (X3DH + Double Ratchet) with forward secrecy and post-compromise security.
- **Multi-device support.** OMEMO supports multiple devices per account, each with its own key.
- **File transfer via OMEMO Media Sharing (AESGCM).** Encrypted attachments.
- **Group chat (MUC).** Multi-user chats, E2E encrypted via OMEMO in supported clients.
- **Open standard.** XMPP is an IETF standard; OMEMO is documented in XEP-0384.

XMPP/OMEMO is a strong choice for users who want federation and self-hosting. The cost is complexity: server selection, client selection, and key management matter more than in a centralized app.

## 2. Threat Model

What XMPP/OMEMO protects against:

- **Server-side plaintext.** With OMEMO, the server sees only ciphertext.
- **Provider shutdown.** A federated network cannot be shut down by taking down one server.
- **Compromised server (for message content).** OMEMO keys are end-to-end; the server does not have them.
- **MITM on message content.** OMEMO authenticates keys via trust messages; a MITM without the private key cannot decrypt.
- **Forward secrecy.** Double Ratchet gives forward secrecy: past messages stay secret if a key is compromised later.
- **Post-compromise security.** Double Ratchet also recovers security after a compromise if the attacker does not stay active.

What XMPP/OMEMO does NOT protect against:

- **Metadata (who talks to whom).** Federated servers see the full roster and timing of messages. This is the biggest weakness of XMPP.
- **Server-side plaintext if OMEMO is off.** Without OMEMO, XMPP is plaintext (or TLS-only, which the server can read).
- **Endpoint compromise.**
- **Offline message storage.** If OMEMO is not enabled, offline messages sit in plaintext on the server.
- **Push notifications.** Mobile push often reveals message metadata to a third party (Apple, Google) and sometimes content.
- **Multi-device key synchronization.** Adding a device requires re-verifying keys with all contacts.
- **Server logs.** Even with OMEMO, servers log IPs, connection times, and roster changes.

Threat model summary:

| Adversary | XMPP/OMEMO |
|-----------|------------|
| Passive network observer | Strong (TLS + OMEMO) |
| Malicious server (content) | No (OMEMO) |
| Malicious server (metadata) | No (server sees roster + timing) |
| Compromised recipient device | No |
| Legal subpoena to server | Partial (content protected, metadata exposed) |
| Global passive adversary | Weak (metadata correlation) |

## 3. How It Works (technical)

XMPP is a client-server protocol with server-to-server federation. OMEMO is a separate layer that encrypts message payloads.

**XMPP layer:**

- Every user has a JID (Jabber ID): `user@server.tld/resource`.
- Clients connect to their home server over TLS (usually port 5222 for c2s, 5269 for s2s).
- Messages between users on different servers are relayed through both servers.
- The server keeps a roster (contact list) for each user.

**OMEMO layer:**

- Each device generates an identity key (Curve25519) and a set of prekeys.
- OMEMO uses the Signal Protocol (X3DH handshake + Double Ratchet).
- Messages are encrypted per-recipient-device. A message to a contact with 3 devices is encrypted 3 times.
- Trust is established by comparing fingerprints out-of-band (QR code, safety number).
- Trust messages (XEP-0450) allow trust to be shared across a user's own devices.

**What the server sees:**

- Who is online.
- Who is on whose roster.
- When messages are sent (timing, size).
- The recipient's device list (if using OMEMO, the server relays the device list).
- Nothing about message content (if OMEMO is used).

**Encryption flow:**

```text
Alice                     Server A              Server B                     Bob
  |                          |                     |                          |
  |-- fetch Bob's device list ->                   |                          |
  |<-- device list (3 devices) -                   |                          |
  |                          |                     |                          |
  |-- encrypt message for each device ------------->                          |
  |                          |-- relay ciphertext ->                          |
  |                          |                     |-- deliver ------------->|
  |                          |                     |                          |
  |                          |                     |      decrypt with private key
```

## 4. Installation and Setup

To use XMPP/OMEMO you need two things: a client and an account on a server.

**Recommended clients:**

- **Conversations** (Android) - paid on Google Play, free on F-Droid. Gold standard for Android XMPP.
- **Monal** (iOS) - free, actively maintained.
- **Gajim** (Linux/Windows/macOS) - desktop, full-featured.
- **Dino** (Linux) - modern desktop client, GTK.
- **Profanity** (terminal) - for users who live in the terminal.

**Recommended public servers:**

- **disroot.org** - privacy-focused, no logs.
- **jabber.ccc.de** - Chaos Computer Club, no logs.
- **xmpp.jp** - public, free.
- **Self-hosted** - Prosody or ejabberd on a VPS you control (best for privacy, most work).

**Steps (Android + Conversations):**

1. Install Conversations from F-Droid.
2. Choose a server and register an account (in-app or via the server's web registration).
3. Log in with your JID and password.
4. Open Settings -> Security -> enable OMEMO by default.
5. Verify your contacts' fingerprints in person or via a second channel.

**Steps (Linux + Gajim):**

```bash
# Debian / Ubuntu
sudo apt install gajim gajim-omemo

# Fedora
sudo dnf install gajim gajim-omemo

# Arch
sudo pacman -S gajim gajim-omemo
```

Then launch Gajim, add your account, and enable OMEMO in Account -> General.

**Server registration (if self-hosting):**

```bash
# Minimal Prosody setup on Debian 12
sudo apt install prosody lua-sec lua-dbi-sqlite3
sudo systemctl enable --now prosody

# Add a user
sudo prosodyctl adduser you@yourdomain.tld
```

See Prosody documentation for TLS certificates (Let's Encrypt via certbot is standard).

## 5. Hardening and Configuration

Default settings in most clients are reasonable, but several can be tightened.

**In-client settings:**

- **OMEMO by default:** enable. Without this, new conversations may be plaintext until you toggle it manually.
- **OMEMO trust:** verify fingerprints and set trust to "Trusted" (not "Blind Trust"). Blind trust defeats the point.
- **Read receipts:** disable if you do not want to leak timing of reads.
- **Typing indicators:** disable.
- **Message carbons:** enable if you use multiple devices (copies messages to all your devices). Understand that the server relays these.
- **Message archive (MAM):** decide carefully. MAM stores encrypted messages on the server; even encrypted, this is metadata.
- **Push notifications:** on Android, use UnifiedPush (no Google). Conversations supports it.
- **File transfer:** use OMEMO Media Sharing (AESGCM), not HTTP Upload (plaintext on server).

**Server hardening (if self-hosting):**

- **TLS only.** Disable plaintext c2s/s2s. Require TLS 1.2+.
- **No logs.** Set Prosody `log = { { levels = { min = "error" }, to = "file", filename = "/var/log/prosody/prosody.log" } }` and `mod_measure_storage` for logging control.
- **Disable message storage.** Set `storage = "none"` for MAM if you do not want the server to keep encrypted archives.
- **Disable vCard and other metadata.** Minimize what the server stores about each user.
- **Rate limiting.** `mod_limits` to prevent abuse.
- **2FA on the account.** Some servers support TOTP.
- **Full-disk encryption on the server.**
- **Off-site encrypted backups.**

**Device hardening:**

- **Full-disk encryption** on every device.
- **Strong screen lock.**
- **No rooted / jailbroken devices.**
- **Keep the client up to date.** OMEMO implementations have had CVEs.

## 6. Operational Usage

Daily practices for a paranoid operator:

**Starting a conversation:**

1. Add the contact by JID: `user@server.tld`.
2. Wait for the roster exchange to complete.
3. Open the conversation and verify OMEMO is active (lock icon).
4. Verify the contact's fingerprint out-of-band.

**Fingerprint verification:**

- In Conversations: open the contact's details, tap "Encryption", and compare the fingerprint with the contact via a second channel.
- In Gajim: Account -> OMEMO -> Trust Management. Compare fingerprints.
- Do NOT skip this step. OMEMO without verification protects against passive attackers, not active MITM.

**Group chats (MUC):**

- Join or create a MUC room (`room@conference.server.tld`).
- Enable OMEMO in the room if supported (Conversations, Gajim, Dino support this).
- Note: MUC metadata (who is in the room) is visible to the server.
- Do NOT discuss sensitive topics in unencrypted MUC rooms.

**Multi-device use:**

- Each device has its own OMEMO key.
- Adding a new device requires re-verifying with all contacts, unless you use trust messages (XEP-0450).
- Remove old devices from your OMEMO device list when you stop using them.

**Files:**

- Use OMEMO Media Sharing (AESGCM), which encrypts files end-to-end.
- Do NOT use HTTP Upload, which uploads files to the server in plaintext.

## 7. Common Mistakes

Real mistakes that break XMPP/OMEMO protections:

1. **Using a public server that logs.** Many public XMPP servers log IPs and roster changes. Pick one with a no-logs policy or self-host.
2. **Not verifying fingerprints.** Without verification, OMEMO protects against passive attackers but not an active MITM.
3. **Blind trust on new devices.** New devices default to "blind trust", which silently accepts any key.
4. **Using HTTP Upload for files.** Files uploaded to the server are not E2E encrypted.
5. **Leaving MAM enabled by default.** Even encrypted, MAM stores metadata on the server.
6. **Not disabling push through Google/Apple.** Push metadata leaks who is messaging whom and when.
7. **Using the same XMPP account for real identity and anonymous activity.** Compartmentalization is required for high-risk use.
8. **Forgetting to remove old devices from the OMEMO list.** A lost device remains trusted.
9. **Assuming XMPP hides metadata.** The server always sees who talks to whom.
10. **Not self-hosting when the threat model requires it.** For a high-risk operator, self-hosting is the only way to control metadata.

## 8. Attacks Against It

Known attacks and limitations:

- **Metadata analysis.** A malicious or compelled server sees the full roster, timing, IP addresses, and device list. This is the primary weakness of XMPP/OMEMO.
- **Server-side plaintext if OMEMO is off.** Plaintext messages and offline messages are readable by the server.
- **Push notification metadata.** Google/Apple push services see who is messaging whom and when.
- **Fingerprint MITM.** If you do not verify fingerprints, an active MITM can impersonate a contact.
- **Device list manipulation.** A malicious server can add a device to your contact's list, causing messages to be encrypted to an attacker-controlled device (mitigated by fingerprint verification).
- **CVE history.** OMEMO implementations have had vulnerabilities (e.g. CVE-2018-18510 in Gajim, CVE-2020-26517 in various clients). Keep clients updated.
- **Server compromise.** If the server is compromised, the attacker gets metadata and (if MAM is enabled) encrypted archives. OMEMO protects content, not metadata.
- **Legal compulsion on the server operator.**
- **XMPP federation complexity.** Some servers block others, causing reliability issues that may push users to insecure fallbacks.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **DNS queries.** The XMPP server domain is resolved in the clear unless the user uses DNS-over-HTTPS.
- **TLS SNI.** The server's hostname may be visible in SNI (unless ECH).
- **Port 5222 / 5269 traffic.** XMPP uses distinctive ports and patterns; easy to fingerprint.
- **Persistent connections.** XMPP connections are long-lived, which is unusual for typical web traffic.
- **Push traffic to Google/Apple.** Push notifications reveal that a messaging app is in use.
- **Roster changes.** On a self-hosted server with logs, roster additions are visible to the operator.
- **On a managed device:** the client app is visible in the installed-apps list. MDM can block it.

Blocking XMPP at the network level is easy: block ports 5222 and 5269, or block specific server domains. Users can bypass by using XMPP over WebSocket or by routing through Tor.

## 10. Case Studies

- **XMPP in the early 2010s.** XMPP was the default open messaging protocol for many years. Google Talk used it until 2013, when Google moved to Hangouts and dropped federation. This is a reminder that federated protocols depend on the good will of large providers.
- **OMEMO adoption (2016-present).** OMEMO replaced OTR as the primary E2E protocol for XMPP. Most modern clients support it. The protocol is stable and audited.
- **XMPP in journalism and activism.** Some journalists use XMPP/OMEMO because self-hosting gives them control over metadata. Others prefer Signal for its simplicity. The trade-off is real: XMPP is more private but more complex.
- **Chaos Computer Club (CCC).** The CCC operates `jabber.ccc.de`, one of the best-known public XMPP servers, with a no-logs policy and a strong security posture.
- **Self-hosting in hostile environments.** Users in countries with strict surveillance sometimes self-host XMPP on a VPS in a different jurisdiction, using Tor to reach it. This is a niche but real use case.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

XMPP/OMEMO is legal to use in most jurisdictions. However:

- **Some countries restrict or ban encrypted messengers.** Check your local law.
- **Using XMPP to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid it.** On a work device, using XMPP may violate acceptable-use policy.
- **Self-hosting shifts legal responsibility to you.** If you run a server for others, you may be legally responsible for what they do with it. Consult a lawyer if in doubt.
- **You are responsible for your contacts' safety.** Explain the metadata limitations honestly.
- **No tool replaces operational discipline.**
- **Authorized use only.** In a professional context, use XMPP/OMEMO only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying XMPP/OMEMO for a small group:

- **Self-host the server.** This is the only way to control metadata. Use Prosody on a VPS in a jurisdiction that respects privacy.
- **Enable OMEMO by default** in the group's recommended client.
- **Standardize the client.** Pick one client (e.g. Conversations + Gajim) and pin the version.
- **Define a verification protocol.** Every member must verify every other member's fingerprint in person or via a second channel.
- **Provide a recovery procedure.** If a device is lost, how is it removed from the OMEMO device list, and how is the group informed?
- **Disable MAM unless there is a specific need.** Encrypted archives are still metadata.
- **Disable push through Google/Apple** where possible (UnifiedPush).
- **Monitor the threat model.** XMPP and OMEMO evolve. Re-evaluate periodically.

## 13. References

- XMPP Standards Foundation - https://xmpp.org/
- XEP-0384: OMEMO Encryption - https://xmpp.org/extensions/xep-0384.html
- XEP-0450: Automatic Trust Management (ATM) - https://xmpp.org/extensions/xep-0450.html
- Conversations (Android) - https://conversations.im/
- Gajim (desktop) - https://gajim.org/
- Dino (Linux) - https://dino.im/
- Prosody XMPP server - https://prosody.im/
- Signal Protocol specification - https://signal.org/docs/
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - Real-Time Communication - https://www.privacyguides.org/en/real-time-communication/
