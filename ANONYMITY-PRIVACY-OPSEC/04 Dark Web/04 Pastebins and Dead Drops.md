# Pastebins and Dead Drops

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Pastebins and dead drops are two patterns for publishing or exchanging data anonymously. A pastebin is a service (or self-hosted tool) that stores text at a URL, often with an expiration timer. A dead drop is a location (physical or digital) where data is left for another party to retrieve later, with no direct contact between the two.

Both are used by journalists, activists, and security researchers to move information without a real-time channel. Both have serious operational caveats.

This file is a hands-on operator guide: what pastebins and dead drops protect against, how to use them, and where they fail.

## 1. Overview

**Pastebins:**

- **Public pastebins:** Pastebin.com, Hastebin, Ghostbin, PrivateBin (public instances), dpaste. Anyone with the URL can read. Some support passwords or expiration.
- **PrivateBin:** Open-source, encrypted pastebin; can be self-hosted. Zero-knowledge: the encryption key is in the URL fragment, never sent to the server.
- **Self-hosted:** PrivateBin, MicroBin, 0x0.st (self-hosted variant), Haste server.
- **Onion pastebins:** some pastebins are reachable only via Tor (.onion). Examples: privatebin instances on Tor.

**Dead drops:**

- **Physical dead drops:** a pre-arranged physical location (a hollow tree, a specific bench, a locker) where a USB stick or paper is left. Used in espionage and by activists in high-risk environments.
- **Digital dead drops:** a server or service where data is deposited and later retrieved, without a real-time channel. Examples: a shared encrypted file on a cloud provider, an email draft folder, an onion service with a pre-shared password.
- **OnionShare in "receive" mode** can be used as a digital dead drop.
- **Burner accounts** on legitimate services (e.g. a Proton Mail account with a shared password) are sometimes used as dead drops.

Key properties:

- **Asynchronous.** No real-time contact between parties.
- **Anonymous (if done correctly).** No accounts, no emails, no identities.
- **Ephemeral (if configured).** Pastebins can expire; dead drops can be cleared.
- **Fragile.** Both patterns depend on operational discipline; mistakes leak identity.

## 2. Threat Model

What pastebins and dead drops protect against:

- **Real-time correlation.** Sender and receiver do not need to be online at the same time.
- **Account correlation.** No accounts, no emails (if done correctly).
- **Provider reading (PrivateBin).** Zero-knowledge encryption means the server cannot read the content.
- **Direct contact.** The parties never meet, never exchange messages in real time.
- **Long-term storage (configurable).** Pastebins can expire; dead drops can be cleared after retrieval.
- **Provider subpoena (PrivateBin with client-side encryption).** The server has only ciphertext.

What pastebins and dead drops do NOT protect against:

- **Metadata in the content.** The paste itself may reveal identity (writing style, IP, file metadata).
- **IP leakage when posting.** Public pastebins log IPs. Use Tor.
- **Public pastebins reading content.** Public pastebins can read everything you paste.
- **Search engine indexing.** Public pastebins may be indexed; the paste can be found by anyone.
- **URL guessing.** Short URLs can be guessed or brute-forced.
- **Server compromise.** If the pastebin server is compromised, pastes may be exposed (unless client-side encrypted).
- **Dead drop discovery.** A physical dead drop can be watched, or a digital one can be found.
- **Endpoint compromise.** If your machine is compromised, the paste or drop is compromised.
- **Global passive adversary.** Traffic correlation remains possible.
- **Legal compulsion on the pastebin operator.** The operator may be compelled to log or hand over data.
- **Deletion is not guaranteed.** Even after expiration, backups may retain the content.

Threat model summary:

| Pattern | Provider reads | IP hidden | Metadata | Long-term exposure |
|---------|----------------|-----------|----------|--------------------|
| Public pastebin (no password) | Yes | Only with Tor | Content may reveal | High (indexed) |
| PrivateBin (client-side encryption) | No | Only with Tor | Content may reveal | Depends on expiration |
| Self-hosted pastebin | Only if you leak | Only with Tor | Content may reveal | You control |
| Physical dead drop | N/A | N/A | Physical evidence | Depends on location |
| Digital dead drop (onion) | No (Tor) | Yes (Tor) | Content may reveal | You control |

## 3. How It Works (technical)

**Public pastebin:**

- You paste text into a web form.
- The server stores the text and returns a URL.
- The URL is the only secret; anyone with the URL can read.
- Optional: password protection, expiration timer, syntax highlighting.
- The server sees your IP and the content (unless client-side encrypted).

**PrivateBin:**

- Client-side encryption: the paste is encrypted in your browser with a key.
- The key is put in the URL fragment (after `#`); the browser does not send the fragment to the server.
- The server stores only ciphertext.
- The recipient opens the URL; the browser decrypts using the key from the fragment.
- Result: the server cannot read the paste; the URL (including the fragment) is the only secret.
- Optional: password (adds a second layer), expiration, burn-after-reading.

**Self-hosted pastebin:**

- You install PrivateBin, MicroBin, or Haste on your own server.
- You control the server, logs, and retention.
- You are responsible for hardening it.

**Onion pastebin:**

- Same as a public pastebin, but reachable only via Tor.
- The service's IP is hidden; the user's IP is hidden by Tor.
- The URL is still the secret (and must be shared over a secure channel).

**Physical dead drop:**

- Two parties agree on a location and a signal (e.g. a chalk mark).
- One party places a physical item (USB, paper) at the location.
- The other party retrieves it later.
- No direct contact. The signal confirms placement or retrieval.

**Digital dead drop:**

- Two parties agree on a service and a shared secret (password, key).
- One party uploads data to the service (e.g. an encrypted file on a cloud provider, or an OnionShare instance in "receive" mode).
- The other party retrieves it.
- No direct contact. The shared secret is the access control.

## 4. Installation and Setup

**Using a public pastebin (Pastebin.com, dpaste, etc.):**

1. Open Tor Browser.
2. Navigate to the pastebin.
3. Paste text.
4. Optional: set expiration, password.
5. Submit.
6. Copy the URL and share it out-of-band.

**Using PrivateBin (public instance):**

1. Open Tor Browser.
2. Navigate to a trusted PrivateBin instance. Examples (verify current status yourself; public instances change):
   - https://privatebin.net/
   - Self-hosted or a .onion mirror.
3. Paste text.
4. Set expiration and (optionally) a password.
5. Submit.
6. Copy the URL (including the fragment after `#`).
7. Share the URL out-of-band.

**Self-hosting PrivateBin (Docker):**

```bash
# On a VPS you control
docker run -d --name privatebin -p 8080:8080 \
    -v /srv/privatebin/data:/srv/data \
    privatebin/nginx-fpm-alpine:latest
```

Then put it behind a reverse proxy with TLS (nginx, Caddy).

**Self-hosting MicroBin (Rust):**

```bash
# From the releases page
wget https://github.com/szabodanika/microbin/releases/latest/download/microbin-x86_64-unknown-linux-musl
chmod +x microbin-x86_64-unknown-linux-musl
./microbin-x86_64-unknown-linux-musl
# Listens on 0.0.0.0:8080 by default
```

**Onion pastebin:**

- Search the Tor network for public PrivateBin instances on .onion.
- Or self-host PrivateBin behind a Tor onion service (see 01 Hidden Services).

**OnionShare as a dead drop (Receive Files):**

1. Open OnionShare.
2. Select "Receive Files".
3. Choose a folder.
4. Enable private mode (password).
5. Set an auto-stop timer (short).
6. Start receiving.
7. Share the .onion address and the password via separate channels.
8. The sender uploads; you retrieve.
9. Stop receiving when done.

**Physical dead drop (conceptual):**

- Choose a location that is accessible but not obvious.
- Agree on a signal (chalk mark, tape, a specific object placed nearby).
- Place or retrieve the item.
- Clear the signal.

Note: physical dead drops are an espionage technique; use only in a legal context (e.g. authorized red-team exercise).

## 5. Hardening and Configuration

**Posting hardening:**

- **Always use Tor Browser** to post. Public pastebins log IPs.
- **Never use a personal account** on a pastebin.
- **Use client-side encrypted pastebins** (PrivateBin) for anything sensitive.
- **Set a short expiration.** Hours, not weeks.
- **Use burn-after-reading** if supported.
- **Use a password** on top of the URL fragment (defense in depth).
- **Do not include metadata** in the paste (no real names, no personal details, no copy-paste from your usual apps if the clipboard may reveal metadata).
- **Strip whitespace and trailing data** that may be a fingerprint (some editors add invisible characters).

**Sharing the URL:**

- **Out-of-band only.** Do not send the URL over the same channel where you discuss the content.
- **Split the secret.** Share the URL via one channel, the password via another.
- **One-time use.** If the paste is burn-after-reading, ensure the recipient opens it once.
- **Confirm receipt.** Use a separate out-of-band signal.

**Self-hosted hardening:**

- **TLS only.**
- **No logs** (or short retention).
- **Rate limiting.**
- **Disable indexing** (robots.txt, no sitemap).
- **Set a hard retention policy.**
- **Backup carefully.** A pastebin backup may retain expired pastes.
- **Isolate the service** (separate container/VM).
- **Update regularly.**

**Dead drop hardening:**

- **Physical:** choose a location with low surveillance. Vary the timing. Do not use the same location twice. Avoid predictable patterns.
- **Digital:** use client-side encryption. Use Tor for deposit and retrieval. Rotate the drop location. Do not reuse the same shared secret.
- **OnionShare:** short auto-stop timer; private mode; do not reuse the .onion address.
- **Cloud-based dead drops:** use end-to-end encrypted storage (e.g. Cryptomator, rclone with encryption) with a strong passphrase shared out-of-band.

**Operational hygiene:**

- **Compartmentalize.** Do not use the same device for pastebins and personal activities.
- **Do not access the pastebin from your home IP.** Use Tor.
- **Do not check the pastebin at the same time every day.**
- **Do not write in your usual style.** Stylometry applies.
- **Do not reuse usernames or URLs.**

## 6. Operational Usage

**Post a paste (PrivateBin):**

1. Open Tor Browser.
2. Navigate to a trusted PrivateBin instance.
3. Paste text.
4. Set expiration (e.g. 1 day) and optionally a password.
5. Submit.
6. Copy the URL (including the fragment).
7. Share the URL via one channel and the password via another.

**Retrieve a paste:**

1. Open Tor Browser.
2. Open the URL.
3. Enter the password if required.
4. Read. If burn-after-reading, the paste is deleted on read.

**Use OnionShare as a dead drop:**

1. Open OnionShare -> Receive Files.
2. Choose a folder.
3. Enable private mode and set a password.
4. Set a short auto-stop timer.
5. Start receiving. Note the .onion address.
6. Share the .onion address and the password via separate channels.
7. Monitor the folder for uploads.
8. When the file arrives, verify it (hash, signature if provided).
9. Stop receiving.
10. Do not leave OnionShare running.

**Use a cloud-based digital dead drop:**

1. Encrypt the file locally (Cryptomator, gocryptfs, age, GPG).
2. Upload the encrypted file to a cloud service (or a shared folder).
3. Share the passphrase/key out-of-band.
4. The recipient downloads the file and decrypts it.
5. Delete the file after retrieval (and remember the cloud provider may retain backups).

**Physical dead drop:**

1. Agree on a location, signal, and timing.
2. Place the item.
3. Leave the signal.
4. The recipient retrieves the item.
5. The recipient removes the signal.
6. Do not reuse the location.

## 7. Common Mistakes

Real mistakes that break pastebin / dead drop protections:

1. **Posting from a personal IP.** Public pastebins log IPs.
2. **Using the same channel to share the URL and the password.** Compartmentalize.
3. **Using a public pastebin for sensitive content.** Use PrivateBin or self-host.
4. **Not setting an expiration.** Pastes can persist indefinitely.
5. **Assuming deletion removes all copies.** Backups may retain content.
6. **Using a guessable URL.** Short URLs can be brute-forced.
7. **Searching for the paste on Google.** Public pastes may be indexed.
8. **Reusing the same dead drop.** Increases discovery risk.
9. **Reusing the same shared secret.** If compromised, all past and future drops are exposed.
10. **Not using Tor.** Your IP leaks.
11. **Writing in your usual style.** Stylometry.
12. **Copy-pasting content with hidden characters** (e.g. from a word processor). These can fingerprint the source.
13. **Forgetting to clear the dead drop.** Data left behind is found.
14. **Using a cloud dead drop without client-side encryption.** The provider can read it.
15. **Assuming OnionShare is a persistent service.** It is not; the .onion address is gone when you stop.
16. **Using physical dead drops without a legal context.** This is an espionage technique; misuse can be illegal.

## 8. Attacks Against It

Known attacks and limitations:

- **IP logging.** Public pastebins log IPs. Tor mitigates.
- **Server compromise.** A compromised pastebin can expose pastes (unless client-side encrypted).
- **URL guessing.** Short URLs can be brute-forced; use long random URLs.
- **Indexing.** Public pastes may be indexed by search engines and archived by third parties.
- **Archive sites.** Some services archive pastebin content; deletion is not absolute.
- **Metadata in content.** Even client-side encrypted pastes leak metadata in the content itself.
- **Stylometry.** Writing style identifies the author.
- **Dead drop surveillance.** A physical dead drop can be watched; a digital one can be monitored.
- **Shared secret compromise.** If the password/key is compromised, the drop is compromised.
- **OnionShare DoS.** While running, the service can be DoS'd.
- **Legal compulsion on the pastebin operator.** The operator may be compelled to log or retain data.
- **Global passive adversary.** Traffic correlation remains possible.
- **Endpoint compromise.** Malware on either side compromises the exchange.
- **Cache and clipboard leaks.** Browser cache, clipboard history, and OS-level caches may retain the paste.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Tor traffic.** Pastebin/dead drop access via Tor is Tor traffic. Entry guards are known.
- **Clearnet pastebin access.** If the user does not use Tor, the pastebin domain is visible.
- **DNS queries.** The pastebin's domain may be resolved in the clear.
- **TLS SNI.** The pastebin's hostname may be visible in SNI.
- **On a managed device:** browser history, cache, and clipboard history may reveal the paste.
- **On a managed network:** DLP (Data Loss Prevention) tools may scan outbound HTTP for pastebin domains.
- **Physical dead drops:** surveillance or physical discovery.

Blocking pastebins at the network level is common (many corporate firewalls block known pastebin domains). Users can route around this with Tor.

## 10. Case Studies

- **Pastebin and data leaks (multiple).** Pastebin.com has been used for both legitimate and criminal data sharing. Leaked credentials, dumps, and manifestos have appeared on pastebins.
- **PrivateBin adoption.** PrivateBin is widely used for client-side encrypted pastes, including by privacy-focused communities.
- **Snowden and dead drops (context).** Snowden used physical and digital dead drops in some phases of his communications. Documented in the Snowden archives.
- **WikiLeaks and dead drops.** WikiLeaks used a submission system that functioned as a digital dead drop, later complemented by SecureDrop.
- **Physical dead drops in espionage.** Documented in many espionage cases (e.g. the Russian illegals case in the US, 2010). A case study in the operational complexity of physical drops.
- **OnionShare as a dead drop.** OnionShare in "receive" mode is a common pattern for one-time anonymous uploads.
- **Criticism.** Pastebins and dead drops are fragile; a single operational mistake can break the anonymity of both parties. The tools are simple; the discipline is not.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Pastebins and dead drops are legal to use in most jurisdictions. However:

- **Some countries restrict or ban Tor and anonymous publishing services.** Check your local law.
- **Using pastebins or dead drops to distribute illegal content is a crime everywhere.**
- **Corporate policy may forbid pastebins.** On a work device, using pastebins may violate acceptable-use policy.
- **Physical dead drops are an espionage technique.** Use only in a legal context (e.g. authorized red-team exercise or a documented research project).
- **You are responsible for what you publish.** A pastebin is a publication.
- **Do not use pastebins or dead drops to harass, stalk, defraud, or harm any person.**
- **Authorized use only.** In a professional context, use these tools only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying pastebin / dead drop workflows for a small group:

- **Standardize on PrivateBin** (client-side encrypted) or self-hosted equivalents.
- **Standardize on Tor.** All posting and retrieval via Tor Browser.
- **Define a channel policy.** URL in one channel, password in another.
- **Define an expiration policy.** Hours, not weeks.
- **Define a burn-after-reading policy.** Use it where supported.
- **Define a dead drop policy.** No reuse; no shared secrets; short windows.
- **Define a retrieval policy.** Confirm receipt out-of-band; clear the drop.
- **Train users.** Pastebins and dead drops are simple tools with subtle operational requirements.
- **Test the workflow** before relying on it.
- **Monitor the threat model.** Services change; re-evaluate periodically.

## 13. References

- PrivateBin - https://privatebin.info/
- PrivateBin demo instance - https://privatebin.net/
- MicroBin - https://github.com/szabodanika/microbin
- Pastebin.com - https://pastebin.com/ (public; not recommended for sensitive content)
- 0x0.st - https://0x0.st/ (file paste, not text-only)
- OnionShare - https://onionshare.org/
- Tor Project - Onion Services - https://community.torproject.org/onion-services/
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - File Sharing - https://www.privacyguides.org/en/file-sharing/
