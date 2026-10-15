# PGP

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

PGP (Pretty Good Privacy) and its open standard OpenPGP are the oldest and most widely deployed end-to-end encryption system for email and files. PGP protects message content and provides digital signatures, but it does NOT protect metadata and it is notoriously easy to misuse.

This file is a hands-on operator guide: what PGP protects against, how to generate and manage keys, how to use it day-to-day, and where it fails.

## 1. Overview

PGP was created by Phil Zimmermann in 1991 and standardized as OpenPGP (RFC 4880, updated by RFC 9580 in 2024). It is used for:

- **Email encryption** (via Thunderbird + Enigmail, or directly in Proton Mail / Mailfence).
- **File encryption** (via GnuPG).
- **Code signing** (Git commits, software releases).
- **Identity verification** (signing keys, web of trust).

Key properties:

- **Hybrid encryption.** A symmetric session key encrypts the message; the session key is encrypted with the recipient's public key (RSA or ECC).
- **Digital signatures.** Messages and files can be signed to prove authenticity and integrity.
- **Key-based identity.** A public key is your identity; a private key proves it.
- **Web of trust.** Decentralized trust model where users sign each other's keys.
- **No metadata protection.** PGP encrypts content, not headers.

PGP is a tool, not a system. Its security depends entirely on how you generate, store, and verify keys.

## 2. Threat Model

What PGP protects against:

- **Message content.** Only the holder of the private key can decrypt.
- **Tampering.** Signatures detect modification.
- **Impersonation (with signature verification).** A signed message proves the sender holds the private key.
- **Server-side plaintext.** The email provider sees only ciphertext.
- **Long-term confidentiality.** Messages stay encrypted indefinitely if the private key is safe.
- **Legal compulsion on the provider.** The provider cannot decrypt what it cannot read.

What PGP does NOT protect against:

- **Metadata.** The `To:`, `From:`, `Subject:`, and `Received:` headers are not encrypted.
- **Sender IP leakage.** The email client's IP is often visible to the recipient.
- **Endpoint compromise.** Malware on your device can read plaintext before encryption or after decryption.
- **Key theft.** If your private key is stolen, all past messages can be decrypted (unless forward secrecy is used, which standard PGP does not provide).
- **Traffic analysis.**
- **Compromised recipient.** The recipient can leak the plaintext.
- **Legal compulsion on you.** If you are compelled to hand over the private key, PGP cannot help.
- **Rubber-hose cryptanalysis.** If someone can force you to decrypt, PGP cannot help.
- **Phishing.** If you sign a malicious message, the recipient may trust it.

Threat model summary:

| Adversary | PGP (with verified keys) | PGP (no verification) |
|-----------|--------------------------|------------------------|
| Passive network observer | Strong | Strong |
| Malicious email provider | Strong (content) | Strong (content) |
| Metadata analyst | None | None |
| Compromised endpoint | None | None |
| Key thief (post-theft) | Partial (past messages exposed) | Partial (past messages exposed) |
| Legal compulsion on you | None | None |

## 3. How It Works (technical)

PGP uses hybrid encryption:

1. **Session key.** A random symmetric key (AES-256 typically) is generated for each message.
2. **Message encryption.** The message is encrypted with the session key.
3. **Session key encryption.** The session key is encrypted with the recipient's public key (RSA or ECC).
4. **Transmission.** The encrypted message and encrypted session key are sent together.
5. **Decryption.** The recipient decrypts the session key with their private key, then decrypts the message.

**Keys:**

- **Public key.** Shared freely. Used to encrypt messages and verify signatures.
- **Private key.** Never shared. Used to decrypt messages and create signatures.
- **Key ID.** A short identifier (last 8 or 16 hex digits of the fingerprint). Used to refer to a key.
- **Fingerprint.** A full hash of the public key (SHA-1 in older keys, SHA-256 in modern keys). Used to verify identity.
- **Subkeys.** Modern keys have a primary key (for signing and certification) and subkeys (for encryption).

**Modern algorithms (OpenPGP RFC 9580, 2024):**

- **Ed25519** for signing.
- **X25519** for encryption.
- **AES-256** for symmetric encryption.
- **SHA-256** for hashing.

Avoid: RSA-1024 (deprecated), DSA (deprecated), SHA-1 (deprecated for signatures).

**Web of trust:**

- Users sign each other's keys to vouch for their identity.
- Key servers (keys.openpgp.org, keyserver.ubuntu.com) distribute public keys.
- WKD (Web Key Directory) allows email providers to publish keys automatically.

**Trust model:**

- **Direct trust.** You have verified the key yourself.
- **Web of trust.** You trust a key because someone you trust has signed it.
- **Blind trust.** You use a key without verification. Useful for casual use, dangerous for high-risk.

## 4. Installation and Setup

**Linux (GnuPG):**

```bash
# Debian / Ubuntu
sudo apt install gnupg

# Fedora
sudo dnf install gnupg2

# Arch
sudo pacman -S gnupg

# Verify
gpg --version
```

**Windows:**

- Install Gpg4win from https://www.gpg4win.org/.
- Includes Kleopatra (GUI) and GnuPG (CLI).

**macOS:**

- Install GPG Suite from https://gpgtools.org/, or use Homebrew: `brew install gnupg`.

**Generating a key (modern, Ed25519):**

```bash
gpg --full-generate-key
# Choose: (9) ECC (sign and encrypt) or (10) ECC (set your own capabilities)
# Choose: (1) Curve 25519
# Set expiration: 2 years (recommended)
# Enter your real name (or a pseudonym if anonymous)
# Enter your email
# Enter a passphrase (strong, unique - store in a password manager)
```

**Export public key:**

```bash
gpg --armor --export you@example.com > public.asc
```

**Publish to keyserver:**

```bash
gpg --keyserver keys.openpgp.org --send-keys <FINGERPRINT>
```

keys.openpgp.org is recommended because it strips third-party signatures and verifies email ownership.

**Import a public key:**

```bash
gpg --import public.asc
gpg --fingerprint you@example.com
```

**Verify a fingerprint:**

- Compare the fingerprint in person or via a second channel.
- Do not trust a fingerprint you received in the same channel as the key (MITM risk).

## 5. Hardening and Configuration

**Key generation:**

- **Use Ed25519 / X25519.** Do not generate RSA below 3072 bits or DSA keys.
- **Set an expiration.** 1-2 years. Renewed keys are better than never-expiring keys.
- **Use a strong passphrase.** At least 5 random words (Diceware) or a long random string.
- **Generate on an air-gapped machine** for high-risk use.
- **Use a pseudonym, not your real name,** if anonymity matters.

**Private key storage:**

- **Best:** hardware token (YubiKey 5, Nitrokey 3) that never exposes the private key.
- **Good:** offline storage on an encrypted USB, mounted only when needed.
- **Acceptable:** encrypted on disk with a strong passphrase and full-disk encryption.
- **Never:** unencrypted, in cloud storage, or on a device you do not control.

**GnuPG configuration (gpg.conf):**

```text
# Strong defaults
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
no-comments
no-emit-version
no-greeting
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
armor
```

**Email client:**

- **Thunderbird + OpenPGP (built-in since v78).** Works on all platforms.
- **Gajim + OMEMO** for XMPP (not email, but relevant).
- **Proton Mail** supports PGP import for advanced users.
- **Do not use webmail with PGP unless the provider supports it natively** (E2E in the browser is hard to verify).

**Operational hardening:**

- **Sign every message** so recipients can verify authenticity.
- **Encrypt by default** where possible.
- **Verify fingerprints** in person or via a second channel.
- **Rotate subkeys** without rotating the primary key.
- **Revocation certificate.** Generate it when you create the key; store it offline.

## 6. Operational Usage

**Encrypt a file:**

```bash
gpg --encrypt --recipient you@example.com file.txt
# Produces file.txt.gpg

gpg --decrypt file.txt.gpg > file.txt
```

**Encrypt and sign:**

```bash
gpg --encrypt --sign --recipient you@example.com file.txt
```

**Sign a message (cleartext):**

```bash
gpg --clearsign message.txt
# Produces message.txt.asc with an inline signature
```

**Verify a signature:**

```bash
gpg --verify message.txt.asc
```

**Sign a Git commit:**

```bash
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true

git commit -S -m "Signed commit"
```

**Encrypt email (Thunderbird):**

1. Import the recipient's public key.
2. Verify the fingerprint.
3. Compose a message. Thunderbird automatically detects if a key is available.
4. Enable "Encrypt" and "Sign" in the compose window.
5. Send.

**Verify an incoming signed message:**

- The client shows a signature status.
- If the key is unknown or untrusted, verify the fingerprint before replying.

**Revoke a compromised key:**

```bash
gpg --import revocation-certificate.asc
gpg --keyserver keys.openpgp.org --send-keys <FINGERPRINT>
```

**Backup your key:**

```bash
gpg --export-secret-keys --armor you@example.com > private-backup.asc
# Store on an encrypted USB, offline. Never in cloud.
```

## 7. Common Mistakes

Real mistakes that break PGP:

1. **Using RSA-1024 or DSA.** Both are deprecated and weak.
2. **No expiration date.** A key without expiration is a key that can never be safely rotated.
3. **Weak passphrase.** A stolen private key with a weak passphrase is a stolen private key.
4. **Storing the private key in cloud storage.** Cloud providers can be subpoenaed or hacked.
5. **Not verifying fingerprints.** A public key without verification is just a claim.
6. **Trusting the key server blindly.** Keyservers can be poisoned with fake signatures (certificate flooding).
7. **Not generating a revocation certificate.** If your key is compromised and you cannot revoke it, the damage is permanent.
8. **Signing without reading.** A signature proves authorship, not safety.
9. **Using PGP for metadata protection.** It does not.
10. **Not rotating keys.** Old keys accumulate risk.
11. **Sending encrypted email to a non-PGP user.** The provider may store the message in plaintext after decryption.
12. **Using PGP in a webmail interface without verification.** Browser-based PGP is hard to audit.
13. **Ignoring the "certificate flooding" attack.** An attacker can flood your key with signatures to bloat it. Mitigation: use keys.openpgp.org (strips third-party signatures).
14. **Not backing up the private key.** Lose the key, lose access to all past encrypted messages.

## 8. Attacks Against It

Known attacks and limitations:

- **Key theft.** A stolen private key compromises all past messages (no forward secrecy in standard PGP).
- **Certificate flooding (2020).** An attacker can flood a victim's key with signatures, causing GnuPG to crash or become unusable. Mitigation: keys.openpgp.org strips third-party signatures.
- **EFAIL (2018).** A class of attacks exploiting HTML email and client behavior to exfiltrate plaintext. Mitigation: use clients that do not auto-decrypt HTML, or use PGP/MIME correctly.
- **Signature spoofing (older keys).** SHA-1 signatures are deprecated. Use SHA-256 or stronger.
- **Compromised keyserver.** Keyservers are not trusted; verify fingerprints out-of-band.
- **Endpoint compromise.**
- **Metadata analysis.** PGP does not protect headers.
- **Legal compulsion on you.**
- **Phishing + signed messages.** A user who signs everything trains recipients to trust signatures; a phished user may sign a malicious message.
- **Quantum adversaries.** RSA and ECC are vulnerable to quantum attacks. Post-quantum PGP is not yet widely deployed (RFC 9580 includes some PQ options, but adoption is slow).
- **Side-channel attacks.** PGP implementations have had timing and memory attacks. Keep GnuPG updated.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Email headers.** PGP-encrypted email has a distinctive `Content-Type` (`application/pgp-encrypted`) and often a `-----BEGIN PGP MESSAGE-----` block. DLP tools flag it.
- **Attachment names.** `.gpg`, `.asc`, `.pgp` extensions.
- **Key server traffic.** Connections to keys.openpgp.org or keyserver.ubuntu.com are visible.
- **Signature blocks in code.** Signed Git commits are visible in the log.
- **On a managed device:** the PGP client (GnuPG, Kleopatra, Thunderbird with OpenPGP) is visible.
- **Metadata in transit.** Even with encrypted content, the `To:` and `From:` headers are visible to any relay.

Blocking PGP is trivial (block emails with PGP content type). Users in a corporate environment will usually comply because PGP is not needed for legitimate work. In high-surveillance environments, PGP is a red flag.

## 10. Case Studies

- **Phil Zimmermann and the US government (1991-1996).** Zimmermann was investigated for "exporting munitions" because PGP used strong cryptography. The case was dropped in 1996. It is the canonical example of cryptography as a political issue.
- **Snowden and PGP (2013).** Edward Snowden used PGP to communicate with journalists. The PGP email exchange was later published. It demonstrated both the power of PGP and its usability problems.
- **EFAIL (2018).** A class of vulnerabilities in PGP-enabled email clients that could exfiltrate plaintext. It forced a re-evaluation of how clients handle PGP and HTML.
- **Certificate flooding (2020).** An attack on SKS keyservers that bloated victim keys with signatures, causing GnuPG to crash. It led to the deprecation of SKS in favor of keys.openpgp.org.
- **Proton Mail and PGP.** Proton supports PGP import and export, bridging PGP with its own zero-access encryption model.
- **OpenPGP RFC 9580 (2024).** The first major revision of OpenPGP in 16 years. It modernizes algorithms (Ed25519, X25519, AES-256, SHA-256) and adds post-quantum options.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

PGP is legal to use in most jurisdictions. However:

- **Some countries restrict or ban strong encryption.** Check your local law.
- **Using PGP to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid it.** Using PGP on a work device may violate acceptable-use policy.
- **Legal compulsion.** If you are legally compelled to decrypt, PGP cannot help.
- **You are responsible for your contacts' safety.**
- **No tool replaces operational discipline.**
- **Authorized use only.** In a professional context, use PGP only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying PGP for a small group:

- **Standardize the algorithm.** Ed25519 + X25519 + AES-256 + SHA-256.
- **Standardize the client.** Thunderbird + built-in OpenPGP, or GnuPG + a mail client.
- **Define a key exchange protocol.** Fingerprints exchanged in person or via a second channel.
- **Define a key rotation policy.** Every 1-2 years.
- **Define a revocation procedure.** Who holds the revocation certificate, and how is it distributed?
- **Define a compromise procedure.** If a private key is stolen, revoke immediately and notify all contacts.
- **Train users.** PGP is easy to use incorrectly. A 30-minute training session prevents most mistakes.
- **Test the workflow** before relying on it.
- **Monitor the threat model.** Cryptographic best practices change. Re-evaluate periodically.

## 13. References

- [GnuPG](https://gnupg.org/)
- [GnuPG documentation](https://gnupg.org/documentation/)
- [OpenPGP RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880)
- [OpenPGP RFC 9580 (2024)](https://datatracker.ietf.org/doc/html/rfc9580)
- [keys.openpgp.org](https://keys.openpgp.org/)
- [Gpg4win (Windows)](https://www.gpg4win.org/)
- [GPG Suite (macOS)](https://gpgtools.org/)
- [Thunderbird OpenPGP](https://support.mozilla.org/en-US/kb/openpgp-thunderbird-howto-and-faq)
- [Riseup OpenPGP Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Encrypted Email](https://www.privacyguides.org/en/email-encryption/)
