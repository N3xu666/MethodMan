# Anonymous Email

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Anonymous email is a layered problem. Even if you use an encrypted provider, the protocol itself (SMTP) leaks metadata: relays, timestamps, and often the sender's IP. This file covers privacy-focused providers (Proton Mail, Tutanota, Mailfence), self-hosted options, and the operational discipline required to use them without leaking your identity.

This file is a hands-on operator guide: what anonymous email protects against, how to set it up, and where it fails.

## 1. Overview

Email was designed in the 1970s with no security or privacy model. SMTP relays messages in plaintext by default, headers leak routing information, and the sender's IP is often included. Modern privacy-focused providers work around this by encrypting at rest, offering E2E encryption between users of the same provider, and stripping metadata where possible. But the protocol's weaknesses remain.

Key approaches:

- **Proton Mail** (Switzerland) - E2E encryption between Proton users, zero-access encryption at rest, Tor onion service, no personal info required (email or phone optional).
- **Tutanota** (Germany) - E2E encryption between Tutanota users, zero-access encryption, no phone required, subject lines and attachments encrypted by default.
- **Mailfence** (Belgium) - OpenPGP-based, WKD support, generous free tier.
- **Self-hosted** (Mail-in-a-Box, Mailcow) - full control, but you own the metadata and the reputation problem.
- **Throwaway / burner** - temporary addresses for one-time signups (ProtonMail alias, SimpleLogin, AnonAddy, Firefox Relay).

What email is bad at:

- **Metadata.** Even with E2E, the server sees who you email and when.
- **Sender IP.** Many clients leak your IP to the recipient unless you use a provider that strips it (Proton does for Proton-to-Proton).
- **Subject lines.** Some providers encrypt them, some do not (Tutanota does, Proton partially).
- **Compatibility with non-private providers.** E2E only works between users of the same provider; email to Gmail is only TLS-protected in transit.

## 2. Threat Model

What anonymous email protects against:

- **Server-side plaintext.** Zero-access encryption means the provider cannot read your mailbox.
- **Legal compulsion on the provider (for message content).** If the provider cannot decrypt, it cannot hand over plaintext.
- **Identity correlation (with a good provider).** No phone number, no email recovery, no IP logging (with Tor).
- **Metadata leakage (partial).** Some providers strip IP headers and minimize logs.
- **Mass surveillance of content.** At-rest encryption + E2E between users of the same provider.
- **Account takeover via SIM swap.** No phone number required for most providers.

What anonymous email does NOT protect against:

- **Metadata (who emails whom).** Servers see recipient addresses, timing, and message size.
- **Email to non-private providers.** Gmail, Outlook, and corporate addresses see plaintext.
- **Endpoint compromise.**
- **Sender IP leakage.** Many webmail clients leak your IP unless you use Tor or a provider that strips it.
- **Compromised provider.** A provider that is legally compelled or hacked may expose metadata.
- **Payment correlation.** If you pay for a premium tier with a personal card, you link your identity.
- **Recovery channel attacks.** A recovery email or phone can be used to take over your account.
- **Legal compulsion on the recipient.**
- **Traffic analysis at the network level.**

Threat model summary:

| Adversary | Proton / Tutanota | Self-hosted | Standard (Gmail) |
|-----------|-------------------|-------------|------------------|
| Provider reads content | No (zero-access) | No | Yes |
| Subpoena to provider (content) | No | No | Yes |
| Metadata (who/when) | Provider sees it | You see it | Google sees it |
| Sender IP to recipient | Stripped (Proton) | Depends | Leaked |
| Endpoint compromise | No | No | No |

## 3. How It Works (technical)

**SMTP (the underlying protocol):**

- Email is relayed through SMTP servers. Each hop adds a `Received:` header with the server IP and timestamp.
- TLS is used in transit for most modern servers (STARTTLS or SMTPS), but TLS is hop-by-hop, not end-to-end.
- The `From:` header is not authenticated by default (that is what SPF, DKIM, and DMARC add).

**Zero-access encryption (Proton, Tutanota):**

- When email arrives, the provider encrypts it with a key derived from your password (which the provider does not store).
- The provider stores only ciphertext. When you log in, your client decrypts.
- Content is never readable by the provider after the initial encryption.

**End-to-end encryption between users of the same provider:**

- Proton: E2E using OpenPGP, keys managed by the client.
- Tutanota: E2E using a custom scheme (AES + RSA), keys managed by the client.
- Between different providers: E2E does not work out of the box (unless both support OpenPGP with WKD).

**Proton-to-non-Proton:**

- Proton can send a password-protected message to a non-Proton recipient. The recipient clicks a link and enters a password shared out-of-band.
- This is not standard PGP; it is a Proton-specific mechanism.

**PGP integration:**

- Proton supports PGP for advanced users; Tutanota does not.
- For full PGP control, self-hosted or Mailfence is better.

**Onion service:**

- Proton runs an onion service (`protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion`) so you can access it over Tor without a browser-to-provider IP leak.

## 4. Installation and Setup

**Proton Mail:**

1. Go to https://proton.me/ (or the onion service via Tor Browser).
2. Sign up. You can use an existing email as recovery (or skip it), and you do NOT need to give a phone number.
3. Choose a username and a strong password.
4. Set a second password for mailbox encryption (recommended).
5. Enable 2FA (TOTP app, not SMS).
6. Optional: enable "Hide my email" (SimpleLogin aliases).
7. For high-risk use: always access via the onion service through Tor Browser.

**Tutanota:**

1. Go to https://tutanota.com/.
2. Sign up. No phone number required.
3. Choose a strong password.
4. Enable 2FA.
5. Note: Tutanota encrypts subject lines and attachments; Proton does not always encrypt subject lines.

**Mailfence:**

1. Go to https://mailfence.com/.
2. Sign up. Free tier includes PGP support.
3. Generate or import a PGP key.
4. Publish the public key to WKD (Web Key Directory) if you want others to find it automatically.

**Self-hosted (Mail-in-a-Box):**

```bash
# On a fresh Ubuntu 22.04 VPS
curl -s https://mailinabox.email/setup.sh | sudo bash
# Follow the prompts; the script handles DNS, TLS (Let's Encrypt), and DKIM
```

See Mail-in-a-Box documentation for DNS records (MX, SPF, DKIM, DMARC) - all required for deliverability.

**Burner / alias services:**

- **SimpleLogin** - email aliases that forward to your real inbox. Can be self-hosted.
- **AnonAddy** - similar to SimpleLogin; open source.
- **Firefox Relay** - simpler, browser-integrated.

Use aliases with a private provider to keep your real address out of signups.

## 5. Hardening and Configuration

**Provider-side hardening:**

- **2FA with TOTP only.** Avoid SMS 2FA (SIM swap risk). Use Aegis, Raivo, or a hardware key.
- **Mailbox password (Proton).** Set a separate password so your login password is not enough to decrypt your mailbox.
- **Recovery options.** If possible, disable recovery email and phone. If you must have recovery, use a separate anonymous email.
- **Payment.** Pay with crypto or a prepaid card if you do not want to link your identity. Free tiers are anonymous but limited.
- **Aliases.** Use SimpleLogin / AnonAddy for signups. Never give your real Proton address to a service you do not trust.
- **Onion service.** Always access via Tor Browser + the onion URL for high-risk use.

**Client-side hardening:**

- **Do not use a mail client (Thunderbird, Outlook) for high-risk accounts.** Use the provider's webmail via Tor Browser.
- **Disable loading of remote content (tracking pixels).** Proton and Tutanota block remote content by default; verify this.
- **Disable read receipts.**
- **Disable link previews.**

**Operational hardening:**

- **Compartmentalization.** Use separate accounts for separate identities. Do not mix work, personal, and anonymous.
- **Separate Tor circuits.** Do not use the same Tor circuit for your anonymous email and your real identity.
- **Time discipline.** Do not check your anonymous email at predictable times if correlation matters.
- **Content discipline.** Do not write in your usual style if stylometry is in your threat model.

**PGP-specific hardening:**

- **Generate keys offline.** Use a live USB with no network for key generation.
- **Use a hardware key (YubiKey, Nitrokey)** to store the private key.
- **Publish the public key to keys.openpgp.org and WKD.**
- **Sign your messages** so recipients can verify authenticity.

## 6. Operational Usage

**Sending an email:**

1. Log in via Tor Browser + the onion service.
2. Compose. If sending to a Proton/Tutanota user, E2E is automatic.
3. If sending to a non-private user, consider PGP (if you have their public key) or a password-protected message.
4. Send.

**Receiving an email:**

1. Log in via the same path.
2. Read. Do not click links; copy them and open in a new Tor tab if needed.
3. Do not enable remote content.

**Signing up for a service:**

1. Create a new alias in SimpleLogin / AnonAddy.
2. Use the alias for the service.
3. If the alias is leaked or spammed, disable it.

**PGP communication:**

1. Exchange public keys out-of-band (QR code, keys.openpgp.org).
2. Verify fingerprints.
3. Sign and encrypt.

**Account recovery:**

- If you must have recovery, use a separate anonymous address or a code stored offline.
- Never use a personal email or phone as recovery for an anonymous account.

**Payment:**

- Prefer crypto (Monero for maximum privacy) or a prepaid card bought with cash.
- Avoid personal credit cards for anonymous accounts.

**Deletion:**

- If you decide to stop using an account, delete it (Proton supports account deletion) and rotate any aliases.

## 7. Common Mistakes

Real mistakes that break anonymous email:

1. **Using Gmail or Outlook for anything you want private.** Google reads your mail and can be subpoenaed.
2. **Enabling SMS 2FA.** SIM swap defeats it.
3. **Adding a personal recovery email.** This links your anonymous account to your real identity.
4. **Paying with a personal credit card.** This links your account to your identity.
5. **Accessing via a regular browser without Tor.** Your IP is logged by the provider and may be visible to recipients.
6. **Sending email to non-private providers with sensitive content.** Gmail sees the plaintext.
7. **Reusing a username across services.** This links your identities.
8. **Writing in your usual style.** Stylometry can deanonymize you.
9. **Checking email at the same time every day.** Timing correlation.
10. **Assuming Proton's password-protected message is PGP.** It is not; it is a proprietary mechanism.
11. **Forgetting about the `Received:` headers.** They leak routing and sometimes IP.
12. **Not disabling remote content (tracking pixels).** Every open is logged.

## 8. Attacks Against It

Known attacks and limitations:

- **Metadata analysis.** Even with E2E, the provider (or a subpoenaed provider) sees who emails whom, when, and message sizes.
- **Sender IP leakage.** Some clients leak your real IP to the recipient. Proton strips it for Proton-to-Proton; other providers vary.
- **Compromised provider.** A provider that is hacked or legally compelled may expose metadata or (in rare cases) plaintext.
- **Endpoint compromise.** Malware on your device can read email before encryption or after decryption.
- **Recovery channel attacks.** A recovery email or phone can be used to take over your account.
- **Password reset attacks.** Weak passwords or reused passwords can be guessed or credential-stuffed.
- **Stylometry.** Writing style can identify you even without metadata.
- **Traffic analysis.** A global passive adversary can correlate login times and message timing.
- **Legal compulsion on the provider (metadata).** Even zero-access providers may be compelled to log IPs or metadata in some jurisdictions.
- **Alias leakage.** If an alias is linked to your real address elsewhere, the anonymity is gone.
- **Phishing.** The provider cannot protect you from clicking a link in a phishing email.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **DNS queries.** The provider's domains are visible to a DNS resolver.
- **TLS SNI.** The provider's hostname may be visible in SNI.
- **Connection to known privacy providers.** Proton, Tutanota, and Mailfence domains are on many blocklists. Some corporate firewalls block them entirely.
- **Tor usage.** If the user uses Tor, the network sees Tor traffic (which may itself be flagged or blocked).
- **Onion service access.** Some networks block `.onion` addresses by policy.
- **Email content (if not E2E).** Corporate DLP can read email to/from non-private addresses.
- **On a managed device:** the app or browser extension is visible. MDM can block it.

Blocking anonymous email at the network level is relatively easy: block the provider's domains, or block Tor entirely. Sophisticated users will route around this with bridges or Snowflake.

## 10. Case Studies

- **Proton Mail and law enforcement (2021).** A French climate activist was identified via Proton Mail after a Swiss court order compelled Proton to log the activist's IP. This is a critical reminder: Proton does not log IPs by default, but it can be legally compelled to do so. If your threat model includes a hostile state, always access via Tor.
- **Tutanota in Germany (2020).** A German court ordered Tutanota to log incoming email for a specific account. Tutanota complied (they can log incoming mail, not content). Again: metadata is the weak point.
- **Proton and the "encrypted email" myth.** In 2021, Proton clarified that "encrypted email" does not mean "anonymous email". Encryption protects content; anonymity requires operational discipline.
- **Hushmail (2007).** Hushmail was legally compelled to hand over plaintext of a specific account by a Canadian court. This was possible because Hushmail controlled the keys. It is the canonical example of why "we encrypt your email" is not the same as "we cannot read your email".
- **Anonymous email in journalism.** SecureDrop and similar systems combine anonymous drop servers with anonymous email to protect sources. The operational complexity is high and requires dedicated infrastructure.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Anonymous email is legal to use in most jurisdictions. However:

- **Some countries restrict or ban encrypted email.** Check your local law.
- **Using anonymous email to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid it.** Using a privacy provider on a work device may violate acceptable-use policy.
- **Privacy providers may be legally compelled to log metadata.** See the Proton and Tutanota case studies above.
- **You are responsible for your contacts' safety.**
- **No tool replaces operational discipline.**
- **Authorized use only.** In a professional context, use anonymous email only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying anonymous email for a small group:

- **Standardize the provider.** Pick one (Proton, Tutanota) and use it consistently.
- **Standardize the access path.** Tor Browser + onion service for high-risk use.
- **2FA policy.** Require TOTP, forbid SMS.
- **Recovery policy.** No personal recovery email or phone. Recovery code stored offline.
- **Alias policy.** Use SimpleLogin / AnonAddy for signups; never share the primary address.
- **Payment policy.** No personal credit cards for anonymous accounts.
- **Metadata awareness.** Explain to all members that metadata is the primary weakness.
- **Compromise procedure.** If a device is lost, how is the account rotated, and how is the group informed?
- **Test the recovery process** before you need it.
- **Monitor the threat model.** Provider policies and legal environments change. Re-evaluate periodically.

## 13. References

- Proton Mail - https://proton.me/mail
- Tutanota - https://tutanota.com/
- Mailfence - https://mailfence.com/
- Proton Mail onion service - https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/
- SimpleLogin - https://simplelogin.io/
- AnonAddy - https://anonaddy.com/
- Mail-in-a-Box - https://mailinabox.email/
- OpenPGP Best Practices - https://riseup.net/en/security/message-security/openpgp/best-practices
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - Email Services - https://www.privacyguides.org/en/email/
