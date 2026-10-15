# SecureDrop

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

SecureDrop is an open-source whistleblowing platform used by hundreds of news organizations worldwide. It lets a source submit documents to a journalist anonymously, over Tor, with no account, no email, and no metadata. The platform runs on dedicated hardware inside the newsroom, isolated from the organization's regular network.

This file is a hands-on operator guide: what SecureDrop protects against, how it is deployed and used, and where it fails.

## 1. Overview

SecureDrop was created by Aaron Swartz and Kevin Poulsen in 2013, then handed to the Freedom of the Press Foundation (FPF), which has maintained it since. It is deployed by news organizations, not by individuals, and each deployment is independent (no central service).

Key properties:

- **Air-gapped architecture.** The application server has no direct internet access; a separate server (the Monitor Server) handles Tor connectivity.
- **Tor-only access.** Both the source interface and the journalist interface are onion services.
- **No source accounts.** A source gets a randomly generated codename; the source uses the codename to return and check for replies.
- **One-time pads (optional).** The source can generate a one-time pad to encrypt a reply; the journalist decrypts offline.
- **Dedicated hardware.** SecureDrop runs on physical servers inside the newsroom, not on shared infrastructure.
- **Physical security matters.** The newsroom is responsible for physically securing the servers.
- **Open source.** Code is audited and published.
- **Strong separation.** Sources never see the journalist interface; journalists never see the source's IP.

Who runs SecureDrop:

- The New York Times, The Washington Post, The Guardian, ProPublica, The Intercept, and hundreds of other outlets.
- The FPF provides training, hardware recommendations, and a security audit program.

Who does NOT run SecureDrop:

- Individuals. SecureDrop is designed for organizations with the operational capacity to run dedicated hardware and follow strict procedures.
- Anyone without physical control over the hardware and the network.

## 2. Threat Model

What SecureDrop protects against:

- **Source identification by the news organization.** Sources never provide an email or phone; they receive a random codename.
- **Source IP exposure.** All source traffic goes through Tor.
- **Network-level surveillance of submissions.** Content is encrypted end-to-end between the source and the SecureDrop server.
- **Server-side compromise (partial).** The application server is air-gapped from the internet; only the Monitor Server talks to Tor.
- **Subpoena to a central provider.** There is no central provider; each deployment is independent.
- **Malicious submissions from the internet.** The air gap limits the attack surface.
- **Insider threats (partial).** Journalists use dedicated hardware (the "Secure Viewing Station", an air-gapped machine) to decrypt submissions.

What SecureDrop does NOT protect against:

- **Source operational mistakes.** If the source leaks identity through the document metadata, the writing style, or a separate channel, SecureDrop cannot help.
- **Newsroom compromise.** If the newsroom's network or physical premises are compromised, SecureDrop's protections are weakened.
- **Endpoint compromise at the source.** Malware on the source's machine can log everything.
- **Endpoint compromise at the journalist's machine.** The air-gapped Secure Viewing Station mitigates this but does not eliminate it.
- **Targeted deanonymization.** A global passive adversary can attempt traffic correlation.
- **Physical access to the servers.** If the servers are seized, the encrypted data may be at risk (SecureDrop uses full-disk encryption, but physical coercion is a real threat).
- **Legal compulsion on the newsroom.** In some jurisdictions, the newsroom may be compelled to hand over data.
- **Insider misuse.** A malicious journalist with access to the Secure Viewing Station can leak a source.
- **Metadata in the submitted document.** The source is responsible for stripping metadata.
- **The source telling someone.** If the source talks, SecureDrop cannot help.

Threat model summary:

| Adversary | SecureDrop |
|-----------|------------|
| Source IP discovery | Strong (Tor) |
| Newsroom identification of source | Strong (no accounts) |
| Network surveillance | Strong (Tor + E2E) |
| Global passive adversary | Weak (traffic correlation) |
| Endpoint compromise (source) | None |
| Endpoint compromise (journalist) | Partial (air-gapped SVS) |
| Physical seizure | Partial (FDE) |
| Legal compulsion on newsroom | Partial (depends on jurisdiction) |

## 3. How It Works (technical)

SecureDrop has three main servers:

1. **Application Server.** Runs the SecureDrop web application. Holds the source submissions. Has NO direct internet access.
2. **Monitor Server.** Runs Tor and the firewall. Is the only server connected to the internet. Relays traffic between Tor and the Application Server.
3. **Secure Viewing Station (SVS).** An air-gapped machine used by journalists to decrypt and read submissions. It never touches the internet.

**Source flow:**

1. The source opens the SecureDrop onion address in Tor Browser.
2. The source submits a document and a message.
3. The source receives a randomly generated codename (e.g. `fiery-hedgehog-swim-vertical`).
4. The source returns to the same onion address and enters the codename to check for replies.

**Journalist flow:**

1. The journalist logs in to the Journalist Interface (a separate onion address) with a username, password, and 2FA (TOTP or hardware token).
2. The journalist sees the submissions, downloads them to an encrypted USB stick.
3. The journalist transfers the USB stick to the SVS (air-gapped).
4. On the SVS, the journalist decrypts the submission with the source's one-time pad (if applicable) and reads it.
5. If the journalist replies, the reply goes back through the Application Server to the source's inbox.

**Encryption:**

- Each source submission is encrypted with a key derived from the source's codename + the journalist's public key (via GPG).
- The source can additionally use a one-time pad for the reply.
- The SVS holds the GPG key for decrypting submissions.

**Air gap:**

- The Application Server and the SVS have no internet access.
- Data moves between the two via an encrypted USB stick.
- This limits the attack surface: an attacker cannot reach the Application Server from the internet.

**Deployment:**

- SecureDrop is deployed on two physical servers (Application + Monitor) inside the newsroom.
- The FPF provides a detailed installation guide and hardware recommendations.
- Deployment usually takes 1-2 days and requires physical access to the newsroom.

## 4. Installation and Setup

SecureDrop is NOT a tool you install casually. It is a deployment project that requires:

- Dedicated physical hardware (two servers + the SVS).
- A physically secure location (locked rack, restricted access).
- A network with controlled firewall rules.
- A trained administrator.
- An organizational commitment to operational security.

**High-level setup (newsroom):**

1. **Procure hardware.** The FPF publishes a hardware guide; follow it exactly.
2. **Install Ubuntu Server** on the Application and Monitor servers.
3. **Run the SecureDrop installer** (the FPF's `securedrop-installer`).
4. **Configure the firewall** on the Monitor Server to allow only Tor traffic.
5. **Configure the Application Server** to have no direct internet access.
6. **Set up the SVS** (air-gapped Ubuntu or Tails with the SecureDrop workstation).
7. **Generate keys** (GPG, 2FA) and store them securely.
8. **Test the deployment** with a source and a journalist account.
9. **Train journalists** on the workflow, especially the SVS and USB handling.
10. **Publish the onion address** on the newsroom's website (in a clear, well-documented way for sources).

**Source side (no installation needed):**

1. Open Tor Browser.
2. Navigate to the SecureDrop onion address.
3. Submit a document and a message.
4. Save the codename.
5. Return with the codename to check for replies.

**Journalist side:**

1. Open Tor Browser.
2. Navigate to the Journalist Interface onion address.
3. Log in with username, password, and 2FA.
4. Download submissions to an encrypted USB.
5. Transfer to the SVS.
6. Decrypt and read on the SVS.

**References:**

- SecureDrop installation guide: https://docs.securedrop.org/
- Freedom of the Press Foundation: https://freedom.press/

## 5. Hardening and Configuration

**Physical hardening:**

- **Locked server rack.** Restricted physical access.
- **No cameras in the server room that stream to the internet.**
- **Signed visitor log.** Anyone entering the server room is logged.
- **No USB devices other than the approved encrypted USB sticks.**

**Network hardening:**

- **Monitor Server is the only internet-facing server.** It runs Tor and a strict firewall.
- **Application Server has NO internet access.** Enforced by the firewall and physically separated if possible.
- **No Wi-Fi.** Wired connections only.
- **No shared network with the newsroom's regular LAN.** SecureDrop should be on an isolated VLAN or a physically separate network.

**Operational hardening:**

- **Strict separation of duties.** The admin who manages the server should not be the same person who reads submissions.
- **Two-person rule for the SVS.** If possible, two people are present when the SVS is used.
- **No personal devices in the server room.**
- **No cloud storage, no email** for SecureDrop-related communication.
- **Air-gapped SVS** with no network hardware (or disabled hardware).
- **Encrypted USB sticks** for data transfer.
- **Regular backups** of the Application Server, encrypted and stored offline.

**Key and credential hardening:**

- **Strong admin password.**
- **2FA for all journalist accounts.** Hardware tokens preferred.
- **GPG keys** generated and stored on the SVS; never leave the SVS.
- **One-time pads** generated for each source that requests them.

**User training:**

- **All journalists must be trained** before they touch SecureDrop.
- **Sources should be instructed** to strip document metadata (see 03 / Metadata).
- **Sources should be warned** that SecureDrop cannot protect them from their own mistakes (leaking identity elsewhere).

## 6. Operational Usage

**As a source:**

1. Open the SecureDrop onion address in Tor Browser.
2. Read the instructions carefully.
3. Write your message and attach files.
4. Submit.
5. Save the codename. Write it down or memorize it.
6. Return later with the codename to check for replies.
7. If the journalist replies with a one-time pad, use it to encrypt your next message.

**As a journalist:**

1. Open the Journalist Interface in Tor Browser.
2. Log in with username, password, and 2FA.
3. Review new submissions.
4. Download submissions to an encrypted USB.
5. Transfer the USB to the SVS.
6. On the SVS, decrypt and read the submission.
7. Draft a reply in the Journalist Interface.
8. Monitor the source's inbox for their next check-in.

**Data handling:**

- **Never transfer SecureDrop data to a networked machine.**
- **Never store SecureDrop data on a general-purpose computer.**
- **Never email or message a source outside SecureDrop.**
- **Keep the SVS offline at all times.**
- **Use the encrypted USB only for SecureDrop.**

**Codename recovery:**

- If the source loses the codename, there is no recovery. The source must start a new submission with a new codename. The journalist cannot recover the old submission.

**Reply flow:**

- The journalist writes a reply in the Journalist Interface.
- The source logs in with the codename and reads the reply.
- For extra security, the reply can be encrypted with a one-time pad that the source generates and shares with the journalist.

## 7. Common Mistakes

Real mistakes that break SecureDrop's protections:

1. **Connecting the Application Server to the internet.** It should only talk to the Monitor Server.
2. **Using a shared network for SecureDrop and the newsroom LAN.** They should be isolated.
3. **Storing SecureDrop data on a networked machine.**
4. **Using a non-encrypted USB stick.**
5. **Using the SVS for anything other than SecureDrop.** The SVS is dedicated.
6. **Emailing or messaging a source outside SecureDrop.** Breaks source anonymity.
7. **Not training sources to strip metadata.** The document may leak identity.
8. **Not training journalists on the SVS workflow.** Mistakes here can expose the source.
9. **Using SMS 2FA.** SIM swap; use TOTP or hardware tokens.
10. **Using a weak admin password.**
11. **Not physically securing the servers.**
12. **Letting unauthorized people into the server room.**
13. **Not backing up the Application Server.**
14. **Backing up to a cloud service.**
15. **Assuming SecureDrop protects against source mistakes.** It does not.

## 8. Attacks Against It

Known attacks and limitations:

- **Traffic correlation.** A global passive adversary can correlate Tor traffic entering and leaving the SecureDrop Monitor Server.
- **Source endpoint compromise.** If the source's machine is compromised, the attacker sees the source's actions.
- **Newsroom endpoint compromise.** If the newsroom's network is compromised, the Monitor Server is reachable; the air gap protects the Application Server but not the Monitor.
- **Physical seizure.** If the servers are seized, the data is protected by FDE, but physical coercion or forensic attacks are possible.
- **Legal compulsion on the newsroom.** In some jurisdictions, the newsroom may be legally compelled to hand over data.
- **Insider misuse.** A malicious journalist or admin can leak submissions.
- **Malicious hardware.** A compromised server (firmware implant) can compromise SecureDrop.
- **Denial of service.** Tor-level DoS against the Monitor Server.
- **Tor vulnerabilities.** Tor has had CVEs; keep Tor updated.
- **SecureDrop bugs.** SecureDrop is audited but not immune. Keep it updated.
- **One-time pad misuse.** If the one-time pad is reused or transmitted insecurely, the encryption is broken.
- **Metadata.** SecureDrop cannot strip metadata from the source's document; the source is responsible.
- **Source's writing style.** Stylometry can identify a source even with no metadata.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Tor traffic to the Monitor Server.** The Monitor Server's IP is on the internet, running Tor. Tor entry guards are known.
- **Tor use at the source side.** If the source is on a corporate network, Tor traffic is visible.
- **Onion service traffic pattern.** The network sees Tor traffic, not the specific onion service.
- **On a managed device:** the Tor process is visible. MDM can block or uninstall it.
- **Physical presence.** A user accessing SecureDrop on a corporate machine is physically detectable.

Blocking SecureDrop at the network level means blocking Tor. This is a broad policy decision. Some corporate networks block Tor entirely; others allow it for legitimate uses.

## 10. Case Studies

- **SecureDrop and The New Yorker (2013).** The first major SecureDrop deployment was at The New Yorker, where it was used for the Strongbox project. Aaron Swartz and Kevin Poulsen built the precursor (DeadDrop); the FPF took over and standardized it as SecureDrop.
- **SecureDrop at The Washington Post, The Guardian, ProPublica.** Hundreds of news organizations have deployed SecureDrop. It is the de-facto standard for anonymous whistleblowing.
- **The FPF's SecureDrop audits.** The FPF sponsors regular security audits of SecureDrop. Audit reports are public.
- **SecureDrop and the Snowden leaks (context).** Snowden did not use SecureDrop (he used other channels), but his leaks accelerated the adoption of SecureDrop at major news outlets.
- **Physical security incidents.** There have been cases of newsroom break-ins and server room intrusions; SecureDrop's physical security model assumes physical control.
- **Criticism.** SecureDrop is criticized for its operational complexity and the effort required to maintain it. It is not suitable for small newsrooms or individual journalists.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

SecureDrop is legal to run in most jurisdictions. However:

- **Some countries restrict or ban Tor and anonymous submission platforms.** Check your local law before deploying or using SecureDrop.
- **Running a SecureDrop server may attract law enforcement attention.** This is expected for a whistleblowing platform, but be aware.
- **Hosting illegal content is a crime everywhere.** SecureDrop is not a place for illegal material.
- **Source protection is a legal and ethical obligation.** If you run SecureDrop, you are responsible for protecting your sources.
- **Corporate policy may forbid Tor.** On a work device, accessing SecureDrop may violate acceptable-use policy.
- **Authorized use only.** In a professional context, use SecureDrop only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying SecureDrop for a newsroom:

- **Follow the FPF's documentation exactly.** Do not improvise.
- **Dedicated hardware.** Two servers + the SVS. No shared infrastructure.
- **Isolated network.** SecureDrop on its own VLAN or physical network.
- **Physical security.** Locked rack, restricted access, signed visitor log.
- **Strict separation of duties.** Admin != journalist.
- **Air-gapped SVS.** No network hardware, or disabled in BIOS.
- **Encrypted USB sticks.** Only for SecureDrop.
- **Training for everyone.** Journalists and sources.
- **Test the workflow** with a dry run before going live.
- **Backup procedure.** Encrypted, offline, documented.
- **Incident response plan.** Document what happens if the servers are compromised or seized.
- **Legal review.** Know the laws in your jurisdiction.
- **Monitor the threat model.** SecureDrop and Tor evolve; re-evaluate periodically.

## 13. References

- [SecureDrop official site](https://securedrop.org/)
- [SecureDrop documentation](https://docs.securedrop.org/)
- [Freedom of the Press Foundation](https://freedom.press/)
- [SecureDrop source code (GitHub)](https://github.com/freedomofpress/securedrop)
- [SecureDrop audits](https://securedrop.org/security-audits/)
- [Tor Project - Onion Services](https://community.torproject.org/onion-services/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
