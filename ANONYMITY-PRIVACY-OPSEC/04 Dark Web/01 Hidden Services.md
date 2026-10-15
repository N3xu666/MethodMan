# Hidden Services

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

A Tor hidden service (officially "onion service") is a server reachable only through the Tor network. Neither the client nor the server needs to reveal its IP address: the client reaches the service via a `.onion` address, and the service never exposes its real IP. Onion services are used for whistleblowing platforms (SecureDrop), privacy-focused file sharing, and anonymous hosting.

This file is a hands-on operator guide: how onion services work, how to run one on your own server, how to harden it, and where they fail.

## 1. Overview

Tor onion services were introduced in 2004 as "hidden services" and renamed "onion services" in 2015. The protocol is now version 3 (v3), which uses 56-character `.onion` addresses derived from an Ed25519 public key. v2 addresses (16 characters) were deprecated in 2021 and removed from Tor.

Key properties:

- **No inbound ports required.** The server makes outbound connections to introduction points; no firewall holes.
- **Server IP hidden.** Clients never learn the server's IP.
- **Client IP hidden.** The server never learns the client's IP.
- **End-to-end encrypted.** Tor circuits are encrypted hop-by-hop; end-to-end encryption between client and server is the application's responsibility (HTTPS or similar).
- **Self-authenticating address.** The `.onion` address is a hash of the service's public key; a client connecting to a `.onion` address is cryptographically guaranteed to reach the correct service.
- **No central registry.** There is no DNS for onion services; the address IS the identity.

Common legitimate uses:

- **SecureDrop.** Journalist-to-source whistleblowing.
- **OnionShare.** Anonymous file sharing and hosting.
- **Privacy-focused forums and chat.**
- **Personal services reachable from anywhere without opening a port.**

## 2. Threat Model

What onion services protect against:

- **Server IP exposure.** The server's real IP is never revealed to clients.
- **Client IP exposure.** The client's real IP is never revealed to the server.
- **Port scanning.** The server has no listening ports exposed to the internet.
- **ISP-level blocking (partially).** Clients connect to the Tor network, not directly to the service.
- **Server location discovery.** The server can be hosted anywhere, including behind NAT.
- **Man-in-the-middle on the .onion address.** The address is derived from the public key; a MITM cannot impersonate the service without the private key.
- **DDoS at the IP level.** The server's real IP is hidden, so IP-level DDoS is not possible (though Tor-level DoS exists).

What onion services do NOT protect against:

- **Application-layer vulnerabilities.** A bug in the web app can still be exploited.
- **Endpoint compromise.** If the server is compromised, the attacker is inside.
- **Metadata leaks in the application.** The app may leak timestamps, file sizes, and other metadata.
- **Traffic correlation.** A global passive adversary can correlate traffic entering and leaving the Tor network.
- **Introduction point attacks.** A malicious introduction point can DoS the service or attempt to learn more.
- **Guard relay attacks.** A malicious guard can attempt correlation.
- **Physical access to the server.**
- **Legal compulsion on the hosting provider.**
- **Configuration mistakes.** Running the service on a server that also has clearnet services can leak the IP.
- **Misconfigured TLS.** HTTPS is not automatic; if the onion service serves HTTP, the traffic between the client and the service is encrypted by Tor but not by the application.

Threat model summary:

| Adversary | Onion Service |
|-----------|---------------|
| Client IP discovery | Strong (Tor) |
| Server IP discovery | Strong (Tor) |
| Passive network observer | Strong |
| Global passive adversary | Weak (traffic correlation) |
| Endpoint compromise | None |
| Application-layer attack | None |
| Physical access | None |
| Legal compulsion on hosting | Partial (depends on jurisdiction) |

## 3. How It Works (technical)

An onion service has three roles: the **service** itself, **introduction points**, and **rendezvous points**.

**Service setup:**

1. The service generates a long-term Ed25519 keypair. The public key becomes the `.onion` address (base32 encoded, 56 characters).
2. The service picks a set of **introduction points** (Tor relays) and publishes signed descriptors to the Tor directory.
3. The descriptor tells clients: "To reach me, go to these introduction points."

**Client connection:**

1. The client fetches the descriptor for the `.onion` address from the Tor directory.
2. The client picks a **rendezvous point** (a Tor relay) and tells it a one-time secret.
3. The client connects to one of the introduction points and sends the rendezvous point's address + the one-time secret.
4. The introduction point forwards this to the service.
5. The service connects to the rendezvous point and proves knowledge of the one-time secret.
6. The rendezvous point connects the client and the service. The circuit is now established.

**Result:**

- The service never learns the client's IP.
- The client never learns the service's IP.
- The rendezvous point knows both circuits meet but cannot read the traffic (encrypted end-to-end at the Tor layer).
- A global passive adversary can observe traffic entering and leaving the Tor network; if the timing and volume match, correlation is possible.

**v3 addresses:**

- Ed25519 public key -> SHA3-256 -> base32 -> 56 characters + `.onion`.
- Self-authenticating: the client verifies the service's key during the handshake.
- v2 (RSA-1024, 16-char addresses) was removed in 2021.

**Onion service authentication (optional):**

- A service can require client authentication: only clients with an authorized key can connect.
- This is done via `ClientOnionAuthDir` on the client and `HiddenServiceAuthorizeClient` (deprecated) or v3 client auth.
- Useful for private services.

## 4. Installation and Setup

**Requirements:**

- A machine to host the service (VPS, home server, or a dedicated machine).
- Tor installed (`tor` package).
- A web server or application to expose (nginx, Apache, a Python app, etc.).

**Install Tor (Debian/Ubuntu):**

```bash
sudo apt install tor
sudo systemctl enable --now tor
```

**Configure the onion service:**

Edit `/etc/tor/torrc` (as root):

```text
HiddenServiceDir /var/lib/tor/myservice/
HiddenServicePort 80 127.0.0.1:8080
```

- `HiddenServiceDir` is where Tor stores the keys and hostname.
- `HiddenServicePort 80 127.0.0.1:8080` forwards onion port 80 to local port 8080 (where your web server listens).

Reload Tor:

```bash
sudo systemctl reload tor
```

**Get the .onion address:**

```bash
sudo cat /var/lib/tor/myservice/hostname
```

This is your `.onion` address. It is derived from the public key stored in the same directory.

**Backup the keys:**

```bash
sudo tar czf myservice-backup.tgz -C /var/lib/tor myservice/
# Store the backup offline, encrypted
```

If you lose `HiddenServiceDir`, you lose the `.onion` address permanently. Back it up.

**Set up a web server (nginx example):**

```bash
sudo apt install nginx
# Serve content from /var/www/html on port 8080
# (nginx default is port 80; change to 8080 in /etc/nginx/sites-available/default)
sudo systemctl restart nginx
```

**Test:**

- Install Tor Browser.
- Navigate to the `.onion` address.
- The service should load.

## 5. Hardening and Configuration

**Isolation:**

- **Do NOT run the onion service on the same machine as your personal services.** The server has the `.onion` private key; if compromised, the attacker can impersonate the service.
- **Do NOT expose clearnet services on the same machine.** A misconfiguration can leak the server's IP.
- **Use a dedicated VM or container** for the onion service.
- **Use a separate Tor instance** for the onion service (not the system Tor).

**Tor configuration hardening:**

- **Disable SocksPort for the onion service Tor instance.** The onion service does not need a SOCKS proxy.
- **Set `HiddenServiceVersion 3`.** v2 is removed, but be explicit.
- **Use `HiddenServiceEnableIntroDoSDefense 1`** (Tor 0.4.2+) to enable introduction point DoS defense.
- **Limit `HiddenServiceMaxStreams`** to prevent resource exhaustion.
- **Use `HiddenServicePoWDefensesEnabled 1`** (Tor 0.4.8+) for proof-of-work DoS protection.
- **Keep Tor updated.** Tor security patches are frequent.

**Application hardening:**

- **Serve only what you intend to serve.** No default pages, no directory listing, no debug endpoints.
- **Disable server banners and version strings.** `server_tokens off;` in nginx.
- **Log minimally.** Logs may leak client behavior if the server is compromised.
- **Set strict Content-Security-Policy.**
- **Use HTTPS within the onion service if you serve forms.** Tor encrypts at the transport layer, but HTTPS adds end-to-end integrity and authentication.
- **Strip or disable unnecessary HTTP headers.**
- **No JavaScript from third-party CDNs.** Load everything locally.

**Operational hardening:**

- **Never access the onion service's admin interface from the same network as the service.**
- **Use SSH keys, not passwords, to manage the server.**
- **Use a dedicated SSH key for the onion server.**
- **Disable password authentication on SSH.**
- **Firewall: block all inbound except SSH (from a known IP) and Tor's outbound.**
- **Monitor for unexpected outbound connections** (a sign of compromise).
- **Automate updates for Tor and the OS.**

**Key management:**

- **Back up `HiddenServiceDir` immediately after first start.**
- **Store the backup encrypted, offline.**
- **Do not copy the private key to your workstation** unless you must.
- **Consider using an offline signing key** (advanced; requires the Tor `offline master key` feature).

## 6. Operational Usage

**Starting and stopping:**

```bash
sudo systemctl status tor
sudo systemctl restart tor
sudo journalctl -u tor -f
```

**Viewing the .onion address:**

```bash
sudo cat /var/lib/tor/myservice/hostname
```

**Testing from the same machine:**

```bash
# With Tor's SOCKS proxy on 9050
curl --socks5-hostname 127.0.0.1:9050 http://<your-onion-address>.onion/
```

**Rotating the .onion address (if the key is compromised):**

1. Stop Tor.
2. Delete (or move) the old `HiddenServiceDir`.
3. Restart Tor. A new keypair (and new `.onion` address) is generated.
4. Notify your users of the new address (out-of-band).

Note: The old address remains reachable only if an attacker has the old key. There is no way to revoke an onion address; you can only abandon it.

**Client authentication (optional):**

- Generate a client keypair on the client.
- Add the client's public key to the server's `authorized_clients/` directory.
- Only clients with authorized keys can connect.

**Monitoring:**

- Check that the service is reachable from a Tor Browser.
- Monitor the Tor log for errors.
- Monitor the application log for anomalies.
- Monitor the server for unexpected outbound connections.

## 7. Common Mistakes

Real mistakes that break onion service protections:

1. **Running the onion service on a machine that also serves clearnet.** A misconfiguration can leak the server's IP.
2. **Not backing up `HiddenServiceDir`.** Losing the key means losing the `.onion` address permanently.
3. **Using a weak or reused SSH key for server management.**
4. **Leaving default web server pages and version banners.**
5. **Logging client IPs (impossible) or request metadata (leaky).**
6. **Serving third-party JavaScript from CDNs.**
7. **Not using HTTPS within the onion service for forms.**
8. **Exposing an admin panel on the onion service.**
9. **Using the same Tor instance for the onion service and for browsing.**
10. **Not updating Tor.**
11. **Not using introduction point DoS defense.**
12. **Assuming Tor hides application-layer mistakes.** It does not.
13. **Publishing the .onion address on a clearnet site linked to your real identity.**
14. **Using the same server for multiple onion services with different threat models.**

## 8. Attacks Against It

Known attacks and limitations:

- **Traffic correlation.** A global passive adversary can correlate traffic entering and leaving the Tor network by timing and volume. Mitigation: none in Tor itself; the risk depends on the adversary's coverage.
- **Introduction point attacks.** A malicious introduction point can DoS the service or attempt to learn the client's identity (limited by the protocol). Mitigation: Tor picks multiple introduction points; DoS defense.
- **Guard relay attacks.** A malicious guard relay can attempt to correlate. Tor's guard selection reduces this risk over time.
- **Onion service deanonymization via application bugs.** A bug in the web app (e.g. SSRF, file disclosure) can leak the server's IP or other metadata.
- **End-to-end correlation with a cooperating client.** If a client is compromised, the attacker learns the client's identity and can correlate.
- **Global adversary with legal subpoena.** If the hosting provider is compelled, the server's identity may be revealed.
- **Physical access to the server.**
- **Tor exit node attacks.** Do not apply (onion services do not use exit nodes for the service side).
- **DNS leaks in the application.** If the app resolves external DNS names, the DNS query can leak the server's IP. Mitigation: no DNS, or Tor's DNS.
- **Malicious HSDir (hidden service directory) relays.** A malicious HSDir can attempt to learn which onion services exist and when they are published. Mitigation: Tor's HSDir selection and the "vanguard" proposal.
- **Tor Browser 0-day.** If the client is compromised by a Tor Browser 0-day, the attacker learns the client's identity.
- **Denial of service.** Tor-level DoS is possible even with DoS defense.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Tor traffic.** The network sees Tor traffic to entry guards. Tor entry guards are known and can be blocked.
- **DNS queries.** If the client resolves `.onion` addresses via a non-Tor DNS, the queries leak. Tor Browser does not do this.
- **Onion service traffic patterns.** A network observer cannot identify the specific onion service from the client side (Tor hides it).
- **Server-side.** If the server is on a corporate network, the outbound connections to introduction points are visible.
- **Hosting provider logs.** A hosting provider can see that a VPS is running Tor and may flag it.
- **On a managed device:** the Tor process is visible. MDM can block or uninstall it.
- **Physical presence.** A user running a hidden service on a corporate machine is physically detectable.

Blocking onion services at the network level means blocking Tor. This is a broad policy decision.

## 10. Case Studies

- **Silk Road (2013).** The Silk Road was an illegal marketplace on Tor. It was taken down not by breaking Tor, but through operational mistakes by its operator (Ross Ulbricht): reused usernames, personal email, and a Stack Overflow question that linked his identity to the site. This is the canonical case study for the importance of operational discipline.
- **AlphaBay (2017).** Another illegal marketplace; taken down through a combination of operational mistakes and international cooperation.
- **Hansa (2017).** Taken down by Dutch police, who then ran it for a month to catch buyers and sellers. A case study in law enforcement operation against dark web services.
- **SecureDrop.** A legitimate onion service used by hundreds of news organizations. It is the standard tool for anonymous whistleblowing.
- **Facebook's onion service (2014-2022).** Facebook ran an onion service to allow users in censored countries to reach it. It was discontinued in 2022. A case study in a large clearnet service providing an onion mirror.
- **ProPublica onion service.** A news organization serving its content over an onion service for readers in censored countries.
- **Tor Project's own onion services.** The Tor Project runs its own onion services for its website and services.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Onion services are legal to run in most jurisdictions. However:

- **Some countries restrict or ban Tor and onion services.** Check your local law before hosting an onion service.
- **Hosting illegal content is a crime everywhere.** Do NOT use onion services to distribute illegal material.
- **You are responsible for what you host.** An onion service is a publication.
- **Using onion services to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid them.** On a work device, running an onion service may violate acceptable-use policy.
- **Law enforcement may target you if you host illegal content.** Tor does not protect against the consequences of illegal activity.
- **Authorized use only.** In a professional context, use onion services only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying an onion service for a small group (journalists, activists, a security team):

- **Dedicated machine or VM.** Never share with personal or clearnet services.
- **Dedicated Tor instance.** Do not share with a Tor client for browsing.
- **Standardize the Tor version.** Pin a specific release and update on a schedule.
- **Backup policy.** The `HiddenServiceDir` is the identity. Back it up encrypted, offline, immediately after first start.
- **Key rotation policy.** Document what triggers a key rotation and how the new address is communicated.
- **DoS defense.** Enable introduction point DoS defense and PoW defense.
- **Application hardening checklist.** No default pages, no banners, no third-party CDNs, strict CSP.
- **Monitoring.** Check reachability regularly. Monitor Tor logs and application logs.
- **Incident response.** If the server is compromised, the `.onion` key is compromised. Document the response.
- **Legal review.** Know the laws in your jurisdiction and in the jurisdiction where the server is hosted.
- **Train operators.** Onion services are easy to misconfigure. A 1-hour training session is a minimum.
- **Test the workflow** before relying on it.
- **Monitor the threat model.** Tor evolves; re-evaluate periodically.

## 13. References

- [Tor Project - Onion Services](https://community.torproject.org/onion-services/)
- [Tor Project - Onion Service Setup](https://community.torproject.org/onion-services/setup/)
- [Tor Project - Onion Service Best Practices](https://community.torproject.org/onion-services/advanced/)
- [Tor Project - v3 Onion Services](https://support.torproject.org/onionservices/v3-onion-services/)
- [OnionShare](https://onionshare.org/)
- [SecureDrop](https://securedrop.org/)
- [Electronic Frontier Foundation - Surveillance Self-Defense](https://ssd.eff.org/)
- [Privacy Guides - Tor](https://www.privacyguides.org/en/tor/)
