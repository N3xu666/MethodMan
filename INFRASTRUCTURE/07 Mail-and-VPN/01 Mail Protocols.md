# Mail Protocols

Primer on the protocols that carry email: SMTP (sending), IMAP and
POP3 (retrieving), Exchange and OWA (Microsoft's proprietary stack),
and the auxiliary protocols (autodiscover, MAPI/HTTP, ActiveSync).
Read this first if SMTP relay, MX records, or IMAP IDLE are
unfamiliar.

> [!CAUTION]
> This file is educational. The attacks that build on it (file 02)
> require written authorization. Merely connecting to a mail server
> you do not own may violate its acceptable-use policy or local law.

---

## 1. Overview

Email is a store-and-forward system. A message travels from the
sender's MUA (mail user agent) through one or more MTAs (mail
transfer agents) to the recipient's MDA (mail delivery agent) and
mailbox.

Core protocols:

- **SMTP** (RFC 5321) - sends mail between servers, and from a client
  to a server. TCP 25 (server-to-server), 587 (submission, STARTTLS),
  465 (implicit TLS, deprecated but common).
- **IMAP** (RFC 3501) - retrieves mail, keeps it on the server, syncs
  across devices. TCP 143 (STARTTLS) or 993 (implicit TLS).
- **POP3** (RFC 1939) - retrieves mail, typically deletes it from the
  server. TCP 110 (STARTTLS) or 995 (implicit TLS).

Microsoft-specific:

- **Exchange** - the mail server. Supports SMTP, IMAP, POP3, MAPI,
  ActiveSync, OWA.
- **OWA** (Outlook Web Access) - web interface. HTTPS.
- **MAPI/HTTP** - the native Outlook protocol. HTTPS.
- **ActiveSync** - mobile sync protocol (EAS). HTTPS.
- **Autodiscover** - service discovery. HTTPS and DNS.

Auxiliary records:

- **MX** (DNS) - points to the mail server for a domain.
- **SPF** (DNS TXT) - lists authorized senders.
- **DKIM** (DNS TXT) - public key for signature verification.
- **DMARC** (DNS TXT) - policy for SPF/DKIM failures.

---

## 2. Reconnaissance / Enumeration

### 2.1 MX record lookup

```bash
# Which server receives mail for the domain?
dig +short MX example.com

# Or with host:
host -t MX example.com
```

Expected output:

```text
10 mail1.example.com.
20 mail2.example.com.
```

### 2.2 SPF/DKIM/DMARC lookup

```bash
# SPF
dig +short TXT example.com | grep "v=spf1"

# DMARC
dig +short TXT _dmarc.example.com

# DKIM (selector varies; common: default, mail, selector1, selector2)
dig +short TXT selector1._domainkey.example.com
```

Expected output:

```text
"v=spf1 include:_spf.google.com -all"
"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
"v=DKIM1; k=rsa; p=MIGfMA0GCSq..."
```

### 2.3 Identify the mail server software

```bash
# Connect to SMTP and read the banner
nc -nv mail.example.com 25

# Expected banner:
#   220 mail.example.com ESMTP Postfix
#   220 mail.example.com ESMTP Sendmail
#   220 mail.example.com Microsoft ESMTP MAIL Service
#   220 mail.example.com ESMTP Exim
```

### 2.4 SMTP command enumeration

```bash
# After connecting, EHLO reveals supported extensions
openssl s_client -connect mail.example.com:25 -starttls smtp -quiet
EHLO test
```

Expected response:

```text
250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250 SMTPUTF8
```

Extensions that matter:

- **VRFY** - verify a user exists (often disabled, but check).
- **EXPN** - expand a mailing list (often disabled).
- **STARTTLS** - can upgrade to TLS.

### 2.5 IMAP/POP3 banner grab

```bash
# IMAP
nc -nv mail.example.com 143

# Expected banner:
#   * OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.
#   * OK Microsoft Exchange IMAP4 service ready.

# POP3
nc -nv mail.example.com 110

# Expected banner:
#   +OK Dovecot ready.
#   +OK Microsoft Exchange POP3 service ready.
```

### 2.6 Exchange and OWA discovery

```bash
# OWA
curl -sk https://mail.example.com/owa/ | head -20

# Autodiscover (used by Outlook clients)
curl -sk https://autodiscover.example.com/autodiscover/autodiscover.xml

# ActiveSync
curl -sk https://mail.example.com/Microsoft-Server-ActiveSync
```

Exchange versions can often be fingerprinted from the OWA login
page (JavaScript paths, CSS hashes) or from the `X-OWA-Version`
HTTP header.

### 2.7 MTA-STS and TLS-RPT

```bash
# MTA-STS (RFC 8461) - enforces TLS for SMTP
dig +short TXT _mta-sts.example.com
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt

# TLS-RPT (RFC 8460) - TLS reporting
dig +short TXT _smtp._tls.example.com
```

If MTA-STS is present, the domain enforces TLS for inbound SMTP.
Useful defensive signal (file 02, section 8).

---

## 3. Common Attack Vectors

### 3.1 Open relay

An SMTP server that forwards mail from any sender to any recipient,
without authentication. Used for spam and phishing. Rare in 2026 but
still found on misconfigured legacy servers.

### 3.2 SMTP user enumeration

`VRFY`, `EXPN`, or `RCPT TO` responses can reveal whether an address
exists. A `250` = exists, `550` = does not. Slow but effective for
building a target list.

### 3.3 IMAP/POP3 brute force

Mail servers often have weaker lockout policies than AD. A slow
password spray against IMAP can recover credentials without
triggering AD lockout.

### 3.4 NTLM relay to Exchange

Exchange accepts NTLM authentication on several endpoints (OWA,
EWS, ActiveSync, Autodiscover). If SMB signing is disabled and the
Exchange server has not enforced Extended Protection for
Authentication (EPA), an attacker can relay NTLM to Exchange and
impersonate the victim.

**Impact:** mailbox access, mail sending as the victim, lateral
movement into AD (Exchange has high privileges).

### 3.5 OWA credential phishing

The OWA login page is a frequent phishing target. Attackers clone
it, host on a lookalike domain, and harvest credentials. MFA is the
main defense.

### 3.6 Autodiscover abuse

Autodiscover can be used to leak NTLM hashes. When a client requests
`autodiscover.example.com` and DNS does not resolve, the client may
fall back to `autodiscover.example.com` over HTTP (not HTTPS), which
can be intercepted or redirected.

### 3.7 Mail-based initial access

Phishing emails with malicious attachments or links are the most
common initial access vector in ransomware campaigns. The mail
server itself is not attacked; the user is.

---

## 4. Exploitation Recipes

### 4.1 Connect and read the SMTP banner

```bash
nc -nv mail.example.com 25
```

### 4.2 Test for open relay

```bash
# Connect to SMTP, then:
HELO test
MAIL FROM:<attacker@external.com>
RCPT TO:<victim@different-domain.com>
DATA
Test message
.
QUIT
```

If the server accepts `RCPT TO` for a different domain and returns
`250` after `DATA`, it is an open relay.

### 4.3 SMTP user enumeration with smtp-user-enum

```bash
smtp-user-enum -M VRFY -U users.txt -t mail.example.com
smtp-user-enum -M RCPT -U users.txt -t mail.example.com
smtp-user-enum -M EXPN -U users.txt -t mail.example.com
```

Expected output:

```text
mail.example.com: admin exists
mail.example.com: jdoe exists
mail.example.com: root does not exist
```

### 4.4 IMAP user enumeration

```bash
# IMAP has LOGIN and AUTHENTICATE commands
nc -nv mail.example.com 143
# a1 LOGIN jdoe password
# * NO [AUTHENTICATIONFAILED] Authentication failed.
# a1 LOGIN jdoe wrongpassword
# * NO [AUTHENTICATIONFAILED] Authentication failed.
# Response times can leak valid usernames (some servers respond
# faster for invalid users than for valid-with-wrong-password).
```

### 4.5 OWA login page fingerprint

```bash
curl -sk https://mail.example.com/owa/ | grep -oE "owa/[a-z0-9]+/" | head -1
curl -skI https://mail.example.com/owa/ | grep -i "X-OWA-Version"
```

Expected output:

```text
X-OWA-Version: 15.2.1118.26
```

Version 15.2.x = Exchange 2019. 15.1.x = Exchange 2016. 15.0.x =
Exchange 2013. Useful for CVE research.

### 4.6 Check MTA-STS and DMARC policy

```bash
# If DMARC is p=none or p=quarantine, spoofing is still possible
# (though likely flagged).
dig +short TXT _dmarc.example.com
```

---

## 5. Post-Exploitation

After obtaining mailbox access:

- **Read email** for sensitive information (credentials, internal
  documents, M&A discussions).
- **Send email as the victim** (business email compromise).
- **Enumerate contacts and calendar** (identify targets, meetings).
- **Reset passwords** for other services via email.
- **Pivot to the corporate network** if the mail server is internal.

After Exchange compromise:

- **Dump mailboxes** with `MailSniper`, `Ruler`, or `Exchange Web
  Services` (EWS).
- **Add a mail rule** to forward all mail to the attacker (persistence).
- **Use Exchange's AD permissions** to escalate to Domain Admin.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Access to the mail service (or a foothold on the network) |
| Detectability | Medium - mail gateway logs, MFA prompts, SIEM rules |
| Business impact | Data theft, BEC, lateral movement, AD compromise |

Mail servers are **edge services**: they are exposed to the internet
and authenticate users. A single compromised mailbox can unlock
significant access.

---

## 7. Root Causes (AppSec)

- SMTP server misconfigured as an open relay.
- VRFY/EXPN left enabled.
- IMAP/POP3 exposed to the internet without rate limiting.
- Exchange endpoints accept NTLM without EPA.
- OWA lacks MFA.
- Autodiscover over HTTP instead of HTTPS.
- Users click phishing links and enter credentials.

---

## 8. Preventive Controls (AppSec)

### 8.1 Enforce authentication on SMTP submission

- Port 587 requires authentication and STARTTLS.
- Port 25 (server-to-server) accepts mail only for local domains.
- Never allow relay for non-local domains.

```text
# Postfix main.cf
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
smtpd_recipient_restrictions = reject_unauth_destination
```

### 8.2 Disable VRFY and EXPN

```text
# Postfix
disable_vrfy_command = yes
```

### 8.3 Publish SPF, DKIM, DMARC

```text
# SPF
example.com. IN TXT "v=spf1 include:_spf.example.com -all"

# DMARC (enforce)
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

# DKIM: selector1._domainkey.example.com IN TXT "v=DKIM1; k=rsa; p=..."
```

DMARC `p=reject` is the strongest policy. `p=quarantine` is weaker.
`p=none` provides reporting only.

### 8.4 Enforce TLS with MTA-STS

```text
# DNS
_mta-sts.example.com. IN TXT "v=STSv1; id=20260101000000Z"

# HTTPS
https://mta-sts.example.com/.well-known/mta-sts.txt:
version: STSv1
mode: enforce
mx: mail1.example.com
mx: mail2.example.com
max_age: 604800
```

### 8.5 Enforce MFA on OWA, EWS, ActiveSync, IMAP

All Microsoft mail protocols support MFA via Azure AD Conditional
Access. Enable it everywhere.

### 8.6 Require Extended Protection (EPA) on Exchange

EPA binds authentication to the TLS channel, defeating NTLM relay.

```text
# Exchange: enable EPA on all virtual directories
Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.tokenChecking"
# Should be "Require"
```

### 8.7 Restrict IMAP/POP3

If IMAP/POP3 are not needed, disable them. If needed, restrict to the
internal network or VPN.

### 8.8 Autodiscover over HTTPS only

- Publish `autodiscover.example.com` with a valid SSL certificate.
- Block the HTTP fallback at the network edge.

### 8.9 Mail gateway

- Inbound: SPF, DKIM, DMARC validation, spam filtering, attachment
  scanning, URL rewriting.
- Outbound: DLP, encryption for sensitive mail.

### 8.10 Exchange patching

Exchange has a long history of critical CVEs (ProxyLogon, ProxyShell,
ProxyToken, etc.). Patch monthly.

---

## 9. Detection Controls (AppSec)

### 9.1 SMTP anomalies

- Relay attempts from unauthenticated sources.
- High volume of outbound mail from a single account (spam).
- Unusual sender/recipient patterns (BEC).
- Failed authentication attempts (brute force).

### 9.2 IMAP/POP3 anomalies

- Authentication from unusual geographies.
- Many failed logins for the same user.
- IMAP connections from outside the corporate network (if not
  expected).

### 9.3 Exchange-specific

- New mailbox rules (auto-forward, delete, move).
- EWS access from unusual clients.
- OWA login from unfamiliar IPs.
- Autodiscover requests without a matching Outlook client.

### 9.4 Windows Event IDs

- **4625** - failed logon (brute force).
- **4768/4769** - Kerberos TGT/TGS (Exchange auth).
- **4776** - NTLM authentication (relay indicator).
- **Exchange logs** (EWS, OWA, ActiveSync) - authentication and
  mailbox access events.

### 9.5 SIEM rules

- Alert on > 10 failed IMAP logins per user per minute.
- Alert on new mailbox forwarding rule.
- Alert on OWA login from a new country.
- Alert on Exchange EWS requests with unusual user agents.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **Open relay:** attempt to relay mail from an external domain to
   another external domain. Should be rejected.
2. **VRFY/EXPN:** run `smtp-user-enum` against the server. Should
   return errors, not user existence.
3. **SPF/DKIM/DMARC:** send a mail with a mismatched sender. Should
   be flagged or rejected at the recipient.
4. **MFA:** attempt OWA login with a valid password but no MFA.
   Should fail.
5. **EPA:** attempt an NTLM relay to Exchange (from a Windows host
   with `ntlmrelayx`). Should be rejected.

---

## 11. OSCP Notes

Mail protocols are **not** in the OSCP exam. They are relevant for:

- Real internal engagements where Exchange is present.
- PEN-200 covers password attacks (IMAP brute force is one).
- Red team operations targeting corporate infrastructure.

For the report, document:

- The mail server software and version.
- The enumeration technique (banner, VRFY, RCPT, autodiscover).
- The attack path (open relay, brute force, NTLM relay to Exchange).
- The defensive control (SPF/DKIM/DMARC, MFA, EPA, patching).

---

## 12. Production Notes

- **Exchange is a high-value target.** A single Exchange exploit can
  lead to full AD compromise. Patch monthly.
- **NTLM relay to Exchange is common.** Enable EPA on all virtual
  directories, and require SMB signing on all hosts.
- **MFA on OWA is essential.** Without it, credential phishing
  succeeds trivially.
- **DMARC p=reject** is the only policy that stops spoofing. `p=none`
  provides reporting only.
- **IMAP/POP3 on the internet are rare** in modern enterprises
  (everything uses MAPI/HTTP or ActiveSync over HTTPS). If they are
  exposed, restrict them.
- **Legacy protocols (IMAP, POP3, SMTP without TLS)** are usually a
  sign of an unmaintained server. Investigate.

---

## 13. References

- RFC 5321 - Simple Mail Transfer Protocol
- RFC 3501 - Internet Message Access Protocol - Version 4rev1
- RFC 1939 - Post Office Protocol - Version 3
- RFC 7208 - Sender Policy Framework (SPF)
- RFC 6376 - DomainKeys Identified Mail (DKIM)
- RFC 7489 - Domain-based Message Authentication (DMARC)
- RFC 8461 - SMTP MTA Strict Transport Security (MTA-STS)
- RFC 8460 - SMTP TLS Reporting
- MITRE ATT&CK T1071.003 - Mail Protocols - https://attack.mitre.org/techniques/T1071/003/
- MITRE ATT&CK T1114 - Email Collection - https://attack.mitre.org/techniques/T1114/
- NIST SP 800-45 - Guidelines on Electronic Mail Security
- Microsoft Docs - Exchange Extended Protection (EPA)
- `man smtp-user-enum`, `man dig`, `man openssl`
