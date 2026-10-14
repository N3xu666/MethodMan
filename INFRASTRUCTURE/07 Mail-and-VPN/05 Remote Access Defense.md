# Remote Access Defense

Defensive controls for mail and VPN infrastructure: Zero Trust,
MFA, conditional access, segmentation, monitoring, and the
operational practices that keep edge services secure. This file is
defensive-only: it does not introduce new attacks, it closes them.

> [!NOTE]
> This file has no offensive track. It is the defensive counterpart
> to files 01-04. Read those first to understand what is being
> defended against.

---

## 1. Overview

Remote access defense has five layers:

- **Identity** - strong authentication (MFA, FIDO2), conditional
  access, least privilege.
- **Endpoint** - device compliance, EDR, patch management, disk
  encryption.
- **Network** - Zero Trust Network Access (ZTNA) or VPN with least
  privilege, micro-segmentation.
- **Application** - hardened mail/VPN servers, patched firmware,
  WAF.
- **Monitoring** - authentication logs, session monitoring, anomaly
  detection, threat hunting.

A remote access service without monitoring and MFA is an open door.
The controls below are ordered by impact: identity first, then
endpoint, then network.

---

## 2. Zero Trust Principles

### 2.1 What Zero Trust means

- **Never trust, always verify.** No implicit trust based on network
  location.
- **Least privilege.** Users get only the access they need, for only
  as long as they need it.
- **Assume breach.** Design as if the attacker is already inside.
- **Verify explicitly.** Every access request is authenticated and
  authorized.

### 2.2 ZTNA vs VPN

- **Traditional VPN:** grants network access; the user can reach
  anything on the internal network.
- **ZTNA:** grants application access; the user reaches only the
  specific app, with continuous verification.

ZTNA is the modern replacement for VPN in many enterprises. It
reduces the blast radius of a compromised account.

### 2.3 Implementation

- **Identity provider (IdP):** Azure AD, Okta, Google Workspace,
  Ping.
- **Policy engine:** conditional access, risk-based policies.
- **Enforcement point:** ZTNA broker (Cloudflare Access, Zscaler
  Private Access, Palo Alto Prisma Access, Cisco Umbrella).
- **Signal sources:** device posture, user risk, location, behavior.

---

## 3. Common Attack Vectors (defensive context)

This section describes the attacks the controls in section 8
mitigate. Full details in files 01-04.

### 3.1 Credential theft (phishing, spray)

The attacker obtains valid credentials and logs in.

**Mitigation:** MFA (especially FIDO2), conditional access.

### 3.2 MFA bypass (fatigue, phishing proxy)

The attacker bypasses MFA via push bombing or a phishing proxy.

**Mitigation:** number matching, FIDO2, rate limiting, session
token binding.

### 3.3 VPN appliance CVE exploitation

The attacker exploits an unpatched VPN appliance for pre-auth RCE.

**Mitigation:** patching, network segmentation, WAF, integrity
monitoring.

### 3.4 Open relay abuse

The mail server forwards mail from external senders.

**Mitigation:** relay restrictions, authentication on submission.

### 3.5 NTLM relay to Exchange

The attacker relays NTLM authentication to Exchange.

**Mitigation:** EPA, SMB signing, LDAP signing, disable LLMNR.

### 3.6 Mailbox rule persistence

The attacker creates a mailbox rule to forward or hide mail.

**Mitigation:** mailbox rule monitoring, alert on new rules,
blocking auto-forward to external domains.

### 3.7 Split tunneling abuse

The attacker intercepts the client's non-VPN traffic.

**Mitigation:** full tunnel, EDR, DNS filtering.

### 3.8 Session token theft

The attacker steals a session token and reuses it.

**Mitigation:** short lifetimes, token binding, IP binding,
monitoring.

---

## 4. Detection Recipes

### 4.1 Authentication anomaly detection

Build baselines for each user:

- Usual login hours.
- Usual source countries/ASNs.
- Usual devices.
- Usual apps accessed.

Alert on deviations:

- New country / ASN.
- Unusual hours.
- New device (first login from that fingerprint).
- Impossible travel (two logins from distant locations within a
  short window).

### 4.2 Session monitoring

- Session duration (unusually long = suspicious).
- Data volume (large transfers = possible exfiltration).
- Concurrent sessions from different geographies.

### 4.3 VPN appliance integrity

- File integrity monitoring (FIM) on critical files.
- Periodic hash comparison against vendor baseline.
- Alert on unexpected processes or network connections.
- Alert on new admin accounts or config changes.

### 4.4 Mail server monitoring

- Authentication logs (success and failure).
- Mailbox rule creation (especially auto-forward to external).
- EWS / OWA / ActiveSync access from unusual clients.
- Volume of outbound mail per user (spam / BEC).

### 4.5 SIEM rules (examples)

- VPN login from a new country for a user.
- > 5 failed VPN logins per user per 5 minutes.
- VPN login outside normal hours.
- New mailbox rule forwarding to external domain.
- OWA login from an unfamiliar IP.
- Exchange EWS request with unusual user-agent.
- Large data transfer (> 1 GB) over VPN in a short window.

---

## 5. Post-Exploitation (defensive)

After a remote access incident:

- **Revoke all sessions** for the affected user (VPN, mail, cloud).
- **Reset credentials** and force MFA re-enrollment.
- **Revoke tokens** (OAuth refresh tokens, session cookies).
- **Hunt for lateral movement.** Check logs for internal access
  after the initial compromise.
- **Check for persistence.** Mailbox rules, scheduled tasks on the
  appliance, new MFA devices.
- **Review logs.** What detection failed? What process needs to
  change?
- **Notify.** Legal, compliance, and possibly the affected user.

---

## 6. Risk Context

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Internet-facing edge service |
| Detectability | High with proper monitoring, Low without |
| Business impact | Credential theft, lateral movement, data exfiltration |

Remote access services are the **most attacked** part of any
enterprise network. Ransomware operators prioritize VPN appliances
and email for initial access.

---

## 7. Root Causes

- No MFA, or weak MFA (SMS, push without number matching).
- No conditional access policies (any country, any device).
- VPN appliances unpatched.
- No monitoring of authentication anomalies.
- No mailbox rule monitoring.
- Split tunneling without endpoint controls.
- No rate limiting on authentication.
- Weak or shared credentials.
- No incident response plan for remote access compromise.

---

## 8. Preventive Controls

### 8.1 Enforce MFA everywhere

- **FIDO2 security keys** for admins, executives, high-risk users.
- **Number matching** for push-based MFA (Duo, Microsoft
  Authenticator).
- **TOTP** as a fallback (avoid SMS).
- **No MFA bypass** without device compliance check.

```text
# Azure AD Conditional Access:
#   Require MFA for all users
#   Require compliant device for admins
#   Block legacy authentication
#   Block countries outside business operations
```

### 8.2 Conditional access policies

- Block legacy authentication protocols (IMAP, POP3, SMTP AUTH).
- Require compliant devices for VPN access.
- Block login from countries where the company does not operate.
- Require MFA re-authentication for high-risk sign-ins.

### 8.3 Patch edge services

- VPN appliances: monthly (or ASAP for critical CVEs).
- Exchange: monthly (Patch Tuesday).
- Mail gateways: monthly.
- Firmware: quarterly.

Subscribe to advisories:

- Cisco, Palo Alto, Fortinet, Citrix, Ivanti (VPN).
- Microsoft (Exchange).
- Proofpoint, Mimecast, Barracuda (mail gateways).

### 8.4 Harden mail servers

- Disable open relay.
- Disable VRFY/EXPN.
- Enforce SPF, DKIM, DMARC (p=reject).
- Enforce MTA-STS.
- Require EPA on Exchange.
- Disable IMAP/POP3 if not needed.
- Block auto-forward to external domains.

### 8.5 Harden VPN configuration

- IKEv2 with certificate authentication.
- Disable IKEv1 Aggressive Mode.
- Strong cipher suites (AES-256-GCM, SHA-384, DH group 19 or
  higher).
- Perfect Forward Secrecy (PFS) enabled.
- Short session lifetimes (8-12 hours).

### 8.6 Zero Trust Network Access (ZTNA)

Replace VPN with ZTNA where possible:

- Application-level access (not network-level).
- Continuous verification.
- Least privilege by default.

### 8.7 Network segmentation

- VPN clients land in a dedicated VLAN with firewall rules.
- No direct access to the management network.
- Mail servers in a DMZ with strict egress rules.
- Micro-segmentation for lateral movement prevention.

### 8.8 Endpoint controls

- EDR on all devices.
- Disk encryption (BitLocker, FileVault).
- Patch management (OS and applications).
- Device compliance check before VPN/mail access.

### 8.9 Rate limiting

- 5 failed attempts per user per 15 minutes, then lockout.
- IP-based rate limiting (10 attempts per minute per IP).
- CAPTCHA after 3 failures.

### 8.10 Session binding

- Client certificates (not just username/password).
- IP binding where possible.
- Token binding (OAuth).
- Short session lifetimes.

### 8.11 Logging and monitoring

- Centralize logs from all edge services (SIEM).
- Retain logs for at least 90 days.
- Alert on anomalies (section 9).
- Threat hunting on a regular cadence.

### 8.12 Incident response plan

- Documented procedures for revoking access.
- Contacts for the IdP, VPN vendor, and mail provider.
- Regular tabletop exercises.

---

## 9. Detection Controls

### 9.1 Authentication monitoring

| Event | Threshold | Action |
|-------|-----------|--------|
| Failed logins | > 5 per user per 5 min | Lockout, alert |
| Login from new country | First occurrence | Alert, verify with user |
| Login outside hours | Outside user's baseline | Alert, verify |
| Impossible travel | Two logins far apart | Alert, likely compromise |
| MFA failure | > 3 per user per hour | Alert, possible bypass attempt |
| New MFA device | First occurrence | Alert, verify with user |

### 9.2 Session monitoring

- Unusually long sessions (> 12 hours).
- Large data transfers (> 1 GB per session).
- Concurrent sessions from different countries.
- Session token reuse from a different IP.

### 9.3 Appliance monitoring

- File integrity monitoring on critical config files.
- Hash comparison against vendor baseline.
- Unexpected processes or network connections.
- New admin accounts.
- Config changes outside change windows.

### 9.4 Mail server monitoring

- New mailbox rules (especially external forwarding).
- EWS / OWA / ActiveSync from unusual clients.
- Volume of outbound mail per user.
- NTLM authentication to Exchange (should be zero with EPA).

### 9.5 SIEM integration

- Forward all edge service logs to the SIEM.
- Correlate across services (VPN login + Exchange access = full
  user session).
- Build dashboards for the SOC.
- Automate response for high-confidence alerts.

### 9.6 Threat hunting

- Regular hunts for known attacker patterns (IOCs).
- Hypothesis-driven hunts (e.g. "which users logged in from a
  new country this week?").
- Purple team exercises.

---

## 10. Verification

Test the controls after deployment:

1. **MFA:** attempt VPN login with valid credentials but no MFA.
   Should fail.
2. **FIDO2:** for admin accounts, attempt login without FIDO2.
   Should fail.
3. **Conditional access:** attempt login from a blocked country.
   Should fail.
4. **Device compliance:** attempt VPN login from a non-compliant
   device. Should fail.
5. **Rate limiting:** attempt 10 failed logins in 1 minute. Should
   lock out.
6. **Mailbox rule:** create a forwarding rule to an external
   address. SIEM should alert, and the rule should be blocked.
7. **EPA:** attempt NTLM relay to Exchange. Should fail.
8. **Patching:** check the VPN appliance firmware version against
   the vendor's latest advisory.
9. **Session binding:** copy a session token to another machine.
   Should be rejected.
10. **Logging:** trigger an authentication anomaly. SIEM should
    alert within 5 minutes.

---

## 11. OSCP Notes

Remote access defense is **not** in the OSCP exam. It is relevant
for:

- Real-world blue team roles.
- Security architecture discussions.
- Incident response.

For the report, focus on:

- The defense-in-depth model (identity, endpoint, network,
  application, monitoring).
- The MFA and conditional access implementation.
- The monitoring and detection capabilities.
- The verification steps (how you tested the controls).

---

## 12. Production Notes

- **MFA is table stakes.** Without it, credential theft is trivial.
  With it, the attacker needs to bypass MFA (phishing proxy, MFA
  fatigue, session token theft).
- **FIDO2 defeats phishing proxies.** For admins and high-risk
  users, require FIDO2 security keys.
- **Number matching defeats MFA fatigue.** Deploy it everywhere.
- **Conditional access is the new perimeter.** Location, device
  compliance, and risk determine access.
- **ZTNA replaces VPN where possible.** Reduces blast radius.
- **Patch edge services fast.** VPN appliance and Exchange CVEs
  are exploited within days of release.
- **Monitor authentication anomalies.** A login from a new country
  is a strong signal.
- **Have an incident response plan.** Revoking access quickly is
  the difference between a contained incident and a breach.
- **Do not rely on a single control.** Defense in depth: MFA +
  conditional access + segmentation + monitoring.
- **Test regularly.** Tabletop exercises, red team engagements,
  and purple team exercises validate the controls.

---

## 13. References

- NIST SP 800-207 - Zero Trust Architecture
- NIST SP 800-77 - Guide to IPsec VPNs
- NIST SP 800-113 - Guide to SSL VPNs
- NIST SP 800-45 - Guidelines on Electronic Mail Security
- NSA - "Selecting and Hardening Remote Access VPNs"
- NSA - "Transition to Multi-Factor Authentication"
- CISA - "Implementing Phishing-Resistant MFA"
- Microsoft Docs - Conditional Access
- Microsoft Docs - Exchange Extended Protection (EPA)
- Microsoft Docs - Defender for Identity
- [MITRE ATT&CK T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1621 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
- CIS Controls v8 - 4 (Secure Configuration), 6 (Access Control),
  12 (Network Infrastructure Management), 13 (Network Monitoring)
- CIS Benchmarks - Microsoft Exchange, Cisco ASA, Palo Alto,
  Fortinet