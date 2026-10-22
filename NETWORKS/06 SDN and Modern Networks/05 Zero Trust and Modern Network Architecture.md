# Zero Trust and Modern Network Architecture

## 1. Overview

Zero Trust is a security model that removes implicit trust from the network perimeter. No user, device or workload is trusted by default because it sits "inside" the network. Every access request is authenticated, authorized and continuously evaluated based on identity, device posture, context and policy.

Zero Trust is not a product; it is an architecture. It combines identity, device trust, network microsegmentation, application access control, data protection and continuous monitoring. NIST SP 800-207 formalizes the model with a Policy Decision Point (PDP) and Policy Enforcement Points (PEP).

This file covers the Zero Trust model, its building blocks, implementation patterns, and how to attack and defend a Zero Trust architecture.

## 2. Threat Model

- **Lateral movement from a compromised endpoint.** Traditional perimeter security assumes inside = trusted; a single compromised host can reach everything.
- **Stolen credentials.** Without continuous verification, a stolen session is as good as the real user.
- **Insider threat.** Legitimate but malicious user with excessive access.
- **Unmanaged device access.** BYOD or unpatched devices connecting to internal resources.
- **Supply chain and third-party access.** Vendors with broad network access.
- **Policy bypass.** Enforcement points that can be circumvented (e.g. direct IP access bypassing the identity-aware proxy).

## 3. How It Works (technical)

NIST SP 800-207 components:

- **Policy Engine (PE)** - the "brain" that decides access.
- **Policy Administrator (PA)** - establishes or shuts down the connection based on the PE decision.
- **Policy Enforcement Point (PEP)** - the component that actually enforces the decision (proxy, gateway, agent).
- **Subject** - user, device, workload.
- **Resource** - application, data, service.
- **Trust algorithm** - inputs: identity, device posture, behavior, threat intel, time, location.

Core principles:

- **Verify explicitly.** Always authenticate and authorize based on all available signals.
- **Least privilege.** Just-in-time, just-enough access.
- **Assume breach.** Design for containment: microsegmentation, encryption, continuous monitoring.

Implementation layers:

- **Identity and access** - SSO, MFA, conditional access (Entra ID, Okta, Google Workspace).
- **Device trust** - MDM, EDR, device certificates, posture checks (Intune, Jamf, CrowdStrike).
- **Network** - microsegmentation, identity-aware proxies (Zscaler, Cloudflare Access, Google BeyondCorp), software-defined perimeter (SDP).
- **Application** - per-app access control, API gateways with auth, service mesh mTLS (Istio, Linkerd).
- **Data** - classification, DLP, encryption, rights management.
- **Visibility and analytics** - SIEM, UEBA, continuous monitoring.

Architecture patterns:

- **BeyondCorp (Google)** - access to internal apps through an identity-aware proxy, no VPN.
- **SDP (Software-Defined Perimeter)** - "need-to-know" network access, hide resources from the internet.
- **ZTNA (Zero Trust Network Access)** - vendor category replacing VPN.
- **Microsegmentation** - workload-to-workload policy, no flat L2 network.
- **Service mesh mTLS** - identity per service, encrypted east-west traffic.

## 4. Installation and Setup

Open-source Zero Trust lab components:

- **Keycloak** - open-source IdP with OIDC/SAML.
- **Pomerium or oauth2-proxy** - identity-aware proxy in front of internal apps.
- **SPIFFE/SPIRE** - workload identity for mTLS.
- **Istio** - service mesh with mTLS, authorization policy.
- **Tailscale / Headscale** - WireGuard-based mesh with ACLs, identity-bound.

Example: Pomerium protecting an internal app:

```yaml
# pomerium config (abbreviated)
authenticate_service_url: https://authenticate.example.com
routes:
  - from: https://app.example.com
    to: http://internal-app:8080
    policy:
      - allow:
          and:
            - email:
                is: alice@example.com
            - device:
                approved: true
```

Istio authorization policy (mTLS enforced, allow only specific service):

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend
spec:
  selector:
    matchLabels:
      app: backend
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/prod/sa/frontend"]
```

## 5. Hardening and Configuration

- **No implicit trust by subnet.** Being in `10.0.0.0/8` gives no access. Every flow authenticated.
- **MFA everywhere, phishing-resistant (FIDO2/WebAuthn).** SMS/TOTP only for fallback.
- **Conditional access policies.** Device compliant, location allowed, risk score low - all must pass.
- **Enforcement point cannot be bypassed.** Direct IP access to internal resources blocked by network policy; only the proxy path works.
- **Service mesh mTLS with per-service identity (SPIFFE).** No shared service accounts.
- **Microsegmentation default-deny.** Explicit allow rules per workload pair.
- **Continuous verification.** Session re-evaluated on risk change; not just at login.
- **Centralized logs.** Every access decision logged with subject, resource, decision, context.

## 6. Operational Usage

- **Onboarding:** user gets identity, device enrolled, conditional access policy applied, access granted per role.
- **Access request:** user requests resource, policy engine evaluates, PEP enforces. Just-in-time access for sensitive resources.
- **Session:** continuously monitored; anomalous behavior triggers re-authentication or block.
- **Offboarding:** identity deactivated, all sessions invalidated, device wiped.
- **Third-party:** separate identity, scoped access, time-boxed, logged.

## 7. Common Mistakes

- Calling a VPN "Zero Trust" because it has MFA.
- Identity-aware proxy deployed, but internal apps still reachable via direct IP.
- Flat network behind the proxy: the proxy is bypassed by an insider.
- MFA only at login, no continuous verification.
- Shared service accounts in the mesh.
- No logging on policy decisions; can't audit what happened.
- Trusting device posture once at login; never re-checking.

## 8. Attacks Against It

- **Proxy bypass.** Direct IP access, DNS rebinding, alternate route to internal app.
- **Token theft and session hijack.** Stolen cookies, refresh tokens, session tokens.
- **MFA fatigue / push bombing.** Repeated push notifications until user approves.
- **Adversary-in-the-middle (AiTM).** Phishing proxy captures session token post-MFA (Evilginx2, Modlishka).
- **Device posture spoofing.** Fake device compliance data.
- **Service mesh compromise.** Compromised workload uses its identity to call other services.
- **Policy engine abuse.** IAM misconfiguration, overly permissive conditional access.

## 9. Detection (Blue Team)

- **Access decision logs.** Every PEP decision: allow/deny, subject, resource, context.
- **Anomalous authentication.** Login from new location, impossible travel, new device.
- **Bypass detection.** Traffic to internal resources not via the proxy; alerts on direct IP connections.
- **Token anomaly.** Same token used from two IPs, token replay.
- **Device posture drift.** Device no longer compliant but still has access.
- **Mesh authorization failures.** Repeated `403` from Istio/Envoy indicates misconfiguration or attack.

## 10. Case Studies

- **Google BeyondCorp (2011+).** Google replaced VPN with identity-aware access; detailed in the BeyondCorp papers.
- **SolarWinds (2020).** Demonstrated that perimeter trust fails; attackers moved laterally because of implicit trust between systems.
- **Colonial Pipeline (2021).** Compromised VPN account without MFA gave initial access; a Zero Trust model with MFA and continuous verification would have detected or blocked it.
- **Microsoft Storm-0558 (2023).** Token signing key compromise allowed forging tokens for any account; shows the importance of protecting identity infrastructure.

## 11. Legal and Ethical Notes

Testing Zero Trust implementations requires explicit authorization. Attempting to bypass access controls (proxy bypass, token theft, MFA fatigue) is unauthorized access if done without permission. Lab environments with real IdP + proxy + mesh are the right place to practice. Never test MFA fatigue or AiTM techniques against real users without written consent.

## 12. Production Notes

- **Phased rollout.** Start with high-value apps, expand gradually. Do not "big bang".
- **Fallback plan.** If the identity provider fails, is there a documented, audited break-glass path?
- **User experience matters.** Friction drives shadow IT and bypasses. Measure.
- **Policy as code.** Conditional access policies version-controlled, reviewed.
- **Test bypass paths.** Periodically attempt to reach internal apps via direct IP; findings are defects.
- **Vendor concentration risk.** A single ZTNA/IdP vendor is a single point of failure and compromise; plan for it.

## 13. Certification Alignment

- **CompTIA Network+** - security concepts, network segmentation.
- **CompTIA Security+** - Zero Trust concepts, identity and access management.
- **Cisco CCNA** - security fundamentals, network segmentation.
- **Cisco CCNP Security** - Zero Trust architecture, identity services engine (ISE).
- **Microsoft AZ-500** - Azure conditional access, Zero Trust implementation.
- **Cross-reference:** CLOUD category for cloud-native Zero Trust (AWS IAM, Azure AD, GCP IAM); DEVSECOPS for service mesh and supply chain.

## References

- NIST SP 800-207 - Zero Trust Architecture - https://csrc.nist.gov/pubs/sp/800/207/final
- Google BeyondCorp Papers - https://cloud.google.com/beyondcorp
- CISA Zero Trust Maturity Model - https://www.cisa.gov/zero-trust-maturity-model
- SPIFFE/SPIRE Documentation - https://spiffe.io/docs/
- Istio Security Documentation - https://istio.io/latest/docs/concepts/security/
- Microsoft Zero Trust Guidance - https://learn.microsoft.com/en-us/security/zero-trust/
- Pomerium Documentation - https://www.pomerium.com/docs
