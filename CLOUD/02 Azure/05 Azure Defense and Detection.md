# Azure Defense and Detection

> [!CAUTION]
> This file is for authorized security testing of Azure subscriptions and tenants you own or have explicit written permission to assess. Do not use these techniques against subscriptions, tenants, or services you do not own or have permission to test.

## 1. Overview

Azure defense is a stack of overlapping services, not a single product. The layers are:

- **Microsoft Defender for Cloud** - the cloud security posture management (CSPM) and cloud workload protection platform (CWPP). CSPM evaluates the configuration of every resource against the Microsoft Cloud Security Benchmark and CIS Azure Foundations; CWPP adds threat detection for servers, App Service, Storage, SQL, Key Vault, containers, and DNS.
- **Microsoft Sentinel** - the SIEM and SOAR. Ingests logs from Azure, Microsoft 365, Entra ID, and third-party sources; correlates them with analytics rules; and runs playbooks (Logic Apps) for automated response.
- **Azure Monitor** - the underlying telemetry platform. Activity logs, resource logs, metrics, and Log Analytics workspaces are all Azure Monitor. Sentinel and Defender for Cloud consume Azure Monitor data.
- **Microsoft Entra ID Protection** - the identity risk engine. Produces `riskySignIn` and `riskyUser` events that feed Conditional Access and Sentinel.
- **Microsoft Defender for Identity** - the on-premises Active Directory sensor. Detects credential theft, lateral movement, and reconnaissance against AD DS.
- **Microsoft Defender for Endpoint** - the endpoint detection and response (EDR) agent. Detects process, network, and file behavior on Windows, Linux, and macOS.
- **Microsoft Defender for Cloud Apps** - the cloud access security broker (CASB). Detects anomalous behavior in SaaS applications, including OAuth app governance.
- **Microsoft Defender XDR** - the unified incident view across Defender for Endpoint, Identity, Cloud Apps, Office 365, and (through integration) Defender for Cloud. Incidents from any of these products appear in one portal.
- **Azure Policy** - the guardrail layer. Denies or audits the creation of non-compliant resources, and can auto-remediate with `deployIfNotExists` and `modify` effects.

The three log sources that matter most for detection:

- **Azure Activity log** - every control-plane operation (create, update, delete) on every resource. Stored for 90 days by default; longer retention requires a diagnostic setting to Log Analytics, a storage account, or an event hub.
- **Entra ID sign-in and audit logs** - every authentication and directory change. Stored for 30 days by default; longer retention requires a diagnostic setting.
- **Resource logs** - data-plane and application logs specific to each service (Storage diagnostic logs, Key Vault audit logs, NSG flow logs, VM guest logs). Disabled by default.

This file is the defense-side counterpart to the rest of the Azure subcategory. It answers three questions:

1. What detection services exist, and what does each one actually see?
2. How does an attacker try to evade each one, and where does the evasion leave traces?
3. How does an incident-response workflow look when the incident is in an Azure tenant, not on a Linux host?

## 2. Reconnaissance / Enumeration

### 2.1 Mapping the logging and detection stack

The first step for an attacker (and for a defender performing a self-assessment) is to enumerate which logging and detection services are enabled, on which resources, and with what coverage. Every call below is read-only and returns a small JSON document.

```bash
# Defender for Cloud: pricing tiers and enabled plans
az security pricing list --query '[].{Name:name,Tier:pricingTier}'
az security auto-provisioning-setting list

# Defender for Cloud: security contacts and alert notifications
az security contact list

# Microsoft Sentinel: workspaces and enabled analytics rules
az sentinel workspace list 2>/dev/null || echo "Sentinel uses az monitor log-analytics workspace list"
az monitor log-analytics workspace list --query '[].{Name:name,ResourceGroup:resourceGroup,RetentionInDays:retentionInDays}'

# Diagnostic settings per resource (Activity log, Entra ID, resource logs)
az monitor diagnostic-settings list --resource <resource-id>
az monitor diagnostic-settings subscription list

# Azure Policy: assignments and compliance state
az policy assignment list --query '[].{Name:name,DisplayName:displayName,Scope:scope}'
az policy state summarize --query 'value[].{Policy:policyAssignmentName,Compliant:results.nonCompliantResources}'
```

### 2.2 Identifying gaps

The reconnaissance output is most useful when read as a coverage map. The gaps that matter most, in order:

- **No diagnostic setting on the subscription Activity log.** The Activity log retains 90 days in the portal, but without a diagnostic setting the events are not queryable in Log Analytics beyond 90 days and are not visible to Sentinel.
- **Entra ID diagnostic settings not configured.** Sign-in and audit logs are not shipped to Log Analytics, so Sentinel cannot correlate identity events with control-plane events.
- **Defender for Cloud plans partially enabled.** Defender for Servers, Storage, App Service, Key Vault, SQL, Containers, and DNS are separate plans. A missing plan means no threat detection for that workload.
- **Microsoft Sentinel not enabled, or enabled without content.** A workspace with no analytics rules is a data lake, not a SIEM.
- **Resource logs disabled.** Storage diagnostic logs, Key Vault audit logs, and NSG flow logs are opt-in. A storage account without diagnostic logs has no record of blob access.
- **No Azure Policy assignments, or assignments in Audit mode only.** A policy in Audit mode reports non-compliance but does not prevent it. `Deny` and `DeployIfNotExists` are the enforcement effects.

### 2.3 Enumerating the responders

Detection is only half of the stack. The response side is equally enumerable:

```bash
# Logic Apps that may be Sentinel playbooks
az logic workflow list --query '[].{Name:name,State:state,ResourceGroup:resourceGroup}'

# Action groups (used by Azure Monitor alerts)
az monitor action-group list --query '[].{Name:name,ResourceGroup:resourceGroup,ShortName:shortName}'

# Alert rules (metric and log search)
az monitor alert list --query '[].{Name:name,Enabled:enabled,Severity:severity}'
```

An attacker who finds that detection fires but no responder runs has found a monitoring theatre: the findings are recorded, but nothing happens. In practice, this is the most common detection gap in real Azure environments.

## 3. Common Attack Vectors

### 3.1 Defense evasion, mapped to detection services

Every defense-evasion action in Azure maps to one or more detection services. The attacker's goal is to find the action that is not covered, or to cover the trace it leaves.

- **Disable diagnostic settings** (`Microsoft.Insights/diagnosticSettings/delete`) - recorded in the Activity log itself (if the Activity log is shipped elsewhere), and in Sentinel if the deletion was itself ingested. Defense: `Deny` policy on `Microsoft.Insights/diagnosticSettings/delete` for the subscription scope, and a separate log-archive subscription with a `DeployIfNotExists` policy that re-creates the setting.
- **Disable Defender for Cloud plans** (`Microsoft.Security/pricings/write` with `pricingTier: Free`) - recorded in the Activity log, and visible in the Defender for Cloud `Security posture` view. Defense: `Deny` policy for non-break-glass identities, and a Sentinel analytics rule on `Microsoft.Security/pricings/write`.
- **Delete analytics rules** (`Microsoft.OperationalInsights/workspaces/savedSearches/delete`) - recorded in the Activity log if the workspace has a diagnostic setting. Defense: `Deny` policy on the Sentinel workspace resource group, and a separate Sentinel workspace in a dedicated subscription.
- **Disable Entra ID diagnostic settings** - recorded in the Entra audit log itself. Defense: a dedicated Entra ID diagnostic setting that ships to a storage account the attacker cannot write to.
- **`Microsoft.Authorization/roleAssignments/write` for a new privileged principal** - recorded in the Activity log and in the Entra audit log; Defender for Cloud's `Suspicious role assignment` alert fires. Defense: `Deny` policy for non-break-glass identities, and just-in-time role activation with PIM.

### 3.2 Log tampering

The Activity log, Entra ID logs, and resource logs are append-only in the portal, but they are also written to a diagnostic destination the attacker may be able to reach:

- **A Log Analytics workspace in the same subscription** - an attacker with `Microsoft.OperationalInsights/workspaces/*` can delete the workspace, or modify the data retention, or run a query that deletes data (`workspace purge`). Defense: put the workspace in a dedicated subscription, restrict access to the `Log Analytics Contributor` role, and enable the workspace's `data export` to an immutable storage account.
- **A storage account in the same subscription** - an attacker with `Microsoft.Storage/storageAccounts/*` can delete the container that holds the logs. Defense: a storage account with `immutableBlobStorage` and a `legalHold`, plus `Deny` policy on delete operations.
- **An event hub in the same subscription** - an attacker with `Microsoft.EventHub/*` can delete the event hub, which breaks the pipeline to the SIEM. Defense: a dedicated event hub namespace with restricted access.

### 3.3 Detection service blind spots

Each detection service has a documented scope and a documented blind spot. The important ones:

- **Defender for Cloud does not detect runtime behavior on a resource whose plan is disabled.** A VM without Defender for Servers has no process-level detection; a storage account without Defender for Storage has no malware scanning.
- **Sentinel analytics rules are only as good as the data they receive.** A rule that depends on `AzureActivity` is blind if the subscription does not ship the Activity log to the workspace.
- **Entra ID Protection requires a P2 license** for the risk-based Conditional Access policies. Without P2, `riskySignIn` events are recorded but not enforced.
- **Defender for Identity requires a sensor on the on-prem AD** (or on Entra Connect). A cloud-only tenant has no AD-side detection.
- **Azure NSG flow logs do not capture the IMDS endpoint** (`169.254.169.254`), because it is link-local and does not leave the VM's network namespace. IMDS token theft is invisible to flow logs; the compensating control is Defender for Servers' anomalous process detection and Defender for Cloud's `Suspicious management session` alert.

### 3.4 Detection evasion through legitimate services

An attacker who has compromised an identity can sometimes use legitimate Azure services to hide:

- **Azure Automation runbooks** produce control-plane events on the Automation Account, not on the target resources the runbook interacts with (unless those resources are also audited). A runbook that runs with a managed identity and exfiltrates data is visible only as a `Microsoft.Automation/automationAccounts/jobs/write` event, not as a data-plane access on the target.
- **Managed identity token requests are not logged** by Azure Monitor (only the downstream resource access is logged). An attacker who steals a token and uses it within the token's lifetime does not leave a trail until the token is used.
- **Azure DevOps / GitHub Actions OIDC tokens** are federated credentials. Their use is logged in the CI/CD platform and in the Entra ID sign-in log as a service principal sign-in, but the actual deployment is visible only through the control-plane events on the target resources.

## 4. Exploitation Recipes

### 4.1 Verifying that the Activity log is actually queryable

Precondition: read access to the subscription's diagnostic settings and to the Log Analytics workspace. The goal is to confirm that a control-plane event the defender expects to see is queryable in the workspace.

```bash
# Generate a known event (read-only, harmless)
az account show

# Query the workspace for the event (KQL)
az monitor log-analytics query \
    --workspace <workspace-id> \
    --analytics-query "AzureActivity | where OperationNameValue == 'MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/READ' | project TimeGenerated, Caller, OperationNameValue | take 10"
```

If the query returns nothing, either the subscription's Activity log is not shipped to this workspace, or the event is older than the diagnostic setting's retention. Both outcomes are findings.

### 4.2 Verifying that Defender for Cloud plans are enabled

Precondition: read access to Defender for Cloud pricing. Defender for Cloud plans are per-subscription, and each workload (Servers, Storage, App Service, Key Vault, SQL, Containers, DNS) is a separate plan.

```bash
# List all Defender plans and their pricing tier
az security pricing list --query '[].{Name:name,Tier:pricingTier}'

# Enable Defender for Servers on the subscription (P2 tier)
az security pricing create --name VirtualMachines --tier StandardP2
```

Expected output: every plan the defender cares about shows `Standard` (or `StandardP2` for Servers). A plan with `Free` is disabled.

### 4.3 Testing Sentinel analytics rule coverage

Precondition: read access to the Sentinel workspace and to its analytics rules. Generate a known event (for example, a `roleAssignments/write`), then confirm the rule fires.

```bash
# List enabled analytics rules
az sentinel alert-rule list --workspace-name <workspace> --resource-group <rg> --query '[?properties.enabled==`true`].{Name:properties.displayName,Severity:properties.severity,Kind:kind}'

# Create a harmless test role assignment, then wait for the rule to fire
az role assignment create --assignee <test-principal-id> --role Reader --scope "/subscriptions/<subscription-id>/resourceGroups/<rg>"

# Check the incident list
az sentinel incident list --workspace-name <workspace> --resource-group <rg> --query '[?properties.status==`New`].{Title:properties.title,Severity:properties.severity,CreatedTime:properties.createdTimeUtc}'
```

Expected result: an incident with a title that matches the analytics rule (for example, "Suspicious role assignment"). If the incident is not created, either the rule is not enabled, the data is not reaching the workspace, or the rule's query does not match the event.

### 4.4 Verifying diagnostic settings on a resource

Precondition: read access to the resource and to its diagnostic settings. A resource without a diagnostic setting is not shipped to Log Analytics, a storage account, or an event hub, and is invisible to Sentinel.

```bash
# List diagnostic settings for a specific resource
az monitor diagnostic-settings list --resource "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>"

# List diagnostic settings at the subscription level (Activity log)
az monitor diagnostic-settings subscription list
```

Expected result: at least one diagnostic setting on every sensitive resource, with `logs.category` covering the operations the defender cares about (Storage: `StorageRead`, `StorageWrite`, `StorageDelete`; Key Vault: `AuditEvent`; NSG: `NetworkSecurityGroupEvent`, `NetworkSecurityGroupRuleCounter`).

### 4.5 Azure Policy for auto-remediation

Precondition: the defender wants to enforce a control automatically. The policy definition below requires that every storage account in the subscription has `AllowBlobPublicAccess: false`. The `DeployIfNotExists` effect (not shown) would also remediate non-compliant resources.

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
      { "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "notEquals": false }
    ]
  },
  "then": {
    "effect": "deny"
  }
}
```

A policy in `Audit` mode reports non-compliance but does not prevent it. A policy in `Deny` mode prevents the creation of non-compliant resources. A policy in `DeployIfNotExists` mode auto-remediates existing resources.

## 5. Post-Exploitation

After a detection event fires, the attacker's behavior determines the outcome. Two patterns:

- **The attacker does not know the alert fired.** The responder has a window (minutes to hours) to isolate the resource, revoke the token, and preserve evidence. Speed is the entire game.
- **The attacker notices and accelerates.** The attacker creates persistence (a new app registration, a role assignment), escalates (a new managed identity with a privileged role), or exfiltrates (a storage account read, a Key Vault read) before the responder can react. This is why automation matters: the responder must be faster than the attacker.

From the defender's perspective, the post-exploitation phase is the incident-response phase:

1. **Contain.** Revoke the compromised user's sessions (`Revoke-AzureADUserAllRefreshToken` / Graph `revokeSignInSessions`), disable the service principal (`az ad sp update --id <app-id> --set accountEnabled=false`), remove the role assignment (`az role assignment delete`), and isolate the VM (`az network nsg rule` to deny all, or `az vm deallocate`).
2. **Preserve.** Export the Activity log for the subscription and time range, export the Entra ID sign-in and audit logs, take a snapshot of the VM disk (`az snapshot create`), and export the Sentinel incident and its raw events.
3. **Eradicate.** Delete the attacker-created app registration, role assignment, managed identity, or access key. Rotate every credential that was reachable from the compromised identity (storage keys, Key Vault secrets, service principal secrets).
4. **Recover.** Restore from a known-good snapshot, re-deploy the affected workloads, and re-validate the controls.
5. **Learn.** Update the detection rules to cover the gap that was exploited. A post-mortem that does not change a rule is a post-mortem that will repeat.

## 6. Preventive Controls

The preventive controls in this file are organization-level guardrails. They are not detection; they are the reason a detection service has fewer events to analyze.

- **Deny the detection-disable APIs with Azure Policy.** `Microsoft.Insights/diagnosticSettings/delete`, `Microsoft.Security/pricings/write` (with `pricingTier: Free`), `Microsoft.OperationalInsights/workspaces/delete`, `Microsoft.OperationsManagement/solutions/delete`. Attach to the management group scope, and exclude a small break-glass group.
- **Deny the log-destination tampering APIs.** `Microsoft.Storage/storageAccounts/blobServices/containers/delete`, `Microsoft.EventHub/namespaces/eventhubs/delete`, `Microsoft.OperationalInsights/workspaces/tables/delete`. Attach to the log-archive subscription, and give no standing access to the log-archive subscription.
- **Enforce diagnostic settings with `DeployIfNotExists`.** A policy that adds a diagnostic setting to every resource of a given type, and re-adds it if it is deleted.
- **Enforce Defender for Cloud plans with policy.** A `DeployIfNotExists` policy that sets every plan to `Standard`. A `Deny` policy on `pricingTier: Free`.
- **Enforce an Azure Policy baseline.** The Microsoft Cloud Security Benchmark and CIS Azure Foundations are available as built-in initiatives. Assign them at the management group scope in `Deny` + `DeployIfNotExists` mode where possible.
- **Use a dedicated log-archive subscription.** The production subscription can write logs to the archive, but cannot delete or modify them. The archive subscription has a separate break-glass identity, no standing role assignments, and no user access.
- **Use just-in-time access for the log-archive subscription.** PIM for the `Log Analytics Contributor` role, with an approval workflow and a 1-hour activation window.
- **Centralize identity and access management.** Entra ID P2 for risk-based Conditional Access, PIM for all administrative roles, and Access Reviews for the break-glass accounts.

## 7. Detection Controls

The detection controls are the services themselves. This section is the map; the sections above are the detail.

- **Microsoft Defender for Cloud** - CSPM (secure score, recommendations, regulatory compliance) and CWPP (threat detection for servers, App Service, Storage, SQL, Key Vault, containers, DNS).
- **Microsoft Sentinel** - SIEM (log ingestion, analytics rules, incidents) and SOAR (playbooks, automation rules).
- **Azure Monitor** - Activity log, resource logs, metrics, and Log Analytics workspaces.
- **Microsoft Entra ID Protection** - risky sign-ins, risky users, and the risk-based Conditional Access policies.
- **Microsoft Defender for Identity** - on-prem AD threat detection.
- **Microsoft Defender for Endpoint** - endpoint detection and response.
- **Microsoft Defender for Cloud Apps** - CASB, SaaS anomaly detection, OAuth app governance.
- **Microsoft Defender XDR** - the unified incident view across all Defender products.
- **Azure Policy** - the configuration guardrail, with `Audit`, `Deny`, `DeployIfNotExists`, and `Modify` effects.

The relationship between them: Azure Monitor is the telemetry layer; Defender for Cloud, Sentinel, and the Defender XDR products are the analyzers; Azure Policy is the preventive control; Logic Apps and Sentinel playbooks are the responders.

## 8. Verification

Read-only checks to confirm the detection stack is enabled, has coverage, and is not removable by a non-break-glass identity.

```bash
# Activity log diagnostic setting on the subscription
az monitor diagnostic-settings subscription list

# Entra ID diagnostic settings (sign-in and audit logs)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' 2>/dev/null || echo "Entra diagnostic settings are configured in the Entra admin center"

# Defender for Cloud plans
az security pricing list --query '[].{Name:name,Tier:pricingTier}'

# Azure Policy assignments at the management group scope
az policy assignment list --scope "/providers/Microsoft.Management/managementGroups/<mg-id>" --query '[].{Name:name,DisplayName:displayName,Scope:scope}'

# Log Analytics workspace retention
az monitor log-analytics workspace list --query '[].{Name:name,ResourceGroup:resourceGroup,RetentionInDays:retentionInDays,DailyQuotaGb:workspaceCapping.dailyQuotaGb}'
```

Expected result: a subscription-level diagnostic setting shipping the Activity log to a Log Analytics workspace (and optionally to a storage account or event hub); Entra ID sign-in and audit logs shipped to the same workspace; every Defender for Cloud plan the defender cares about in `Standard` tier; Azure Policy assignments at the management group scope; a Log Analytics workspace with a retention of at least 90 days and no daily quota that would drop events.

## 9. Certification Alignment

- **Microsoft Certified: Azure Security Engineer Associate (AZ-500)** - the primary certification for this file. Defender for Cloud, Sentinel, Azure Monitor, Azure Policy, incident response.
- **Microsoft Certified: Security Operations Analyst Associate (SC-200)** - the primary certification for Sentinel and Defender XDR. KQL, analytics rules, incidents, playbooks.
- **Microsoft Certified: Azure Administrator Associate (AZ-104)** - diagnostic settings, Log Analytics, alerts.
- **CompTIA Security+** - monitoring, detection, incident response, logging.

## 10. Production Notes

- The Activity log retains 90 days in the portal. For longer retention, configure a subscription-level diagnostic setting to a Log Analytics workspace, a storage account, or an event hub. Without it, you cannot query events older than 90 days and Sentinel does not receive them.
- Entra ID sign-in logs retain 30 days in the portal (7 days for free, 30 days for P1/P2). For longer retention, configure a diagnostic setting to a Log Analytics workspace. This is the single most important log for identity attacks.
- Defender for Cloud's free tier provides CSPM recommendations and the secure score. The paid plans (Servers, Storage, App Service, Key Vault, SQL, Containers, DNS) provide the CWPP detections. Plan the tier per workload, not per subscription.
- Sentinel analytics rules are free to create, but ingestion is billed per GB. The cost of a full-fidelity deployment is significant; a log-source-by-log-source rollout is the practical approach.
- Azure Policy in `Deny` mode can break a deployment. Test in `Audit` mode first, then roll out `Deny` to a non-production subscription, then to production.
- The log-archive subscription is the single most important architectural control in this file. Without it, an attacker with subscription-level access can delete the very evidence that would prove the compromise.

## 11. References

- Microsoft Defender for Cloud documentation - https://learn.microsoft.com/en-us/azure/defender-for-cloud/
- Microsoft Sentinel documentation - https://learn.microsoft.com/en-us/azure/sentinel/
- Azure Monitor documentation - https://learn.microsoft.com/en-us/azure/azure-monitor/
- Microsoft Entra ID Protection - https://learn.microsoft.com/en-us/entra/id-protection/
- Microsoft Defender XDR - https://learn.microsoft.com/en-us/defender-xdr/
- Azure Policy documentation - https://learn.microsoft.com/en-us/azure/governance/policy/
- Azure security best practices - https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns
- Microsoft cloud security benchmark - https://learn.microsoft.com/en-us/security/benchmark/azure/
