# GCP Fundamentals

Google Cloud Platform security reference: architecture, identity model, and the primitives an attacker or defender must understand before touching any specific service.

## 1. Overview

Google Cloud Platform (GCP) is a public cloud with four primitives that recur across every attack and every control:

- **Projects** - the top-level resource container. Billing, IAM policy and API enablement are scoped to a project.
- **IAM** - role bindings that grant permissions to principals (users, groups, service accounts) on resources.
- **Service Accounts** - non-human identities used by workloads. They authenticate with long-lived JSON keys or short-lived tokens.
- **Audit Logs** - Admin Activity, Data Access and System Event logs in Cloud Logging.

Most GCP attacks reduce to one of two moves: abuse an over-permissive IAM binding, or steal a service account credential. Defensive work is the mirror: least privilege, key rotation, and detection of anomalous log activity.

## 2. Reconnaissance and Enumeration

### 2.1 Unauthenticated recon

Public GCP resources are enumerable without any credential:

- **Cloud Storage buckets** - bucket names are globally unique and DNS-resolvable. `https://storage.googleapis.com/<bucket>` returns 200 for public buckets, 403 for private existing buckets, 404 for non-existent ones. Enumerating naming patterns (project name, company domain, environment) reveals exposed storage.
- **Cloud Functions / Cloud Run endpoints** - `*.run.app` and `*.cloudfunctions.net` are public hostnames. If the service allows unauthenticated invocation, it is directly reachable.
- **Firebase projects** - `https://<project>.firebaseio.com/.json` and `https://identitytoolkit.googleapis.com/v1/projects?key=<API_KEY>` expose misconfigured Firebase rules.
- **Metadata endpoints** - `http://metadata.google.internal/` and `http://169.254.169.254/` are only reachable from inside GCP, but they are the most common post-exploitation target.

### 2.2 Authenticated recon

With any valid credential (even a low-privilege service account), the following are usually allowed and form the attacker's map:

```bash
gcloud auth list
gcloud config list
gcloud projects list
gcloud services list --enabled
gcloud iam service-accounts list
gcloud compute instances list
gcloud storage buckets list
gcloud logging sinks list
```

Expected output (trimmed):

```text
ACTIVE  ACCOUNT
*       attacker@project.iam.gserviceaccount.com

PROJECT_ID     NAME           PROJECT_NUMBER
target-prod    target-prod    123456789012

NAME                                    EMAIL
default-compute@target-prod.iam...      default-compute@target-prod.iam.gserviceaccount.com

NAME           ZONE           MACHINE_TYPE   STATUS
web-01         us-central1-a  e2-medium      RUNNING
```

### 2.3 Organization and folder structure

If the credential has `resourcemanager.organizations.get` or `resourcemanager.folders.list`, map the hierarchy:

```bash
gcloud organizations list
gcloud resource-manager folders list --organization=<ORG_ID>
gcloud projects list --format="table(projectId,parent.id,parent.type)"
```

A project under an organization inherits IAM policies from folders above it. A project with no parent is standalone and often less monitored.

## 3. Common Attack Vectors

| Vector | Primitive | What the attacker gains |
|--------|-----------|-------------------------|
| Over-permissive IAM binding | IAM | Access to other projects, service accounts, or the whole org |
| Leaked service account JSON key | Service Accounts | Persistent identity until the key is rotated |
| Metadata server SSRF | Compute Engine | Short-lived token for the attached service account |
| Public Cloud Storage bucket | Cloud Storage | Data read or write, sometimes code execution via client apps |
| Default service account on a VM | Compute Engine | Editor-level permissions by default (legacy projects) |
| Cloud Build / Cloud Run misconfig | CI/CD | Build-time access to secrets and deploy rights |

The dominant vector in real GCP compromises is **stolen service account credentials**. They are long-lived, easy to exfiltrate (JSON file, environment variable, CI secret), and often over-privileged.

## 4. Exploitation Recipes

### 4.1 Verify a stolen service account key

```bash
gcloud auth activate-service-account --key-file=stolen.json
gcloud auth list
gcloud projects list
```

If the key works, the next question is what it can reach:

```bash
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" --filter="bindings.members:<SA_EMAIL>" --format="table(bindings.role)"
```

Expected output:

```text
ROLE
roles/editor
roles/storage.admin
```

`roles/editor` on a project is effectively full control of non-IAM resources. `roles/owner` also grants IAM changes.

### 4.2 Enumerate reachable resources

```bash
gcloud compute instances list --project=<PROJECT_ID>
gcloud storage buckets list --project=<PROJECT_ID>
gcloud functions list --project=<PROJECT_ID>
gcloud run services list --project=<PROJECT_ID>
gcloud secrets list --project=<PROJECT_ID>
```

Each list call returns 403 if the role does not allow it; the pattern of 200/403 responses maps the effective permission set.

### 4.3 Metadata server access from a compromised VM

From inside a Compute Engine instance:

```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Expected output (trimmed):

```text
{"access_token":"ya29.c.xxxxx","expires_in":3599,"token_type":"Bearer"}
```

The token belongs to the service account attached to the VM. Decode it to see the identity and scopes:

```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com&format=full"
```

## 5. Post-Exploitation

Once a valid identity is established, the usual goals are:

- **Persistence** - create a new service account key (`gcloud iam service-accounts keys create`), add an IAM binding for an attacker-controlled principal, or deploy a Cloud Function with a trigger.
- **Privilege escalation** - find a role that can act as a more privileged service account (`iam.serviceAccounts.actAs`), then run compute as that account.
- **Lateral movement** - hop between projects by abusing IAM bindings at the folder or organization level.
- **Data access** - read Cloud Storage, Secret Manager, Cloud SQL exports, BigQuery datasets.

All of these produce Admin Activity or Data Access log entries, which is why detection depends on Cloud Logging being enabled and exported.

## 6. Preventive Controls

- **Least privilege IAM** - never bind `roles/editor` or `roles/owner` to service accounts. Use predefined roles or custom roles scoped to the specific resource.
- **Disable default service account attachment** - create a dedicated service account per workload with the minimum roles, and set `--no-service-account` on instances that do not need one.
- **Workload Identity Federation** - replace long-lived JSON keys with short-lived federated tokens (GitHub Actions, AWS, Azure AD). This removes the primary credential-theft vector.
- **Organization policies** - enforce `constraints/iam.disableServiceAccountKeyCreation` and `constraints/compute.vmExternalIpAccess` at the org level.
- **VPC Service Controls** - wrap sensitive projects in a service perimeter so that even a valid token cannot exfiltrate data outside the perimeter.
- **Bucket public access prevention** - set `public_access_prevention = "enforced"` on every bucket.

## 7. Detection Controls

- **Admin Activity logs** - always on, cannot be disabled. Watch for `SetIamPolicy`, `CreateServiceAccountKey`, `CreateServiceAccount`, `SetMetadata` on the metadata server.
- **Data Access logs** - off by default for most services. Enable for Cloud Storage, Secret Manager, and BigQuery on sensitive projects.
- **VPC Flow Logs** - detect egress from Compute Engine to the metadata server and to unfamiliar external IPs.
- **Security Command Center** - built-in detectors for public buckets, disabled logging, and anomalous IAM grants.
- **Cloud Audit Logs export** - sink Admin Activity and Data Access logs to a separate logging project or to BigQuery for retention beyond the default 400 days.

## 8. Verification

To verify that the controls are in place in a project:

```bash
gcloud projects get-iam-policy <PROJECT_ID> --format=json | jq '.bindings[] | select(.role=="roles/editor" or .role=="roles/owner")'
gcloud storage buckets list --format="table(name,iamConfiguration.publicAccessPrevention)"
gcloud logging sinks list
gcloud resource-manager org-policies list --project=<PROJECT_ID>
```

Expected: no `roles/editor` or `roles/owner` bindings on service accounts; every bucket shows `enforced`; at least one log sink exists.

## 9. Cloud-Specific Considerations

- **Project vs folder vs org scope** - a binding at the org level applies to every current and future project. Auditing a project in isolation misses org-level grants.
- **Service account impersonation** - `iam.serviceAccounts.actAs` is a separate permission from `iam.serviceAccounts.getAccessToken`. A principal with `actAs` can run workloads as the target service account without ever holding a key.
- **Domain-restricted sharing** - `constraints/iam.allowedPolicyMemberDomains` prevents binding to external identities. Without it, an attacker who controls any Google account can be added to the project.
- **Google-managed vs customer-managed keys** - default encryption is Google-managed. Regulated workloads need CMEK, which changes who can read the data.

## 10. Production Notes

- Rotate service account keys every 90 days, or better, eliminate them entirely with Workload Identity Federation.
- Treat any project that has `roles/editor` on a service account as already compromised in a tabletop exercise.
- Export Admin Activity logs to a separate project with a separate retention policy. An attacker with project-owner rights can otherwise delete sinks.
- Use `gcloud alpha resource-manager liens create` on critical projects to prevent accidental or malicious deletion.
- Review IAM bindings monthly with `gcloud asset search-all-iam-policies` across the organization.

## 11. References

- Google Cloud IAM overview - https://cloud.google.com/iam/docs/overview
- Google Cloud service accounts - https://cloud.google.com/iam/docs/service-accounts
- Google Cloud audit logs - https://cloud.google.com/logging/docs/audit
- Google Cloud VPC Service Controls - https://cloud.google.com/vpc-service-controls/docs/overview
- Google Cloud Security Best Practices - https://cloud.google.com/security/best-practices
- MITRE ATT&CK Cloud Matrix - https://attack.mitre.org/matrices/enterprise/cloud/

## Certification Alignment

- **Google Cloud Professional Cloud Security Engineer** - IAM, VPC Service Controls, audit logging, key management.
- **Google Cloud Associate Cloud Engineer** - projects, service accounts, gcloud basics.
- **Google Cloud Professional Cloud Architect** - organization hierarchy, folder policies, project design.
- **CompTIA Security+** - identity and access management, cloud security concepts.
