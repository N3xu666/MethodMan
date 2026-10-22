# GCP Defense and Detection

Google Cloud Platform security reference: how to build a defensive posture across GCP primitives, detect the attacks described in the rest of this subcategory, and respond to a GCP compromise.

## 1. Overview

Defending GCP is not the sum of defending each service in isolation. The GCP-specific threats share three characteristics:

- **Identity is the perimeter.** A stolen service account token is access to every resource that SA can reach, across projects and services. Network controls matter less than IAM hygiene.
- **Logs are off by default.** Admin Activity logs are always on, but Data Access logs are opt-in per service. Most GCP attacks succeed because the relevant log was not enabled.
- **Organization policies trump project IAM.** A policy at the org level applies to every current and future project. This is the only reliable way to enforce a baseline across a growing estate.

The defensive posture described here is organized around the attack stages from the rest of the subcategory: reconnaissance, credential compromise, storage exposure, and compute escalation. Each section below maps to those stages.

## 2. Reconnaissance and Enumeration (Defensive View)

**What the attacker sees:**
- Public bucket names (via DNS and HTTP probes)
- Cloud Run and Cloud Functions hostnames
- Project IDs (in TLS SANs, in error pages, in DNS)
- IAM bindings (if any credential is available)

**What to hide:**
- Do not use project IDs in DNS names that point to public endpoints. Use custom domains.
- Do not put environment names (`-prod`, `-dev`, `-backup`) in bucket names. They are the first thing an attacker guesses.
- Do not expose the project ID in error pages or in HTTP headers. `Server: Google Frontend` is unavoidable; `X-Goog-Project-Id` is not.
- Restrict Cloud Run and Cloud Functions invocation to authenticated identities. `allUsers` invocation is almost never intentional.

**Detection:**
- Cloud Storage 403s on non-existent or private buckets are not logged by default. Enable access logs on sensitive buckets to see probing.
- Cloud Armor can rate-limit and block IPs that probe unusual paths or bucket names. This is the closest GCP has to a WAF for recon.
- Security Command Center surfaces publicly accessible buckets and unauthenticated Cloud Run services as findings. Enable it at the org level.

## 3. Common Attack Vectors (Defensive View)

| Attack | Detection signal | Preventive control |
|--------|------------------|--------------------|
| Public bucket | SCC public bucket finding; `SetIamPolicy` with `allUsers` | Org policy `storage.publicAccessPrevention` |
| Leaked SA key | `CreateServiceAccountKey` in Admin Activity logs | Org policy `iam.disableServiceAccountKeyCreation` |
| Metadata SSRF | Data access logs show SA token use from unexpected IP | Disable default SA; `--no-service-account` on non-API workloads |
| SSH key injection | `setCommonInstanceMetadata` in Admin Activity logs | Org policy `compute.requireOsLogin` |
| IAM escalation | `SetIamPolicy` changing `roles/owner` bindings | Separation of duties; approval workflow for IAM changes |
| Cross-project binding | `SetIamPolicy` with a principal from another project | Org policy `iam.allowedPolicyMemberDomains` |

Each row is a detection signal plus a preventive control. The preventive control is the primary defense; the detection signal is the safety net when prevention fails.

## 4. Exploitation Recipes (Defensive View)

**How to detect the exploitation recipes from the rest of the subcategory:**

- **Stolen SA key activation** - `google.iam.admin.v1.CreateServiceAccountKey` followed within minutes by API calls from a new IP. The key creation log entry is the highest-fidelity signal in GCP.
- **Metadata token use** - the token itself is not logged, but the API calls made with it are. Alert on SA token use from an IP that has never used that SA before, or from a Cloud Run/Cloud Functions IP range when the SA is not a Cloud Run SA.
- **SSH key injection** - `compute.projects.setCommonInstanceMetadata` or `compute.instances.setMetadata` with a new `ssh-keys` value. These are always logged and rarely legitimate outside Terraform.
- **Startup script injection** - `compute.projects.setCommonInstanceMetadata` with a new `startup-script` value. Same detection as SSH key injection.
- **Bucket takeover** - `storage.buckets.delete` followed by a new bucket with the same name in a different project. Alert on bucket deletion in production projects.
- **Signed URL replay** - no direct signal, but a spike in `storage.objects.get` from a single IP or user agent is a signal. Correlate with signed URL issuance logs if you generate your own signed URLs.

## 5. Post-Exploitation (Defensive View)

**What an attacker does after initial access:**
- Creates new SAs with broad roles (persistence)
- Creates new SA keys on existing SAs (persistence)
- Adds external principals to IAM policies (persistence)
- Exfiltrates data from Cloud Storage, BigQuery, Cloud SQL
- Deletes logs or sinks to cover tracks

**Detection for each:**
- **New SAs** - `google.iam.admin.v1.CreateServiceAccount` with `roles/owner` or `roles/editor` bound within minutes. Alert on any new SA with a broad role.
- **New SA keys** - `google.iam.admin.v1.CreateServiceAccountKey` on a production SA. Alert on every occurrence.
- **External principals** - `SetIamPolicy` adding `user:*@gmail.com`, `group:*`, or a principal from a project outside your org. Alert on every occurrence.
- **Data exfiltration** - Data access logs show unusual read volume. Correlate with VPC Flow Logs for egress to unfamiliar IPs.
- **Log deletion** - `logging.sinks.delete` and `logging.logs.delete` are Admin Activity. Alert on every occurrence in production.
- **SIEM integration** - export Admin Activity and Data Access logs to a SIEM (Chronicle, Splunk, Elastic) with longer retention than the default 400 days.

## 6. Preventive Controls

### 6.1 Organization-level baseline

These policies apply to every project in the org and should be enforced from day one:

```text
constraints/iam.disableServiceAccountKeyCreation         = enforced
constraints/iam.allowedPolicyMemberDomains               = enforced (to your domain)
constraints/storage.publicAccessPrevention               = enforced
constraints/storage.uniformBucketLevelAccess             = enforced
constraints/compute.requireOsLogin                       = enforced
constraints/compute.vmExternalIpAccess                   = enforced (to a specific tag)
constraints/compute.skipDefaultNetworkCreation           = enforced
constraints/iam.automaticIamGrantsForDefaultServiceAccounts = enforced (to a no-op)
```

A project that cannot override these policies is a project whose blast radius is bounded even if its own IAM is misconfigured.

### 6.2 Project-level baseline

- **No default service accounts** - disable or delete the default Compute Engine and App Engine SAs. Create dedicated SAs per workload.
- **No `roles/editor` or `roles/owner` on SAs** - use predefined service-scoped roles or custom roles.
- **No user-managed keys on production SAs** - use Workload Identity Federation.
- **VPC Service Controls perimeters** - wrap production projects in a perimeter that includes Cloud Storage, BigQuery, and Secret Manager.
- **Log sinks in a separate project** - Admin Activity and Data Access logs sink to a dedicated logging project that production SAs cannot modify.

### 6.3 Resource-level baseline

- **Buckets** - `uniformBucketLevelAccess=true`, `publicAccessPrevention=enforced`, CMEK for sensitive data, object versioning and soft delete enabled.
- **Compute** - `--no-service-account --no-scopes` on non-API workloads, OS Login enforced, external IPs restricted.
- **Cloud Run / Cloud Functions** - no `allUsers` invocation, ingress restricted to internal or load balancer, secrets from Secret Manager not environment variables.
- **Secret Manager** - CMEK, automatic rotation, IAM bindings scoped to specific secrets not project-wide.

## 7. Detection Controls

### 7.1 Log sources to enable

- **Cloud Audit Logs** - Admin Activity is always on; enable Data Access for Cloud Storage, BigQuery, Secret Manager, and Cloud SQL on production projects.
- **VPC Flow Logs** - enable on every VPC, sample rate 100% for production. Detect egress to unfamiliar IPs, traffic to the metadata server from non-metadata processes, and lateral movement between subnets.
- **Cloud IDS** - managed IDS/IPS for GCP traffic, if budget allows. Complements VPC Flow Logs with payload inspection.
- **Cloud Armor** - request logs from the load balancer. Detect probing, SSRF from internal services, and credential stuffing.
- **Security Command Center** - Premium tier for the full set of detectors: public buckets, exposed services, misconfigured IAM, vulnerable images.
- **Google Workspace logs** - if you use Google Workspace, the admin audit log is a source for compromised admin accounts.

### 7.2 High-fidelity alert rules

```text
1. Any CreateServiceAccountKey on a production SA
2. Any SetIamPolicy adding a principal outside your domain
3. Any setCommonInstanceMetadata changing ssh-keys or startup-script
4. Any new SA with roles/owner or roles/editor bound within 5 minutes
5. Any DeleteBucket in a production project
6. Any logging.sinks.delete or logging.logs.delete in production
7. Any storage.objects.get from an IP that has never accessed the bucket
8. Any SA token use from a Cloud Run/Cloud Functions IP when the SA is not a Cloud Run SA
9. Any compute.instances.setServiceAccount changing the SA to a more privileged one
10. Any organization policy override in a project
```

These ten rules catch the majority of real GCP compromises. They are ordered roughly by signal-to-noise ratio: #1 and #2 are the highest fidelity.

## 8. Verification

To verify that the defensive baseline is in place across the org:

```bash
# 1. Organization policies
for c in iam.disableServiceAccountKeyCreation iam.allowedPolicyMemberDomains storage.publicAccessPrevention storage.uniformBucketLevelAccess compute.requireOsLogin; do
  gcloud resource-manager org-policies describe constraints/$c --organization=<ORG_ID> 2>/dev/null || echo "NOT SET: $c"
done

# 2. Log sinks
gcloud logging sinks list --organization=<ORG_ID>
gcloud logging sinks list --project=<PROJECT_ID>

# 3. Security Command Center sources
gcloud scc sources list --organization=<ORG_ID>

# 4. Buckets without uniform access or public access prevention
gcloud asset search-all-resources --asset-types=storage.googleapis.com/Bucket --format="table(name,additionalAttributes.iamConfiguration.uniformBucketLevelAccess.enabled,additionalAttributes.iamConfiguration.publicAccessPrevention)"
```

Expected: every org policy enforced; at least one sink at the org level and one per production project; SCC sources listed; every bucket shows `True` and `enforced`.

## 9. Cloud-Specific Considerations

- **Admin Activity logs are immutable at the API level** - but a project owner can delete the sink, so the sink must live in a separate project.
- **Data Access logs cost money** - the cost scales with the number of objects read. Enable them only on sensitive buckets, or use VPC Service Controls to bound the data that can be exfiltrated.
- **Security Command Center findings are per-project** - aggregate them at the org level. A finding in a dev project may be noise, but the same finding in a prod project is an incident.
- **Cloud Audit Logs retention is 400 days by default** - an attacker who operates within a 400-day window can hide in the default retention if logs are not exported. Export to BigQuery for longer retention.
- **Organization policies are inherited** - a policy set at the org level cannot be overridden by a project unless the policy itself allows overrides. Verify that no project has an override.
- **Workload Identity Federation trust policies are IAM** - a trust policy that accepts any GitHub repo in the org is equivalent to granting the SA to every repo. Audit WIF configurations like IAM.
- **VPC Service Controls is the only network-layer control on GCP APIs** - it prevents data exfiltration even with a valid token. It is the strongest single control for a cloud environment.

## 10. Production Notes

- Enforce the org-level baseline from day one. Every day without it is a day where a project can create a public bucket or a permanent SA key.
- Export Admin Activity and Data Access logs to a separate project before you need them. An attacker who deletes logs is gone before you notice.
- Automate the ten high-fidelity alert rules as code (Terraform, Cloud Monitoring alerting policies). Manual SIEM rules drift.
- Test the incident response plan annually with a tabletop exercise: "a service account key was committed to a public GitHub repo, what do we do?" The answer must not be "we need to figure out who owns that SA".
- Rotate SA keys every 90 days if keys must exist. Set a calendar reminder; there is no built-in auto-rotation.
- Review WIF configurations quarterly. Trust policies are IAM and drift silently.
- Use Cloud Asset Inventory to inventory IAM bindings, buckets, and compute resources across the org, and diff the inventory weekly.

## 11. References

- Google Cloud security best practices - https://cloud.google.com/security/best-practices
- Security Command Center - https://cloud.google.com/security-command-center
- Cloud Audit Logs - https://cloud.google.com/logging/docs/audit
- Organization policy constraints - https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- VPC Service Controls - https://cloud.google.com/vpc-service-controls/docs/overview
- Cloud Asset Inventory - https://cloud.google.com/asset-inventory/docs/overview
- Workload Identity Federation - https://cloud.google.com/iam/docs/workload-identity-federation
- MITRE ATT&CK Cloud Matrix - https://attack.mitre.org/matrices/enterprise/cloud/

## Certification Alignment

- **Google Cloud Professional Cloud Security Engineer** - organization policy design, IAM hardening, VPC Service Controls, audit logging, incident response.
- **Google Cloud Associate Cloud Engineer** - day-to-day IAM and bucket hygiene, log inspection.
- **Google Cloud Professional Cloud Architect** - org and folder design, cross-project logging architecture, WIF design.
- **CompTIA Security+** - defense in depth, monitoring, incident response, least privilege.
