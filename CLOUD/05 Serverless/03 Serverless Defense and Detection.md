# Serverless Defense and Detection

Defensive controls and detection engineering for serverless workloads across AWS, Azure and GCP. This file is the blue-team counterpart to the attack files in this subcategory.

## 1. Overview

Serverless defense rests on three pillars: least privilege on the execution identity, input validation at the event boundary, and observability that survives the short-lived execution model. The provider handles the OS, the hypervisor and the runtime; the operator owns the function code, its configuration, its identity, and its integration with the rest of the cloud account.

Threats to defend against:

- execution-role abuse (over-privileged role, SSRF to IMDS)
- event injection (S3 key, SQS body, Pub/Sub message, HTTP parameter)
- supply chain (layer substitution, dependency confusion, backdoored image)
- persistence (event source mapping, alias swap, scheduled job)
- exfiltration (function role reads storage, function outbound used as a proxy)

## 2. Reconnaissance / Enumeration

### Defensive

Before defending, inventory what exists. Inventory is the first defense because unknown functions are unmonitored functions.

- Enumerate every function across all regions (functions can be deployed to multiple regions).
- For each function, record: runtime, execution role / managed identity / service account, event sources, VPC configuration, environment variables, layers / bundles, and public endpoints.
- Enumerate the IAM policies attached to each function role and resolve them through the assume-role chain.
- Enumerate event source mappings and identify cross-account and public triggers.
- Enumerate container images and layers by digest, not tag.

### Offensive

An attacker would perform the same inventory using a low-privilege cloud credential. Assume any credential in the account can list functions. Do not rely on the "obscurity" of function names.

## 3. Common Attack Vectors

- **Execution-role abuse.** The dominant risk. A role with `*` action or `*` resource turns any function code execution into full account access.
- **Event injection.** Untrusted data reaching a shell, a query, a template, a deserializer, or a URL fetch.
- **SSRF to the metadata service.** A fetch primitive inside a function that accepts user URLs.
- **Supply chain compromise.** A dependency pulled at cold start, a layer updated by a compromised CI, a base image pulled by tag.
- **Persistence via trigger.** A new event source mapping, a scheduled job, or a new subscription that invokes an attacker-controlled function.
- **Credential leakage.** Secrets in environment variables, secrets in logs, secrets in error traces.
- **Lateral movement via the function role.** The function role is often broader than the user role; it is the pivot.

## 4. Exploitation Recipes

### Defensive: reproducing the attack to validate controls

Detection engineering benefits from a controlled reproduction. In an authorized lab environment, reproduce each attack from the attack files and verify the detection fires.

Example: SSRF to IMDS in a Lambda.

```bash
# Authorized lab only. Deploy a test Lambda with an SSRF primitive.
$ curl "https://<test-lambda-url>/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Expected result: the request succeeds (function code fetches IMDS). This is the failure of the control. Then verify:

- GuardDuty Lambda Protection raises `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` or `CredentialAccess:IAMUser/AnomalousBehavior`.
- VPC Flow Logs show outbound traffic from the function subnet to `169.254.169.254` (visible only when the function is VPC-attached).
- CloudTrail shows the role being used from an external IP address.

Example: event injection via S3 key.

```bash
$ aws s3 cp payload.sh "s3://<test-bucket>/a;id;#"
```

Expected: the command runs in the function. Detection: CloudWatch Logs contain the `id` output that was never expected by the handler.

### Defensive: coverage of every attack in file 02

Each attack in `02 Lambda and Cloud Functions Attacks.md` maps to one or more detections below. Use this list as a control coverage checklist:

| Attack | Detection |
|--------|-----------|
| SSRF to IMDS | GuardDuty Lambda Protection, VPC Flow Logs, CloudTrail anomalous role usage |
| Event injection (S3 key) | Function application logs (shell escape patterns), unusual S3 GetObject patterns |
| Event injection (SQS / Pub/Sub) | Message content audit, application logs |
| Layer substitution | CloudTrail `lambda:PublishLayerVersion`, `lambda:UpdateFunctionConfiguration` |
| App settings exfiltration | Azure Activity Log `Microsoft.Web/sites/config/list/action` from unusual IPs |
| Function key leakage | HTTP 4xx on unauthenticated endpoint followed by 200 on authenticated, function key rotation |
| SA key creation | Cloud Audit Logs `google.iam.admin.v1.CreateServiceAccountKey` |
| Pub/Sub message injection | Pub/Sub audit logs, application logs |
| Dependency confusion | Build log diff of resolved package versions, private registry mismatch |

## 5. Post-Exploitation

### Defensive: what an attacker does after code execution

Post-exploitation in serverless is short-lived. The function runs for seconds to minutes. The attacker's goal is to persist, pivot, or exfiltrate. Detection must cover:

- **New event source mapping.** Any `lambda:CreateEventSourceMapping` outside deployment windows is suspicious.
- **Alias swap.** Any `lambda:UpdateAlias` to a new version outside CI/CD is suspicious.
- **New scheduled job.** CloudWatch Events, Azure Timer, Cloud Scheduler - all can invoke a function on a schedule.
- **New subscription.** Pub/Sub subscription, SNS subscription, EventBridge rule.
- **New IAM role or attached policy.** Any `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:CreateRole` outside deployment windows.
- **New service account key.** Any `iam.serviceAccountKeys.create` outside deployment windows.
- **New storage bucket policy.** Any `s3:PutBucketPolicy`, `Microsoft.Storage/storageAccounts/blobServices/containers/write`, `storage.buckets.setIamPolicy`.

## 6. Preventive Controls

### Identity and access
- Least-privilege execution role per function. No `*` action, no `*` resource.
- Permission boundary on every function role.
- No `iam:PassRole` to broad roles from function roles.
- No `sts:AssumeRole` to `*` from function roles.
- Organization policy denying service-account-key creation on default compute accounts (GCP).
- No Contributor / Owner managed identities on subscriptions (Azure).

### Code and configuration
- Typed schemas for event payloads. Reject unexpected fields.
- No `eval`, no `os.system`, no `subprocess` with user input, no template rendering with user input.
- Secrets from a secret manager, never from env vars.
- Function keys and app settings rotated on a schedule.
- Dependency pinning with lockfiles. Private registry with scoped tokens.
- Signed layers and container images. Deploy by digest, not tag.

### Network
- VPC-attached functions with egress restricted to needed destinations.
- No IMDS access from user-supplied fetchers (where the platform allows blocking).
- Private endpoints for managed services (S3 gateway, Azure private link, Private Service Connect).

### Deployment pipeline
- Deployment IAM role scoped to specific functions and specific code versions.
- Manual approval for `UpdateFunctionCode` on production.
- Separate accounts for dev, staging, production.

## 7. Detection Controls

### AWS
- GuardDuty with Lambda Protection enabled.
- CloudTrail with all management events and S3 data events on sensitive buckets.
- CloudWatch Logs Insights queries for shell escape patterns:
  ```
  fields @timestamp, @message
  | filter @message like /(\;|\||\$\(|\`|\&\&)/
  | sort @timestamp desc
  ```
- VPC Flow Logs for function subnet.
- Security Hub with the AWS Foundational Security Best Practices standard.

### Azure
- Defender for Cloud with serverless protection enabled.
- Activity Log with all `Microsoft.Web/*` and `Microsoft.ManagedIdentity/*` events retained for 90+ days.
- Azure Monitor Workbooks for Function App anomalies (invocation count, duration, egress).
- Network Security Group Flow Logs for the Function App integration subnet.

### GCP
- Event Threat Detection enabled.
- Cloud Audit Logs with `Admin Activity` and `Data Access` for Cloud Functions and Cloud Run.
- Cloud Logging sinks to a central project for retention.
- VPC Flow Logs on the serverless VPC connector subnet.

### Cross-platform
- Honey functions: deploy a function with a suspicious name (`lambda-admin`, `backup-runner`) and no legitimate caller. Any invocation is an indicator.
- Cost anomaly detection: sudden cost spikes from function invocations indicate cryptomining or exfiltration.
- Invocation anomalies: concurrency, duration, cold start count outside the baseline.

## 8. Verification

- [ ] Every function role has a least-privilege policy with no `*` action.
- [ ] Permission boundaries attached to every function role.
- [ ] No long-lived secrets in env vars or app settings.
- [ ] Function URLs require authentication.
- [ ] Event source mappings point to same-account resources with explicit policies.
- [ ] Layers and container images deployed by digest.
- [ ] GuardDuty Lambda Protection / Defender for Cloud serverless / Event Threat Detection enabled.
- [ ] CloudTrail / Activity Log / Cloud Audit Logs retained for 90+ days.
- [ ] Honey function deployed and monitored.
- [ ] Cost anomaly alerting configured.
- [ ] Manual approval gate in CI/CD for `UpdateFunctionCode` on production.
- [ ] Incident response runbook for serverless compromise tested in the last 6 months.

## 9. Certification Alignment

- **AWS Certified Security - Specialty:** Domain 1 (Incident Response), Domain 2 (Logging and Monitoring), Domain 4 (Identity and Access Management).
- **AWS Certified Solutions Architect - Associate:** Domain 2 (Resilience), Domain 4 (Cost-Optimized).
- **Google Cloud Professional Cloud Security Engineer:** Section 3 (Configure access), Section 4 (Secure data), Section 6 (Detect).
- **Azure Security Engineer Associate (AZ-500):** Platform protection, security operations.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **Function roles rotate every hour.** Detection must look at the role usage from unusual IPs, not at the credentials themselves.
- **CloudTrail for Lambda:** not every Lambda API is logged by default. Enable `Management events` for Lambda and `Data events` for S3 buckets that trigger functions.
- **Log retention cost.** CloudWatch Logs costs grow linearly with retention. Set 90-180 days for functions that handle sensitive data; 14-30 days for the rest.
- **Cost anomaly as a security signal.** In serverless, cost spikes are often the first indicator of abuse.
- **Incident response playbook.** Freeze the function (`lambda:PutFunctionConcurrency` to 0), rotate the role, snapshot the deployment package, then investigate logs.

## 11. References

- AWS GuardDuty Lambda Protection - https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html
- AWS Security Hub Foundational Security Best Practices - https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp.html
- Azure Defender for Cloud serverless protection - https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
- Azure Functions security concepts - https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- Google Cloud Event Threat Detection - https://cloud.google.com/security-command-center/docs/event-threat-detection
- Google Cloud Audit Logs - https://cloud.google.com/logging/docs/audit
- OWASP Serverless Top 10 - https://owasp.org/www-project-serverless-top-10/
- NIST SP 800-204A - https://csrc.nist.gov/publications/detail/sp/800-204a/final
- NIST SP 800-61r3 (Incident Handling) - https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final