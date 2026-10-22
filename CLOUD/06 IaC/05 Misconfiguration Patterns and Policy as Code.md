# Misconfiguration Patterns and Policy as Code

Reference for the misconfiguration classes that IaC consistently reintroduces, and the policy-as-code tooling that catches them before they reach production.

## 1. Overview

IaC does not create new vulnerability classes. It automates the ones operators already know, at scale. A single misconfigured module applied across ten environments produces ten identical exposures. The defensive answer is policy as code: encode the forbidden configurations as executable rules that the pipeline evaluates on every plan.

The recurring misconfiguration classes:

| Class | Example | Consequence |
|-------|---------|-------------|
| Network exposure | Security group `0.0.0.0/0` on SSH | Direct attack surface |
| Storage exposure | S3 bucket public-read | Data breach |
| Encryption disabled | RDS `storage_encrypted = false` | Compliance failure, data at rest exposed |
| Logging disabled | CloudTrail disabled | No forensic trail |
| Identity over-privilege | IAM policy `Action: "*"` | Blast radius |
| IMDSv1 | EC2 instance `metadata_options` default | SSRF to credentials |
| Public database | `publicly_accessible = true` on RDS | Direct database exposure |
| Versioning disabled | S3 bucket without versioning | Ransomware, accidental delete |
| MFA delete disabled | S3 bucket without MFA delete | State bucket vulnerability |
| Deletion protection off | RDS without `deletion_protection` | Accidental or malicious destroy |

Policy as code turns each of these into a rule. The rule runs in the pipeline. A plan that violates a rule does not apply.

## 2. Reconnaissance / Enumeration

### Offensive

- **Scan for policy files.** A repository with OPA/Rego, Checkov, tfsec, KICS, or Trivy configuration reveals what the org considers forbidden. A scan of the rules shows what is NOT covered.
- **Scan for exception markers.** `# checkov:skip=...`, `# tfsec:ignore:...`, `# trivy:ignore:...` in IaC files reveal exceptions. Each exception is a potential misconfiguration that the org decided to accept.
- **Scan for `depends_on`.** A resource that `depends_on` another resource is often added to bypass an ordering constraint. Sometimes used to bypass policy.
- **Scan for the resource types the policy does not cover.** A policy that covers `aws_security_group` but not `aws_security_group_rule` misses rules added separately.
- **Scan the module registry.** A public module that provisions a misconfigured resource is used by every pipeline that adopts it. Find the popular module, read the code, find the misconfiguration.
- **Scan the plan output for resource types outside the policy.** A `null_resource` with `local-exec` runs arbitrary code and is not covered by most policies.

### Defensive

- Inventory every policy rule across every pipeline.
- Confirm coverage of every resource type the org actually uses.
- Confirm exception markers have an expiry date and a linked ticket.
- Confirm the plan output is scanned, not just the source files. Plan is the ground truth.

## 3. Common Attack Vectors

- **Policy gaps.** The policy covers `aws_security_group` ingress but not `aws_security_group_rule` (a separate resource). A rule added via `aws_security_group_rule` bypasses the check.
- **Policy bypass via resource type.** The policy covers `aws_s3_bucket` but not `aws_s3_bucket_public_access_block`. A public bucket without the block is caught; a bucket with the block removed is not.
- **Policy bypass via provider aliases.** The policy checks the default provider but not `aws.west`, `aws.east`, etc.
- **Policy bypass via module.** A module that provisions a misconfigured resource is trusted. The policy checks the module's outputs, not its internals.
- **Policy bypass via plan-apply separation.** The policy runs on `plan.out` at plan time. If the plan is swapped before apply (see `02 State Files and Plan Artifacts.md`), the policy is bypassed.
- **Exception abuse.** An exception marker added without review expands over time. Each exception is a permanent bypass.
- **Policy drift.** The policy is updated for one resource type but not another. Over time, coverage gaps accumulate.
- **Policy disabled during incident.** During an incident, the policy is often disabled to allow a quick fix. If not re-enabled, it stays off.

## 4. Exploitation Recipes

### 4.1 Bypass via resource type

```hcl
# Policy checks aws_security_group but not aws_security_group_rule.
# The rule below opens SSH to the world without tripping the policy.

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.main.id
}
```

### 4.2 Bypass via provider alias

```hcl
# Policy checks the default provider. The resource is created in us-west-2
# via an aliased provider, which the policy does not inspect.

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}

resource "aws_instance" "west" {
  provider = aws.west
  # ...
}
```

### 4.3 Bypass via exception marker

```hcl
# checkov:skip=CKV_AWS_24:Legacy service, will be fixed in Q4 2099.
resource "aws_security_group_rule" "ssh" {
  # ...
}
```

The exception is never revisited. The rule remains open indefinitely.

### 4.4 Bypass via `null_resource` and `local-exec`

Most policies do not inspect `provisioner` blocks. A `null_resource` with `local-exec` runs arbitrary code on the runner, which can modify infrastructure outside the IaC pipeline, bypassing policy entirely.

```hcl
resource "null_resource" "post_apply" {
  provisioner "local-exec" {
    command = "aws iam attach-user-policy --user-name ci-deployer --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
  }
}
```

### 4.5 Bypass via module

A module that internally creates a misconfigured resource is trusted. The policy checks the module's inputs and outputs, not the resources it creates.

```hcl
module "storage" {
  source = "terraform-aws-modules/s3-bucket/aws"
  # Policy checks the module, but the module has been modified
  # in the private mirror to remove the public_access_block.
}
```

### 4.6 Disable the policy during an incident

A pipeline that allows disabling the policy via a variable is vulnerable. An attacker with write access to the pipeline sets the variable to `true` and merges a PR. The next apply runs without the policy.

## 5. Post-Exploitation

- **Persist via exception.** An exception marker in a common module is applied to every use of the module. Remove it? It comes back on the next module sync.
- **Persist via policy edit.** Modify the policy to exclude the resource type. Requires write access to the policy repository, but the change looks like maintenance.
- **Persist via pipeline variable.** Set a variable that disables policy on every run. Requires write access to the pipeline.
- **Lateral movement.** Once the misconfiguration exists, the attacker uses it as a foothold: public bucket for data access, open SSH for direct entry, IMDSv1 for credential access.
- **Covering tracks.** Policy bypass is silent. The pipeline reports success, the plan is applied, no alert fires.

## 6. Preventive Controls

### Policy as code
- **Every resource type covered.** The policy must cover every resource type the org uses, including the resource types that most policies ignore: `aws_security_group_rule`, `aws_s3_bucket_public_access_block`, `aws_iam_policy_attachment`, `null_resource`.
- **Plan output scanned, not source.** The policy runs on `terraform show -json plan.out`, not on the `.tf` files. Plan is the ground truth.
- **Provider alias coverage.** The policy checks every provider alias in the plan.
- **Module internals checked.** The policy sees the resources the module created, not the module's inputs.
- **Mandatory, not optional.** The pipeline fails if policy is not run. No `--soft-fail`.
- **Exceptions require review and expiry.** Every exception marker has an owner, a ticket, and an expiry date. Expired exceptions fail the pipeline.

### Tooling
- **OPA / Conftest.** General-purpose policy engine. Rego rules over plan JSON.
- **Checkov.** Pre-built rules for Terraform, CloudFormation, Kubernetes, Helm.
- **tfsec / Trivy.** Static analysis of Terraform.
- **Sentinel.** HashiCorp's policy engine, integrated with Terraform Cloud / Enterprise.
- **KICS.** Open source static analysis.
- **Cloud provider native.** AWS Config Rules, Azure Policy, GCP Organization Policy.

### Process
- **Policy repository under review.** Changes to the policy go through the same review as any code change.
- **Coverage tests.** Every policy rule has a positive test (the rule fires) and a negative test (the rule does not fire on valid config).
- **Regular policy review.** Quarterly review of exceptions and coverage.
- **Incident playbook.** A clear process for temporarily disabling the policy, with mandatory re-enablement.

## 7. Detection Controls

- **Policy bypass attempts.** Every plan that violates the policy is logged. A pattern of violations from one user or one repository is suspicious.
- **Exception marker changes.** Any PR that adds or modifies an exception marker triggers a review.
- **Policy rule changes.** Any change to the policy itself triggers a security review.
- **Plan-apply mismatch.** Compare the plan that was checked against the plan that was applied. A mismatch indicates tampering (see `02 State Files and Plan Artifacts.md`).
- **Resources created outside IaC.** Cloud provider audit logs. Any resource created outside the CI identity is drift.
- **Provider alias use.** Alert on aliases that are not in the approved list.
- **`null_resource` / `local-exec` presence.** Alert on any PR that adds one.

## 8. Verification

- [ ] Policy covers every resource type the org uses, including `aws_security_group_rule`, `aws_s3_bucket_public_access_block`, `aws_iam_policy_attachment`, `null_resource`.
- [ ] Policy runs on plan JSON, not on source `.tf`.
- [ ] Policy checks every provider alias.
- [ ] Policy fails the pipeline; no soft-fail.
- [ ] Exceptions have owner, ticket, expiry.
- [ ] Policy repository under review.
- [ ] Coverage tests exist for every rule.
- [ ] Resources created outside the CI identity are alerted.
- [ ] `null_resource` / `local-exec` PRs are reviewed.
- [ ] Plan-apply hash comparison in place.

## 9. Certification Alignment

- **HashiCorp Certified: Terraform Associate:** plan output, modules, providers.
- **AWS Certified DevOps Engineer - Professional:** Domain 3 (Security and Compliance).
- **AWS Certified Security - Specialty:** Domain 3 (Infrastructure Security).
- **Google Cloud Professional Cloud DevOps Engineer:** IaC and policy.
- **Azure DevOps Engineer Expert (AZ-400):** policy as code.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **Policy bypass via `local-exec` is the most underrated risk.** Most policies do not see provisioner blocks. Either forbid `local-exec` entirely or wrap it in a dedicated, reviewed resource type.
- **`null_resource` with `local-exec` is the IaC equivalent of `eval`.** It runs arbitrary code with the runner's credentials. Review every use.
- **Policy is a floor, not a ceiling.** A resource that passes policy is not necessarily secure. Policy catches known misconfigurations, not novel ones.
- **Exception markers are debt.** Every exception is a place where the policy does not apply. Track them, expire them, review them.
- **Plan-apply integrity.** Policy runs on the plan. If the plan is swapped before apply, policy is bypassed. Sign the plan, or run plan and apply in the same job.

## 11. References

- Open Policy Agent - https://www.openpolicyagent.org/docs/latest/
- Conftest - https://www.conftest.dev/
- Checkov - https://www.checkov.io/
- tfsec / Trivy - https://trivy.dev/
- KICS - https://www.kics.io/
- HashiCorp Sentinel - https://developer.hashicorp.com/sentinel
- AWS Config Rules - https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html
- Azure Policy - https://learn.microsoft.com/en-us/azure/governance/policy/overview
- GCP Organization Policy - https://cloud.google.com/resource-manager/docs/organization-policy/overview
- CIS Benchmarks for AWS, Azure, GCP - https://www.cisecurity.org/cis-benchmarks/
- NIST SP 800-204D - https://csrc.nist.gov/publications/detail/sp/800-204d/final