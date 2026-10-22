# Network Automation and Infrastructure as Code

## 1. Overview

Network automation replaces manual CLI configuration with programmatic, repeatable, version-controlled workflows. Infrastructure as Code (IaC) treats network configuration as source code: declared in files, reviewed, tested, and applied by a pipeline. The goals are consistency, auditability, speed and reduced human error.

Automation changes the threat model. The pipeline, the inventory, the credential store and the template renderer become attack surface. A compromised pipeline can push a malicious change to every device in the fabric in a single run.

This file covers the tooling, the security properties of each layer, and how to attack and defend automation stacks.

## 2. Threat Model

- **Pipeline compromise.** A malicious commit, PR or runner in CI/CD can apply arbitrary configuration to the entire fleet.
- **Credential theft.** Automation needs credentials to devices; stolen credentials grant broad access.
- **Inventory poisoning.** Corrupted inventory or source-of-truth data misdirects changes to attacker-controlled targets.
- **Template injection.** User-controlled data rendered into a Jinja2/Go template can execute code or leak secrets.
- **Supply chain.** Malicious Ansible collection, Python package, Terraform provider or container image in the pipeline.
- **Insider with merge rights.** Can bypass review and push a destructive change.

## 3. How It Works (technical)

Common tools:

- **Ansible** - agentless, YAML playbooks, SSH/NETCONF/REST to devices. Collections provide vendor modules.
- **Terraform / OpenTofu** - declarative IaC, providers for cloud and network appliances, state file is the source of truth.
- **Nornir** - Python framework for network automation, parallel execution, inventory plugins.
- **Netmiko / Scrapli** - SSH libraries for device interaction.
- **Napalm** - vendor-neutral abstraction over network OS.
- **Salt / Chef / Puppet** - general configuration management, sometimes used for network.
- **GitOps** - Git as the single source of truth; a controller (Argo CD, Flux) reconciles state from the repo.

Typical pipeline:

```text
developer -> git push -> CI (lint, test, render) -> approval -> CD (apply) -> devices
```

Key components:

- **Inventory / source of truth** - NetBox, Nautobot, Ansible inventory, Terraform state.
- **Templates** - Jinja2, Go templates, vendor-specific.
- **Secrets store** - Vault, AWS Secrets Manager, Azure Key Vault, sealed secrets.
- **Execution environment** - runner, container, bastion.

## 4. Installation and Setup

Ansible for network automation:

```bash
pip install ansible ansible.netcommon ansible.utils
ansible-galaxy collection install cisco.ios arista.eos
```

Terraform for cloud networking:

```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Nornir:

```bash
pip install nornir nornir_netmiko nornir_utils
```

NetBox as source of truth:

```bash
docker run -d --name netbox -p 8000:8080 netboxcommunity/netbox:latest
```

## 5. Hardening and Configuration

- **Pin every dependency.** Ansible collections, Python packages, Terraform providers, container images by digest. Unpinned dependencies are a supply-chain defect.
- **Signed commits and protected branches.** Merge to main only via reviewed PR; no direct pushes.
- **Secrets never in Git.** Use Vault or a cloud secrets manager; injected into the runner at execution time. Detect with gitleaks/trufflehog in CI.
- **Least-privilege device accounts.** Automation uses a dedicated account per environment, scoped to the commands it needs; not the admin account.
- **Dry-run before apply.** `--check` in Ansible, `plan` in Terraform, mandatory review of the diff.
- **Runner isolation.** CI runners are ephemeral, no persistent credentials, no shared home directory.
- **Approval gates for production.** Protected environment in GitHub Actions (or equivalent) with required reviewer.
- **Audit and drift detection.** Log every apply; compare running config with intended state continuously.

## 6. Operational Usage

- **Change:** branch, edit playbook/HCL, PR, review, merge, pipeline applies.
- **Rollback:** revert the commit; the pipeline re-applies the previous state.
- **Drift:** scheduled dry-run compares intended vs actual; deviations alert.
- **Inventory changes:** NetBox/Nautobot PR, reviewed, synced to the automation inventory.
- **Break-glass:** documented, logged manual access for emergencies, followed by a commit that reflects the change.

## 7. Common Mistakes

- Storing device passwords in `group_vars/` in plaintext.
- Running the pipeline with an admin account "because it is easier".
- Unpinned Ansible collections and Terraform providers.
- Using `--check` and then applying with `--no-check` without a diff review.
- Rendering user input into templates without sanitization.
- Treating the runner as a trusted host; storing tokens in its environment.
- No drift detection; the real configuration drifts from Git unnoticed.

## 8. Attacks Against It

- **Pipeline injection.** Malicious PR modifies `.github/workflows/*.yml` or Ansible playbook to exfiltrate secrets or push a backdoor config.
- **Template injection (Jinja2).** Attacker-controlled inventory variable rendered into a template executes `{{ config.items() }}` or environment lookups.
- **Terraform state exfiltration.** State file contains secrets; an S3 bucket with overly broad read is a gold mine.
- **Ansible collection hijack.** Malicious collection in the wild (e.g. a lookalike name) executes on the control node.
- **CI runner persistence.** Attacker plants a long-running process on a self-hosted runner.
- **Inventory poisoning.** Compromised NetBox lets the attacker redirect automation to a rogue device.

## 9. Detection (Blue Team)

- **Config-change audit on devices.** Syslog/TACACS+ accounting on every configuration push, correlated with the automation pipeline run ID.
- **Pipeline audit.** Alert on changes to `.github/workflows/`, Ansible `group_vars/`, Terraform state and providers.
- **Secret scanning.** Block commits that contain tokens; scan history weekly.
- **Out-of-band changes.** Detect device configuration changes not originating from the pipeline (manual CLI).
- **Runner anomalies.** New processes, network connections, or file writes on the runner.
- **Template rendering errors.** Unexpected Jinja2 syntax errors may indicate injection attempts.

## 10. Case Studies

- **Terraform state leaks.** Multiple incidents where `.tfstate` files were committed to public repos, exposing cloud credentials and network topology.
- **Ansible Galaxy typosquatting.** Malicious Ansible roles with names close to popular ones have been found hosting credential stealers.
- **GitHub Actions secret exfiltration.** Compromised actions (e.g. tj-actions/changed-files in 2025) exfiltrated environment secrets from thousands of repos.
- **CI runner compromise.** Self-hosted runners have been used as persistent footholds in enterprise environments.

## 11. Legal and Ethical Notes

Automation accounts often have broad, privileged access across the entire network. Testing automation stacks, tampering with CI pipelines, or exfiltrating state files is only legal with explicit written authorization. Lab environments (personal GitLab, GitHub test repos, Terraform with local state) are the right place to practice. Never commit real credentials or state files containing secrets, even to a private repository.

## 12. Production Notes

- **Everything through the pipeline.** Manual device configuration is a finding; it defeats the purpose of IaC.
- **State file security.** Terraform state is encrypted at rest and in transit; access is scoped per project.
- **Version everything.** Playbooks, inventory, templates, providers, and CI workflows are under version control.
- **Reconcile constantly.** Drift detection runs at least daily, alerts on any deviation.
- **Destroy safely.** `terraform destroy` requires the same approval gate as `apply`.
- **Recovery drills.** Rebuild a segment from code, without manual steps, at least quarterly.

## 13. Certification Alignment

- **CompTIA Network+** - network automation concepts, IaC principles.
- **Cisco CCNA** - automation and programmability, REST APIs, Ansible, YANG/NETCONF.
- **Cisco DEVASC** - Python, Ansible, IaC, CI/CD for network automation.
- **Cisco CCNP** - automation solutions (DNA Center, SD-WAN automation).
- **Cross-reference:** CLOUD category for Terraform and cloud IaC; DEVSECOPS category for CI/CD and supply-chain security.

## References

- Ansible Network Automation Documentation - https://docs.ansible.com/ansible/latest/network/
- Terraform Documentation - https://developer.hashicorp.com/terraform/docs
- Nornir Documentation - https://nornir.readthedocs.io/
- NetBox Documentation - https://docs.netbox.dev/
- NIST SP 800-204D - Strategies for the Integration of Software Supply Chain Security in DevSecOps CI/CD Pipelines - https://csrc.nist.gov/pubs/sp/800/204/d/final
- SLSA Framework - Supply-chain Levels for Software Artifacts - https://slsa.dev/
