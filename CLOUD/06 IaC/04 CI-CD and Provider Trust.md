# CI/CD and Provider Trust

Reference for the trust relationship between the CI/CD pipeline and the cloud provider. The pipeline holds the credentials that create infrastructure. Compromise of the pipeline is compromise of the account.

## 1. Overview

In an IaC pipeline, the cloud provider credential is the highest-value asset. It creates, modifies, and deletes every resource the pipeline manages. The credential can be a static access key, an assumed role, a managed identity, a service account, or a short-lived OIDC token.

The trust relationship has three parts:

- **Who runs the pipeline.** The CI runner, the CI identity, the job workflow file.
- **What the pipeline can do.** The IAM role, its permission boundary, the resources it can touch.
- **How the credential is issued.** Static key in CI secrets, OIDC federation, or a self-hosted token issuer.

Every part is an attack surface. The pipeline is the primary target for an attacker who wants to create persistent infrastructure.

## 2. Reconnaissance / Enumeration

### Offensive

- **Repository contents.** Workflow files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`) reveal the CI provider, the runner type, the secrets referenced, and the AWS/Azure/GCP role assumed.
- **Job logs.** Build logs sometimes print the assumed role ARN, the account ID, or even the OIDC token claims.
- **CI runner public information.** GitHub-hosted runners have well-known IP ranges. Self-hosted runners have different exposures: the runner registration token, the runner group, the label.
- **OIDC configuration.** AWS `sts:AssumeRoleWithWebIdentity`, Azure federated credentials, GCP workload identity federation. Misconfiguration (wrong `sub` claim, wrong audience, wildcard repo match) allows any repository to assume the role.
- **Static secrets in CI settings.** Secrets set in the CI UI are encrypted but readable by anyone with admin access to the repository or organization. A compromised admin account reads them.
- **Third-party actions and plugins.** Marketplace actions that run in the same job environment have access to the same secrets as the job.
- **Self-hosted runner exposure.** A self-hosted runner is often a long-lived VM with persistent credentials, network access to internal resources, and no sandbox.

### Defensive

- Inventory every pipeline, every credential source, and every role assumed.
- Confirm OIDC federation is used instead of static keys.
- Confirm the OIDC trust policy is scoped to a specific repository, branch, and workflow.
- Confirm third-party actions are pinned to a commit SHA, not a tag.
- Confirm self-hosted runners are ephemeral, isolated, and not used for public repositories.

## 3. Common Attack Vectors

- **OIDC trust policy too broad.** `sub: repo:org/*` allows any repository in the org to assume the role. `sub: repo:org/repo:*` allows any branch or tag. `sub: repo:org/repo:ref:refs/heads/*` allows any branch.
- **OIDC without audience validation.** The provider accepts tokens from any audience. A token issued to a different service is accepted by the role.
- **Static credentials in CI.** Long-lived access keys in CI secrets. Compromise of the CI account is compromise of the key.
- **Third-party action compromise.** A marketplace action is updated by its author. A tag rewrite serves attacker content. The action runs with the job's credentials.
- **Self-hosted runner exposure.** A self-hosted runner on a public repository is accessible to any contributor via a PR. `pull_request_target` and `workflow_run` triggers give attacker code access to the runner.
- **Pipeline file modification.** A PR that modifies `.github/workflows/*.yml` runs on the CI with the same credentials as any other PR.
- **Environment protection bypass.** GitHub environments with required reviewers; a PR that runs a job without the environment requirement bypasses review.
- **Secret exfiltration via error.** A failing job prints an error that includes the environment variable value. Logs are accessible.

## 4. Exploitation Recipes

### 4.1 PR-triggered workflow with write token

A repository that runs a workflow on `pull_request_target` and checks out the PR branch is a classic target. The workflow has a write-scoped `GITHUB_TOKEN` and any secrets the workflow declares.

```yaml
# Vulnerable workflow
name: PR build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
```

`npm install` runs arbitrary code from the PR. The code has access to the workflow's secrets and the `GITHUB_TOKEN`.

### 4.2 Third-party action compromise

```yaml
- uses: some-org/some-action@v1   # tag, mutable
```

The author of `some-action` can rewrite `v1` to point at attacker code. The next pipeline run executes the attacker code with the job's credentials. Fix: pin to a full commit SHA: `uses: some-org/some-action@<40-char-sha>`.

### 4.3 OIDC trust policy abuse

```json
// Vulnerable AWS trust policy
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:my-org/*"
    }
  }
}
```

Any repository in `my-org` assumes the role. A contributor who creates a new repository in the org (or a compromised repository) inherits the role.

### 4.4 Environment protection bypass

```yaml
# Job that requires an environment with reviewers:
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps: [...]
```

If the workflow also has a job that does not require the environment, that job runs with the same credentials (because the OIDC trust policy is at the repository level, not the environment level). Fix: scope the OIDC trust policy to the environment claim: `repo:org/repo:environment:production`.

### 4.5 Self-hosted runner persistence

A self-hosted runner on a public repository is compromised by any PR. The attacker installs a persistence mechanism in the runner's work directory, which is reused across jobs. Every subsequent job runs attacker code.

### 4.6 Secret exfiltration via error message

A workflow that references a secret in a shell command prints the secret on error:

```yaml
- run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com/endpoint
```

If the endpoint returns an error, the command echo includes the token in the log (depending on shell settings). Fix: use `set +x` (default on non-interactive shells) and pass the secret via an environment variable that is masked in the log:

```yaml
- env:
    TOKEN: ${{ secrets.API_TOKEN }}
  run: curl -H "Authorization: Bearer $TOKEN" https://api.example.com/endpoint
```

GitHub masks `$TOKEN` in the log if it was registered as a secret.

## 5. Post-Exploitation

- **Persist in the pipeline.** Modify the workflow file to add a step that runs on every push. Requires the ability to merge to the target branch.
- **Persist in the OIDC trust policy.** Modify the role's trust policy to add a wildcard `sub`. Requires IAM permissions.
- **Persist in the runner.** Self-hosted runner persistence survives across pipeline runs.
- **Lateral movement via the CI role.** The CI role is often broader than any individual engineer's role. Assume it, then assume other roles from there.
- **Exfiltrate through the pipeline.** The pipeline has outbound network access. Use it to send data to attacker infrastructure, disguised as a build artifact or a test report.

## 6. Preventive Controls

### Credentials
- **OIDC federation for cloud providers.** GitHub Actions, GitLab CI, Azure DevOps, CircleCI, and Buildkite all support OIDC to AWS, Azure, and GCP. No static keys.
- **Scoped trust policy.** `sub: repo:org/repo:ref:refs/heads/main` (specific branch) or `sub: repo:org/repo:environment:prod` (specific environment). Not `repo:org/*`.
- **Audience validation.** The provider validates the `aud` claim matches the expected CI audience.
- **Short-lived credentials.** Even OIDC tokens are short-lived. Do not embed them in artifacts or logs.

### Runner
- **Ephemeral runners.** GitHub-hosted, or self-hosted with auto-scaling that destroys the runner after each job.
- **No self-hosted runner for public repositories.** A public repository exposes the runner to any contributor.
- **Network isolation.** The runner has no inbound network access. Outbound is restricted to the registries and the provider APIs.
- **Read-only filesystem** except for the workspace.

### Pipeline
- **Pin every action to a commit SHA.** Never to a tag. Never to a branch.
- **Minimal permissions on the workflow.** `permissions: contents: read` at the workflow level. Elevate per job.
- **Environment protection for production.** Required reviewers, deployment branches.
- **`pull_request_target` only with untrusted-content checks.** If you must use it, do not check out the PR branch and run arbitrary code. If you must, use a separate workflow with no secrets.
- **No secrets in PR workflows from forks.** GitHub does not expose secrets to PRs from forks by default. Do not override this.
- **Review workflow changes.** Any change to `.github/workflows/*.yml` requires review from a security champion.

### Secrets
- **Secret masking.** CI masks secrets in logs. Confirm by testing with a known value.
- **Secret scanning.** GitHub secret scanning, GitGuardian, trufflehog in CI.
- **No secrets in environment variables for third-party actions.** Pass secrets to the specific step that needs them via `env:`, not to the whole workflow.

## 7. Detection Controls

- **OIDC token usage.** CloudTrail `AssumeRoleWithWebIdentity`, Azure Entra sign-in logs, GCP `sts.googleapis.com` logs. Alert on tokens assumed from outside the expected repository/branch.
- **Static credential usage.** If static keys still exist, alert on any use from a new IP address or a new user-agent.
- **Pipeline file changes.** Any PR that modifies `.github/workflows/`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`.
- **Environment bypass.** Any run of a production-deploying job without the environment approval.
- **Third-party action version changes.** Any change to a `uses:` line.
- **Runner registration.** Any new self-hosted runner registration.
- **Outbound network from runner.** Unusual destinations, unusual ports.

## 8. Verification

- [ ] OIDC federation is used for every cloud provider credential.
- [ ] OIDC trust policy scoped to a specific repository, branch, and environment.
- [ ] No static credentials in CI secrets.
- [ ] Ephemeral runners for every job.
- [ ] No self-hosted runners on public repositories.
- [ ] Every third-party action pinned to a full commit SHA.
- [ ] Workflow `permissions` set to minimum.
- [ ] Environment protection on production deployments.
- [ ] Any change to workflow files requires review.
- [ ] Secret masking verified by test.
- [ ] Secret scanning enabled on the repository.
- [ ] CloudTrail / sign-in logs alert on OIDC token usage outside the expected source.

## 9. Certification Alignment

- **AWS Certified DevOps Engineer - Professional:** Domain 3 (Security and Compliance), Domain 4 (Monitoring and Logging).
- **AWS Certified Security - Specialty:** Domain 4 (Identity and Access Management).
- **Google Cloud Professional Cloud DevOps Engineer:** CI/CD security, workload identity federation.
- **Azure DevOps Engineer Expert (AZ-400):** pipeline security, federated credentials.
- **CompTIA Security+:** Domains 2-4.

## 10. Production Notes

- **GitHub Actions OIDC token claims.** `sub` includes repo, branch, environment. `aud` is `sts.amazonaws.com` for AWS. Scope by `sub`, not by `aud`.
- **`permissions: write-all` is a backdoor.** Any workflow with this permission that runs on a PR is a target. Minimum is `contents: read`.
- **`actions/checkout` is not the only attack surface.** Any action can be malicious. Pin all of them.
- **Self-hosted runner registration.** Requires a registration token. The token is scoped to a repository, organization, or enterprise. Rotate it, do not log it.
- **OIDC token caching.** Providers cache OIDC tokens briefly. An attacker who can read the token within its lifetime has the same access as the pipeline.
- **Audit trail.** Every OIDC assume-role is logged. Alert on assumptions from unexpected IP addresses, user agents, or repository/branch combinations.

## 11. References

- GitHub Actions OIDC for AWS - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- GitHub Actions security hardening - https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- GitHub Actions permissions - https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication
- GitLab CI OIDC for AWS - https://docs.gitlab.com/ee/ci/cloud_services/aws/
- Azure federated credentials - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- GCP Workload Identity Federation - https://cloud.google.com/iam/docs/workload-identity-federation
- OWASP CI/CD Security Top 10 - https://owasp.org/www-project-top-10-ci-cd-security-risks/
- SLSA - https://slsa.dev/
- Sigstore / Cosign - https://docs.sigstore.dev/
- OpenSSF Scorecard - https://github.com/ossf/scorecard
- NIST SP 800-204D - https://csrc.nist.gov/publications/detail/sp/800-204d/final