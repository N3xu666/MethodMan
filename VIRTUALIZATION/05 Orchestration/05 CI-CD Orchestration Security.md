# CI-CD Orchestration Security

CI/CD is the orchestration layer most teams forget to threat-model. A
pipeline has three things an attacker wants: a build environment with
secrets, a credential that can deploy, and a path to the cluster. When the
pipeline is compromised, the attacker gets all three without ever touching
the cluster's admission layer.

Modern CI/CD platforms are also orchestrators in their own right. GitHub
Actions, GitLab CI, Jenkins and Argo CD schedule jobs, inject secrets,
and call cloud and cluster APIs. The security model of the pipeline is the
security model of the deployment.

## 1. Overview

The CI/CD orchestration boundary has four components:

- **Source** - the Git repository and its access model (branches,
  protection rules, review requirements).
- **Runner** - the machine that executes the pipeline. Shared runners are
  hosted by the platform; self-hosted runners are part of the
  organization's infrastructure.
- **Secrets** - long-lived tokens, cloud IAM keys, or short-lived OIDC
  tokens exchanged at job runtime.
- **Deployment target** - the cluster or cloud account the pipeline
  deploys into.

A weakness in any one component collapses the others. A compromised
source pushes malicious code; a compromised runner reads every secret; a
compromised deployment credential deploys anything.

## 2. Reconnaissance / Enumeration

From a compromised repository or pipeline, the first step is to see what
credentials the pipeline already has:

```bash
# GitHub Actions: list workflow files and their secrets usage
grep -rE "secrets\\.[A-Z_]+" .github/workflows/
```

Expected output (trimmed):

```text
.github/workflows/deploy.yml:  token: ${{ secrets.KUBE_TOKEN }}
.github/workflows/deploy.yml:  key: ${{ secrets.AWS_KEY }}
```

From inside a running job, check for mounted cloud identity:

```bash
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

If that returns a token, the runner carries a cloud identity that the job
did not explicitly request.

## 3. Common Attack Vectors

- **Untrusted pipeline execution** - a workflow that checks out and runs
  code from a pull request from a fork, with access to secrets.
- **Runner hijacking** - a self-hosted runner with weak network isolation
  is a machine an attacker can use to read every secret the platform
  injects.
- **Long-lived deployment credentials** - a static `KUBECONFIG` or cloud
  IAM key stored in the CI/CD system; leakage grants permanent access.
- **Dependency confusion and typosquatting** - a malicious package that
  runs at install time inside the pipeline.
- **Manifest tampering** - a GitOps controller that applies any commit
  without review can be used to deploy attacker-controlled manifests.
- **Cache poisoning** - a pipeline cache shared between branches lets an
  untrusted branch poison a later trusted build.

## 4. Exploitation Recipes

A classic example: a PR workflow that runs untrusted code with secrets
available.

```yaml
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm run build
      - run: echo "${{ secrets.KUBE_TOKEN }}" | base64 -d > kubeconfig
      - run: kubectl apply -f k8s/
```

A malicious PR can replace `package.json`'s `preinstall` script with a
command that exfiltrates the token before the legitimate build runs.

A second path: a self-hosted runner with a persistent workspace. A
compromised repository can write to the workspace, and a later trusted
job picks up the attacker's files.

## 5. Post-Exploitation

Once inside the CI/CD system:

- Exfiltrate every secret in the platform, not just the current job's.
- Create a workflow that runs on a schedule and re-deploys the payload.
- Modify branch protection to allow direct pushes to main.
- Add a new self-hosted runner that calls back to the attacker, giving a
  persistent foothold inside the organization's network.
- Push a malicious image into the internal registry that downstream
  clusters pull automatically.

The last item matters most: a CI/CD compromise that pushes a trusted
image is a supply chain compromise that bypasses every image policy in the
cluster.

## 6. Risk Context (Offensive)

CI/CD is the highest-privilege, least-monitored system in most
organizations. It holds deployment credentials for every environment, runs
code from every contributor, and is accessed by a small group of engineers
who often have broad permissions.

Realistic paths:

- PR from fork -> pipeline executes untrusted code -> secret exfiltration.
- Compromised contributor account -> pipeline pushes to main -> deploy.
- Self-hosted runner -> network pivot -> cluster.
- Malicious dependency -> install-time script -> token theft.

## 7. Root Causes (Defensive)

- Secrets are long-lived because rotating them is painful.
- Pipelines run untrusted code because the build script is "just a test".
- Self-hosted runners are treated as build machines, not as
  high-privilege infrastructure.
- Branch protection is a social agreement, not an enforced control.
- GitOps applies any commit that reaches the tracked branch.

## 8. Preventive Controls (Defensive)

- Use OIDC federation between the CI platform and the cloud or cluster;
  never store long-lived cloud keys.
- Separate workflows for untrusted PRs (no secrets) and trusted pushes
  (secrets allowed, protected branch required).
- Run untrusted code only on ephemeral, isolated runners.
- Protect the default branch with required reviews and signed commits.
- Use a GitOps controller that requires a reviewed pull request, not a
  direct commit.
- Pin third-party actions and container images to a full commit SHA.
- Require provenance attestations on every image pushed to the registry.

## 9. Detection Controls (Defensive)

- Alert on new workflow files, modified branch protection, and new
  self-hosted runners.
- Alert on any workflow that reads a secret and then runs an
  externally-sourced script.
- Detect image pushes from unexpected workflows or unexpected source
  repositories.
- Monitor the cloud audit log for token exchanges from IP ranges not
  owned by the CI platform.
- Detect sudden changes to the GitOps tracked branch outside of the
  normal review process.

## 10. Verification (Defensive)

- Confirm no workflow triggers on `pull_request_target` with a checkout
  of the PR head and access to secrets.
- Confirm deployment credentials are OIDC-exchanged and short-lived.
- Confirm branch protection requires review and signed commits.
- Confirm the GitOps controller only reconciles from a protected branch
  and rejects unsigned commits.
- Confirm image provenance attestations are required by admission.

## Certification Alignment

- **CKS** - supply chain security, runtime security, cluster hardening.
- **GitHub Actions Certification** - workflow security, secrets
  management, OIDC.
- **AWS Certified Security - Specialty** - IAM roles, OIDC federation,
  audit logging.

## References

- GitHub Actions security hardening - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- GitHub OIDC for cloud deployments - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- SLSA supply chain framework - https://slsa.dev/
- Sigstore and cosign - https://docs.sigstore.dev/
- NIST SP 800-204D, Strategies for the Integration of Software Supply Chain Security in DevSecOps CI/CD Pipelines - https://csrc.nist.gov/pubs/sp/800/204/d/final