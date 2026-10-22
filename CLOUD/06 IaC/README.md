# 06 IaC

Infrastructure as Code (IaC) security reference: Terraform, CloudFormation, Pulumi, Helm and Kubernetes manifests as attack surface and as defensive control.

## Scope

This subcategory covers the security of the tools that provision cloud infrastructure:

- state files and plan artifacts (secret leakage, tampering)
- provider authentication and CI/CD trust
- modules, registries and supply chain
- misconfiguration patterns that produce exploitable infrastructure
- drift detection and policy as code

It does NOT repeat cloud service attacks (covered in 01 AWS, 02 Azure, 03 GCP) or Kubernetes internals (covered in 04 Kubernetes-Cloud). This is about how the infrastructure is described, generated, and applied.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [IaC Fundamentals](./01%20IaC%20Fundamentals.md) | Two-track |
| 02 | [State Files and Plan Artifacts](./02%20State%20Files%20and%20Plan%20Artifacts.md) | Two-track |
| 03 | [Modules and Supply Chain](./03%20Modules%20and%20Supply%20Chain.md) | Two-track |
| 04 | [CI/CD and Provider Trust](./04%20CI-CD%20and%20Provider%20Trust.md) | Two-track |
| 05 | [Misconfiguration Patterns and Policy as Code](./05%20Misconfiguration%20Patterns%20and%20Policy%20as%20Code.md) | Two-track |

## Format

Two-track (Offensive / Defensive). 11 sections:

```
## 1. Overview
## 2. Reconnaissance / Enumeration
## 3. Common Attack Vectors
## 4. Exploitation Recipes
## 5. Post-Exploitation
## 6. Preventive Controls
## 7. Detection Controls
## 8. Verification
## 9. Certification Alignment
## 10. Production Notes
## 11. References
```

## Certification Alignment

- HashiCorp Certified: Terraform Associate
- AWS Certified DevOps Engineer - Professional
- AWS Certified Security - Specialty
- Google Cloud Professional Cloud DevOps Engineer
- Azure DevOps Engineer Expert (AZ-400)
- CompTIA Security+

## Related

- 01 AWS
- 02 Azure
- 03 GCP
- 04 Kubernetes-Cloud
- 05 Serverless
- DEVSECOPS (planned category, supply chain and CI/CD)

## Authorized Use Only

> [!CAUTION]
> All techniques in this subcategory are for authorized security testing, CTF environments and educational purposes only. Testing cloud accounts or CI/CD pipelines without written authorization violates the provider terms of service and may be illegal.

## References

- Terraform security best practices - https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices
- Terraform state security - https://developer.hashicorp.com/terraform/language/state/sensitive-data
- AWS CloudFormation security best practices - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/security-best-practices.html
- Pulumi security - https://www.pulumi.com/docs/using-pulumi/crossguard/
- Open Policy Agent - https://www.openpolicyagent.org/docs/latest/
- Checkov - https://www.checkov.io/
- tfsec / Trivy - https://trivy.dev/
- NIST SP 800-204D (Securing the Software Supply Chain) - https://csrc.nist.gov/publications/detail/sp/800-204d/final
- CIS Benchmarks for Terraform - https://www.cisecurity.org/benchmark/terraform