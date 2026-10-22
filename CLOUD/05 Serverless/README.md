# 05 Serverless

Serverless compute platforms (AWS Lambda, Azure Functions, Google Cloud Functions, Cloud Run, Container Apps) attack and defense reference.

## Scope

This subcategory covers the attack surface and defensive controls of function-as-a-service (FaaS) and container-based serverless platforms:

- identity and permission models (execution roles, managed identities, service accounts)
- event source integrations (API Gateway, S3, EventBridge, Pub/Sub, Storage triggers)
- code and dependency supply chain of deployed functions
- runtime isolation, network egress and metadata access
- logging, tracing and detection of serverless abuse

It does NOT repeat generic cloud identity attacks (covered in 01 AWS, 02 Azure, 03 GCP) or Kubernetes internals (covered in 04 Kubernetes-Cloud).

## Files

| # | File | Format |
|---|------|--------|
| 01 | Serverless Fundamentals | Two-track |
| 02 | Lambda and Cloud Functions Attacks | Two-track |
| 03 | Serverless Defense and Detection | Two-track |
| 04 | Container-Based Serverless | Two-track |

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

- AWS Certified Security - Specialty
- AWS Certified Solutions Architect - Associate
- Google Cloud Professional Cloud Security Engineer
- Azure Security Engineer Associate
- CompTIA Security+

## Related

- 01 AWS
- 02 Azure
- 03 GCP
- 04 Kubernetes-Cloud
- 06 IaC

## Authorized Use Only

> [!CAUTION]
> All techniques in this subcategory are for authorized security testing, CTF environments and educational purposes only. Testing cloud accounts without written authorization violates the provider terms of service and may be illegal.

## References

- OWASP Serverless Top 10 - https://owasp.org/www-project-serverless-top-10/
- AWS Lambda security documentation - https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- Azure Functions security concepts - https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- Google Cloud Functions security overview - https://cloud.google.com/functions/docs/securing
- NIST SP 800-204A (Serverless Security Strategies) - https://csrc.nist.gov/publications/detail/sp/800-204a/final