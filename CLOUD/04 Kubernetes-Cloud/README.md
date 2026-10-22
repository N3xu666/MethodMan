# Kubernetes and Cloud-Native

Containers orchestrated by Kubernetes across managed cloud services (EKS, GKE, AKS) and self-managed clusters. This subcategory covers the Kubernetes control plane, workload security, container escape, managed-cluster attack paths, and defense.

## Scope

- Kubernetes architecture: control plane (API server, etcd, scheduler, controller manager), nodes (kubelet, kube-proxy, container runtime), workloads (Pods, Deployments, StatefulSets, DaemonSets).
- Identity and authorization: ServiceAccounts, RBAC, admission controllers, OIDC integration with cloud IAM (IRSA on EKS, Workload Identity on GKE).
- Attack surface: exposed API server, kubelet, dashboard, misconfigured RBAC, privileged pods, hostPath mounts, cloud metadata access from pods.
- Container escape: privileged containers, host namespace sharing, kernel exploits, runtime socket access.
- Managed cloud paths: EKS IRSA abuse, GKE Workload Identity abuse, AKS pod identity, node pool privilege escalation.
- Defense: Pod Security Standards, admission control (OPA/Gatekeeper, Kyverno), network policies, runtime detection (Falco), audit logging.

## Files

| # | File | Track |
|---|------|-------|
| 01 | [Kubernetes Fundamentals](./01%20Kubernetes%20Fundamentals.md) | Two-track |
| 02 | [Kubernetes Attack Surface](./02%20Kubernetes%20Attack%20Surface.md) | Two-track |
| 03 | [Container Escape](./03%20Container%20Escape.md) | Two-track |
| 04 | [GKE and EKS Attack Paths](./04%20GKE%20and%20EKS%20Attack%20Paths.md) | Two-track |
| 05 | [Kubernetes Defense and Detection](./05%20Kubernetes%20Defense%20and%20Detection.md) | Two-track |

## Format

Two-track: each file covers the offensive and defensive side.

Sections (11):

1. Overview
2. Reconnaissance and Enumeration
3. Common Attack Vectors
4. Exploitation Recipes
5. Post-Exploitation
6. Preventive Controls
7. Detection Controls
8. Verification
9. Cloud-Specific Considerations
10. Production Notes
11. References

Each file also includes a `## Certification Alignment` section.

## Certification Alignment

Core certifications for this subcategory:

- CKA - Certified Kubernetes Administrator
- CKS - Certified Kubernetes Security Specialist
- CompTIA Security+

Extended certifications:

- Google Cloud Professional Cloud Security Engineer
- AWS Certified Security - Specialty
- Azure Security Engineer Associate

## Related

- AWS subcategory (cloud IAM, metadata service, EKS integration)
- Azure subcategory (AKS, Entra ID workload identity)
- GCP subcategory (GKE, Workload Identity)
- CLOUD/06 Infrastructure as Code (cluster provisioning)

## Authorized Use Only

> [!CAUTION]
> All techniques in this subcategory are for authorized security testing only. Kubernetes clusters, cloud accounts, and container runtimes must be tested only with explicit written authorization from the owner. Unauthorized access to cloud infrastructure is illegal in most jurisdictions and violates the terms of service of every cloud provider.

## References

- Kubernetes documentation - https://kubernetes.io/docs/
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- NSA/CISA Kubernetes Hardening Guide - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- OWASP Kubernetes Top 10 - https://owasp.org/www-project-kubernetes-top-ten/
- MITRE ATT&CK for Containers - https://attack.mitre.org/matrices/enterprise/containers/
