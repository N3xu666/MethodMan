# Cloud Security - Certification Alignment

Mapping between the CLOUD subcategories and the objectives of relevant cloud and cloud-native certifications. This is a study guide, not a substitute for the official exam objectives.

## Core certifications

| Certification | Issuer | Scope | Relevant subcategories |
|---------------|--------|-------|------------------------|
| AWS Certified Advanced Networking - Specialty | AWS | Advanced AWS networking, hybrid connectivity, VPC design | 01 AWS, 04 Kubernetes-Cloud |
| AWS Certified Solutions Architect - Associate | AWS | Core AWS services, architecture, shared responsibility model | 01 AWS, 05 Serverless, 06 IaC |
| Azure Network Engineer Associate (AZ-700) | Microsoft | Azure networking, hybrid connectivity, security | 02 Azure, 04 Kubernetes-Cloud |
| Google Cloud Network Engineer | Google | GCP networking, VPC design, hybrid connectivity | 03 GCP, 04 Kubernetes-Cloud |
| Certified Kubernetes Administrator (CKA) | CNCF | Kubernetes cluster administration, security basics | 04 Kubernetes-Cloud |
| Certified Kubernetes Security Specialist (CKS) | CNCF | Kubernetes supply chain, runtime, network security | 04 Kubernetes-Cloud |
| HashiCorp Terraform Associate | HashiCorp | Infrastructure as Code, state management, modules | 06 IaC |

## Cross-category certifications

| Certification | Issuer | Relevant categories |
|---------------|--------|---------------------|
| CompTIA Network+ | CompTIA | NETWORKS (all), CLOUD 01-03 |
| Cisco CCNA | Cisco | NETWORKS (all), CLOUD 04 |
| CompTIA Security+ | CompTIA | CLOUD (all), INFRASTRUCTURE (all) |
| OSCP | OffSec | WRITEUPS, INFRASTRUCTURE, CLOUD (offensive track) |

## How each subcategory maps

- **01 AWS** - AWS Advanced Networking, AWS Solutions Architect Associate, Security+.
- **02 Azure** - Azure Network Engineer (AZ-700), Security+.
- **03 GCP** - GCP Cloud Network Engineer, Security+.
- **04 Kubernetes-Cloud** - CKA, CKS, AWS Advanced Networking (EKS networking), Azure Network Engineer (AKS networking), GCP Cloud Network Engineer (GKE networking).
- **05 Serverless** - AWS Solutions Architect Associate, Security+.
- **06 IaC** - HashiCorp Terraform Associate, AWS Solutions Architect Associate.

## Study order (suggested)

1. Foundations: 01 AWS or 02 Azure or 03 GCP (pick one provider first).
2. Kubernetes: 04 Kubernetes-Cloud (after the chosen provider).
3. Serverless and IaC: 05 Serverless, 06 IaC.
4. Cross-reference: NETWORKS (all), INFRASTRUCTURE (all).

## References

- AWS Certification - https://aws.amazon.com/certification/
- Microsoft Azure Certification - https://learn.microsoft.com/en-us/credentials/
- Google Cloud Certification - https://cloud.google.com/learn/certification
- CNCF Kubernetes Certification - https://www.cncf.io/certification/cka/
- HashiCorp Terraform Certification - https://www.hashicorp.com/certification/terraform-associate
