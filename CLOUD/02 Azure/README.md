# Azure Security

Microsoft Azure attack and defense - Entra ID, subscriptions, resource groups, Storage, Virtual Machines, VNet, Key Vault, Microsoft Defender for Cloud and Azure Monitor. Two-track format (Offensive / Defensive).

## Scope

This subcategory covers Azure-specific security: identity (Entra ID), storage, compute, networking, secrets management, and logging. Multi-cloud and provider-neutral topics live in the sibling subcategories. Microsoft 365 and Microsoft Graph are referenced only where they intersect with Azure resource access.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [Azure Fundamentals](./01%20Azure%20Fundamentals.md) | done |
| 02 | [Entra ID and Identity Attacks](./02%20Entra%20ID%20and%20Identity%20Attacks.md) | done |
| 03 | [Storage and Blob Attacks](./03%20Storage%20and%20Blob%20Attacks.md) | done |
| 04 | [VM and Compute Attacks](./04%20VM%20and%20Compute%20Attacks.md) | done |
| 05 | [Azure Defense and Detection](./05%20Azure%20Defense%20and%20Detection.md) | done |

## Format

Every file follows the two-track skeleton:

1. Overview
2. Reconnaissance / Enumeration
3. Common Attack Vectors
4. Exploitation Recipes
5. Post-Exploitation
6. Preventive Controls
7. Detection Controls
8. Verification
9. Certification Alignment
10. Production Notes
11. References

## Certification Alignment

- Microsoft Certified: Azure Security Engineer Associate (AZ-500)
- Microsoft Certified: Azure Administrator Associate (AZ-104)
- Microsoft Certified: Azure Network Engineer Associate (AZ-700)
- CompTIA Security+

See [../CERTIFICATIONS.md](../CERTIFICATIONS.md) for the full mapping.

## Related

- [01 AWS](../01%20AWS/) - Amazon Web Services attack and defense
- [03 GCP](../03%20GCP/) - Google Cloud attack and defense
- 04 Kubernetes-Cloud - Kubernetes in managed cloud
- 06 IaC - Infrastructure as Code security
- [INFRASTRUCTURE](../../INFRASTRUCTURE/) - on-premises infrastructure attack and defense

## Authorized Use Only

> [!CAUTION]
> All content in this subcategory is for authorized penetration testing and cloud security assessment of Azure subscriptions and tenants you own or have explicit written permission to test, and educational use. Do not use these techniques against Azure subscriptions, tenants, or services without authorization.
