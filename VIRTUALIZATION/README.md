# Virtualization Security Reference

Virtualization and container security - hypervisors, VM escape, containers, sandboxes and orchestration, from both the offensive (attack) and defensive (detection, hardening) perspective.

This category follows the two-track format: each file covers both the offensive (attack) and defensive (detection, hardening) side of the topic, with no suffix in the section headers.

## Scope

This category covers the virtualization and container stack end to end:

- Hypervisors: Type 1 and Type 2, ESXi, Hyper-V, Proxmox, KVM, Xen.
- VM escape: hypervisor CVEs, shared clipboard, device passthrough, GPU passthrough, VMware Tools, Hyper-V integration services.
- Containers: Docker, Podman, containerd, OCI runtime, image security, namespace and cgroup isolation, capabilities.
- Sandboxes: browser sandboxes (Chromium, Firefox), OS-level sandboxes (seccomp, AppArmor, SELinux), mobile sandboxes (iOS, Android), Windows Sandbox, malware analysis environments.
- Orchestration: Kubernetes, Docker Swarm, Nomad, service mesh (Istio, Linkerd, Consul), CI/CD orchestration security.

## Subcategories

| # | Subcategory | Files | Focus |
|---|-------------|-------|-------|
| 01 | [Hypervisors](./01%20Hypervisors/) | 5 | ESXi, Hyper-V, KVM, Proxmox, management plane |
| 02 | [VM Escape](./02%20VM%20Escape/) | 5 | Hypervisor escapes, device passthrough, isolation bypass |
| 03 | [Containers](./03%20Containers/) | 5 | Docker, OCI, namespace/cgroup escapes, image supply chain |
| 04 | [Sandboxes](./04%20Sandboxes/) | 5 | Browser, OS-level, mobile and malware analysis sandboxes |
| 05 | [Orchestration](./05%20Orchestration/) | 5 | Kubernetes, Swarm, Nomad, service mesh, CI/CD orchestration |

## Format

Files in this category follow the two-track skeleton:

```text
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

The Offensive track covers sections 2-5 (recon through post-exploitation). The Defensive track covers sections 6-8 (preventive controls, detection, verification). Section 9 maps the content to certification objectives.

## Certification Alignment

See [CERTIFICATIONS.md](./CERTIFICATIONS.md) for the full matrix. Core: Security+, CySA+, CISSP. Extended: CCSP, CKS, CKA, CCSE, VCP-DCV.

## Related Categories

- [INFRASTRUCTURE](../INFRASTRUCTURE/) - on-premises infrastructure attack and defense.
- [CLOUD](../CLOUD/) - cloud platforms, cloud-native architecture, Kubernetes in the cloud.
- [NETWORKS](../NETWORKS/) - network fundamentals, protocols, devices.

## References

- NIST SP 800-125A - Security Recommendations for Hypervisor Deployment - https://csrc.nist.gov/pubs/sp/800/125/a/final
- NIST SP 800-190 - Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final
- NIST SP 800-125B - Secure Virtual Network Configuration for Virtual Machine (VM) Protection - https://csrc.nist.gov/pubs/sp/800/125/b/final
- NIST SP 800-125 - Guide to Security for Full Virtualization Technologies - https://csrc.nist.gov/pubs/sp/800/125/final
- CIS Benchmarks - Docker, Kubernetes, VMware ESXi - https://www.cisecurity.org/cis-benchmarks
- Kubernetes Security Documentation - https://kubernetes.io/docs/concepts/security/

