# Containers

Container security from both offensive and defensive perspectives. Covers container isolation, attack surface, runtime security, image security, and orchestration security. Containers share the host kernel, which makes the isolation boundary fundamentally different from virtual machines.

## Format

Two-track (Offensive / Defensive). Every file covers both the attack path and the corresponding detection and prevention controls.

## Scope

- Container isolation internals (namespaces, cgroups, capabilities, LSMs).
- Container attack surface (Docker, containerd, Podman).
- Image supply chain security (base images, layers, registries).
- Container runtime security (seccomp, AppArmor, SELinux).
- Kubernetes security (pod security, network policies, RBAC).
- Container escape (covered in detail in `02 VM Escape`).

## Files

| # | File | Format |
|---|------|--------|
| 01 | [Container Fundamentals](./01%20Container%20Fundamentals.md) | Two-track |
| 02 | [Container Attack Surface](./02%20Container%20Attack%20Surface.md) | Two-track |
| 03 | [Image and Supply Chain Security](./03%20Image%20and%20Supply%20Chain%20Security.md) | Two-track |
| 04 | [Container Runtime Security](./04%20Container%20Runtime%20Security.md) | Two-track |
| 05 | [Kubernetes Security](./05%20Kubernetes%20Security.md) | Two-track |

## Certification Alignment

- Cloud Native: CKA, CKS (Kubernetes security).
- Vendor: Docker Certified Associate.
- Offensive Security: OSCP (container escape context).

## References

- Docker Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- Kubernetes Security Documentation - https://kubernetes.io/docs/concepts/security/
- CIS Docker Benchmark - https://www.cisecurity.org/benchmark/docker
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- Container Security (Liz Rice) - O'Reilly Media