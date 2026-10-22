# Orchestration

Platforms that schedule, deploy and manage workloads across a cluster of
machines. This subcategory covers the control plane, the scheduling logic,
the service mesh and the CI/CD orchestration layer - where they break and
how to defend them.

Orchestration sits above containers and virtual machines: it decides where a
workload runs, what it can reach, and which identity it assumes. A
compromised orchestrator is a compromise of every workload it manages, which
is why the control plane is the highest-value target in a modern cluster.

## Scope

This subcategory covers:

- The control plane and scheduling model of Kubernetes and comparable
  orchestrators.
- Attack surface of the API server, kubelet, etcd and admission controllers.
- Docker Swarm and HashiCorp Nomad as alternative orchestration models.
- Service mesh data planes and control planes (mTLS, sidecars, ingress).
- CI/CD orchestration as a trust boundary that can deploy into the cluster.
- Defensive controls: RBAC, admission policy, network policy, audit logging,
  and verification.

## Format

Each file uses the two-track format:

- **Offensive** - attack surface, exploitation paths, proof-of-concept recipes.
- **Defensive** - preventive controls, detection signals, hardening, verification.

## Files

| # | File | Format |
|---|------|--------|
| 01 | Orchestration Fundamentals | Two-track |
| 02 | Kubernetes Orchestration Security | Two-track |
| 03 | Docker Swarm and Nomad Security | Two-track |
| 04 | Service Mesh Security | Two-track |
| 05 | CI-CD Orchestration Security | Two-track |

## Related

- Virtualization 01 Hypervisors - hypervisor-level isolation.
- Virtualization 02 VM Escape - escapes from the VM boundary.
- Virtualization 03 Containers - namespace and cgroup isolation.
- Virtualization 04 Sandboxes - isolation of untrusted code and content.

## References

- Kubernetes Documentation - https://kubernetes.io/docs/
- NIST SP 800-190, Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final
- NIST SP 800-204A, Building Secure Microservices-based Applications Using Service-Mesh Architecture - https://csrc.nist.gov/pubs/sp/800/204/a/final