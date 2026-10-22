# Kubernetes Attack Surface

## 1. Overview

The Kubernetes attack surface is the sum of every externally reachable endpoint, every identity, and every object attribute that an attacker can influence. It splits into six areas:

- **Control plane endpoints** - the API server, etcd, scheduler, controller manager.
- **Node endpoints** - kubelet (10250/10255), kube-proxy, container runtime sockets.
- **Admission and authorization** - RBAC, admission controllers, service account tokens, OIDC.
- **Workload configuration** - Pod security context, volumes, host namespace sharing.
- **Network exposure** - Services, Ingress, NetworkPolicy gaps.
- **Supply chain** - image registries, Helm charts, operators, admission webhooks.

Each area has its own enumeration technique, its own misconfigurations, and its own detection signals. This file maps the surface systematically so that later files (Container Escape, GKE and EKS Attack Paths) can drill into specific exploitation paths.

## 2. Reconnaissance and Enumeration

Start from outside, then move inward.

External scan order:

1. **API server** - 6443, 8443, 443. `curl -k https://<host>:6443/version` to confirm. If `--anonymous-auth` is on, `/api` and `/apis` respond without a token.
2. **kubelet** - 10250 (auth) and 10255 (read-only). `curl -k https://<node>:10255/pods` is unauthenticated on old clusters.
3. **etcd** - 2379 (client), 2380 (peer). `etcdctl --endpoints=https://<host>:2379 endpoint health` works only with client certs, but an open port is a red flag.
4. **Dashboard** - typically NodePort 30000-32767 or behind Ingress. `/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/` is the legacy path.
5. **Ingress and Services** - enumerate hostnames and ports; internal services may be exposed by a misconfigured Ingress.
6. **Cloud metadata** - from inside any Pod, `http://169.254.169.254/` (AWS/GCP) or `http://169.254.169.254/metadata/` (Azure).

Once you have any identity (token, kubeconfig, ServiceAccount):

- `kubectl auth can-i --list` - the authorization matrix for this identity.
- `kubectl get clusterrolebindings -o wide` - who is cluster-admin.
- `kubectl get rolebindings -A -o wide` - namespace-scoped bindings.
- `kubectl get sa -A` - all ServiceAccounts.
- `kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: sa={.spec.serviceAccountName} priv={.spec.containers[*].securityContext.privileged} host={.spec.hostNetwork}{"\n"}{end}'` - workloads and their security context.
- `kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations` - admission webhooks (a compromised webhook can inject into every new Pod).
- `kubectl get secrets -A` - every Secret in every namespace the identity can read.

## 3. Common Attack Vectors

**3.1 API server exposure**

- Anonymous authentication enabled (`--anonymous-auth=true`, the default in older versions).
- Weak static token file (`--token-auth-file`) with predictable tokens.
- Public endpoint with no IP allowlist.
- Client certificate authentication where a stolen `admin.conf` gives cluster-admin.

**3.2 kubelet exposure**

- Anonymous auth on 10250 (`--anonymous-auth=true`), allowing `/pods`, `/run`, `/exec`, `/logs`.
- Read-only port 10255 (`--read-only-port=10255`, removed in recent versions but common on old clusters).
- kubelet client certificate accepted by the API server with broad permissions (Node authorizer bypass if misconfigured).

**3.3 etcd exposure**

- etcd reachable without client cert authentication.
- etcd data not encrypted at rest, readable from a compromised control-plane node.

**3.4 RBAC misconfiguration**

- `cluster-admin` bound to a default ServiceAccount or to `system:authenticated`.
- Wildcard verbs (`*`) and resources (`*`) in a Role.
- `create pods` in a namespace with no Pod Security Admission - the attacker can schedule a privileged Pod.
- `get secrets` cluster-wide - every Secret readable.
- `impersonate` on `users`, `groups`, or `serviceaccounts` - privilege escalation to any identity.
- `escalate` or `bind` on Roles/ClusterRoles - privilege escalation by creating a higher-privileged binding.

**3.5 ServiceAccount token abuse**

- Token mounted into every Pod by default (`automountServiceAccountToken: true`).
- Token readable by anyone with `exec` into the Pod.
- Token has the permissions of its ServiceAccount, which may be over-privileged.
- Long-lived tokens (legacy) vs. projected short-lived tokens (modern clusters).

**3.6 Workload configuration**

- Privileged containers.
- hostPath mounts of `/`, `/var/run/docker.sock`, `/var/run/containerd/containerd.sock`, `/proc`, `/sys`.
- hostNetwork, hostPID, hostIPC.
- `allowPrivilegeEscalation: true` (default).
- Missing `runAsNonRoot`, `readOnlyRootFilesystem`, dropped capabilities.

**3.7 Admission webhook abuse**

- A compromised MutatingWebhookConfiguration can inject a sidecar into every new Pod.
- A webhook with `failurePolicy: Ignore` can be bypassed by crashing it.

**3.8 Cloud integration**

- IRSA / Workload Identity / Pod Identity misconfiguration: a ServiceAccount can assume a cloud role that is too permissive.
- IMDS reachable from Pods: the Pod can steal the node's instance role.
- Cloud control plane exposed publicly with a weak or missing authorizer.

## 4. Exploitation Recipes

**Recipe 1 - enumerate the authorization matrix of a stolen token:**

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --server=https://kubernetes.default.svc auth can-i --list
```

Expected output:

```text
Resources   Non-Resource URLs   Resource Names   Verbs
pods        []                  []               [get list create]
secrets     []                  []               [get]
```

**Recipe 2 - read all Secrets in scope:**

```bash
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl -n $ns get secrets -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null
done
```

Expected output:

```text
default-token-abc12
db-credentials
```

**Recipe 3 - check for privileged workloads already running:**

```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"'
```

Expected output:

```text
kube-system/privileged-agent
```

**Recipe 4 - abuse a misconfigured webhook (failurePolicy: Ignore):**

```bash
# Delete the webhook service; with failurePolicy: Ignore, admission proceeds without it
kubectl -n webhook-system delete svc webhook-svc
```

Expected output:

```text
service "webhook-svc" deleted
```

**Recipe 5 - check IMDS reachability from a Pod:**

```bash
curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ || echo "blocked"
```

Expected output:

```text
eks-node-role
```

## 5. Post-Exploitation

Once an identity is confirmed, the escalation path depends on what that identity can do.

Escalation primitives to look for in `auth can-i --list`:

- `create pods` in a namespace with weak PSA -> privileged Pod -> node root.
- `create pods/exec` on existing Pods -> exec into a higher-privileged workload.
- `get secrets` -> cloud credentials, database passwords, other tokens.
- `impersonate` -> become any user/group/ServiceAccount.
- `escalate` or `bind` on Roles -> create a higher-privileged binding.
- `create clusterrolebindings` -> bind `cluster-admin` to yourself.
- `patch` or `update` on `daemonsets` -> run code on every node.
- `patch` on `mutatingwebhookconfigurations` -> inject a sidecar into every new Pod.

Persistence primitives:

- Create a DaemonSet that runs a beacon on every node.
- Create a CronJob that re-establishes the foothold.
- Create a ServiceAccount with a token that is not rotated.
- Add an admission webhook that re-injects the backdoor if removed.

## 6. Preventive Controls

API server:

- Disable anonymous auth, enable `--authorization-mode=Node,RBAC`, enable `--audit-log-path`.
- Private endpoint only, or IP allowlist + VPN.
- Require client certificates for admin access; no static token files.

kubelet:

- `--anonymous-auth=false`, `--authorization-mode=Webhook`.
- Disable the read-only port (`--read-only-port=0`).
- Rotate kubelet client certificates (`--rotate-certificates=true`).

etcd:

- Client certificate authentication only.
- Encryption at rest with a KMS provider.
- Network isolation from worker nodes.

RBAC:

- No `cluster-admin` for ServiceAccounts or default accounts.
- No wildcards in Roles.
- Regular audit of bindings with `kubectl-who-can` and `rbac-tool`.

Workloads:

- Pod Security Admission `restricted` on all namespaces.
- OPA/Gatekeeper or Kyverno to block privileged, hostPath, hostNetwork, hostPID.
- `automountServiceAccountToken: false` on Pods that do not need the API.
- Drop all capabilities, `runAsNonRoot: true`, `readOnlyRootFilesystem: true`.

Webhooks:

- `failurePolicy: Fail` for security-critical webhooks.
- Audit MutatingWebhookConfiguration changes.

Cloud:

- Block IMDS from Pods with NetworkPolicy (or IMDSv2 with hop limit 1 on AWS).
- Scope IRSA / Workload Identity trust policies to specific namespaces and ServiceAccounts.
- Enable cloud-native threat detection (GuardDuty EKS Runtime Monitoring, GCP SCC, Defender for Containers).

## 7. Detection Controls

Audit log events:

- `401` on `/api` or `/apis` from unexpected sources.
- `create` on `pods` with `privileged: true` or `hostPath`.
- `create` on `clusterrolebindings` binding to `cluster-admin`.
- `get` on `secrets` across many namespaces in a short window.
- `create` on `pods/exec` into `kube-system`.
- `patch` or `update` on `mutatingwebhookconfigurations`.
- `delete` on webhooks or webhook services.

Kubelet and runtime signals:

- Access to `/pods` or `/run` from outside the Pod CIDR.
- Shell spawning in a container that does not normally run a shell.
- Container reading `/var/run/secrets/kubernetes.io/serviceaccount/token` outside normal startup.
- Process accessing `/proc/1/root` or `/proc/sys`.

Detection tools:

- Falco - rule-based runtime detection with Kubernetes context.
- Tetragon - eBPF-based observability and enforcement.
- kube-bench - CIS Kubernetes Benchmark checks.
- kube-hunter - external attack surface scanner (good for red team recon).
- Kubescape - NSA/CISA and MITRE ATT&CK for Kubernetes controls.

## 8. Verification

To verify controls against the attack surface:

- `kube-hunter --remote <api>` - external scan; should show no anonymous access, no exposed kubelet.
- `kube-bench` - CIS benchmark; should report PASS on all master and node controls.
- `kubectl auth can-i --list --as=system:serviceaccount:default:default` - default SA should have no permissions.
- Create a Pod with `privileged: true` as a non-admin; PSA should reject it.
- `curl -k https://<api>:6443/api` without a token; should return `401`.
- `curl -k https://<node>:10250/pods` without a token; should return `401`.
- `curl -s -m 2 http://169.254.169.254/latest/meta-data/` from a Pod; should time out.

## 9. Cloud-Specific Considerations

**EKS:**

- Public API endpoint by default unless configured private. Enable `endpointPublicAccess: false` or restrict with CIDRs.
- IMDS reachable from Pods by default; block with NetworkPolicy or use IMDSv2 with `HttpPutResponseHopLimit: 1`.
- IRSA trust policy misconfigurations are the most common privilege escalation path.

**GKE:**

- Public control plane unless Private Cluster is enabled.
- Workload Identity metadata server on `169.254.169.254` is a GKE-specific endpoint that returns GSA tokens - do not block it blindly.
- GKE Autopilot enforces PSA; standard clusters do not by default.

**AKS:**

- Public API server unless Private Cluster or authorized IP ranges are configured.
- Azure AD Workload Identity uses OIDC federation; a misconfigured federated credential is a privilege escalation path.
- Local accounts (`--admin` kubeconfig) bypass Azure AD - disable them.

## 10. Production Notes

- The attack surface is not static; new webhooks, operators, and CRDs add surface. Review after every install.
- `kubectl auth can-i --list` is the single fastest way to map an identity. Automate it for every ServiceAccount in a CI check.
- Default ServiceAccounts must have no permissions; make this a policy (Gatekeeper constraint) rather than a convention.
- Webhook TLS certificates are a supply-chain target; rotate them and audit the CA bundle.
- Cluster autoscaler and node pool upgrades can re-enable anonymous auth or read-only port if the node bootstrap template is not controlled.

## 11. References

- Kubernetes API access control - https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/
- Kubernetes kubelet authentication - https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
- Kubernetes RBAC good practices - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes audit logging - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- NSA/CISA Kubernetes Hardening Guide - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- kube-hunter - https://github.com/aquasecurity/kube-hunter
- kube-bench - https://github.com/aquasecurity/kube-bench
- Kubescape - https://github.com/kubescape/kubescape
- MITRE ATT&CK for Containers - https://attack.mitre.org/matrices/enterprise/containers/

## Certification Alignment

- CKA (Certified Kubernetes Administrator) - cluster access control, API server configuration, kubelet configuration, troubleshooting.
- CKS (Certified Kubernetes Security Specialist) - cluster setup, cluster hardening, system hardening, monitoring and logging.
- CompTIA Security+ - network security, identity and access management.
- AWS Certified Security - Specialty - EKS API server exposure, IMDS, IRSA trust policies.
- Google Cloud Professional Cloud Security Engineer - GKE private clusters, Workload Identity.
- Azure Security Engineer Associate - AKS private clusters, Azure AD Workload Identity.
