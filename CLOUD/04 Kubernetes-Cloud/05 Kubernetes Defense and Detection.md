# Kubernetes Defense and Detection

## 1. Overview

Kubernetes defense is a layered problem: the cluster has more moving parts than a traditional host, and the attack surface changes every time a new operator, CRD, or webhook is installed. A defense program that only hardens the API server and ignores runtime behavior will miss configuration escapes and cloud IAM abuse. A program that only watches runtime behavior and ignores admission control will miss privileged Pods before they start.

This file covers the defensive side in four layers:

- **Preventive controls** - what stops an attack before it starts (RBAC, Pod Security Admission, admission webhooks, network policies, cloud IAM scoping).
- **Detection controls** - what reveals an attack in progress (audit logs, runtime detection, cloud-native threat detection).
- **Response** - what to do when a detection fires (isolate the workload, rotate credentials, preserve evidence).
- **Verification** - how to prove the controls work (kube-bench, kube-hunter, policy tests).

The offensive side is in `01 Kubernetes Fundamentals.md` through `04 GKE and EKS Attack Paths.md`. This file is written from the blue team perspective, but it assumes the reader knows the attacks.

## 2. Reconnaissance and Enumeration

A defender's reconnaissance is a continuous inventory of what exists in the cluster.

Cluster inventory:

```bash
# All namespaces, workloads, and their security context
kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name) sa=\(.spec.serviceAccountName) priv=\(.spec.containers[0].securityContext.privileged // false) host=\(.spec.hostNetwork // false)"'

# All ServiceAccounts and their bindings
kubectl get clusterrolebindings,rolebindings -A -o wide

# All admission webhooks
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations

# All CRDs (each is a new attack surface)
kubectl get crd
```

Expected output (truncated):

```text
kube-system/coredns sa=coredns priv=false host=false
kube-system/kube-proxy sa=kube-proxy priv=false host=true
prod/app-abc sa=app priv=false host=false
```

RBAC audit:

```bash
# Who can do what
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Who is cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | "\(.metadata.name) -> \(.subjects // [])"'
```

Expected output:

```text
default -> []
```

An empty `default -> []` means the default ServiceAccount has no cluster-admin binding - the correct state.

Network policy inventory:

```bash
kubectl get networkpolicies -A
```

Expected output (empty means no policies - default allow):

```text
No resources found.
```

Cloud identity inventory (EKS):

```bash
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `system:serviceaccount:*:*`)].RoleName'
```

Expected output (empty means no wildcard IRSA trust policies):

```text
[]
```

## 3. Common Attack Vectors

This section restates the attack vectors from the offensive files in defender terms - what each vector requires, and what stops it.

**3.1 Privileged Pod**

Requires: `create pods` permission in a namespace without PSA `restricted`.
Stops: Pod Security Admission `restricted`; Gatekeeper/Kyverno constraint on `privileged`.

**3.2 hostPath mount**

Requires: `create pods` permission; no admission check on volumes.
Stops: PSA `restricted` (blocks all hostPath); Gatekeeper constraint on `hostPath` paths.

**3.3 hostNetwork / hostPID**

Requires: `create pods` permission; no admission check on `hostNetwork` / `hostPID`.
Stops: PSA `baseline` blocks `hostNetwork`; `restricted` also blocks `hostPID`; Gatekeeper constraint.

**3.4 Runtime socket mount**

Requires: `create pods` permission; no admission check on volumes.
Stops: Gatekeeper constraint on any hostPath ending in `.sock`; PSA `restricted` blocks all hostPath.

**3.5 Over-privileged ServiceAccount**

Requires: a Role or ClusterRole binding that grants more than needed.
Stops: RBAC review; `kubectl-who-can`; CI check that rejects wildcards.

**3.6 Anonymous API server / kubelet access**

Requires: `--anonymous-auth=true` on the API server or kubelet.
Stops: explicit `--anonymous-auth=false`; network allowlist; private endpoint.

**3.7 IMDS from Pods**

Requires: no NetworkPolicy blocking `169.254.169.254`.
Stops: NetworkPolicy egress deny to `169.254.169.254/32`; IMDSv2 with hop limit 1.

**3.8 Wildcard IRSA trust policy**

Requires: an IAM role with `system:serviceaccount:*:*` in the trust policy.
Stops: trust policy scoped to `system:serviceaccount:prod:app`; CI check on `AssumeRolePolicyDocument`.

**3.9 Cloud metadata token from a Pod**

Requires: Pod can reach the metadata server.
Stops: NetworkPolicy egress deny; metadata concealment (GKE); IMDSv2 hop limit 1 (EKS).

**3.10 Admission webhook abuse**

Requires: `patch` or `update` on `mutatingwebhookconfigurations`.
Stops: RBAC restricting webhook write to cluster-admin; audit log alert.

## 4. Exploitation Recipes

This section is written from the defender's perspective: for each attack, the recipe is the detection or the prevention that stops it. The offensive recipes are in the earlier files.

**Recipe 1 - block privileged Pods with Pod Security Admission:**

```bash
kubectl label namespace prod pod-security.kubernetes.io/enforce=restricted
kubectl label namespace prod pod-security.kubernetes.io/enforce-version=latest
```

Expected output:

```text
namespace/prod labeled
```

After labeling, a Pod with `privileged: true` is rejected:

```text
Error from server (Forbidden): error when creating "pod.yaml": pods "escape" is forbidden: violates PodSecurity "restricted:latest": privileged (container "escape" must not set securityContext.privileged=true)
```

**Recipe 2 - block hostPath with Gatekeeper:**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockHostPath
metadata:
  name: block-hostpath
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

Expected output:

```text
k8sblockhostpath.constraints.gatekeeper.sh/block-hostpath created
```

**Recipe 3 - block IMDS from Pods with NetworkPolicy:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-imds
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

Expected output:

```text
networkpolicy.networking.k8s.io/block-imds created
```

**Recipe 4 - alert on privileged Pod creation (audit log):**

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods"]
    omitStages:
      - RequestReceived
```

Expected output:

```text
# Audit log entry for a privileged Pod create:
{"kind":"Event","verb":"create","objectRef":{"resource":"pods","namespace":"prod","name":"escape"},"requestObject":{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}}
```

**Recipe 5 - detect nsenter from a container (Falco):**

```yaml
- rule: Container Escape via nsenter
  desc: Detect nsenter execution in a container
  condition: >
    spawned_process and container and
    proc.name = nsenter
  output: >
    nsenter executed in container (user=%user.name container=%container.name
    command=%proc.cmdline)
  priority: CRITICAL
```

Expected output:

```text
# Falco alert:
14:22:01.123456789: Critical nsenter executed in container (user=root container=escape command=nsenter --target 1 --mount ...)
```

## 5. Post-Exploitation

What a defender does after a detection fires.

Isolation:

- Cordon and drain the node: `kubectl cordon <node>`; `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`.
- Delete the compromised Pod: `kubectl delete pod <name> -n <ns> --grace-period=0 --force`. Preserve the node for forensics.
- If the escape reached the host, isolate the node at the network layer (security group, NACL, firewall).

Credential rotation:

- Rotate the ServiceAccount token for the compromised identity: delete the token Secret and re-create; for projected tokens, the token expires automatically within 1 hour, but assume it is compromised and revoke any downstream credentials.
- Rotate the cloud role: for IRSA, update the trust policy or delete the role; for the node instance role, rotate the instance profile credentials.
- Rotate any Secrets the compromised identity could read.

Evidence preservation:

- Export the API server audit log for the time window.
- Export `kubectl get pods -A -o yaml`, `kubectl get events -A`, and the node's `journalctl -u kubelet` for the time window.
- Export the container runtime logs (`crictl logs <container>`).
- Snapshot the node's disk if the escape reached the host.

Containment:

- Delete any Pod, DaemonSet, CronJob, or webhook the attacker created.
- Review `clusterrolebindings` and `rolebindings` for new bindings.
- Review `mutatingwebhookconfigurations` and `validatingwebhookconfigurations` for new webhooks.
- Review `aws-auth` (EKS) or Workload Identity bindings (GKE) for new mappings.

## 6. Preventive Controls

**Layer 1 - cluster configuration**

- API server: `--anonymous-auth=false`, `--authorization-mode=Node,RBAC`, `--audit-log-path`, `--audit-policy-file`.
- kubelet: `--anonymous-auth=false`, `--authorization-mode=Webhook`, `--read-only-port=0`, `--rotate-certificates=true`.
- etcd: client cert auth, encryption at rest with KMS.
- Control plane endpoint: private, or IP allowlist + VPN.

**Layer 2 - admission control**

- Pod Security Admission `restricted` on all namespaces (`pod-security.kubernetes.io/enforce=restricted`).
- Gatekeeper or Kyverno constraints: no privileged, no hostPath, no hostNetwork, no hostPID, no `allowPrivilegeEscalation`, no `latest` tag, mandatory resource limits.
- Image policy: only signed images from a trusted registry (Cosign, Notation, Kyverno verifyImages).

**Layer 3 - identity and authorization**

- RBAC least privilege: no `cluster-admin` for ServiceAccounts, no wildcards, no default SA permissions.
- `automountServiceAccountToken: false` on Pods that do not need API access.
- OIDC integration with the cloud provider for user authentication (no static admin kubeconfig).
- IRSA / Workload Identity trust policies scoped to specific namespace + ServiceAccount.
- `aws-auth` ConfigMap write restricted to cluster-admin.

**Layer 4 - network**

- NetworkPolicy default-deny per namespace; allow only required egress.
- Block IMDS from Pods: egress deny to `169.254.169.254/32`.
- Ingress controller with WAF (ModSecurity, Coraza) in front of exposed services.
- Service mesh (Istio, Linkerd) with mTLS for service-to-service traffic.

**Layer 5 - runtime**

- Falco or Tetragon for runtime detection.
- Read-only root filesystem, non-root user, dropped capabilities.
- gVisor (GKE Sandbox), Kata Containers, or Firecracker for untrusted workloads.
- Node OS hardening: Bottlerocket (EKS), Container-Optimized OS (GKE), Azure Linux (AKS).

**Layer 6 - supply chain**

- Signed images (Cosign, Notation), verified at admission.
- SBOM generation and scanning (Syft, Trivy).
- Helm chart provenance verification (helm verify).
- Operator and CRD review before installation.

## 7. Detection Controls

**API server audit log**

Events to alert on:

- `create` on `pods` with `privileged: true`, `hostPath`, `hostNetwork`, `hostPID`.
- `create` on `clusterrolebindings` or `rolebindings` binding to `cluster-admin`.
- `get` or `list` on `secrets` across many namespaces in a short window.
- `create` on `pods/exec` or `pods/attach` into `kube-system`.
- `patch` or `update` on `mutatingwebhookconfigurations` or `validatingwebhookconfigurations`.
- `delete` on webhooks or webhook services.
- `401` on `/api` or `/apis` from unexpected source IPs.
- `create` on `serviceaccounts/token` (token minting).

**Kubelet and runtime**

Falco rules (baseline set):

- `Privileged Container Started`
- `Container Escape via nsenter`
- `Container Escape via chroot`
- `Docker Socket Mounted`
- `Read Sensitive File Untrusted` (includes `/var/lib/kubelet/kubeconfig`, `/etc/kubernetes/admin.conf`, `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- `Write Below Etc`
- `Netcat Remote Code Execution in Container`
- `AWS IMDS Access from Pod`
- `GCP Metadata Access from Pod`

Tetragon traces:

- `execve` of `nsenter`, `chroot`, `unshare`, `mount`, `docker`, `ctr`, `crictl` from a container.
- `open` on runtime sockets.
- `connect` to `169.254.169.254` or `metadata.google.internal`.

**Cloud-native detection**

EKS:

- GuardDuty EKS Runtime Monitoring (`PrivilegeEscalation:Kubernetes/PrivilegedContainer`, `CredentialAccess:IAMUser/AnomalousBehavior`).
- CloudTrail `AssumeRoleWithWebIdentity` from unexpected source IP.
- CloudTrail `GetSecretValue` spikes.

GKE:

- Security Command Center (`Privileged Container`, `Container Escape`).
- Cloud Audit Log `google.cloud.container.v1.ClusterManager` from unexpected principal.
- Cloud Audit Log `storage.objects.get` spikes.

AKS:

- Microsoft Defender for Containers (`K8S.NODE_NamespaceEscalation`, `K8S.NODE_SuspiciousFileAccess`).
- Azure Activity Log `Microsoft.ContainerService/managedClusters/write` from unexpected principal.

**Network detection**

- Cilium Hubble for flow-level visibility.
- Egress deny events from NetworkPolicy (no direct log, but the connection failure is visible in the application log).
- DNS exfiltration detection (unusual domains, high-entropy subdomains).

## 8. Verification

**Compliance and benchmark**

```bash
kube-bench
```

Expected output:

```text
[INFO] 1 Master Node Security Configuration
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.2 Ensure that the --basic-auth-file argument is not set
...
== Summary ==
45 checks PASS
2 checks FAIL
5 checks WARN
```

**Attack surface scan**

```bash
kube-hunter --remote <api-server>
```

Expected output (truncated):

```text
Kubernetes exposed services:
  <api-server>:6443 - Kubernetes API Server
Vulnerabilities:
  None found
```

**Policy tests**

```bash
# Apply a privileged Pod; expect rejection
kubectl apply -f privileged-pod.yaml
```

Expected output:

```text
Error from server (Forbidden): error when creating "privileged-pod.yaml": pods "escape" is forbidden: violates PodSecurity "restricted:latest": privileged
```

**Runtime detection test**

```bash
# Run nsenter in a Pod; expect Falco alert
kubectl exec -it test-pod -- nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

Expected output (Falco):

```text
14:22:01.123456789: Critical nsenter executed in container (user=root container=test-pod command=nsenter --target 1 ...)
```

## 9. Cloud-Specific Considerations

**EKS:**

- Enable control plane logging (api, audit, authenticator, controllerManager, scheduler) to CloudWatch.
- Enable GuardDuty EKS Runtime Monitoring and EKS Audit Log Monitoring.
- Use Bottlerocket nodes (no SSH, no Docker socket).
- Enable EKS Pod Identity where IRSA is not required.
- Use AWS Network Firewall or Security Groups for Pods to control egress to IMDS.

**GKE:**

- Enable GKE audit logging and Security Command Center Premium.
- Enable Workload Identity on all node pools.
- Enable GKE Sandbox for untrusted workloads.
- Use private clusters (no public control plane endpoint).
- Enable Dataplane V2 (Cilium-based) for network policy and Hubble visibility.

**AKS:**

- Enable Microsoft Defender for Containers.
- Enable Azure Policy for AKS.
- Disable local accounts (`--disable-local-accounts`).
- Use Azure AD Workload Identity.
- Use Azure CNI with network policy (Calico or Azure NPM).

## 10. Production Notes

- Defense in depth is not optional. A single layer (e.g., PSA `restricted`) blocks many attacks but not all; combine admission, RBAC, network, runtime, and cloud IAM controls.
- Detection without response is noise. Every alert must have a runbook that says what to isolate, what to rotate, and what to preserve.
- The audit log is the highest-value detection source. Configure the audit policy before an incident, not during.
- Runtime detection (Falco, Tetragon) catches the attacks that admission control misses (kernel exploits, configuration escapes on already-running workloads).
- Cloud-native detection (GuardDuty, SCC, Defender) catches the cloud IAM abuse that Kubernetes-native detection cannot see.
- Quarterly RBAC review and IRSA trust policy review catch the drift that accumulates from fast-moving development.
- Back up etcd before any upgrade; etcd loss is cluster loss.

## 11. References

- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes Pod Security Admission - https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Kubernetes audit logging - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Kubernetes RBAC good practices - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes Secrets encryption at rest - https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- NSA/CISA Kubernetes Hardening Guide - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- OWASP Kubernetes Top 10 - https://owasp.org/www-project-kubernetes-top-ten/
- MITRE ATT&CK for Containers - https://attack.mitre.org/matrices/enterprise/containers/
- kube-bench - https://github.com/aquasecurity/kube-bench
- kube-hunter - https://github.com/aquasecurity/kube-hunter
- Kubescape - https://github.com/kubescape/kubescape
- Falco - https://falco.org/
- Tetragon - https://github.com/cilium/tetragon
- Cilium Hubble - https://github.com/cilium/hubble

## Certification Alignment

- CKS (Certified Kubernetes Security Specialist) - cluster hardening, system hardening, microservice vulnerabilities, supply chain security, monitoring and logging.
- CKA (Certified Kubernetes Administrator) - cluster architecture, troubleshooting, logging.
- CompTIA Security+ - incident response, monitoring, network security.
- AWS Certified Security - Specialty - GuardDuty, CloudTrail, IRSA.
- Google Cloud Professional Cloud Security Engineer - SCC, Workload Identity, GKE security.
- Azure Security Engineer Associate - Defender for Containers, Azure Policy for AKS.
