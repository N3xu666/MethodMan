# Container Attack Surface

This file covers the container attack surface from an offensive perspective: what an attacker can do once they have code execution inside a container, and how to reach the host or other containers. It also maps the defensive controls that reduce this surface.

## 1. Overview

A container is not a security boundary by default. Once an attacker gains code execution inside a container, the next step is usually to enumerate the environment, find misconfigurations, and attempt to escape to the host.

This file covers:

- Container enumeration (what to look for inside).
- Common misconfigurations (privileged mode, host mounts, capabilities).
- Attack paths from container to host.
- Post-exploitation from a compromised container.

## 2. Container Enumeration

### 2.1 System Information

When you land inside a container, the first step is to understand the environment:

```bash
# Basic system information
$ id
$ hostname
$ cat /etc/os-release
$ uname -a
$ ps aux
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
uid=0(root) gid=0(root) groups=0(root)
container-hostname
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
Linux container-hostname 5.15.0-91-generic #101-Ubuntu SMP ... x86_64 x86_64 x86_64 GNU/Linux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   4232  3412 ?        Ss   10:00   0:00 /bin/bash
```

### 2.2 Detect Container Environment

```bash
# Check if we are in a container
$ cat /proc/1/cgroup
$ ls -la /.dockerenv
$ mount | grep -E 'overlay|docker'
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
12:pids:/docker/...
-rwxr-xr-x 1 root root 0 ...
overlay on / type overlay (rw,relatime,lowerdir=...)
```

### 2.3 Check Capabilities

```bash
# Check effective capabilities
$ capsh --print
$ cat /proc/self/status | grep Cap
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
CapEff: 00000000a80425fb
```

### 2.4 Check Mounted Host Paths

```bash
# Check for host mounts (Docker socket, host filesystem)
$ mount | grep -E '/var/run/docker.sock|/host|/proc|/sys'
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
/dev/sda1 on /host type ext4 (rw,relatime)
```

### 2.5 Check for Privileged Mode

```bash
# Check if the container is privileged
$ cat /proc/1/status | grep CapEff
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
CapEff: 0000003fffffffff
```

## 3. Common Attack Paths

### 3.1 Privileged Container

If `CapEff` is `0000003fffffffff`, the container has all capabilities. An attacker can:

- Mount the host disk: `mount /dev/sda1 /mnt`.
- Access host devices: `/dev/mem`, `/dev/kmsg`.
- Escape via `nsenter` to the host namespaces.

### 3.2 Docker Socket Mounted

If `/var/run/docker.sock` is mounted, the attacker can use the Docker API to create a new privileged container that mounts the host filesystem.

### 3.3 Host Path Mount

If a host path (e.g., `/`, `/etc`, `/root`) is mounted inside the container, the attacker can read/write host files, add SSH keys, or modify configuration.

### 3.4 Dangerous Capabilities

- `CAP_SYS_ADMIN` - allows mounting, `pivot_root`, and many escapes.
- `CAP_SYS_PTRACE` - allows attaching to host processes if PID namespace is shared.
- `CAP_NET_ADMIN` - allows network manipulation.
- `CAP_SYS_MODULE` - allows loading kernel modules (very dangerous).

### 3.5 Kernel Exploits

Kernel vulnerabilities (e.g., CVE-2022-0847 "Dirty Pipe") can be triggered from inside a container to escalate to root on the host.

## 4. Post-Exploitation

Once on the host:

- Access other containers' filesystems.
- Read host secrets (SSH keys, cloud credentials).
- Pivot to the internal network.
- Install persistence (systemd service, cron job).

## 5. Defensive Controls

- **Never use `--privileged`** unless absolutely necessary.
- **Do not mount the Docker socket** into containers.
- **Use read-only mounts** for host paths.
- **Drop all capabilities** and add only the required ones.
- **Enforce seccomp and AppArmor/SELinux profiles.**
- **Keep the host kernel patched.**

## 6. Detection Controls

- **Audit container configurations** for privileged mode, host mounts, and dangerous capabilities.
- **Monitor `mount`, `chroot`, and `nsenter` syscalls** from containers.
- **Use Falco or similar runtime security tools** to detect escape attempts.
- **Kubernetes Pod Security Standards** (Restricted profile) to prevent privileged pods.

## 7. Verification

To verify isolation:

- Run a container without `--privileged` and attempt `mount`; it should fail with "permission denied".
- Check that the Docker socket is not mounted: `ls /var/run/docker.sock`.
- Verify capabilities: `capsh --print`.

## 8. Production Notes

- In Kubernetes, use Pod Security Admission (PSA) to enforce the Restricted profile.
- Regularly scan container images for vulnerabilities and misconfigurations.
- Assume a container escape is possible and segment the host network accordingly.

## 9. References

- Docker Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- CVE-2022-0847 (Dirty Pipe) - https://nvd.nist.gov/vuln/detail/CVE-2022-0847
- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco runtime security - https://falco.org/
- Container Security (Liz Rice) - O'Reilly Media