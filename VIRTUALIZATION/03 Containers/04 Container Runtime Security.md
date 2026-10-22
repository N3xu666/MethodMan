# Container Runtime Security

This file covers the security of the container runtime: the component that creates and runs containers. It focuses on the runtime configuration that affects isolation, and the defensive controls that harden it.

## 1. Overview

The container runtime is the software that creates and runs containers. It sits between the orchestrator (e.g., Kubernetes) and the host kernel. Key runtimes include:

- **Docker** (dockerd, containerd, runc).
- **containerd** (used by Docker and Kubernetes).
- **CRI-O** (Kubernetes-native runtime).
- **Podman** (daemonless).

Runtime security is about configuring these runtimes to enforce the strongest possible isolation. A misconfigured runtime is often the easiest path to a container escape.

## 2. Runtime Components

- **High-level runtime** (e.g., containerd, CRI-O) - manages image pull, container lifecycle, and API.
- **Low-level runtime** (e.g., runc) - creates the container using Linux namespaces and cgroups.
- **Shim** (e.g., containerd-shim) - keeps the container alive and manages its lifecycle.

## 3. Security-Relevant Runtime Settings

### 3.1 User Namespaces

User namespaces map a container's root user to an unprivileged user on the host. This means that even if an attacker gains root inside the container, they are not root on the host.

Enable user namespaces:

```bash
# On the host, enable user namespaces
$ sudo sysctl -w kernel.unprivileged_userns_clone=1
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
kernel.unprivileged_userns_clone = 1
```

### 3.2 Seccomp Profiles

seccomp filters system calls. Docker's default profile blocks ~44 dangerous syscalls. Custom profiles can be stricter.

Apply a seccomp profile:

```bash
$ docker run --security-opt seccomp=/path/to/profile.json ...
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the container runs with the custom seccomp profile)
```

### 3.3 AppArmor / SELinux

Linux Security Modules provide mandatory access control. Docker uses AppArmor by default on Ubuntu and SELinux on RHEL/CentOS.

Check the profile:

```bash
$ docker inspect --format='{{.AppArmorProfile}}' <container>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
docker-default
```

### 3.4 Capabilities

Drop all capabilities and add only the required ones:

```bash
$ docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the container runs with only NET_BIND_SERVICE)
```

### 3.5 Read-Only Root Filesystem

Use a read-only root filesystem to prevent an attacker from writing to disk:

```bash
$ docker run --read-only ...
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the root filesystem is read-only)
```

## 4. Runtime Hardening Checklist

- [ ] Use user namespaces (`--userns-remap`).
- [ ] Apply a strict seccomp profile.
- [ ] Enforce AppArmor or SELinux.
- [ ] Drop all capabilities; add only the required ones.
- [ ] Use a read-only root filesystem.
- [ ] Do not mount the Docker socket.
- [ ] Do not use `--privileged`.
- [ ] Limit resources (CPU, memory) with cgroups.
- [ ] Run as non-root user (`--user`).

## 5. Defensive Controls

- **Enforce policies** with Open Policy Agent (OPA) or Kubernetes Pod Security Admission.
- **Audit runtime configurations** regularly.
- **Monitor for deviations** from the baseline.
- **Use a runtime security tool** (Falco, Sysdig) to detect anomalous behavior.

## 6. Detection Controls

- **Falco rules** detect privileged containers, host mounts, and dangerous capabilities.
- **Audit logs** show which containers were started with which flags.
- **Runtime telemetry** can detect unexpected `execve` or `mount` calls.

## 7. Verification

To verify runtime security:

- Check that the container is not privileged: `docker inspect --format='{{.HostConfig.Privileged}}' <container>`.
- Check that the Docker socket is not mounted: `docker inspect --format='{{.Mounts}}' <container>`.
- Check that user namespaces are enabled: `docker info | grep Userns`.
- Check seccomp: `docker inspect --format='{{.HostConfig.SecurityOpt}}' <container>`.

## 8. Production Notes

- Use a hardened runtime like gVisor or Kata Containers for high-security workloads.
- Enable audit logging on the container runtime.
- Regularly review runtime configurations for drift.

## 9. References

- Docker Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- CIS Docker Benchmark - https://www.cisecurity.org/benchmark/docker
- Kubernetes Pod Security Standards - https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco runtime security - https://falco.org/
- gVisor documentation - https://gvisor.dev/docs/