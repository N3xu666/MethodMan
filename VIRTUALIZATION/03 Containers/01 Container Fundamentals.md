# Container Fundamentals

This file covers the foundational concepts of containerization: how containers work, what isolates them, and what makes them different from virtual machines. It is the entry point for the Containers subcategory.

## 1. Overview

A container is a lightweight, isolated execution environment that shares the host operating system kernel. Unlike a virtual machine, which runs a full guest OS on top of a hypervisor, a container packages an application and its dependencies into a single image that runs as a process on the host.

Containers are built on Linux kernel features:

- **Namespaces** - isolate the view of system resources (PID, network, mount, IPC, UTS, user, cgroup).
- **cgroups** - limit and account for resource usage (CPU, memory, I/O).
- **Capabilities** - split root privileges into fine-grained units.
- **seccomp** - filter system calls.
- **LSM (AppArmor, SELinux)** - mandatory access control.

## 2. Containers vs Virtual Machines

| Feature | Container | Virtual Machine |
|---------|-----------|-----------------|
| Isolation | Kernel namespaces | Hardware virtualization |
| Kernel | Shared with host | Separate guest kernel |
| Startup time | Milliseconds | Seconds to minutes |
| Resource overhead | Low | High |
| Security boundary | Kernel features | Hypervisor |
| Image size | MBs | GBs |

## 3. Container Runtimes

- **Docker** - the most widely used container platform. Includes the Docker daemon (`dockerd`), CLI, and image format.
- **containerd** - a CNCF graduated project, the core runtime used by Docker and Kubernetes. Manages container lifecycle.
- **CRI-O** - a lightweight runtime for Kubernetes, implementing the Container Runtime Interface (CRI).
- **Podman** - a daemonless container engine, often used as a Docker alternative.
- **runc** - the low-level OCI runtime that actually creates containers using Linux namespaces and cgroups.

## 4. Container Images

A container image is a layered filesystem. Each layer represents a change (e.g., installing a package). Layers are cached and shared between images.

- **Base image** - the starting point (e.g., `ubuntu:22.04`, `alpine:3.18`).
- **Dockerfile** - a text file that defines how to build an image.
- **Registry** - a repository for images (Docker Hub, GitHub Container Registry, private registries).

Image security is critical: a vulnerable base image compromises every container built from it.

## 5. Container Isolation Model

### 5.1 Namespaces

Namespaces provide isolation. Each namespace type isolates a different resource:

- **PID** - process IDs.
- **NET** - network interfaces, routes, ports.
- **MNT** - filesystem mount points.
- **IPC** - inter-process communication.
- **UTS** - hostname and domain name.
- **USER** - user and group IDs.
- **CGROUP** - cgroup hierarchy.

### 5.2 cgroups

Control groups limit and monitor resource usage:

- **CPU** - shares, quotas, periods.
- **Memory** - limits, soft limits, OOM behavior.
- **BlkIO** - block device I/O.
- **PIDs** - maximum number of processes.

### 5.3 Capabilities

Linux capabilities split root privileges into discrete units. Common dangerous capabilities:

- `CAP_SYS_ADMIN` - mount, pivot_root, and many privileged operations.
- `CAP_SYS_PTRACE` - attach to other processes.
- `CAP_NET_ADMIN` - network configuration.
- `CAP_SYS_MODULE` - load kernel modules.

A container running as root with all capabilities is effectively root on the host.

### 5.4 seccomp

seccomp filters system calls. A container can be restricted to a subset of syscalls, reducing the attack surface. Docker's default seccomp profile blocks ~44 syscalls.

### 5.5 LSM (AppArmor / SELinux)

Linux Security Modules provide mandatory access control. Docker uses AppArmor by default on Ubuntu and SELinux on RHEL/CentOS.

## 6. Container Lifecycle

1. **Build** - create an image from a Dockerfile.
2. **Push** - upload the image to a registry.
3. **Pull** - download the image to a host.
4. **Run** - create and start a container from the image.
5. **Stop** - gracefully stop the container.
6. **Remove** - delete the container and its writable layer.

## 7. Security Implications

- **Shared kernel** - a kernel vulnerability affects all containers on the host.
- **Misconfiguration** - privileged containers, mounted host paths, and dangerous capabilities are common.
- **Supply chain** - a compromised base image or dependency compromises every container.
- **Secrets management** - secrets in images or environment variables are easily leaked.

## 8. Verification

To verify container isolation:

- Check namespaces: `lsns` on the host shows container namespaces.
- Check capabilities: `capsh --print` inside a container.
- Check seccomp: `grep Seccomp /proc/self/status`.
- Check AppArmor: `aa-status` on the host.

## 9. Production Notes

- Use minimal base images (Alpine, distroless) to reduce attack surface.
- Run containers as non-root (`USER` directive in Dockerfile).
- Drop all capabilities and add only the required ones.
- Use read-only root filesystems where possible.
- Scan images for vulnerabilities before deployment.

## 10. References

- Docker documentation - https://docs.docker.com/
- containerd documentation - https://containerd.io/
- Kubernetes documentation - https://kubernetes.io/docs/
- Linux namespaces man page - https://man7.org/linux/man-pages/man7/namespaces.7.html
- Linux capabilities man page - https://man7.org/linux/man-pages/man7/capabilities.7.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final