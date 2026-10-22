# Sandbox Fundamentals

> [!CAUTION]
> Educational reference only. Escape techniques must be used exclusively in
> authorized testing, CTF environments, or your own isolated lab. Running them
> against systems you do not own is illegal.

## 1. Overview

A sandbox is an isolation boundary that constrains the actions of untrusted
code or content. The goal is containment: even if the code is malicious or
compromised, it cannot read other processes' memory, write outside its
assigned storage, open arbitrary network connections, or escalate its own
privileges.

Sandboxes are not a single technology. They are a composition of isolation
primitives provided by the OS and hardware: address space separation,
privilege levels, namespaces, syscall filtering, mandatory access control,
and (in the strongest cases) a hypervisor boundary.

This file covers the shared concepts. The following files apply them to
specific layers: browser, OS, mobile, and malware analysis sandboxes.

## 2. Threat Model

The sandbox threat model assumes:

- The code inside is untrusted (user content, downloaded apps, attacker
  payloads, malware).
- The code may actively try to escape, not just fail accidentally.
- A single bug in one isolation layer must not break the whole boundary
  (defense in depth).
- The sandbox is not the last line of defense - privilege separation and
  least privilege still apply outside it.

What a sandbox is NOT:

- Not a replacement for patching. Escapes usually exploit a kernel or
  renderer bug that a patch would fix.
- Not a guarantee against denial of service. Resource exhaustion is often
  possible even when data exfiltration is not.
- Not a protection against social engineering. If the user approves the
  action, the sandbox is bypassed by design.

## 3. Isolation Primitives

Modern sandboxes are built from a small set of primitives. Each one carries
a specific guarantee and a specific failure mode.

### 3.1 Address Space Isolation

Each process has its own virtual address space. The MMU enforces that a
process cannot read or write another process's memory. This is the oldest
and most fundamental isolation primitive.

Failure mode: a kernel bug that maps attacker-controlled pages into a
privileged process, or a side-channel that leaks memory (Spectre-class).

### 3.2 Privilege Levels

The CPU enforces at least two privilege levels (ring 0 kernel, ring 3 user).
Untrusted code runs at the lowest level. Privileged instructions and
privileged memory are reachable only through controlled kernel entry points.

Failure mode: a kernel vulnerability (use-after-free, type confusion,
missing bounds check) that lets a ring-3 process execute ring-0 code.

### 3.3 Namespaces

Namespaces give a process its own view of a global resource: PID namespace
(its own process tree), mount namespace (its own filesystem tree), network
namespace (its own interfaces and routing table), user namespace (its own
UID/GID mapping).

Failure mode: a namespace that is created without the matching capability
check, or a cross-namespace kernel object that is still shared (the classic
source of container escapes).

### 3.4 Syscall Filtering

seccomp-bpf (Linux) and similar mechanisms restrict which syscalls a process
may make. A renderer process that never needs `socket()` can be forbidden
from calling it, removing an entire attack surface.

Failure mode: an allowed syscall that is sufficient for an escape (e.g.
`ioctl` or `userfaultfd`), or a TOCTOU between the filter check and the use.

### 3.5 Mandatory Access Control

SELinux, AppArmor, and the macOS sandbox profiles restrict what a process can
do even if it runs as a privileged user. The policy is enforced by the kernel
and cannot be overridden by the confined process.

Failure mode: an overly permissive profile, or a policy that fails open when
a path is missing.

### 3.6 Capability and Resource Limits

Dropping capabilities (Linux `CAP_*`), rlimits, cgroups, and job objects
limit what a compromised process can do and how many resources it can consume.

Failure mode: an inherited capability that the sandbox designer assumed was
dropped, or a cgroup escape via a writable `release_agent`.

### 3.7 Hypervisor Boundary

The strongest isolation: the untrusted code runs in a separate VM, and the
only interface to the host is the hypervisor's device emulation. A bug in the
guest cannot touch host memory unless the hypervisor itself is exploited.

Failure mode: a hypervisor escape (see Virtualization 02 VM Escape). This is
why hypervisor boundaries are also hardened with the primitives above.

## 4. Isolation Layers by Use Case

Different sandboxes combine the primitives differently.

| Layer | Example | Primary primitives | Escape target |
|-------|---------|-------------------|---------------|
| Browser renderer | Chromium site isolation | Process per site, seccomp, sandbox helper | Renderer -> browser -> OS |
| OS application | Windows AppContainer, macOS App Sandbox | Job object, AppContainer, seatbelt profiles | App -> user -> admin |
| OS process | Flatpak, Snap, Firejail | Namespaces, seccomp, bind mounts | Confined app -> host |
| Container | Docker, Kubernetes pod | Namespaces, cgroups, capabilities | Container -> node |
| Mobile app | iOS, Android app sandbox | Per-app UID, entitlements, SELinux | App -> system -> other apps |
| Malware analysis | Cuckoo, CAPE, ANY.RUN | Full VM + network emulation | Guest -> host (rare) |

The general rule: the closer the untrusted code is to the user, the more
layers are stacked. A browser renderer has more isolation primitives than a
normal desktop process because it handles arbitrary web content all day.

## 5. Common Attack Vectors

Sandbox escapes follow a small number of patterns.

### 5.1 Kernel Vulnerability

The sandboxed process triggers a memory-safety bug in the kernel (or in a
kernel driver) and gains kernel-level execution. From ring 0, all the
sandbox's user-space restrictions are irrelevant.

Examples: io_uring bugs, netfilter bugs, filesystem bugs, GPU driver bugs.
This is the most common class of container and OS sandbox escapes.

### 5.2 Logic Bug in the Broker

A sandbox usually has a privileged broker process that performs actions on
behalf of the sandboxed process (open a file the user picked, launch a
helper). A logic bug in the broker's validation lets the sandboxed process
request something it should not be allowed to.

Examples: path traversal in a file-open broker, missing validation of a
returned handle, confused deputy in an IPC handler.

### 5.3 IPC Confusion

The sandboxed process talks to privileged services over IPC (D-Bus, XPC,
Binder, Mojo). A type confusion or a missing sender check lets it invoke a
privileged method that was meant only for a trusted caller.

### 5.4 Symlink and Path Races

A sandbox that allows access to a path but re-resolves it later is vulnerable
to a symlink swap or a TOCTOU race. The classic container escape: a writable
host path mounted into the container, where the container replaces a file
with a symlink to `/etc/shadow`.

### 5.5 Resource Exhaustion

Even without a memory-safety bug, a sandbox that does not limit CPU, memory,
file descriptors, or disk can be forced into a state where another component
(the broker, the host) fails. This is denial of service, not escape, but it
often precedes an escape by creating a race window.

## 6. Exploitation Recipes

### 6.1 Reconnaissance from Inside the Sandbox

Before attempting an escape, map the environment:

```bash
# what am I, what can I see
id; uname -a; cat /proc/self/status | grep -E 'Cap|Seccomp|NoNewPrivs'

# what namespaces am I in
ls -l /proc/self/ns/

# what is mounted, and what is writable
mount | grep -E 'rw|nosuid|noexec'
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS

# what capabilities do I hold
capsh --print 2>/dev/null || grep Cap /proc/self/status
```

Expected (container example):

```text
CapEff: 00000000a80425fb
Seccomp: 2
NoNewPrivs: 1
```

`CapEff` non-zero means capabilities remain. `Seccomp: 2` means a filter is
active. `NoNewPrivs: 1` means setuid binaries cannot gain privileges.

### 6.2 Writable Host Mount

The most common misconfiguration: a host directory is mounted read-write
into the sandbox.

```bash
# is any host path mounted rw
findmnt -o TARGET,SOURCE,OPTIONS | grep -i ' /host\| /mnt\|docker'

# if yes, can a symlink be created there
ln -s /etc/shadow /host/mnt/innocent.txt && ls -l /host/mnt/innocent.txt
```

If the symlink is created and the host resolves it later, the sandbox has
read (or write) access to a host file it should never see.

### 6.3 Capability Check

```bash
# look for capabilities that are rarely needed and often dangerous
grep -E 'Cap(Prm|Eff|Bnd)' /proc/self/status

# CAP_SYS_ADMIN is the classic "root equivalent in a container"
capsh --decode=00000000a80425fb
```

`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, and `CAP_DAC_READ_SEARCH`
are each sufficient for a container escape in most configurations.

### 6.4 Kernel Version Check

A kernel version by itself is not a vulnerability, but it narrows the
candidate bug class.

```bash
uname -r
cat /proc/version
```

Match against the kernel CVE list for the exact version range. Do not guess:
a version that looks old may already be patched by the distribution.

## 7. Post-Exploitation

Once out of the sandbox, the attacker is at the privilege level of the
sandbox host component that was escaped.

- Renderer escape: code runs as the browser's sandbox helper, still confined
  by the OS sandbox. A second escape is required to reach the user's files.
- Container escape: code runs as the host user that started the container
  (often root if the daemon runs as root).
- OS sandbox escape: code runs as the user that launched the sandboxed app.

Post-exploitation priorities, in order:

1. Confirm the actual privilege level (`id`, `whoami /priv`).
2. Map the new filesystem and network view.
3. Look for credentials (the host user's SSH keys, browser profile, tokens).
4. Establish persistence at the new level.
5. Cover tracks if this is a red-team engagement.

## 8. Preventive Controls

- Keep the isolation boundary patched. Kernel and hypervisor updates close
  the majority of known escapes.
- Apply least privilege outside the sandbox. A container that escapes into a
  host process running as root is a full compromise; the same container
  escaping into an unprivileged user is contained.
- Drop capabilities that the workload does not need. Deny-by-default
  (`--cap-drop ALL` then add back the minimum) is the correct posture.
- Enable the syscall filter. A seccomp allow-list removes entire bug classes.
- Do not mount host paths read-write unless the workload genuinely needs it.
  Prefer bind mounts of specific files over directory mounts.
- Enable mandatory access control (SELinux/AppArmor) even inside the sandbox.
- Use user namespaces with a non-root mapping so that a kernel bug that
  yields "root in the namespace" does not yield root on the host.

## 9. Detection Controls

- Audit syscall activity from sandboxed processes. A sudden burst of unusual
  syscalls (`ioctl` on device nodes, `unshare`, `mount`) is a strong signal.
- Monitor for namespace creation and capability changes at runtime.
- Alert on writes to host-mounted paths from inside a sandbox.
- Correlate kernel crash reports (oops, panic) with sandboxed process PIDs.
- For browser sandboxes, monitor renderer crashes and restarts - repeated
  crashes in the same site are a fuzzing/exploitation signal.
- For mobile, monitor entitlement abuse and cross-app data access attempts.

## 10. Verification

To verify a sandbox configuration is effective:

1. Enumerate the active primitives from inside the sandbox (section 6.1).
2. Confirm each primitive that should be active is active. A missing
   `Seccomp` line or a non-zero `CapEff` is a defect.
3. Test the isolation boundary with a benign escape attempt (a symlink to a
   host file, a request to a privileged broker method).
4. Confirm the attempt is blocked AND logged. Blocked without a log is a
   detection gap.
5. Re-run after every configuration change. Sandbox configuration drifts.

## 11. References

- seccomp - https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- Linux namespaces - https://man7.org/linux/man-pages/man7/namespaces.7.html
- Linux capabilities - https://man7.org/linux/man-pages/man7/capabilities.7.html
- SELinux - https://selinuxproject.org/page/Main_Page
- AppArmor - https://apparmor.net/
- Chromium sandbox - https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- Windows AppContainer - https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
- NIST SP 800-190, Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final