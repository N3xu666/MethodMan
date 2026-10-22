# OS-Level Sandboxes

> [!CAUTION]
> Educational reference only. Escape techniques must be used exclusively in
> authorized testing, CTF environments, or your own isolated lab. Running them
> against systems you do not own is illegal.

## 1. Overview

OS-level sandboxes confine an application to a restricted view of the system
without running a full virtual machine. The OS itself enforces the boundary
using namespaces, syscall filters, mandatory access control, capabilities, and
job objects. The application runs directly on the host kernel, so an escape
means a kernel-level bug (or a logic bug in the broker) rather than a
hypervisor bug.

This file covers the OS-level sandbox mechanisms on Linux, Windows, and macOS,
how they break, and how to test and harden them.

## 2. Threat Model

OS-level sandboxes defend against:

- A compromised application process (a PDF reader parsing a malicious file,
  a media player decoding a crafted stream).
- A malicious package or app the user installed but should not fully trust.
- A compromised browser renderer or plugin (the OS sandbox is the second
  layer beneath the browser's own sandbox).
- A container workload that is expected to be less trusted than the host.

What they do NOT defend against:

- A kernel vulnerability that the sandbox itself relies on (the escape target).
- A misconfiguration that grants the sandboxed process a capability it should
  not have (the escape is often trivial once a capability leaks).
- A user who grants broad file access through a file-picker broker.

The boundary is only as strong as the kernel and the configuration.

## 3. How OS-Level Sandboxes Work

### 3.1 Linux

The Linux sandbox is a composition of independent mechanisms:

- **Namespaces**: PID, mount, network, user, UTS, IPC, cgroup. Each gives the
  process a private view of one global resource.
- **seccomp-bpf**: a per-process syscall allow-list or deny-list enforced by
  the kernel before the syscall runs.
- **Capabilities**: fine-grained root privileges (`CAP_NET_ADMIN`,
  `CAP_SYS_ADMIN`, etc.). A sandbox usually drops all of them.
- **LSM (SELinux/AppArmor)**: mandatory access control that restricts what the
  process can do even if it has the UID or capability.
- **cgroups**: resource limits (CPU, memory, pids) and, in v2, some access
  control.
- **Landlock**: an unprivileged LSM for filesystem and network access, usable
  by the process itself.

A typical Linux application sandbox (Flatpak, Snap, Firejail, bubblewrap)
combines namespaces + seccomp + a bind-mounted filesystem + a capability drop.

### 3.2 Windows

The Windows sandbox is built from:

- **Restricted token / job object**: a token with fewer privileges, and a job
  that limits process creation and resource use.
- **AppContainer**: a per-app isolation boundary; the app cannot access
  resources outside its container unless a capability is granted.
- **Integrity levels**: Low/Medium/High/System; a low-integrity process cannot
  write to a high-integrity object.
- **Win32k lockdown**: removes the window-manager syscall surface from a
  sandboxed process (used by the browser renderer).
- **Arbitrary Code Guard / Code Integrity Guard**: prevents the sandboxed
  process from loading unsigned or dynamically generated code.

Windows Defender Application Guard (WDAG) and Windows Sandbox are full
VM-based sandboxes; AppContainer is the lighter process-level boundary.

### 3.3 macOS

macOS uses the Seatbelt (sandbox) framework. A profile lists which operations
the process may perform (file read, file write, network, mach IPC, sysctl).
The kernel enforces the profile via the `sandbox` MAC framework.

App Sandbox (for Mac App Store apps) is a Seatbelt profile generated from the
app's entitlements. A hardened runtime adds code-signing enforcement and
library validation.

## 4. Common Attack Vectors

### 4.1 Kernel Vulnerabilities

The most direct escape: the sandboxed process triggers a memory-safety bug in
the kernel and gains kernel-level execution. From ring 0, the sandbox
configuration is irrelevant.

High-value targets inside a sandbox:

- io_uring (Linux): a large, complex syscall surface reachable from many
  sandboxes.
- Netfilter/nftables (Linux): reachable if the sandbox has network namespace
  privileges.
- Filesystem drivers (all OSes): reached through a mounted image or a crafted
  filesystem.
- GPU drivers (all OSes): reached through a graphics API from a sandboxed
  process.
- win32k (Windows): historically the largest sandbox-escape surface, which is
  why Win32k lockdown exists.

### 4.2 Capability Leak

A capability that the sandbox designer assumed was dropped, but was inherited
from the parent process, is sufficient for a full escape.

Classic examples on Linux:

- `CAP_SYS_ADMIN` in a container = root on the host in most configurations.
- `CAP_SYS_PTRACE` = attach to host processes.
- `CAP_DAC_READ_SEARCH` = read any file regardless of permissions.
- `CAP_SYS_MODULE` = load a kernel module.

### 4.3 Writable Host Mount

A host path bind-mounted read-write into the sandbox lets the sandbox write
files on the host. A symlink or a hardlink turns this into arbitrary file
read/write on the host.

### 4.4 Broker and IPC Bugs

The sandbox's privileged broker (the component that performs actions on the
sandboxed process's behalf) is a target. A path traversal, a missing sender
check, or a type confusion in the broker's handler can let the sandboxed
process perform operations it should not.

Examples: D-Bus services reachable from a Flatpak app, XPC services on macOS,
COM/RPC endpoints on Windows.

### 4.5 Namespace Confusion

A process that joins a namespace it should not (e.g. inherits the host
network namespace when it expected a private one) has a broader view than the
sandbox designer intended. Often caused by a missing `CLONE_NEW*` flag or a
permissive `nsenter`.

### 4.6 Setuid and File Capabilities

A setuid binary or a file with a file capability inside the sandbox defeats
the capability drop. The sandbox must also set `no_new_privs` to prevent this.

## 5. Exploitation Recipes

### 5.1 Enumerate the Sandbox State

From inside the sandbox, map what is active.

```bash
# identity and privilege state
id; uname -a
cat /proc/self/status | grep -E 'Cap|Seccomp|NoNewPrivs'

# namespaces I am in
ls -l /proc/self/ns/

# capabilities, decoded
capsh --print 2>/dev/null || true

# filesystem view and writable mounts
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
```

Expected (a well-confined app):

```text
CapEff: 0000000000000000
Seccomp: 2
NoNewPrivs: 1
```

Any non-zero `CapEff`, missing `Seccomp`, or `NoNewPrivs: 0` is a defect
worth investigating.

### 5.2 Look for Dangerous Capabilities

```bash
# decode the effective capability mask
grep CapEff /proc/self/status
capsh --decode=00000000a80425fb 2>/dev/null

# specific high-risk capabilities
for c in sys_admin sys_ptrace sys_module dac_read_search; do
  grep -qi "cap_$c" /proc/self/status && echo "HAS cap_$c"
done
```

### 5.3 Writable Host Mount Check

```bash
# any host path writable from inside
findmnt -o TARGET,SOURCE,OPTIONS -r | grep -E 'rw' | grep -v -E '/proc|/sys|/dev'

# test a symlink attack against a bind-mounted host directory
# (replace /host with the actual mount target)
ls -ld /host 2>/dev/null && ln -s /etc/passwd /host/x 2>/dev/null && ls -l /host/x
```

If the symlink is created and the host resolves it later, the sandbox has
host file access.

### 5.4 Broker Surface Enumeration

```bash
# D-Bus services reachable from inside the sandbox (Linux)
busctl list 2>/dev/null | head
dbus-send --session --dest=org.freedesktop.DBus --type=method_call \
  --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null

# XPC services on macOS (from inside the sandbox)
launchctl list 2>/dev/null | head
```

Each reachable service is a potential broker. Validate its methods' input
handling before trusting it.

### 5.5 Setuid and File Capabilities

```bash
# setuid binaries visible from inside
find / -perm -4000 -type f 2>/dev/null

# files with file capabilities
getcap -r / 2>/dev/null

# is no_new_privs set (blocks the above from being exploitable)
grep NoNewPrivs /proc/self/status
```

## 6. Post-Exploitation

Once out of the OS sandbox, the attacker runs at the privilege level of the
sandbox broker or the host user that launched the sandboxed process.

Typical post-exploitation:

1. Confirm the actual privilege level (`id`, `whoami /priv`, `csrutil status`).
2. Map the host filesystem and network view.
3. Look for credentials: SSH keys, browser profile, cloud tokens, keychain.
4. Establish persistence at the new level.
5. For red-team engagements, document the escape path and clean up.

A kernel-level escape yields ring 0 and bypasses all user-space controls;
that is a full host compromise and must be reported as critical.

## 7. Preventive Controls

- Keep the kernel patched. Kernel vulnerabilities are the primary escape path.
- Drop all capabilities; add back only the ones the workload genuinely needs
  (`--cap-drop ALL` then `--cap-add`).
- Enable seccomp with an allow-list, not a deny-list.
- Set `no_new_privs` so setuid binaries and file capabilities cannot re-grant
  privilege inside the sandbox.
- Do not bind-mount host directories read-write. Bind specific files if
  needed, and make the bind mount read-only when possible.
- Use user namespaces with a non-root UID mapping so that "root in the
  namespace" is not root on the host.
- Enable an LSM (SELinux or AppArmor) even inside the sandbox.
- On Windows, use AppContainer + Win32k lockdown + ACG/CIG for renderer-type
  workloads.
- On macOS, use App Sandbox + hardened runtime for apps that handle
  untrusted content.

## 8. Detection Controls

- Audit syscall activity from sandboxed processes; a sudden burst of
  `ioctl`, `mount`, `unshare`, `bpf`, or `perf_event_open` is a signal.
- Monitor capability changes at runtime (a process acquiring a capability it
  did not start with).
- Alert on writes to host-mounted paths from inside a sandbox.
- Correlate kernel oops/panic reports with sandboxed process PIDs.
- On Windows, monitor token integrity-level changes and job-object breakouts.
- On macOS, monitor Seatbelt profile violations in the system log.

## 9. Verification

To verify an OS-level sandbox configuration:

1. Enumerate the active primitives from inside the sandbox (section 5.1).
2. Confirm each primitive that should be active is active. Missing seccomp,
   non-zero capabilities, or `NoNewPrivs: 0` are defects.
3. Confirm no host directory is mounted read-write.
4. Confirm setuid binaries and file capabilities are either absent or
   neutralized by `no_new_privs`.
5. Test the broker surface with a benign malformed request; confirm it is
   rejected and logged.
6. Re-verify after every configuration change and after every kernel update.

## 10. References

- bubblewrap - https://github.com/containers/bubblewrap
- Flatpak sandbox - https://docs.flatpak.org/en/latest/sandbox-permissions.html
- seccomp - https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- Linux capabilities - https://man7.org/linux/man-pages/man7/capabilities.7.html
- Landlock - https://landlock.io/
- AppContainer isolation - https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
- Win32k lockdown - https://learn.microsoft.com/en-us/windows/win32/winmsg/win32k-lockdown
- macOS App Sandbox - https://developer.apple.com/documentation/security/app_sandbox
- NIST SP 800-190, Application Container Security Guide - https://csrc.nist.gov/pubs/sp/800/190/final