sudo nmap -sC -sV -Pn -T5 -A 10.113.130.161 -oN Mr-Robot

Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-06 08:49 +0400
Nmap scan report for 10.113.130.161
Host is up (0.073s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 f7:ae:63:d8:73:ee:66:1c:a4:03:ab:08:92:9b:43:83 (RSA)
|   256 41:34:e0:18:8e:99:bd:d0:38:3d:0c:ae:a4:b4:52:06 (ECDSA)
|_  256 7d:5f:8d:67:da:73:a4:e1:0e:ae:d5:86:77:3c:83:98 (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 4.X|5.X|3.X (91%), Crestron 2-Series (86%), Google Android 10.X|11.X|12.X (85%),
HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:crestron:2_series cpe:/o:linux:linux_kernel:3 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 4.15 - 5.19 (91%), Linux 4.15 (90%), Linux 5.4 (90%), Crestron XPanel control system (86%), Linux 3.8 - 3.16 (86%), Android 10 - 12 (Linux 4.14 - 4.19) (85%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   67.26 ms 192.168.128.1
2   ...
3   68.48 ms 10.113.130.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.11 seconds



----------------------------------------------------------------------------------------------------------------------




gobuster dir -u http://10.113.130.161:80 -w /usr/share/wordlists/dirb/common.txt

===============================================================

Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.113.130.161:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta                 (Status: 403) [Size: 213]
.htaccess            (Status: 403) [Size: 218]
.htpasswd            (Status: 403) [Size: 218]
0                    (Status: 301) [Size: 0] [--> http://10.113.130.161:80/0/]
admin                (Status: 301) [Size: 236] [--> http://10.113.130.161/admin/]
atom                 (Status: 200) [Size: 631]
audio                (Status: 301) [Size: 236] [--> http://10.113.130.161/audio/]
blog                 (Status: 301) [Size: 235] [--> http://10.113.130.161/blog/]
css                  (Status: 301) [Size: 234] [--> http://10.113.130.161/css/]
dashboard            (Status: 302) [Size: 0] [--> http://10.113.130.161:80/wp-admin/]
favicon.ico          (Status: 200) [Size: 0]
feed                 (Status: 200) [Size: 813]
Image                (Status: 301) [Size: 0] [--> http://10.113.130.161:80/Image/]
image                (Status: 301) [Size: 0] [--> http://10.113.130.161:80/image/]
images               (Status: 301) [Size: 237] [--> http://10.113.130.161/images/]
index.html           (Status: 200) [Size: 1188]
index.php            (Status: 301) [Size: 0] [--> http://10.113.130.161:80/]
intro                (Status: 200) [Size: 516314]
js                   (Status: 301) [Size: 233] [--> http://10.113.130.161/js/]
license              (Status: 200) [Size: 309]
login                (Status: 302) [Size: 0] [--> http://10.113.130.161:80/wp-login.php]
page1                (Status: 200) [Size: 8263]
phpmyadmin           (Status: 403) [Size: 94]
rdf                  (Status: 200) [Size: 817]
readme               (Status: 200) [Size: 64]
robots               (Status: 200) [Size: 41]
robots.txt           (Status: 200) [Size: 41]
rss                  (Status: 200) [Size: 366]
rss2                 (Status: 200) [Size: 813]
sitemap              (Status: 200) [Size: 0]
sitemap.xml          (Status: 200) [Size: 0]
video                (Status: 301) [Size: 236] [--> http://10.113.130.161/video/]
wp-admin             (Status: 301) [Size: 239] [--> http://10.113.130.161/wp-admin/]
wp-content           (Status: 301) [Size: 241] [--> http://10.113.130.161/wp-content/]
wp-config            (Status: 200) [Size: 0]
wp-cron              (Status: 200) [Size: 0]
wp-includes          (Status: 301) [Size: 242] [--> http://10.113.130.161/wp-includes/]
wp-links-opml        (Status: 200) [Size: 227]
wp-load              (Status: 200) [Size: 0]
wp-login             (Status: 200) [Size: 2667]
wp-mail              (Status: 500) [Size: 3074]
wp-settings          (Status: 500) [Size: 0]
wp-signup            (Status: 302) [Size: 0] [--> http://10.113.130.161:80/wp-login.php?action=register]
xmlrpc               (Status: 405) [Size: 42]
xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================



----------------------------------------------------------------------------------------------------------------------



http://10.113.130.161/robots.txt            ->          User-agent: *
                                                        fsocity.dic
                                                        key-1-of-3.txt


http://10.113.130.161/key-1-of-3.txt        ->          <USER_FLAG>



http://10.113.130.161/fsocity.dic           ->          wordlist




----------------------------------------------------------------------------------------------------------------------





