# OSCP Linux

Linux machines prepared for the OSCP certification.

Final writeups are located in [`md/ru/`](./md/ru/). Raw drafts are kept in [`txt/ru/`](./txt/ru/). English translations (`md/en/`) are planned.

## Machines

| # | Machine | Difficulty | Key Techniques | Writeup |
|---|---------|------------|----------------|---------|
| 01 | Sea | Easy | WonderCMS CVE-2023-41425 (XSS to RCE), bcrypt crack, SSRF via monitoring service | [md](./md/ru/01%20Sea%20%28WonderCMS%20XSS%20to%20RCE%20CVE-2023-41425%20%2B%20bcrypt%20crack%20%2B%20SSRF%20via%20monitoring%29.md) |
| 02 | Nibbles | Easy | Nibbleblog 4.0.3 My Image upload, sudo NOPASSWD monitor.sh | [md](./md/ru/02%20Nibbles%20%28Nibbleblog%204.0.3%20My%20Image%20upload%20%2B%20sudo%20NOPASSWD%20monitor.sh%29.md) |
| 03 | Solidstate | Medium | Apache James password reset, rbash escape, cron tmp.py chmod SUID | [md](./md/ru/03%20Solidstate%20%28Apache%20James%20password%20reset%20%2B%20rbash%20escape%20%2B%20cron%20tmp.py%20chmod%20SUID%29.md) |
| 04 | Poison | Medium | phpinfo LFI race condition, base64 x13, VNC via SSH tunnel | [md](./md/ru/04%20Poison%20%28phpinfo%20LFI%20race%20condition%20%2B%20base64%20x13%20%2B%20VNC%20via%20SSH%20tunnel%29.md) |
| 05 | Editor | Easy | XWiki Groovy RCE CVE-2025-24893, hibernate.cfg password reuse, ndsudo PATH privesc | [md](./md/ru/05%20Editor%20%28XWiki%20Groovy%20RCE%20CVE-2025-24893%20%2B%20hibernate.cfg%20password%20reuse%20%2B%20ndsudo%20PATH%20privesc%29.md) |
| 06 | Enigma | Medium | NFS leak, OpenSTAManager P7M RCE, OliveTin command injection | [md](./md/ru/06%20Enigma%20%28NFS%20leak%20%2B%20OpenSTAManager%20P7M%20RCE%20%2B%20OliveTin%20command%20injection%29.md) |
| 07 | Sunday | Easy | Finger enum, shadow backup, hashcat SHA-256 crypt, sudo wget GTFOBins | [md](./md/ru/07%20Sunday%20%28Finger%20enum%20%2B%20shadow%20backup%20%2B%20hashcat%20SHA-256%20crypt%20%2B%20sudo%20wget%20GTFOBins%29.md) |
| 08 | Keeper | Easy | Request Tracker default creds, KeePass CVE-2023-32784, PPK SSH key | [md](./md/ru/08%20Keeper%20%28Request%20Tracker%20default%20creds%20%2B%20KeePass%20CVE-2023-32784%20%2B%20PPK%20SSH%20key%29.md) |
| 09 | Pilgrimage | Easy | Git dump, ImageMagick CVE-2022-44268 LFI, Binwalk CVE-2022-4510 RCE | [md](./md/ru/09%20Pilgrimage%20%28Git%20dump%20%2B%20ImageMagick%20CVE-2022-44268%20LFI%20%2B%20Binwalk%20CVE-2022-4510%20RCE%29.md) |
| 10 | CozyHosting | Easy | Spring Boot Actuator session leak, IFS injection, sudo ssh ProxyCommand | [md](./md/ru/10%20CozyHosting%20%28Spring%20Boot%20Actuator%20session%20leak%20%2B%20IFS%20injection%20%2B%20sudo%20ssh%20ProxyCommand%29.md) |
| 11 | Codify | Easy | vm2 CVE-2023-30547 sandbox escape, SQLite bcrypt, glob injection, pspy | [md](./md/ru/11%20Codify%20%28vm2%20CVE-2023-30547%20sandbox%20escape%20%2B%20SQLite%20bcrypt%20%2B%20glob%20injection%20%2B%20pspy%29.md) |
| 12 | TartarSauce | Medium | gwolle-gb RFI CVE-2015-8351, tar checkpoint, backuperer race, static SUID | [md](./md/ru/12%20TartarSauce%20%28gwolle-gb%20RFI%20CVE-2015-8351%20%2B%20tar%20checkpoint%20%2B%20backuperer%20race%20%2B%20static%20SUID%29.md) |
| 13 | Jarvis | Medium | SQL injection (manual UNION), INTO OUTFILE webshell, simpler.py command injection via `$()`, SUID systemctl | [md](./md/ru/13%20Jarvis%20%28SQL%20injection%20manual%20UNION%20INTO%20OUTFILE%20webshell%20%2B%20simpler.py%20command%20injection%20%2B%20SUID%20systemctl%29.md) |

## Archive

Raw drafts (before formatting) are stored in [`txt/ru/`](./txt/ru/).